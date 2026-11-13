"""Etapa 1: descoberta de nomes com procedência, filtragem de escopo, DNS e wildcard."""

from __future__ import annotations

import json
from pathlib import Path

from . import dns as dnsmod
from .escopo import Escopo, normalizar_host
from .ferramentas import LimitadorTaxa, Montador, executar_simples, exigir, inspecionar
from .rodada import Rodada, agora_utc, escrever_json, escrever_jsonl, ler_csv, ler_jsonl

FONTES_INTERNAS = {"zona_dns", "f5", "firewall", "proxy", "gateway", "nuvem", "inventario_interno"}


def _ler_lista(caminho: Path) -> list[tuple[int, str, dict]]:
    """Lê TXT (um nome por linha) ou CSV com coluna 'host'. Retorna (linha, valor, metadados)."""
    if caminho.suffix.lower() == ".csv":
        saida = []
        for i, linha in enumerate(ler_csv(caminho), start=2):
            valor = linha.get("host") or linha.get("nome") or ""
            saida.append((i, valor, {k: v for k, v in linha.items() if k not in ("host", "nome") and v}))
        return saida
    with open(caminho, encoding="utf-8-sig", errors="replace") as f:
        return [(i, l.rstrip("\n"), {}) for i, l in enumerate(f, start=1) if l.strip() and not l.lstrip().startswith("#")]


def _ler_subfinder(caminho: Path) -> list[tuple[int, str, dict]]:
    """Aceita saída texto ou JSONL (-oJ -cs) do Subfinder, preservando as fontes passivas."""
    saida = []
    if not caminho.exists():
        return saida
    with open(caminho, encoding="utf-8", errors="replace") as f:
        for i, linha in enumerate(f, start=1):
            linha = linha.strip()
            if not linha:
                continue
            if linha.startswith("{"):
                try:
                    obj = json.loads(linha)
                except json.JSONDecodeError:
                    continue
                fontes = obj.get("sources") or ([obj["source"]] if obj.get("source") else [])
                saida.append((i, obj.get("host", ""), {"fontes_passivas": sorted(set(fontes))}))
            else:
                saida.append((i, linha, {}))
    return saida


def consolidar_candidatos(escopo: Escopo, entradas: list[tuple[str, Path, list]]) -> dict:
    """entradas: (fonte, arquivo, linhas). Retorna candidatos, fora do escopo, dependências e curingas."""
    candidatos: dict[str, dict] = {}
    fora: list[dict] = []
    dependencias: list[dict] = []
    curingas: list[dict] = []
    for fonte, arquivo, linhas in entradas:
        for num, valor, meta in linhas:
            proc = {"fonte": fonte, "arquivo": arquivo.name, "linha": num}
            if meta.get("fontes_passivas"):
                proc["fontes_passivas"] = meta["fontes_passivas"]
            if meta.get("fonte"):
                proc["fonte_interna"] = meta["fonte"]
            host, motivo = normalizar_host(valor)
            if motivo == "vazio":
                continue
            if motivo == "curinga":
                base, _ = normalizar_host(str(valor).strip().lower()[2:])
                curingas.append({"valor": str(valor).strip()[:255], "ramo": base, **proc,
                                 "nota": "registro/certificado curinga não equivale a wildcard DNS"})
                continue
            if not host:
                fora.append({"valor": str(valor).strip()[:255], "motivo": motivo, **proc})
                continue
            ok, motivo_escopo = escopo.host_no_escopo(host)
            if not ok:
                registro = {"host": host, "motivo": motivo_escopo, **proc}
                if fonte != "subfinder":
                    # Nomes externos vindos de fontes internas (parceiros, fornecedores) são dependências.
                    dependencias.append({**registro, "responsavel": meta.get("responsavel", ""),
                                         "observacao": meta.get("observacao", "")})
                else:
                    fora.append(registro)
                continue
            c = candidatos.setdefault(host, {"host": host, "fontes": [], "procedencia": [], "responsavel": "",
                                             "portas_declaradas": [], "terceiro": escopo.eh_terceiro(host),
                                             "motivo_escopo": motivo_escopo, "estado": {"nome_descoberto": True}})
            if fonte not in c["fontes"]:
                c["fontes"].append(fonte)
            c["procedencia"].append(proc)
            if meta.get("responsavel") and not c["responsavel"]:
                c["responsavel"] = meta["responsavel"]
            for p in str(meta.get("portas", "")).replace(";", ",").split(","):
                p = p.strip()
                if p.isdigit() and int(p) not in c["portas_declaradas"]:
                    c["portas_declaradas"].append(int(p))
            if str(meta.get("terceiro", "")).lower() in ("sim", "s", "true", "1"):
                c["terceiro"] = True
    for c in candidatos.values():
        c["respaldo_interno"] = any(f in ("semente", "inventario_interno") for f in c["fontes"])
    return {"candidatos": dict(sorted(candidatos.items())), "fora": fora, "dependencias": dependencias,
            "curingas": curingas}


def executar(rodada: Rodada, sementes: Path | None, hosts_internos: Path | None, subfinder_saida: Path | None,
             usar_subfinder: bool, usar_dns: bool, dns_fixture: Path | None, dry_run: bool, forcar: bool,
             argv_cli: list[str]) -> dict:
    etapa = rodada.etapa("descoberta")
    if etapa.get("estado") == "concluida" and not forcar and not dry_run:
        print("descoberta já concluída nesta rodada (use --forcar para refazer)")
        return etapa.get("resumo", {})
    cfg = rodada.config
    escopo = Escopo.de_config(cfg)
    rodada.iniciar_etapa("descoberta", dry_run, argv_cli)
    plano: dict = {"etapa": "descoberta", "dry_run": dry_run, "comandos": [], "consultas_dns_estimadas": 0}

    entradas = []
    if sementes:
        s = rodada.registrar_entrada("sementes", sementes)
        entradas.append(("semente", s, _ler_lista(s)))
    if hosts_internos:
        h = rodada.registrar_entrada("hosts-internos", hosts_internos)
        entradas.append(("inventario_interno", h, _ler_lista(h)))

    # ---- Subfinder (passivo: consulta fontes de terceiros, não o alvo)
    dcfg = cfg.get("descoberta", {})
    raizes = dcfg.get("dominios_raiz") or escopo.dominios_exatos[:1] or escopo.sufixos[:1]
    if subfinder_saida:
        sf = rodada.registrar_entrada("subfinder-importado", subfinder_saida)
        entradas.append(("subfinder", sf, _ler_subfinder(sf)))
    elif usar_subfinder:
        info = inspecionar("subfinder", cfg.get("ferramentas", {}).get("subfinder", "subfinder"))
        rodada.manifesto["ferramentas"]["subfinder"] = info.resumo()
        rodada.salvar()
        exigir(info, dry_run)
        for raiz in raizes:
            destino = rodada.p("bruto", f"subfinder-{raiz}.jsonl")
            m = Montador(info)
            m.add("-d", raiz).add("-silent").add("-o", destino).add("-duc", opcional=True)
            m.add("-oJ", opcional=True).add("-cs", opcional=True).add("-nc", opcional=True)
            m.add("-timeout", int(dcfg.get("subfinder_timeout_s", 30)))
            m.add("-max-time", int(dcfg.get("subfinder_max_minutos", 10)))
            plano["comandos"].append({"argv": m.argv, "omitidas": m.omitidas})
            if dry_run:
                continue
            if destino.exists():
                destino.unlink()
            r = executar_simples(m.argv, rodada.p("bruto", f"subfinder-{raiz}.log"),
                                 duracao_max_s=int(dcfg.get("subfinder_max_minutos", 10)) * 60 + 60)
            if r.codigo != 0 or r.interrompido:
                rodada.registrar_erro("descoberta", "subfinder", raiz, f"código={r.codigo} interrompido={r.interrompido}")
            entradas.append(("subfinder", destino, _ler_subfinder(destino)))

    res = consolidar_candidatos(escopo, entradas)
    candidatos = res["candidatos"]

    # ---- DNS e wildcard
    wildcards: dict[str, dict] = {}
    if usar_dns:
        amostras = int(cfg.get("dns", {}).get("amostras_wildcard", 3))
        ramos = dnsmod.ramos_para_wildcard(list(candidatos), [*escopo.dominios_exatos, *escopo.sufixos],
                                           int(cfg.get("dns", {}).get("ramos_wildcard_max", 20)))
        ramos = list(dict.fromkeys(ramos))
        plano["consultas_dns_estimadas"] = len(candidatos) * 3 + len(ramos) * amostras * 3
        plano["ramos_wildcard"] = ramos
        if not dry_run:
            resolvedor = dnsmod.criar_resolvedor(cfg, dns_fixture)
            limitador = LimitadorTaxa(float(cfg.get("dns", {}).get("taxa_por_segundo", 5)))
            rodada.manifesto["dns"] = {"resolvedor": resolvedor.descrever(), "consultado_em": agora_utc()}

            def consultar(nome: str) -> dict[str, dnsmod.RespostaDNS]:
                out = {}
                for tipo in dnsmod.TIPOS:
                    limitador.aguardar()
                    out[tipo] = resolvedor.consultar(nome, tipo)
                return out

            for ramo in ramos:
                testes = []
                for _ in range(amostras):
                    nome = f"{dnsmod.rotulo_aleatorio()}.{ramo}"
                    resp = consultar(nome)
                    testes.append({"nome": nome, "estado": dnsmod.classificar(resp),
                                   "registros": dnsmod.registros_consolidados(resp)})
                resolvidos = [t for t in testes if t["estado"] == "resolvido"]
                valores = sorted({v for t in resolvidos for vs in t["registros"].values() for v in vs})
                wildcards[ramo] = {"ramo": ramo, "wildcard": bool(resolvidos),
                                   "amostras": testes, "valores_genericos": valores,
                                   "conclusao": "wildcard DNS observado" if resolvidos else
                                   ("inconclusivo (erros)" if any(t["estado"] == "erro" for t in testes)
                                    else "sem wildcard observado")}
            for host, c in candidatos.items():
                resp = consultar(host)
                estado = dnsmod.classificar(resp)
                regs = dnsmod.registros_consolidados(resp)
                c["dns"] = {"estado": estado, "registros": regs,
                            "por_tipo": {t: {"status": r.status, "erro": r.erro} for t, r in resp.items()}}
                ramo = dnsmod.ramo_wildcard_de(host, wildcards)
                generico = False
                if ramo and estado == "resolvido":
                    vals = {v for vs in regs.values() for v in vs}
                    generico = bool(vals) and vals <= set(wildcards[ramo]["valores_genericos"])
                c["dns"]["ramo_wildcard"] = ramo
                c["dns"]["resposta_generica"] = generico
                c["estado"]["dns_resolvido"] = estado == "resolvido"
                # Nomes respaldados por registros internos são mantidos mesmo com resposta genérica.
                if generico and not c["respaldo_interno"]:
                    c["manter"] = False
                    c["motivo_descartar"] = "resposta idêntica ao wildcard do ramo; sem respaldo interno"
                else:
                    c["manter"] = estado == "resolvido" or c["respaldo_interno"]
                    if not c["manter"]:
                        c["motivo_descartar"] = f"dns {estado} e sem respaldo interno"
                if estado == "erro":
                    rodada.registrar_erro("descoberta", "dns", host, json.dumps(c["dns"]["por_tipo"]))
    for c in candidatos.values():
        c.setdefault("manter", True)

    if dry_run:
        plano["candidatos_sem_subfinder"] = len(candidatos)
        escrever_json(rodada.p("descoberta", "plano.json"), plano)
        rodada.concluir_etapa("descoberta", {"candidatos": len(candidatos)}, dry_run=True)
        return plano

    escrever_jsonl(rodada.p("descoberta", "candidatos.jsonl"), candidatos.values())
    with open(rodada.p("descoberta", "candidatos.txt"), "w", encoding="utf-8") as f:
        f.writelines(h + "\n" for h in candidatos)
    escrever_jsonl(rodada.p("descoberta", "fora-escopo.jsonl"), res["fora"])
    escrever_jsonl(rodada.p("descoberta", "dependencias.jsonl"), res["dependencias"])
    escrever_jsonl(rodada.p("descoberta", "curingas-declarados.jsonl"), res["curingas"])
    escrever_jsonl(rodada.p("descoberta", "wildcard.jsonl"), wildcards.values())
    resumo = {
        "candidatos": len(candidatos),
        "por_fonte": _contar(f for c in candidatos.values() for f in c["fontes"]),
        "fora_escopo": len(res["fora"]),
        "dependencias": len(res["dependencias"]),
        "curingas_declarados": len(res["curingas"]),
        "dns_executado": usar_dns,
        "dns_estados": _contar(c.get("dns", {}).get("estado", "nao_consultado") for c in candidatos.values()),
        "respostas_genericas": sum(1 for c in candidatos.values() if c.get("dns", {}).get("resposta_generica")),
        "ramos_com_wildcard": sorted(r for r, w in wildcards.items() if w["wildcard"]),
        "mantidos": sum(1 for c in candidatos.values() if c["manter"]),
    }
    escrever_json(rodada.p("descoberta", "cobertura.json"), resumo)
    rodada.concluir_etapa("descoberta", resumo)
    return resumo


def _contar(itens) -> dict:
    out: dict[str, int] = {}
    for i in itens:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items()))


def carregar_candidatos(rodada: Rodada) -> dict[str, dict]:
    return {c["host"]: c for c in ler_jsonl(rodada.p("descoberta", "candidatos.jsonl"))}
