"""Etapa 3: confirmação de exposição HTTP com httpx, salto a salto, sem seguir redirecionamentos automaticamente."""

from __future__ import annotations

import time
from urllib.parse import urljoin, urlsplit

from .escopo import Escopo, chave_origem
from .ferramentas import ErroFerramenta, Montador, executar_streaming, exigir, inspecionar, verificar_janela
from .revisao import carregar_aprovados
from .rodada import Rodada, escrever_json, escrever_jsonl, ler_jsonl
from .sanitizacao import sanitizar_texto, sanitizar_url

CAMPOS_DESCARTADOS = ("body", "raw_header", "response", "request", "raw", "header", "headers", "hash",
                      "favicon", "jarm", "screenshot_bytes", "chain")

ASSINATURAS_WAF_TITULO = ("request rejected", "the requested url was rejected", "access denied",
                          "attention required", "web application firewall", "acesso negado")
ASSINATURAS_WAF_SERVIDOR = ("bigip", "big-ip", "f5", "cloudflare", "akamaighost", "imperva", "incapsula")


def filtrar_httpx(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in CAMPOS_DESCARTADOS}


def classificar_erro(mensagem: str) -> str:
    m = (mensagem or "").lower()
    if any(s in m for s in ("no address found", "no such host", "could not resolve", "dns")):
        return "falha_dns"
    if any(s in m for s in ("timeout", "deadline exceeded", "timed out", "i/o timeout")):
        return "timeout"
    if any(s in m for s in ("tls", "x509", "certificate", "handshake")):
        return "erro_tls"
    if "refused" in m:
        return "conexao_recusada"
    if "reset" in m or "eof" in m:
        return "conexao_encerrada"
    return "erro_outro" if m else "falha_sem_detalhe"


def classificar_resposta(status: int | None, titulo: str, servidor: str) -> str:
    if status is None:
        return "sem_status"
    t, s = (titulo or "").lower(), (servidor or "").lower()
    waf = any(x in t for x in ASSINATURAS_WAF_TITULO) or any(x in s for x in ASSINATURAS_WAF_SERVIDOR)
    if status in (401, 407):
        return "controle_observado_autenticacao"
    if status == 403:
        return "possivel_bloqueio_waf" if waf else "controle_observado_proibido"
    if status in (406, 429, 503) and waf:
        return "possivel_bloqueio_waf"
    if status == 429:
        return "limite_de_taxa"
    if 300 <= status < 400:
        return "redirecionamento"
    if 200 <= status < 300:
        return "respondeu"
    if 400 <= status < 500:
        return "erro_http_4xx"
    return "erro_http_5xx"


def normalizar(obj: dict | None, alvo: str, salto: int, pai: str | None, preservar) -> dict:
    p = urlsplit(alvo)
    base = {"alvo": alvo, "alvo_sanitizado": sanitizar_url(alvo, preservar), "host": (p.hostname or "").lower(),
            "esquema": p.scheme, "porta": p.port or (443 if p.scheme == "https" else 80), "salto": salto,
            "alvo_pai": sanitizar_url(pai, preservar) if pai else None}
    if obj is None:
        return {**base, "estado": "sem_resultado", "classificacao": "sem_resultado"}
    if obj.get("failed"):
        erro = obj.get("error") or obj.get("err") or ""
        return {**base, "estado": "falha", "classificacao": classificar_erro(erro),
                "erro": sanitizar_texto(erro, 200)}
    status = obj.get("status_code") or obj.get("status-code")
    titulo = sanitizar_texto(obj.get("title", ""), 160)
    servidor = sanitizar_texto(obj.get("webserver", ""), 120)
    tls = obj.get("tls") or {}
    return {
        **base,
        "estado": "respondeu",
        "status_code": status,
        "classificacao": classificar_resposta(status, titulo, servidor),
        "titulo": titulo,
        "servidor": servidor,
        "content_type": sanitizar_texto(obj.get("content_type", ""), 100),
        "content_length": obj.get("content_length"),
        "ips": sorted(set((obj.get("a") or []) + (obj.get("aaaa") or []))),
        "cnames": obj.get("cname") or [],
        "location": sanitizar_url(obj.get("location", ""), preservar) if obj.get("location") else "",
        "tecnologias_inferidas": sorted(set(obj.get("tech") or [])),
        "tls": {
            "versao": tls.get("tls_version"),
            "emissor": sanitizar_texto(tls.get("issuer_cn") or tls.get("issuer_dn") or "", 160),
            "sujeito_cn": tls.get("subject_cn"),
            "sans": (tls.get("subject_an") or [])[:50],
            "nao_antes": tls.get("not_before"),
            "nao_depois": tls.get("not_after"),
            "autoassinado": tls.get("self_signed"),
            "expirado": tls.get("expired"),
            "nome_incompativel": tls.get("mismatched"),
        } if tls else None,
    }


def decidir_redirecionamento(escopo: Escopo, origem_url: str, location: str, origens_aprovadas: set[str],
                             seguir: bool, salto: int, max_saltos: int, visitados: set[str]) -> tuple[str, str | None, list[str]]:
    """Valida um salto. Retorna (decisao, url_destino_absoluta, motivos)."""
    destino = urljoin(origem_url, location)
    v = escopo.validar_url(destino)
    if not v.ok:
        return "fora_do_escopo_registrado", destino, v.motivos
    if chave_origem(v.esquema, v.host, v.porta) not in origens_aprovadas:
        return "no_escopo_origem_nao_revisada_registrado", destino, ["origem_nao_revisada"]
    if destino in visitados:
        return "laco_ou_repetido", destino, []
    if not seguir:
        return "registrado_nao_seguido", destino, []
    if salto + 1 > max_saltos:
        return "limite_de_saltos", destino, []
    return "seguido", destino, []


def executar(rodada: Rodada, dry_run: bool, forcar: bool, retomar: bool, ignorar_janela: bool, argv_cli: list[str]) -> dict:
    etapa = rodada.etapa("sondagem")
    if etapa.get("estado") == "concluida" and not (forcar or retomar) and not dry_run:
        print("sondagem já concluída nesta rodada (use --retomar ou --forcar)")
        return etapa.get("resumo", {})
    cfg = rodada.config
    s = cfg.get("sondagem", {})
    escopo = Escopo.de_config(cfg)
    preservar = frozenset(x.lower() for x in cfg.get("relatorio", {}).get("parametros_preservados", []))
    aprovados = carregar_aprovados(rodada, "sondar")
    origens_aprovadas = {a["origem"] for a in aprovados}
    if not dry_run and not ignorar_janela:
        ok, msg = verificar_janela(rodada.manifesto.get("janela", ""))
        if not ok:
            raise PermissionError(msg)

    info = inspecionar("httpx", cfg.get("ferramentas", {}).get("httpx", "httpx"))
    rodada.manifesto["ferramentas"]["httpx"] = info.resumo()
    rodada.salvar()
    exigir(info, dry_run)
    rodada.iniciar_etapa("sondagem", dry_run, argv_cli)

    max_req = int(s.get("max_requisicoes", 50))
    max_saltos = int(s.get("max_saltos_redirecionamento", 3))
    seguir = bool(s.get("seguir_redirecionamentos_revisados", False))
    duracao_max = float(s.get("duracao_max_s", 600))
    tentativa = rodada.etapa("sondagem").get("tentativas", 1)

    resultados: dict[str, dict] = {}
    redirecionamentos: list[dict] = []
    if retomar:
        for r in ler_jsonl(rodada.p("sondagem", "servicos.jsonl")):
            if r.get("estado") in ("respondeu", "falha"):
                resultados[r["alvo"]] = r
        redirecionamentos = [r for r in ler_jsonl(rodada.p("sondagem", "redirecionamentos.jsonl"))
                             if r.get("origem") in resultados]

    fila = [(a["url"], 0, None) for a in aprovados if a["url"] not in resultados]
    visitados = set(resultados)
    requisicoes = 0
    inicio = time.monotonic()
    plano = {"etapa": "sondagem", "dry_run": dry_run, "alvos": len(fila), "comandos": [],
             "limites": {"max_requisicoes": max_req, "taxa_por_segundo": s.get("taxa_por_segundo", 1),
                         "concorrencia": s.get("concorrencia", 1), "timeout_s": s.get("timeout_s", 8),
                         "duracao_max_s": duracao_max, "max_bytes_resposta": s.get("max_bytes_resposta", 1048576)}}
    salto = 0
    while fila:
        lote = []
        for url, sl, pai in fila:
            if url in visitados:
                continue
            visitados.add(url)
            lote.append((url, sl, pai))
        fila = []
        if not lote:
            break
        restante = max_req - requisicoes
        excedentes = lote[max(restante, 0):]
        lote = lote[:max(restante, 0)]
        for url, sl, pai in excedentes:
            resultados[url] = {**normalizar(None, url, sl, pai, preservar), "estado": "nao_sondado_cota",
                               "classificacao": "nao_sondado_cota"}
            rodada.registrar_erro("sondagem", "cota_de_requisicoes", sanitizar_url(url, preservar), "")
        if not lote:
            break
        arq_alvos = rodada.p("bruto", f"httpx-alvos-t{tentativa}-s{salto}.txt")
        with open(arq_alvos, "w", encoding="utf-8") as f:
            f.writelines(u + "\n" for u, _, _ in lote)
        m = Montador(info)
        m.add("-l", arq_alvos).add("-nfs").add("-silent").add("-j")
        m.add("-sc").add("-title").add("-server").add("-ip").add("-cname").add("-location").add("-ct")
        m.add("-cl", opcional=True).add("-td", opcional=True).add("-tls-grab", opcional=True)
        m.add("-probe", opcional=True).add("-ob", opcional=True).add("-duc", opcional=True).add("-nc", opcional=True)
        m.add("-t", int(s.get("concorrencia", 1))).add("-rl", int(s.get("taxa_por_segundo", 1)))
        m.add("-timeout", int(s.get("timeout_s", 8))).add("-retries", 0)
        m.add("-rstr", int(s.get("max_bytes_resposta", 1048576)))
        if cfg.get("identificacao", {}).get("user_agent"):
            m.add("-H", "User-Agent: " + cfg["identificacao"]["user_agent"], opcional=True)
        plano["comandos"].append({"salto": salto, "argv": m.argv, "omitidas": m.omitidas, "alvos": len(lote)})
        if dry_run:
            break
        tempo_restante = duracao_max - (time.monotonic() - inicio)
        if tempo_restante <= 0:
            for url, sl, pai in lote:
                resultados[url] = {**normalizar(None, url, sl, pai, preservar), "estado": "interrompido",
                                   "classificacao": "duracao_maxima"}
            break
        bruto = rodada.p("bruto", f"httpx-t{tentativa}-s{salto}.jsonl")
        if bruto.exists():
            bruto.unlink()
        r = executar_streaming(m.argv, bruto, rodada.p("bruto", f"httpx-t{tentativa}-s{salto}.log"),
                               duracao_max_s=tempo_restante, max_linhas=len(lote), filtro=filtrar_httpx)
        requisicoes += len(lote)
        if r.codigo not in (0, None) and not r.interrompido:
            rodada.registrar_erro("sondagem", "httpx_codigo_saida", "", f"código={r.codigo}")
        if r.interrompido == "duracao":
            rodada.registrar_erro("sondagem", "duracao_maxima", "", f"{r.duracao_s}s")
        saidas: dict[str, dict] = {}
        for obj in ler_jsonl(bruto):
            chave = obj.get("input") or obj.get("url")
            if chave:
                saidas.setdefault(chave, obj)
        for url, sl, pai in lote:
            obj = saidas.get(url) or saidas.get(url.rstrip("/"))
            res = normalizar(obj, url, sl, pai, preservar)
            if obj is None and r.interrompido:
                res.update({"estado": "interrompido", "classificacao": "duracao_maxima"})
            resultados[url] = res
            if obj is None:
                rodada.registrar_erro("sondagem", "sem_resultado", res["alvo_sanitizado"],
                                      "sem linha de saída do httpx; verifique httpx log")
            elif res["estado"] == "falha":
                rodada.registrar_erro("sondagem", res["classificacao"], res["alvo_sanitizado"], res.get("erro", ""))
            if obj and obj.get("location"):
                decisao, destino, motivos = decidir_redirecionamento(
                    escopo, url, obj["location"], origens_aprovadas, seguir, sl, max_saltos, visitados)
                redirecionamentos.append({"origem": url, "origem_sanitizada": res["alvo_sanitizado"], "salto": sl,
                                          "status_code": res.get("status_code"),
                                          "destino_sanitizado": sanitizar_url(destino, preservar),
                                          "decisao": decisao, "motivos": motivos})
                if decisao == "seguido":
                    fila.append((destino, sl + 1, url))
        salto += 1

    if dry_run:
        escrever_json(rodada.p("sondagem", "plano.json"), plano)
        rodada.concluir_etapa("sondagem", {"alvos_planejados": plano["alvos"]}, dry_run=True)
        return plano

    escrever_jsonl(rodada.p("sondagem", "servicos.jsonl"), resultados.values())
    escrever_jsonl(rodada.p("sondagem", "redirecionamentos.jsonl"), redirecionamentos)
    cobertura = {
        "alvos_aprovados": len(aprovados),
        "alvos_avaliados": len(resultados),
        "requisicoes_nesta_execucao": requisicoes,
        "estados": _contar(r["estado"] for r in resultados.values()),
        "classificacoes": _contar(r["classificacao"] for r in resultados.values()),
        "redirecionamentos": _contar(r["decisao"] for r in redirecionamentos),
        "aprovados_sem_resultado": sorted(r["alvo_sanitizado"] for r in resultados.values()
                                          if r["estado"] in ("sem_resultado", "interrompido", "nao_sondado_cota")),
        "flags_omitidas": sorted({f for c in plano["comandos"] for f in c["omitidas"]}),
        "retomada": retomar,
    }
    escrever_json(rodada.p("sondagem", "cobertura.json"), cobertura)
    pendentes = cobertura["estados"].get("interrompido", 0) + cobertura["estados"].get("nao_sondado_cota", 0)
    rodada.concluir_etapa("sondagem", cobertura, estado="parcial" if pendentes else "concluida")
    return cobertura


def _contar(itens) -> dict:
    out: dict[str, int] = {}
    for i in itens:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items()))


__all__ = ["executar", "ErroFerramenta"]
