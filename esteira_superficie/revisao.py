"""Etapa 2: revisão de escopo. Gera modelo para a equipe de segurança e valida a lista de origens revisadas.

Sondagem e rastreamento só aceitam alvos aprovados aqui, e conferem o hash da lista.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from urllib.parse import urlsplit

from .descoberta import carregar_candidatos
from .escopo import PORTAS_PADRAO, Escopo
from .rodada import Rodada, agora_utc, escrever_csv, escrever_json, ler_csv, ler_json, sha256_arquivo

COLUNAS_ORIGENS = ["url", "sondar", "rastrear", "responsavel", "revisado_por", "data_revisao",
                   "terceiro_confirmado", "observacao"]
SIM = {"sim", "s", "yes", "y", "true", "1", "x"}
NAO = {"nao", "não", "n", "no", "false", "0", ""}


def gerar_modelo(rodada: Rodada, escopo: Escopo) -> int:
    """Modelo com todos os candidatos mantidos e sondar/rastrear = 'nao' (a equipe de segurança marca explicitamente)."""
    linhas = []
    for host, c in carregar_candidatos(rodada).items():
        obs = []
        if not c.get("manter", True):
            obs.append("descartado na descoberta: " + c.get("motivo_descartar", ""))
        if c.get("dns", {}).get("resposta_generica"):
            obs.append("resposta DNS genérica (wildcard)")
        if c.get("terceiro"):
            obs.append("operado por terceiro: confirmar titularidade e escopo")
        if "dns" in c and c["dns"]["estado"] != "resolvido":
            obs.append(f"dns {c['dns']['estado']}")
        portas = {(e, PORTAS_PADRAO[e]) for e in ("https", "http") if e in escopo.esquemas}
        for p in c.get("portas_declaradas", []):
            for e in ("https", "http"):
                if e in escopo.esquemas:
                    portas.add((e, p))
        portas = {(e, p) for e, p in portas if p in escopo.portas}
        for esquema, porta in sorted(portas, key=lambda x: (x[1], x[0])):
            sufixo = "" if PORTAS_PADRAO.get(esquema) == porta else f":{porta}"
            linhas.append({"url": f"{esquema}://{host}{sufixo}/", "sondar": "nao", "rastrear": "nao",
                           "responsavel": c.get("responsavel", ""), "revisado_por": "", "data_revisao": "",
                           "terceiro_confirmado": "pendente" if c.get("terceiro") else "na",
                           "observacao": "; ".join(obs)})
    escrever_csv(rodada.p("revisao", "modelo-origens.csv"), COLUNAS_ORIGENS, linhas,
                 bom=rodada.config.get("relatorio", {}).get("csv_bom", True))
    return len(linhas)


def _bool(valor: str, campo: str, erros: list[str]) -> bool:
    v = (valor or "").strip().lower()
    if v in SIM:
        return True
    if v in NAO:
        return False
    erros.append(f"{campo}_invalido:{valor!r}")
    return False


def validar_origens(rodada: Rodada, escopo: Escopo, caminho: Path, exigir_procedencia: bool) -> dict:
    candidatos = carregar_candidatos(rodada)
    aprovados, rejeitados, avisos = [], [], []
    vistos = set()
    for num, linha in enumerate(ler_csv(caminho), start=2):
        erros: list[str] = []
        url = linha.get("url", "")
        sondar = _bool(linha.get("sondar", ""), "sondar", erros)
        rastrear = _bool(linha.get("rastrear", ""), "rastrear", erros)
        if not (sondar or rastrear) and not erros:
            continue  # linha não selecionada pela revisão
        v = escopo.validar_url(url)
        erros.extend(v.motivos)
        try:
            partes = urlsplit(url)
            if partes.query or partes.fragment:
                erros.append("query_ou_fragmento_nao_permitidos")
        except ValueError:
            pass
        if not linha.get("revisado_por"):
            erros.append("revisado_por_ausente")
        data = linha.get("data_revisao", "")
        try:
            dt.date.fromisoformat(data[:10])
        except ValueError:
            erros.append("data_revisao_invalida")
        cand = candidatos.get(v.host)
        terceiro = escopo.eh_terceiro(v.host) or bool(cand and cand.get("terceiro"))
        if terceiro and linha.get("terceiro_confirmado", "").lower() not in SIM:
            erros.append("terceiro_sem_confirmacao_de_titularidade")
        if v.host and not cand:
            if exigir_procedencia:
                erros.append("host_sem_procedencia_na_descoberta")
            else:
                avisos.append({"linha": num, "url": url, "aviso": "host sem procedência na descoberta"})
        elif cand and not cand.get("manter", True):
            avisos.append({"linha": num, "url": url, "aviso": "host descartado na descoberta: "
                           + cand.get("motivo_descartar", "")})
        chave = (url.rstrip("/"), sondar, rastrear)
        if chave in vistos:
            avisos.append({"linha": num, "url": url, "aviso": "duplicada"})
            continue
        vistos.add(chave)
        registro = {"linha": num, "url": url, "origem": v.origem, "esquema": v.esquema, "host": v.host,
                    "porta": v.porta, "sondar": sondar, "rastrear": rastrear,
                    "responsavel": linha.get("responsavel", ""), "revisado_por": linha.get("revisado_por", ""),
                    "data_revisao": data, "terceiro": terceiro}
        if erros:
            rejeitados.append({**registro, "motivos": erros})
        else:
            aprovados.append(registro)
    return {"aprovados": aprovados, "rejeitados": rejeitados, "avisos": avisos}


def executar(rodada: Rodada, origens: Path | None, exigir_procedencia: bool, dry_run: bool, argv_cli: list[str]) -> dict:
    escopo = Escopo.de_config(rodada.config)
    rodada.iniciar_etapa("revisao", dry_run, argv_cli)
    n_modelo = gerar_modelo(rodada, escopo) if rodada.p("descoberta", "candidatos.jsonl").exists() else 0
    if not origens:
        resumo = {"modelo_gerado": str(rodada.p("revisao", "modelo-origens.csv")), "linhas_modelo": n_modelo,
                  "aprovados": 0, "nota": "preencha sondar/rastrear/revisado_por/data_revisao e rode 'revisar --origens'"}
        rodada.concluir_etapa("revisao", resumo, estado="aguardando_origens")
        return resumo
    copia = rodada.registrar_entrada("origens-revisadas", origens)
    res = validar_origens(rodada, escopo, copia, exigir_procedencia)
    dados = {"gerado_em": agora_utc(), "arquivo": str(copia.relative_to(rodada.dir)),
             "sha256_origens": sha256_arquivo(copia), **res}
    resumo = {"linhas_modelo": n_modelo, "aprovados": len(res["aprovados"]), "rejeitados": len(res["rejeitados"]),
              "avisos": len(res["avisos"]),
              "para_sondar": sum(1 for a in res["aprovados"] if a["sondar"]),
              "para_rastrear": sum(1 for a in res["aprovados"] if a["rastrear"])}
    if dry_run:
        print("[dry-run] revisão validada mas não gravada como aprovada")
        rodada.concluir_etapa("revisao", resumo, dry_run=True)
        return {**resumo, **res}
    escrever_json(rodada.p("revisao", "aprovadas.json"), dados)
    for r in res["rejeitados"]:
        rodada.registrar_erro("revisao", "origem_rejeitada", r["url"], ",".join(r["motivos"]))
    rodada.concluir_etapa("revisao", resumo)
    return {**resumo, **res}


def carregar_aprovados(rodada: Rodada, finalidade: str) -> list[dict]:
    """Retorna alvos aprovados para 'sondar' ou 'rastrear', verificando integridade da revisão."""
    dados = ler_json(rodada.p("revisao", "aprovadas.json"))
    if not dados:
        raise PermissionError("não há lista de origens revisadas aprovada; rode 'revisar --origens <csv>'")
    copia = rodada.dir / dados["arquivo"]
    if not copia.exists() or sha256_arquivo(copia) != dados["sha256_origens"]:
        raise PermissionError("a lista de origens revisadas foi alterada após a aprovação; rode 'revisar' novamente")
    escopo = Escopo.de_config(rodada.config)
    saida = []
    for a in dados["aprovados"]:
        if not a.get(finalidade):
            continue
        # Revalida com o escopo atual (defesa em profundidade).
        if not escopo.validar_url(a["url"]).ok:
            continue
        saida.append(a)
    if not saida:
        raise PermissionError(f"nenhuma origem aprovada para {finalidade}")
    return saida
