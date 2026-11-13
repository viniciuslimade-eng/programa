"""Etapa 4: mapeamento de páginas, arquivos e webservices com Katana, por origem revisada."""

from __future__ import annotations

import re
import time
from urllib.parse import urljoin, urlsplit

from .escopo import Escopo, regex_origem
from .ferramentas import Montador, executar_streaming, exigir, inspecionar, verificar_janela
from .revisao import carregar_aprovados
from .rodada import Rodada, escrever_json, escrever_jsonl, ler_json, ler_jsonl
from .sanitizacao import sanitizar_texto, sanitizar_url

EXT_DOCUMENTO = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "csv", "txt", "xml"}
EXT_BACKUP = {"bak", "old", "orig", "backup", "sql", "dump", "tar", "gz", "tgz", "zip", "7z", "rar", "swp", "tmp",
              "save", "copy", "config", "env", "ini", "log", "mdb", "db", "sqlite"}
EXT_SCRIPT = {"js", "mjs", "map"}
EXT_ESTILO = {"css"}
EXT_IMAGEM = {"png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp"}
EXT_FONTE = {"woff", "woff2", "ttf", "eot", "otf"}
_DOC_API = re.compile(r"(?i)(\?wsdl\b|\.wsdl$|\?singlewsdl|/swagger(/|\.json|-ui|$)|openapi(\.json|\.ya?ml)?$|"
                      r"/api-docs|/\$metadata$|/v[0-9]+/api-docs|\?disco\b|/help/?$)")
_WEBSERVICE = re.compile(r"(?i)(\.asmx|\.svc|\.ashx|/api/|/rest/|/ws/|/services?/|/soap|/graphql|/odata/|/rpc/|"
                         r"\.jsonp?$|/v[0-9]+/)")


def classificar_url(url: str) -> str:
    p = urlsplit(url)
    caminho = p.path.lower()
    alvo = caminho + ("?" + p.query.lower() if p.query else "")
    ext = caminho.rsplit(".", 1)[-1] if "." in caminho.rsplit("/", 1)[-1] else ""
    if caminho.endswith("~") or ext in EXT_BACKUP:
        return "arquivo_suspeito"
    if _DOC_API.search(alvo):
        return "documentacao_api"
    if _WEBSERVICE.search(caminho):
        return "webservice"
    if ext in EXT_DOCUMENTO:
        return "documento"
    if ext in EXT_SCRIPT:
        return "script"
    if ext in EXT_ESTILO:
        return "estilo"
    if ext in EXT_IMAGEM:
        return "imagem"
    if ext in EXT_FONTE:
        return "fonte_tipografica"
    if caminho.endswith(("robots.txt", "sitemap.xml")):
        return "arquivo_conhecido"
    return "pagina"


def filtrar_katana(obj: dict) -> dict:
    """Remove corpo e requisição/resposta brutas antes de gravar."""
    obj = dict(obj)
    resp = dict(obj.get("response") or {})
    for k in ("body", "raw", "forms", "xhr_requests"):
        resp.pop(k, None)
    if "headers" in resp and isinstance(resp["headers"], dict):
        resp["headers"] = {k: v for k, v in resp["headers"].items()
                           if k.lower() in ("location", "content_type", "content-type", "server",
                                            "www_authenticate", "www-authenticate", "content_length",
                                            "content-length")}
    obj["response"] = resp
    req = dict(obj.get("request") or {})
    req.pop("raw", None)
    req.pop("body", None)
    obj["request"] = req
    return obj


def _cabecalho(headers: dict, *nomes) -> str:
    for k, v in (headers or {}).items():
        if k.lower().replace("-", "_") in nomes:
            return v if isinstance(v, str) else (v[0] if v else "")
    return ""


def normalizar_linha(obj: dict, origem: str, escopo: Escopo, preservar) -> dict:
    req = obj.get("request") or {}
    resp = obj.get("response") or {}
    url = req.get("endpoint") or obj.get("url") or ""
    status = resp.get("status_code")
    headers = resp.get("headers") or {}
    v = escopo.validar_url(url)
    if status is None and obj.get("error"):
        estado = "erro"
    elif status is None:
        estado = "mencionada_nao_requisitada"
    else:
        estado = f"http_{status}"
    if status in (401, 407):
        controle = "autenticacao_exigida (validar eficácia)"
    elif status == 403:
        controle = "acesso_proibido (validar eficácia)"
    elif status is not None and 200 <= status < 300:
        controle = "acesso_anonimo_observado"
    else:
        controle = ""
    p = urlsplit(url)
    location = _cabecalho(headers, "location")
    return {
        "origem": origem,
        "url": url,
        "url_sanitizada": sanitizar_url(url, preservar),
        "host": (p.hostname or "").lower(),
        "caminho_sanitizado": sanitizar_url(p.path + (("?" + p.query) if p.query else ""), preservar) or "/",
        "tipo": classificar_url(url),
        "metodo": req.get("method", "GET"),
        "fonte": sanitizar_texto(":".join(x for x in (req.get("source"), req.get("tag"), req.get("attribute")) if x), 200),
        "estado_observado": estado,
        "status_code": status,
        "content_type": sanitizar_texto(_cabecalho(headers, "content_type") or resp.get("content_type", ""), 100),
        "content_length": resp.get("content_length"),
        "controle_acesso": controle,
        "location_bruta": urljoin(url, location) if location else "",
        "no_escopo": v.ok,
        "motivos_escopo": v.motivos,
        "erro": sanitizar_texto(obj.get("error", ""), 200),
    }


def executar(rodada: Rodada, dry_run: bool, forcar: bool, retomar: bool, ignorar_janela: bool,
             argv_cli: list[str], somente: list[str] | None = None) -> dict:
    etapa = rodada.etapa("rastreamento")
    if etapa.get("estado") == "concluida" and not (forcar or retomar) and not dry_run:
        print("rastreamento já concluído nesta rodada (use --retomar ou --forcar)")
        return etapa.get("resumo", {})
    cfg = rodada.config
    k = cfg.get("rastreamento", {})
    escopo = Escopo.de_config(cfg)
    preservar = frozenset(x.lower() for x in cfg.get("relatorio", {}).get("parametros_preservados", []))
    aprovados = carregar_aprovados(rodada, "rastrear")
    if somente:
        aprovados = [a for a in aprovados if a["url"] in somente or a["origem"] in somente]
    if not dry_run and not ignorar_janela:
        ok, msg = verificar_janela(rodada.manifesto.get("janela", ""))
        if not ok:
            raise PermissionError(msg)
    info = inspecionar("katana", cfg.get("ferramentas", {}).get("katana", "katana"))
    rodada.manifesto["ferramentas"]["katana"] = info.resumo()
    rodada.salvar()
    exigir(info, dry_run)
    rodada.iniciar_etapa("rastreamento", dry_run, argv_cli)

    estado_path = rodada.p("rastreamento", "estado.json")
    estado = ler_json(estado_path, {}) if (retomar and not forcar) else {}
    max_total = int(k.get("max_requisicoes", 500))
    max_por_origem = int(k.get("max_requisicoes_por_origem", max_total))
    duracao_total = float(k.get("duracao_total_max_s", 3600))
    duracao_origem = int(k.get("duracao_max_s", 300))
    usadas = sum(e.get("linhas", 0) for e in estado.values())
    inicio = time.monotonic()
    plano = {"etapa": "rastreamento", "dry_run": dry_run, "comandos": []}

    for i, a in enumerate(aprovados):
        chave = a["url"]
        if estado.get(chave, {}).get("estado") == "concluida":
            continue
        cota = min(max_por_origem, max_total - usadas)
        m = Montador(info)
        m.add("-u", a["url"])
        m.add("-cs", regex_origem(a["esquema"], a["host"], a["porta"]))
        m.add("-fs", "fqdn").add("-dr")
        if k.get("exclusoes"):
            m.add("-cos", k["exclusoes"])
        m.add("-d", int(k.get("profundidade", 3))).add("-ct", f"{duracao_origem}s")
        m.add("-mrs", int(k.get("max_bytes_resposta", 1048576))).add("-timeout", int(k.get("timeout_s", 8)))
        m.add("-retry", 0).add("-c", int(k.get("concorrencia", 1))).add("-p", int(k.get("paralelismo", 1)))
        m.add("-rl", int(k.get("taxa_por_segundo", 1))).add("-j").add("-silent")
        # -ob não é usado: no Katana v1.8.0 ele impede a extração de endpoints em JavaScript (-jc).
        # O corpo é descartado por filtrar_katana antes de qualquer gravação em disco.
        m.add("-or", opcional=True).add("-duc", opcional=True).add("-nc", opcional=True)
        if k.get("max_paginas_por_dominio"):
            m.add("-mdp", int(k["max_paginas_por_dominio"]), opcional=True)
        if k.get("arquivos_conhecidos"):
            m.add("-kf", k["arquivos_conhecidos"], opcional=True)
        if k.get("js_crawl", False):
            m.add("-jc", opcional=True)
        if k.get("incluir_estaticos", True):
            # Sem -ndef o Katana omite da saída PDFs, imagens e outros estáticos (anexos ficariam fora do inventário).
            m.add("-ndef", opcional=True)
        if cfg.get("identificacao", {}).get("user_agent"):
            m.add("-H", "User-Agent: " + cfg["identificacao"]["user_agent"], opcional=True)
        plano["comandos"].append({"origem": sanitizar_url(a["url"]), "argv": m.argv, "omitidas": m.omitidas,
                                  "cota_linhas": cota})
        if dry_run:
            continue
        if cota <= 0:
            estado[chave] = {"estado": "nao_rastreada_cota", "linhas": 0}
            rodada.registrar_erro("rastreamento", "cota_de_requisicoes", sanitizar_url(a["url"]), "")
            continue
        restante = duracao_total - (time.monotonic() - inicio)
        if restante <= 0:
            estado[chave] = {"estado": "nao_rastreada_duracao", "linhas": 0}
            rodada.registrar_erro("rastreamento", "duracao_total_maxima", sanitizar_url(a["url"]), "")
            continue
        slug = f"{i:03d}-{a['host']}-{a['esquema']}-{a['porta']}"
        bruto = rodada.p("bruto", f"katana-{slug}.jsonl")
        if bruto.exists():
            bruto.unlink()
        r = executar_streaming(m.argv, bruto, rodada.p("bruto", f"katana-{slug}.log"),
                               duracao_max_s=min(restante, duracao_origem + 60), max_linhas=cota,
                               filtro=filtrar_katana)
        usadas += r.linhas
        st = "concluida" if not r.interrompido and r.codigo == 0 else (
            f"interrompida_{r.interrompido}" if r.interrompido else "falhou")
        estado[chave] = {"estado": st, "linhas": r.linhas, "codigo": r.codigo, "duracao_s": r.duracao_s,
                         "bruto": bruto.name, "origem": a["origem"]}
        if st != "concluida":
            rodada.registrar_erro("rastreamento", st, sanitizar_url(a["url"]), f"código={r.codigo} linhas={r.linhas}")
        escrever_json(estado_path, estado)

    if dry_run:
        escrever_json(rodada.p("rastreamento", "plano.json"), plano)
        rodada.concluir_etapa("rastreamento", {"origens_planejadas": len(plano["comandos"])}, dry_run=True)
        return plano

    # Consolida todas as origens (inclusive as de execuções anteriores).
    urls: dict[str, dict] = {}
    redirecionamentos = []
    descartadas_fora = 0
    for chave, e in estado.items():
        if not e.get("bruto"):
            continue
        for obj in ler_jsonl(rodada.p("bruto", e["bruto"])):
            n = normalizar_linha(obj, e.get("origem", ""), escopo, preservar)
            if not n["url"]:
                continue
            if not n["no_escopo"]:
                descartadas_fora += 1
                continue
            if n["location_bruta"]:
                v = escopo.validar_url(n["location_bruta"])
                redirecionamentos.append({"origem_sanitizada": n["url_sanitizada"], "status_code": n["status_code"],
                                          "destino_sanitizado": sanitizar_url(n["location_bruta"], preservar),
                                          "decisao": "registrado_nao_seguido" if v.ok else "fora_do_escopo_registrado",
                                          "motivos": v.motivos})
            n.pop("location_bruta", None)
            atual = urls.get(n["url"])
            if atual is None or (atual["status_code"] is None and n["status_code"] is not None):
                urls[n["url"]] = n
    lista = sorted(urls.values(), key=lambda x: x["url"])
    for u in lista:
        u.pop("url", None)  # mantém apenas a forma sanitizada fora do diretório bruto
    escrever_jsonl(rodada.p("rastreamento", "urls.jsonl"), lista)
    escrever_jsonl(rodada.p("rastreamento", "redirecionamentos.jsonl"), redirecionamentos)
    cobertura = {
        "origens_aprovadas": len(aprovados),
        "origens": {sanitizar_url(c): {kk: vv for kk, vv in e.items() if kk != "bruto"} for c, e in estado.items()},
        "urls": len(lista),
        "por_tipo": _contar(u["tipo"] for u in lista),
        "por_estado": _contar(u["estado_observado"] for u in lista),
        "descartadas_fora_do_escopo": descartadas_fora,
        "redirecionamentos": _contar(r["decisao"] for r in redirecionamentos),
        "limites": {"profundidade": k.get("profundidade", 3), "duracao_por_origem_s": duracao_origem,
                    "max_bytes_resposta": k.get("max_bytes_resposta", 1048576), "max_requisicoes": max_total,
                    "exclusoes": k.get("exclusoes", ""), "dominios": "origem exata (esquema+host+porta)"},
        "flags_omitidas": sorted({f for c in plano["comandos"] for f in c["omitidas"]}),
    }
    escrever_json(rodada.p("rastreamento", "cobertura.json"), cobertura)
    pendentes = [c for c, e in estado.items() if e.get("estado") != "concluida"]
    rodada.concluir_etapa("rastreamento", {kk: vv for kk, vv in cobertura.items() if kk != "origens"},
                          estado="parcial" if pendentes else "concluida")
    return cobertura


def _contar(itens) -> dict:
    out: dict[str, int] = {}
    for i in itens:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items()))
