"""Etapa 5: consolidação em CSV/JSONL/Markdown, achados 'a validar' e comparação entre rodadas."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from urllib.parse import urlsplit

from .descoberta import carregar_candidatos
from .rodada import Rodada, agora_utc, escrever_csv, escrever_json, escrever_jsonl, ler_csv, ler_json, ler_jsonl
from .sanitizacao import sanitizar_texto, sanitizar_url

COL_ATIVOS = ["host", "fonte", "responsavel", "a", "aaaa", "cname", "dns_estado", "wildcard", "porta", "esquema", "alvo",
              "nome_descoberto", "dns_resolvido", "servico_observado", "resposta", "titulo", "redirecionamento",
              "tls", "tecnologia_inferida", "tecnologia_confirmada", "data_utc"]
COL_URLS = ["origem", "caminho", "tipo", "fonte", "estado_observado", "controle_acesso", "evidencia"]
COL_WS = ["host", "rota", "protocolo", "ambiente", "versao", "documentacao", "finalidade", "dados_tratados",
          "consumidores", "controle_observado", "estado", "fonte", "responsavel"]
COL_ACHADOS = ["id", "ativo", "categoria", "evidencia_minima", "confianca", "prioridade", "prioridade_revisao",
               "impacto", "acao", "responsavel", "estado_validacao"]


def _protocolo(rota: str) -> str:
    r = rota.lower()
    if ".svc" in r:
        return "WCF/SOAP"
    if ".asmx" in r or "wsdl" in r or "/soap" in r:
        return "SOAP"
    if "graphql" in r:
        return "GraphQL"
    if "odata" in r or "$metadata" in r:
        return "OData"
    if "/api" in r or "/rest" in r or "swagger" in r or "openapi" in r or r.endswith(".json"):
        return "REST"
    return "a identificar"


def _versao(rota: str) -> str:
    import re
    m = re.search(r"/v(\d+(?:\.\d+)?)(/|$)", rota.lower())
    return "v" + m.group(1) if m else ""


def _ambiente(host: str) -> str:
    h = host.lower()
    for marca, amb in (("hml", "homologação (inferido)"), ("homolog", "homologação (inferido)"),
                       ("dev", "desenvolvimento (inferido)"), ("teste", "teste (inferido)"),
                       ("test", "teste (inferido)"), ("stg", "staging (inferido)")):
        if marca in h.split(".")[0]:
            return amb
    return "a confirmar"


def _rota_base(caminho: str) -> str:
    return caminho.split("?", 1)[0] or "/"


def _tls_resumo(tls: dict | None) -> str:
    if not tls:
        return ""
    partes = [f"emissor={tls.get('emissor') or '?'}", f"validade={tls.get('nao_depois') or '?'}"]
    if tls.get("expirado"):
        partes.append("EXPIRADO")
    if tls.get("nome_incompativel"):
        partes.append("NOME_INCOMPATIVEL")
    if tls.get("autoassinado"):
        partes.append("AUTOASSINADO")
    return "; ".join(partes)


def executar(rodada: Rodada, tecnologias: Path | None, webservices_doc: Path | None, comparar_com: Path | None,
             dry_run: bool, argv_cli: list[str]) -> dict:
    cfg = rodada.config
    bom = cfg.get("relatorio", {}).get("csv_bom", True)
    rodada.iniciar_etapa("consolidacao", dry_run, argv_cli)
    data = agora_utc()
    candidatos = carregar_candidatos(rodada)
    wildcards = {w["ramo"]: w for w in ler_jsonl(rodada.p("descoberta", "wildcard.jsonl"))}
    dependencias = ler_jsonl(rodada.p("descoberta", "dependencias.jsonl"))
    servicos = ler_jsonl(rodada.p("sondagem", "servicos.jsonl"))
    redir_s = ler_jsonl(rodada.p("sondagem", "redirecionamentos.jsonl"))
    urls = ler_jsonl(rodada.p("rastreamento", "urls.jsonl"))
    redir_k = ler_jsonl(rodada.p("rastreamento", "redirecionamentos.jsonl"))
    aprovadas = ler_json(rodada.p("revisao", "aprovadas.json"), {}) or {}

    tec_conf: dict[str, list[str]] = {}
    if tecnologias:
        copia = rodada.registrar_entrada("tecnologias-confirmadas", tecnologias)
        for l in ler_csv(copia):
            h = l.get("host", "").lower()
            if h:
                tec_conf.setdefault(h, []).append(
                    sanitizar_texto(f"{l.get('componente','')} {l.get('versao','')} ({l.get('responsavel','')}, {l.get('data','')})"))
    ws_doc = []
    if webservices_doc:
        copia = rodada.registrar_entrada("webservices-documentados", webservices_doc)
        ws_doc = ler_csv(copia)

    # ------------------------------------------------------------- ativos
    redir_por_origem = {}
    for r in redir_s:
        redir_por_origem.setdefault(r["origem_sanitizada"], r)
    servicos_por_host: dict[str, list[dict]] = {}
    for s in servicos:
        servicos_por_host.setdefault(s["host"], []).append(s)
    ativos = []
    hosts = list(candidatos) + sorted(h for h in servicos_por_host if h not in candidatos)
    for host in hosts:
        c = candidatos.get(host, {"fontes": ["origem_revisada_sem_procedencia"], "responsavel": "", "estado": {}})
        dnsd = c.get("dns", {})
        regs = dnsd.get("registros", {})
        wc = ""
        if dnsd.get("ramo_wildcard"):
            wc = f"ramo {dnsd['ramo_wildcard']} com wildcard" + ("; resposta genérica" if dnsd.get("resposta_generica") else "")
        base = {"host": host, "fonte": c.get("fontes", []), "responsavel": c.get("responsavel", ""),
                "a": regs.get("A", []), "aaaa": regs.get("AAAA", []), "cname": regs.get("CNAME", []),
                "dns_estado": dnsd.get("estado", "nao_consultado"), "wildcard": wc,
                "nome_descoberto": "sim" if host in candidatos else "não",
                "dns_resolvido": {"resolvido": "sim", "nao_consultado": "não consultado"}.get(dnsd.get("estado"), "não")
                + (" (genérico)" if dnsd.get("resposta_generica") else ""),
                "tecnologia_confirmada": tec_conf.get(host, []), "data_utc": data}
        svcs = servicos_por_host.get(host, [])
        if not svcs:
            ativos.append({**base, "porta": "", "esquema": "", "alvo": "", "servico_observado": "não sondado",
                           "resposta": "", "titulo": "", "redirecionamento": "", "tls": "", "tecnologia_inferida": []})
            continue
        for s in sorted(svcs, key=lambda x: (x["esquema"], x["porta"], x["salto"])):
            r = redir_por_origem.get(s["alvo_sanitizado"])
            resposta = s["classificacao"] if s["estado"] != "respondeu" else f"{s.get('status_code')} {s['classificacao']}"
            observado = {"respondeu": "sim", "falha": f"não ({s['classificacao']})"}.get(s["estado"], f"não ({s['estado']})")
            ativos.append({**base, "porta": s["porta"], "esquema": s["esquema"], "servico_observado": observado,
                           "resposta": resposta, "titulo": s.get("titulo", ""),
                           "redirecionamento": f"{r['destino_sanitizado']} [{r['decisao']}]" if r else (s.get("location") or ""),
                           "tls": _tls_resumo(s.get("tls")), "tecnologia_inferida": s.get("tecnologias_inferidas", []),
                           "alvo": s["alvo_sanitizado"]})

    # --------------------------------------------------------------- urls
    linhas_urls = []
    for u in urls:
        linhas_urls.append({"origem": sanitizar_url(u["origem"]) if "://" in u.get("origem", "") else u.get("origem", ""),
                            "caminho": u["caminho_sanitizado"], "tipo": u["tipo"], "fonte": u["fonte"],
                            "estado_observado": u["estado_observado"], "controle_acesso": u["controle_acesso"],
                            "evidencia": f"rastreamento/urls.jsonl ({u['url_sanitizada']})", "host": u["host"],
                            "status_code": u["status_code"]})

    # -------------------------------------------------------- webservices
    ws: dict[tuple[str, str], dict] = {}
    for u in linhas_urls:
        if u["tipo"] not in ("webservice", "documentacao_api"):
            continue
        rota = _rota_base(u["caminho"])
        chave = (u["host"], rota.lower())
        atual = ws.setdefault(chave, {"host": u["host"], "rota": rota, "protocolo": _protocolo(u["caminho"]),
                                      "ambiente": _ambiente(u["host"]), "versao": _versao(rota), "documentacao": "",
                                      "finalidade": "", "dados_tratados": "", "consumidores": "",
                                      "controle_observado": "", "estado": "", "fonte": "rastreamento",
                                      "responsavel": candidatos.get(u["host"], {}).get("responsavel", ""),
                                      "_status": [], "_tipos": set()})
        atual["_status"].append(u["status_code"])
        atual["_tipos"].add(u["tipo"])
        if u["tipo"] == "documentacao_api":
            atual["documentacao"] = ("WSDL público" if "wsdl" in u["caminho"].lower() else "documentação de API pública") \
                + f" (HTTP {u['status_code']})" if u["status_code"] else "referência a documentação (não requisitada)"
        if u["controle_acesso"]:
            atual["controle_observado"] = u["controle_acesso"]
    for doc in ws_doc:
        host = doc.get("host", "").lower()
        rota = doc.get("rota", "") or "/"
        chave = (host, rota.lower())
        reg = ws.get(chave)
        if reg is None:
            reg = ws.setdefault(chave, {"host": host, "rota": rota, "protocolo": doc.get("protocolo") or _protocolo(rota),
                                        "ambiente": doc.get("ambiente") or _ambiente(host),
                                        "versao": doc.get("versao") or _versao(rota),
                                        "documentacao": doc.get("documentacao", ""), "finalidade": "",
                                        "dados_tratados": "", "consumidores": "", "controle_observado": "não observado",
                                        "estado": "", "fonte": "", "responsavel": "", "_status": [],
                                        "_tipos": set()})
        for campo in ("finalidade", "dados_tratados", "consumidores", "responsavel", "ambiente", "versao", "documentacao"):
            if doc.get(campo) and not reg.get(campo):
                reg[campo] = doc[campo]
        reg["fonte"] = "; ".join(x for x in (reg.get("fonte"), "documentação: " + (doc.get("fonte") or "inventário")) if x)
        reg["_documentado"] = True
    linhas_ws = []
    for reg in ws.values():
        st = [s for s in reg.pop("_status") if s is not None]
        doc = reg.pop("_documentado", False)
        reg["_somente_doc"] = reg.pop("_tipos") == {"documentacao_api"}
        if not st and reg["fonte"].startswith("documentação"):
            reg["estado"] = "apenas_documentado (não observado nesta rodada)"
        elif not st:
            reg["estado"] = "mencionado_nao_requisitado"
        elif any(200 <= s < 300 for s in st):
            reg["estado"] = "endpoint_acessivel" + (" + documentado" if doc else "")
        elif any(s in (401, 403, 407) for s in st):
            reg["estado"] = "controle_observado" + (" + documentado" if doc else "")
        else:
            reg["estado"] = "observado_http_" + "/".join(str(s) for s in sorted(set(st)))
        reg["rota"] = sanitizar_url(reg["rota"])
        linhas_ws.append(reg)
    linhas_ws.sort(key=lambda r: (r["host"], r["rota"]))
    somente_doc = {(w["host"], w["rota"]): w.pop("_somente_doc") for w in linhas_ws}

    # ------------------------------------------------------------ achados
    achados = []

    def achado(ativo, categoria, evidencia, confianca, revisao, impacto, acao, resp=""):
        achados.append({"id": f"A{len(achados)+1:03d}", "ativo": ativo, "categoria": categoria,
                        "evidencia_minima": evidencia, "confianca": confianca, "prioridade": "a validar",
                        "prioridade_revisao": revisao, "impacto": impacto, "acao": acao,
                        "responsavel": resp, "estado_validacao": "pendente"})

    for u in linhas_urls:
        resp = candidatos.get(u["host"], {}).get("responsavel", "")
        ok = u["status_code"] is not None and 200 <= u["status_code"] < 300
        if u["tipo"] == "arquivo_suspeito" and ok:
            achado(f"{u['origem']}{u['caminho']}", "arquivo_esquecido_ou_backup", f"HTTP {u['status_code']} sem autenticação; conteúdo não coletado",
                   "média", "alta", "possível exposição de backup, configuração ou base", "validar conteúdo com o responsável; se confirmado, acionar incidentes", resp)
        if u["tipo"] == "documentacao_api" and ok:
            achado(f"{u['origem']}{u['caminho']}", "documentacao_api_publica", f"HTTP {u['status_code']}",
                   "alta", "média", "facilita mapear operações e dados do serviço", "confirmar necessidade de publicação e controles por operação", resp)
    for w in linhas_ws:
        if w["estado"].startswith("endpoint_acessivel") and not somente_doc[(w["host"], w["rota"])]:
            achado(f"{w['host']}{w['rota']}", "webservice_acesso_anonimo", "rota respondeu 2xx sem credenciais (GET)",
                   "média", "média", "avaliar se a operação expõe dados sem autenticação", "validar autenticação/autorização por operação e objeto", w["responsavel"])
        if w["estado"].startswith("apenas_documentado"):
            achado(f"{w['host']}{w['rota']}", "webservice_documentado_nao_observado", "consta em documentação; não observado",
                   "baixa", "baixa", "pode indicar endpoint retirado ou fora da cobertura", "confirmar retirada ou publicação com o responsável", w["responsavel"])
    for a in ativos:
        if a.get("esquema") == "http" and a["resposta"].startswith("200"):
            achado(a.get("alvo", a["host"]), "http_sem_redirecionamento_https", "HTTP 200 em texto claro", "alta", "média",
                   "tráfego sem TLS", "avaliar redirecionamento para HTTPS e HSTS", a["responsavel"])
        if "EXPIRADO" in a["tls"] or "NOME_INCOMPATIVEL" in a["tls"]:
            achado(a.get("alvo", a["host"]), "tls_invalido", a["tls"], "alta", "média", "certificado inválido para o nome",
                   "renovar/corrigir certificado", a["responsavel"])
        if "index of" in str(a.get("titulo", "")).lower():
            achado(a.get("alvo", a["host"]), "listagem_de_diretorio", "título 'Index of'", "média", "alta",
                   "listagem pode expor arquivos não referenciados", "desativar listagem e revisar conteúdo", a["responsavel"])
    for r in redir_s + redir_k:
        if r["decisao"].startswith("fora_do_escopo"):
            achado(r["origem_sanitizada"], "redirecionamento_externo", f"destino {r['destino_sanitizado']} ({','.join(r['motivos'])})",
                   "alta", "baixa", "destino fora do escopo; não acessado", "confirmar se o destino é esperado")
    for host, c in candidatos.items():
        d = c.get("dns", {})
        if c.get("respaldo_interno") and d.get("estado") in ("nxdomain", "sem_registro"):
            achado(host, "divergencia_inventario", f"inventário interno lista o nome; DNS público: {d['estado']}",
                   "alta", "baixa", "inventário desatualizado ou nome apenas interno", "atualizar inventário", c.get("responsavel", ""))
        if not c.get("respaldo_interno") and d.get("estado") == "resolvido" and not d.get("resposta_generica"):
            achado(host, "ativo_fora_do_inventario_interno", "descoberto apenas por fonte passiva e resolve publicamente",
                   "média", "média", "ativo sem responsável conhecido", "identificar responsável e necessidade de publicação")
    for ramo, w in wildcards.items():
        if w.get("wildcard"):
            achado(ramo, "wildcard_dns", f"{len([t for t in w['amostras'] if t['estado']=='resolvido'])} nomes aleatórios resolveram",
                   "alta", "baixa", "nomes inexistentes resolvem; amplia superfície aparente", "confirmar necessidade do wildcard")

    # --------------------------------------------------------- cobertura
    cob_desc = ler_json(rodada.p("descoberta", "cobertura.json"), {}) or {}
    cob_sond = ler_json(rodada.p("sondagem", "cobertura.json"), {}) or {}
    cob_rast = ler_json(rodada.p("rastreamento", "cobertura.json"), {}) or {}
    erros = rodada.erros()

    # ------------------------------------------------------------ comparação
    comparacao = _comparar(comparar_com, ativos, linhas_urls, servicos, rodada) if comparar_com else None

    # ------------------------------------------------- assinaturas repetidas
    assin: dict[tuple, list[str]] = {}
    for s in servicos:
        if s["estado"] == "respondeu":
            assin.setdefault((s.get("status_code"), s.get("titulo"), s.get("content_length")), []).append(s["alvo_sanitizado"])
    repetidas = {f"{k[0]} | {k[1]} | {k[2]}": v for k, v in assin.items() if len(v) >= 3}

    if dry_run:
        rodada.concluir_etapa("consolidacao", {"ativos": len(ativos), "urls": len(linhas_urls)}, dry_run=True)
        print("[dry-run] consolidação calculada e não gravada")
        return {"ativos": len(ativos)}

    d = rodada.p("relatorios")
    escrever_csv(d / "ativos.csv", COL_ATIVOS, ativos, bom)
    escrever_csv(d / "urls.csv", COL_URLS, linhas_urls, bom)
    escrever_csv(d / "webservices.csv", COL_WS, linhas_ws, bom)
    escrever_csv(d / "achados.csv", COL_ACHADOS, achados, bom)
    escrever_jsonl(d / "ativos.jsonl", ativos)
    escrever_jsonl(d / "urls.jsonl", linhas_urls)
    escrever_jsonl(d / "webservices.jsonl", linhas_ws)
    escrever_jsonl(d / "achados.jsonl", achados)
    cobertura = {"descoberta": cob_desc, "sondagem": cob_sond, "rastreamento": cob_rast,
                 "erros_por_tipo": _contar(f"{e['etapa']}:{e['tipo']}" for e in erros)}
    escrever_json(d / "cobertura.json", cobertura)
    if comparacao:
        escrever_json(d / "comparacao.json", comparacao)
    md = _relatorio_md(rodada, ativos, linhas_urls, linhas_ws, achados, cobertura, dependencias, wildcards,
                       aprovadas, comparacao, repetidas, erros)
    with open(d / "relatorio.md", "w", encoding="utf-8") as f:
        f.write(md)
    resumo = {"ativos": len(ativos), "urls": len(linhas_urls), "webservices": len(linhas_ws), "achados": len(achados)}
    rodada.concluir_etapa("consolidacao", resumo)
    return resumo


def _contar(itens) -> dict:
    out: dict[str, int] = {}
    for i in itens:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items()))


def _comparar(anterior: Path, ativos, urls, servicos, rodada: Rodada) -> dict:
    ant_dir = Path(anterior) / "relatorios"
    ant_ativos = ler_jsonl(ant_dir / "ativos.jsonl")
    ant_urls = ler_jsonl(ant_dir / "urls.jsonl")
    chave_a = lambda a: f"{a['host']}|{a.get('esquema','')}|{a.get('porta','')}"  # noqa: E731
    chave_u = lambda u: f"{u['origem']}{u['caminho']}".lower()  # noqa: E731
    atuais_a = {chave_a(a): a for a in ativos}
    antigos_a = {chave_a(a): a for a in ant_ativos}
    sondados = {f"{s['host']}|{s['esquema']}|{s['porta']}": s for s in servicos}
    hosts_rastreados = {u["host"] for u in urls}
    removidos = []
    for k, a in antigos_a.items():
        if k in atuais_a:
            continue
        s = sondados.get(k)
        if s and s["estado"] in ("respondeu", "falha"):
            motivo = "desaparecimento_observado"
        else:
            motivo = "perda_de_cobertura (não sondado ou coleta falhou nesta rodada)"
        removidos.append({"chave": k, "classificacao": motivo})
    alterados = []
    for k, a in atuais_a.items():
        b = antigos_a.get(k)
        if b and (b.get("resposta") != a.get("resposta") or b.get("tls") != a.get("tls")):
            alterados.append({"chave": k, "antes": b.get("resposta"), "depois": a.get("resposta")})
    atuais_u = {chave_u(u) for u in urls}
    antigos_u = {chave_u(u): u for u in ant_urls}
    urls_removidas = []
    for k, u in antigos_u.items():
        if k not in atuais_u:
            urls_removidas.append({"url": k, "classificacao": "desaparecimento_observado" if u.get("host") in hosts_rastreados
                                   else "perda_de_cobertura (origem não rastreada nesta rodada)"})
    return {"rodada_anterior": str(anterior), "comparado_em": agora_utc(),
            "ativos_novos": sorted(set(atuais_a) - set(antigos_a)), "ativos_removidos": removidos,
            "ativos_alterados": alterados, "urls_novas": sorted(atuais_u - set(antigos_u)),
            "urls_removidas": urls_removidas}


def _tabela(colunas: list[str], linhas: list[dict], limite: int = 50) -> str:
    def cel(v):
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(colunas) + " |", "|" + "---|" * len(colunas)]
    for l in linhas[:limite]:
        out.append("| " + " | ".join(cel(l.get(c)) for c in colunas) + " |")
    if len(linhas) > limite:
        out.append(f"\n_… {len(linhas) - limite} linhas omitidas; ver CSV._")
    return "\n".join(out)


def _relatorio_md(rodada, ativos, urls, ws, achados, cobertura, dependencias, wildcards, aprovadas, comparacao,
                  repetidas, erros) -> str:
    m = rodada.manifesto
    ferr = m.get("ferramentas", {})
    ordem = {"alta": 0, "média": 1, "baixa": 2}
    prioritarios = sorted(achados, key=lambda a: (ordem.get(a["prioridade_revisao"], 3), a["categoria"]))
    cd, cs, cr = cobertura["descoberta"], cobertura["sondagem"], cobertura["rastreamento"]
    linhas = [
        f"# Relatório da rodada {m['rodada']}",
        "",
        "> Conteúdo sanitizado: sem corpos de resposta, sem valores de parâmetros e com padrões sensíveis mascarados. "
        "Saídas brutas permanecem em `bruto/` com acesso restrito à equipe de segurança. Todos os achados automáticos estão **a validar**.",
        "",
        "## Escopo",
        "",
        f"- Domínios exatos: {', '.join(m['escopo'].get('dominios_exatos', [])) or '—'}",
        f"- Sufixos (com ponto): {', '.join('*.' + s for s in m['escopo'].get('sufixos', [])) or '—'}",
        f"- Esquemas: {', '.join(m['escopo'].get('esquemas', []))}; portas: {', '.join(str(p) for p in m['escopo'].get('portas', []))}",
        f"- Origens aprovadas na revisão: {len(aprovadas.get('aprovados', []))} (rejeitadas: {len(aprovadas.get('rejeitados', []))}); "
        f"lista sha256 `{aprovadas.get('sha256_origens', '—')[:16]}…`",
        "",
        "## Ponto de observação",
        "",
        f"- IP de saída declarado: {m.get('ip_saida_declarado') or 'não informado'}",
        f"- Janela: {m.get('janela') or 'não declarada'}; operador: {m.get('operador') or '—'}",
        f"- Resolvedor DNS: {m.get('dns', {}).get('resolvedor', 'não executado')}",
        "- Ferramentas: " + ", ".join(f"{n} {i.get('versao') or '?'}" for n, i in ferr.items()) if ferr else "- Ferramentas: —",
        "",
        "## Cobertura por etapa",
        "",
        f"- **Descoberta**: {cd.get('candidatos', 0)} candidatos ({cd.get('por_fonte', {})}); fora do escopo: {cd.get('fora_escopo', 0)}; "
        f"dependências externas: {cd.get('dependencias', 0)}; estados DNS: {cd.get('dns_estados', {})}; "
        f"respostas genéricas: {cd.get('respostas_genericas', 0)}; ramos com wildcard: {', '.join(cd.get('ramos_com_wildcard', [])) or 'nenhum'}",
        f"- **Sondagem**: {cs.get('alvos_avaliados', 0)} alvos avaliados de {cs.get('alvos_aprovados', 0)} aprovados; "
        f"estados: {cs.get('estados', {})}; classificações: {cs.get('classificacoes', {})}; redirecionamentos: {cs.get('redirecionamentos', {})}",
        f"- **Rastreamento**: {cr.get('urls', 0)} URLs; por tipo: {cr.get('por_tipo', {})}; por estado: {cr.get('por_estado', {})}; "
        f"descartadas fora do escopo: {cr.get('descartadas_fora_do_escopo', 0)}; limites: {cr.get('limites', {})}",
        "- Estados distintos: *nome descoberto* → *DNS resolvido* → *serviço observado* → *tecnologia confirmada*. "
        "Tecnologia detectada por assinatura é inferência.",
        "",
        "## Divergências com o inventário interno",
        "",
    ]
    div = [a for a in achados if a["categoria"] in ("divergencia_inventario", "ativo_fora_do_inventario_interno",
                                                    "webservice_documentado_nao_observado")]
    linhas.append(_tabela(["ativo", "categoria", "evidencia_minima"], div) if div else "Nenhuma divergência detectada automaticamente.")
    linhas += ["", "## Dependências externas registradas", ""]
    linhas.append(_tabela(["host", "fonte", "responsavel"], dependencias) if dependencias else "Nenhuma.")
    linhas += ["", "## Lacunas de cobertura", ""]
    lac = []
    for alvo in cs.get("aprovados_sem_resultado", []):
        lac.append({"item": alvo, "lacuna": "alvo aprovado sem resultado (sem resposta, cota ou duração)"})
    for origem, e in (cr.get("origens") or {}).items():
        if e.get("estado") != "concluida":
            lac.append({"item": origem, "lacuna": f"rastreamento {e.get('estado')}"})
    for k, v in cobertura.get("erros_por_tipo", {}).items():
        lac.append({"item": k, "lacuna": f"{v} ocorrência(s) em erros.jsonl"})
    if cs.get("flags_omitidas") or cr.get("flags_omitidas"):
        lac.append({"item": "flags", "lacuna": f"opcionais não suportadas: {cs.get('flags_omitidas', []) + cr.get('flags_omitidas', [])}"})
    waf = [a for a in ativos if "waf" in str(a.get("resposta", ""))]
    for a in waf:
        lac.append({"item": a.get("alvo", a["host"]), "lacuna": "possível bloqueio de WAF; resposta pode não refletir o serviço"})
    linhas.append(_tabela(["item", "lacuna"], lac) if lac else "Nenhuma lacuna registrada.")
    if repetidas:
        linhas += ["", "## Assinaturas HTTP repetidas (possível página padrão/wildcard)", ""]
        linhas.append(_tabela(["assinatura", "alvos"], [{"assinatura": k, "alvos": v} for k, v in repetidas.items()]))
    linhas += ["", "## Itens prioritários para validação", ""]
    linhas.append(_tabela(["id", "ativo", "categoria", "evidencia_minima", "prioridade_revisao", "acao"], prioritarios, 30)
                  if prioritarios else "Nenhum achado automático.")
    linhas += ["", "## Webservices", ""]
    linhas.append(_tabela(["host", "rota", "protocolo", "estado", "controle_observado", "documentacao"], ws) if ws else "Nenhum.")
    if comparacao:
        linhas += ["", "## Comparação com a rodada anterior", "",
                   f"- Ativos novos: {len(comparacao['ativos_novos'])}; removidos: {len(comparacao['ativos_removidos'])} "
                   f"({_contar(r['classificacao'] for r in comparacao['ativos_removidos'])}); alterados: {len(comparacao['ativos_alterados'])}",
                   f"- URLs novas: {len(comparacao['urls_novas'])}; removidas: {len(comparacao['urls_removidas'])} "
                   f"({_contar(r['classificacao'] for r in comparacao['urls_removidas'])})"]
    linhas += ["", "## Escala de prioridade (após validação humana)", "",
               "- **crítica**: credenciais, cópia de base ou dados restritos em escala sem autorização → fluxo de incidentes.",
               "- **alta**: serviço sensível exposto com controle ausente ou inadequado.",
               "- **média**: informação desnecessária que ajuda materialmente a mapear/atacar.",
               "- **baixa/informativa**: conteúdo esperado ou de impacto limitado.",
               "- A idade de uma página e a presença de um WSDL, isoladamente, não determinam gravidade.",
               "", f"_Gerado em {agora_utc()} por esteira-superficie._", ""]
    return "\n".join(linhas)
