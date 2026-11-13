"""Interface de linha de comando da esteira."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, consolidacao, descoberta, rastreamento, revisao, sondagem
from .ferramentas import ErroFerramenta, inspecionar_todas
from .rodada import ETAPAS, Rodada, carregar_config, escrever_json

PROXIMOS = {
    "descoberta": "revisar --rodada {r}  # gera revisao/modelo-origens.csv",
    "revisao": "revisar --rodada {r} --origens origens-revisadas.csv",
    "sondagem": "sondar --rodada {r} --dry-run && sondar --rodada {r}",
    "rastreamento": "rastrear --rodada {r} --dry-run && rastrear --rodada {r}",
    "consolidacao": "consolidar --rodada {r}",
}


def _p(caminho: str | None) -> Path | None:
    return Path(caminho) if caminho else None


def construir_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="esteira-superficie",
                                 description="Inventário da superfície externa: descoberta, revisão, sondagem, rastreamento e consolidação.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="comando", required=True)

    def comum(p, rodada=True):
        if rodada:
            p.add_argument("--rodada", required=True, help="diretório da rodada")
        p.add_argument("--dry-run", action="store_true", help="planeja e registra comandos sem gerar tráfego")
        return p

    p = sub.add_parser("iniciar", help="cria o diretório da rodada e o manifesto")
    p.add_argument("--config", required=True)
    p.add_argument("--base", default=".", help="diretório onde a rodada será criada")
    p.add_argument("--nome", help="nome da rodada (padrão: <prefixo>-<UTC>)")
    p.add_argument("--ip-saida", default="", help="IP de saída declarado (não é consultado automaticamente)")
    p.add_argument("--janela", default="", help="janela autorizada UTC: 2026-11-20T22:00Z/2026-11-21T02:00Z")
    p.add_argument("--operador", default="")
    p.add_argument("--observacao", default="")

    p = sub.add_parser("ferramentas", help="registra versões e valida as flags das ferramentas instaladas (sem tráfego)")
    p.add_argument("--rodada", help="grava o resultado no manifesto desta rodada")
    p.add_argument("--config", help="config (se não houver rodada)")

    p = comum(sub.add_parser("descobrir", help="etapa 1: sementes, inventário interno, Subfinder, DNS e wildcard"))
    p.add_argument("--sementes", help="TXT com nomes semente")
    p.add_argument("--hosts-internos", help="TXT ou CSV (host,fonte,responsavel,portas,terceiro,observacao)")
    p.add_argument("--subfinder-saida", help="importa saída já existente do Subfinder em vez de executá-lo")
    p.add_argument("--sem-subfinder", action="store_true")
    p.add_argument("--sem-dns", action="store_true")
    p.add_argument("--dns-fixture", help="resolvedor simulado (JSON) para testes")
    p.add_argument("--forcar", action="store_true")

    p = comum(sub.add_parser("revisar", help="etapa 2: gera modelo e valida a lista de origens revisadas"))
    p.add_argument("--origens", help="CSV revisado (url,sondar,rastrear,responsavel,revisado_por,data_revisao,terceiro_confirmado,observacao)")
    p.add_argument("--exigir-procedencia", action="store_true", help="rejeita hosts ausentes da descoberta")

    for nome, ajuda in (("sondar", "etapa 3: httpx nas origens aprovadas"), ("rastrear", "etapa 4: Katana nas origens aprovadas")):
        p = comum(sub.add_parser(nome, help=ajuda))
        p.add_argument("--forcar", action="store_true", help="refaz a etapa do zero")
        p.add_argument("--retomar", action="store_true", help="processa apenas o que ficou pendente")
        p.add_argument("--ignorar-janela", action="store_true", help="permite execução fora da janela (uso em laboratório)")
        if nome == "rastrear":
            p.add_argument("--somente", action="append", help="URL ou origem aprovada a rastrear (repetível)")

    p = comum(sub.add_parser("consolidar", help="etapa 5: CSV, JSONL, Markdown, achados e comparação"))
    p.add_argument("--tecnologias-confirmadas", help="CSV host,componente,versao,responsavel,data")
    p.add_argument("--webservices-documentados", help="CSV host,rota,protocolo,ambiente,versao,documentacao,finalidade,dados_tratados,consumidores,responsavel,fonte")
    p.add_argument("--comparar-com", help="diretório de rodada anterior")

    p = sub.add_parser("status", help="mostra estado das etapas e próximos comandos")
    p.add_argument("--rodada", required=True)
    return ap


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    argv = list(sys.argv[1:] if argv is None else argv)
    args = construir_parser().parse_args(argv)
    try:
        return _despachar(args, argv)
    except (PermissionError, ErroFerramenta, FileNotFoundError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        if getattr(args, "rodada", None) and args.comando not in ("iniciar", "ferramentas", "status"):
            try:
                r = Rodada(Path(args.rodada))
                etapa = {"descobrir": "descoberta", "revisar": "revisao", "sondar": "sondagem",
                         "rastrear": "rastreamento", "consolidar": "consolidacao"}[args.comando]
                if not getattr(args, "dry_run", False):
                    r.falhar_etapa(etapa, str(exc))
                r.registrar_erro(etapa, "etapa_bloqueada", "", str(exc))
            except Exception:  # noqa: BLE001
                pass
        return 2


def _imprimir(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _despachar(args, argv) -> int:
    if args.comando == "iniciar":
        r = Rodada.criar(Path(args.base), Path(args.config), args.nome, args.ip_saida, args.janela,
                         args.operador, args.observacao)
        print(r.dir)
        return 0
    if args.comando == "ferramentas":
        if args.rodada:
            r = Rodada(Path(args.rodada))
            cfg = r.config
        elif args.config:
            r, cfg = None, carregar_config(Path(args.config))
        else:
            print("informe --rodada ou --config", file=sys.stderr)
            return 2
        infos = inspecionar_todas(cfg)
        resumo = {n: i.resumo() for n, i in infos.items()}
        if r:
            r.manifesto["ferramentas"].update(resumo)
            r.iniciar_etapa("ferramentas", False, argv)
            r.concluir_etapa("ferramentas", {n: i.ok for n, i in infos.items()},
                             estado="concluida" if all(i.ok for i in infos.values()) else "falhou")
        _imprimir(resumo)
        return 0 if all(i.ok for i in infos.values()) else 1
    if args.comando == "status":
        r = Rodada(Path(args.rodada))
        print(f"rodada: {r.manifesto['rodada']}  ({r.dir})")
        for e in ETAPAS:
            st = r.etapa(e)
            print(f"  {e:<14} {st.get('estado'):<20} {st.get('fim') or st.get('inicio') or ''}")
        for e in ETAPAS[1:]:
            if r.etapa(e).get("estado") not in ("concluida",):
                print("próximo: esteira-superficie " + PROXIMOS[e].format(r=r.dir))
                break
        print(f"erros registrados: {len(r.erros())}")
        return 0

    r = Rodada(Path(args.rodada))
    if args.comando == "descobrir":
        res = descoberta.executar(r, _p(args.sementes), _p(args.hosts_internos), _p(args.subfinder_saida),
                                  usar_subfinder=not args.sem_subfinder, usar_dns=not args.sem_dns,
                                  dns_fixture=_p(args.dns_fixture), dry_run=args.dry_run, forcar=args.forcar,
                                  argv_cli=argv)
    elif args.comando == "revisar":
        res = revisao.executar(r, _p(args.origens), args.exigir_procedencia, args.dry_run, argv)
        if not args.origens:
            print(f"modelo gerado em {r.p('revisao', 'modelo-origens.csv')}")
        res = {k: v for k, v in res.items() if k not in ("aprovados",)}
    elif args.comando == "sondar":
        res = sondagem.executar(r, args.dry_run, args.forcar, args.retomar, args.ignorar_janela, argv)
    elif args.comando == "rastrear":
        res = rastreamento.executar(r, args.dry_run, args.forcar, args.retomar, args.ignorar_janela, argv, args.somente)
    elif args.comando == "consolidar":
        res = consolidacao.executar(r, _p(args.tecnologias_confirmadas), _p(args.webservices_documentados),
                                    _p(args.comparar_com), args.dry_run, argv)
    else:  # pragma: no cover
        return 2
    _imprimir(res)
    if args.comando in ("sondar", "rastrear") and r.etapa({"sondar": "sondagem", "rastrear": "rastreamento"}[args.comando]).get("estado") == "parcial":
        print(f"etapa parcial: retome com 'esteira-superficie {args.comando} --rodada {r.dir} --retomar'", file=sys.stderr)
        return 3
    return 0


__all__ = ["main", "escrever_json"]
