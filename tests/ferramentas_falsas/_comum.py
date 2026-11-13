"""Utilidades das ferramentas falsas usadas nos testes (emulam a interface de linha de comando)."""

import os
import sys
from pathlib import Path

AJUDA = Path(__file__).resolve().parent.parent / "fixtures" / "ajuda"


def tratar_meta(nome: str, versao: str, argv: list[str]) -> None:
    if "-version" in argv:
        print(f"[INF] Current Version: v{versao}", file=sys.stderr)
        sys.exit(0)
    if "-h" in argv or "-help" in argv:
        texto = (AJUDA / f"{nome}-h.txt").read_text(encoding="utf-8")
        remover = [f for f in os.environ.get("FALSA_REMOVER_FLAGS", "").split(",") if f]
        linhas = []
        for linha in texto.splitlines():
            if any(linha.lstrip().startswith(f + ",") or linha.lstrip().startswith(f + " ") for f in remover):
                continue
            linhas.append(linha)
        print("\n".join(linhas))
        sys.exit(0)


def args(argv: list[str], booleanas: set[str]) -> dict[str, list[str]]:
    saida: dict[str, list[str]] = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("-"):
            if a in booleanas or i + 1 >= len(argv) or (argv[i + 1].startswith("-") and len(argv[i + 1]) > 1
                                                         and not argv[i + 1][1:2].isdigit()):
                saida.setdefault(a, []).append("")
                i += 1
            else:
                saida.setdefault(a, []).append(argv[i + 1])
                i += 2
        else:
            i += 1
    return saida
