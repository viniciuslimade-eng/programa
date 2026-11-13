"""Consultas DNS (dig ou fixture), classificação e detecção de wildcard."""

from __future__ import annotations

import json
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

TIPOS = ("A", "AAAA", "CNAME")
_STATUS = re.compile(r"status:\s*([A-Z]+)")


@dataclass
class RespostaDNS:
    status: str  # NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT, ERRO
    registros: dict[str, list[str]] = field(default_factory=dict)
    erro: str | None = None

    def valores(self) -> set[str]:
        return {v for vs in self.registros.values() for v in vs}

    def para_dict(self) -> dict:
        return {"status": self.status, "registros": self.registros, "erro": self.erro}


def analisar_saida_dig(texto: str, codigo: int) -> RespostaDNS:
    m = _STATUS.search(texto)
    if not m:
        if "timed out" in texto or "no servers could be reached" in texto or codigo == 9:
            return RespostaDNS("TIMEOUT", erro="sem resposta do resolvedor")
        return RespostaDNS("ERRO", erro=(texto.strip().splitlines() or ["saída vazia"])[-1][:200])
    resp = RespostaDNS(m.group(1))
    for linha in texto.splitlines():
        if not linha or linha.startswith(";"):
            continue
        partes = linha.split()
        if len(partes) >= 5 and partes[2] == "IN" and partes[3] in TIPOS:
            resp.registros.setdefault(partes[3], []).append(partes[4].rstrip(".").lower())
    return resp


class ResolvedorDig:
    def __init__(self, binario: str = "dig", servidores: list[str] | None = None, timeout_s: int = 3):
        caminho = shutil.which(binario)
        if not caminho:
            raise FileNotFoundError(f"dig não encontrado ({binario})")
        self.binario = caminho
        self.servidores = servidores or []
        self.timeout_s = timeout_s
        self._rr = 0

    def descrever(self) -> str:
        return f"dig ({', '.join(self.servidores) or 'resolvedor do sistema'})"

    def consultar(self, nome: str, tipo: str) -> RespostaDNS:
        argv = [self.binario, f"+time={self.timeout_s}", "+tries=1", "+noall", "+comments", "+answer"]
        if self.servidores:
            argv.append("@" + self.servidores[self._rr % len(self.servidores)])
            self._rr += 1
        argv += [nome, tipo]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout_s * 3 + 2,
                               stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return RespostaDNS("TIMEOUT", erro="dig excedeu o tempo")
        return analisar_saida_dig(r.stdout + "\n" + r.stderr, r.returncode)


class ResolvedorFixture:
    """Resolvedor determinístico para testes e demonstrações (sem tráfego).

    Formato JSON::

        {"registros": {"www.ex.test": {"A": ["192.0.2.1"], "CNAME": ["lb.ex.test"]}},
         "wildcards": {"dev.ex.test": {"A": ["192.0.2.99"]}},
         "falhas": {"quebrado.ex.test": "SERVFAIL", "lento.ex.test": "TIMEOUT"}}
    """

    def __init__(self, caminho: Path):
        with open(caminho, encoding="utf-8") as f:
            dados = json.load(f)
        self.registros = {k.lower(): v for k, v in dados.get("registros", {}).items()}
        self.wildcards = {k.lower().lstrip("*."): v for k, v in dados.get("wildcards", {}).items()}
        self.falhas = {k.lower(): v for k, v in dados.get("falhas", {}).items()}
        self.consultas: list[tuple[str, str]] = []

    def descrever(self) -> str:
        return "fixture"

    def _existe(self, nome: str) -> bool:
        return nome in self.registros or any(k.endswith("." + nome) for k in self.registros)

    def consultar(self, nome: str, tipo: str) -> RespostaDNS:
        nome = nome.lower().rstrip(".")
        self.consultas.append((nome, tipo))
        if nome in self.falhas:
            st = self.falhas[nome]
            return RespostaDNS(st, erro="simulado")
        dados = self.registros.get(nome)
        if dados is None:
            for ramo, wdados in sorted(self.wildcards.items(), key=lambda x: -len(x[0])):
                if nome.endswith("." + ramo):
                    dados = wdados
                    break
        if dados is None:
            return RespostaDNS("NOERROR" if self._existe(nome) else "NXDOMAIN")
        resp = RespostaDNS("NOERROR")
        if tipo == "CNAME" or (tipo in ("A", "AAAA") and dados.get("CNAME")):
            if dados.get("CNAME"):
                resp.registros["CNAME"] = list(dados["CNAME"])
        if tipo in ("A", "AAAA") and dados.get(tipo):
            resp.registros[tipo] = list(dados[tipo])
        return resp


def criar_resolvedor(cfg: dict, fixture: Path | None = None):
    if fixture:
        return ResolvedorFixture(fixture)
    d = cfg.get("dns", {})
    return ResolvedorDig(cfg.get("ferramentas", {}).get("dig", "dig"), d.get("resolvedores", []),
                         int(d.get("timeout_s", 3)))


def classificar(respostas: dict[str, RespostaDNS]) -> str:
    """Estado DNS de um nome a partir das respostas A/AAAA/CNAME."""
    status = {r.status for r in respostas.values()}
    if any(r.registros for r in respostas.values()):
        return "resolvido"
    if status == {"NXDOMAIN"}:
        return "nxdomain"
    if "NXDOMAIN" in status and status <= {"NXDOMAIN", "NOERROR"}:
        return "nxdomain"
    if status == {"NOERROR"}:
        return "sem_registro"  # nome existe, mas sem A/AAAA/CNAME (NODATA)
    return "erro"


def registros_consolidados(respostas: dict[str, RespostaDNS]) -> dict[str, list[str]]:
    saida: dict[str, list[str]] = {}
    for r in respostas.values():
        for tipo, vals in r.registros.items():
            for v in vals:
                if v not in saida.setdefault(tipo, []):
                    saida[tipo].append(v)
    return saida


def rotulo_aleatorio() -> str:
    return "esteira-wc-" + secrets.token_hex(6)


def ramos_para_wildcard(candidatos: list[str], raizes: list[str], maximo: int) -> list[str]:
    """Raízes do escopo + domínios-pai dos candidatos, priorizando os ramos com mais nomes."""
    contagem: dict[str, int] = {}
    for c in candidatos:
        partes = c.split(".")
        for i in range(1, len(partes) - 1):
            pai = ".".join(partes[i:])
            if any(pai == r or pai.endswith("." + r) for r in raizes):
                contagem[pai] = contagem.get(pai, 0) + 1
    ramos = list(dict.fromkeys(raizes))
    for pai, _ in sorted(contagem.items(), key=lambda x: (-x[1], x[0])):
        if pai not in ramos:
            ramos.append(pai)
    return ramos[:maximo]


def ramo_wildcard_de(host: str, wildcards: dict[str, dict]) -> str | None:
    """Ramo com wildcard mais próximo acima do host."""
    melhor = None
    for ramo, info in wildcards.items():
        if info.get("wildcard") and host.endswith("." + ramo):
            if melhor is None or len(ramo) > len(melhor):
                melhor = ramo
    return melhor
