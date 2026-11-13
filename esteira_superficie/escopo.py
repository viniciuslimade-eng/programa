"""Regras de escopo: domínio exato ou sufixo com ponto, esquema e porta."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

PORTAS_PADRAO = {"http": 80, "https": 443}
_ROTULO = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalizar_host(valor: str) -> tuple[str | None, str | None]:
    """Normaliza um nome (minúsculas, sem ponto final, IDNA). Retorna (host, motivo_rejeicao)."""
    if valor is None:
        return None, "vazio"
    v = str(valor).strip().strip("﻿")
    if not v or v.startswith("#"):
        return None, "vazio"
    v = v.split()[0].lower().rstrip(".")
    if "://" in v:
        try:
            v = (urlsplit(v).hostname or "").rstrip(".")
        except ValueError:
            return None, "invalido"
    if v.startswith("*."):
        return None, "curinga"
    try:
        ipaddress.ip_address(v)
        return None, "ip_literal"
    except ValueError:
        pass
    if not v.isascii():
        try:
            v = v.encode("idna").decode("ascii")
        except UnicodeError:
            return None, "invalido"
    # Nomes de rótulo único (ex.: "localhost") só entram no escopo se listados como domínio exato.
    if len(v) > 253:
        return None, "invalido"
    if not all(_ROTULO.match(r) for r in v.split(".")):
        return None, "invalido"
    return v, None


@dataclass
class ValidacaoURL:
    ok: bool
    url: str
    motivos: list[str] = field(default_factory=list)
    esquema: str = ""
    host: str = ""
    porta: int | None = None

    @property
    def origem(self) -> str:
        return f"{self.esquema}://{self.host}:{self.porta}" if self.host else ""


@dataclass
class Escopo:
    dominios_exatos: list[str]
    sufixos: list[str]
    esquemas: list[str]
    portas: list[int]
    hosts_excluidos: list[str] = field(default_factory=list)
    terceiros: list[str] = field(default_factory=list)

    @classmethod
    def de_config(cls, cfg: dict) -> "Escopo":
        e = cfg.get("escopo", {})
        norm = lambda xs: [normalizar_host(x)[0] or str(x).lower() for x in xs]  # noqa: E731
        escopo = cls(
            dominios_exatos=norm(e.get("dominios_exatos", [])),
            sufixos=[s.lower().strip(".") for s in e.get("sufixos", [])],
            esquemas=[s.lower() for s in e.get("esquemas", ["http", "https"])],
            portas=[int(p) for p in e.get("portas", [80, 443])],
            hosts_excluidos=norm(e.get("hosts_excluidos", [])),
            terceiros=norm(e.get("terceiros", [])),
        )
        if not escopo.dominios_exatos and not escopo.sufixos:
            raise ValueError("escopo vazio: defina escopo.dominios_exatos e/ou escopo.sufixos")
        return escopo

    def host_no_escopo(self, host: str) -> tuple[bool, str]:
        h, motivo = normalizar_host(host)
        if not h:
            return False, motivo or "invalido"
        if h in self.hosts_excluidos:
            return False, "host_excluido"
        if h in self.dominios_exatos:
            return True, "dominio_exato"
        for s in self.sufixos:
            # Sufixo exige o ponto: "xexample.org" não casa com "example.org".
            if h.endswith("." + s):
                return True, "sufixo:" + s
        return False, "fora_do_dominio"

    def eh_terceiro(self, host: str) -> bool:
        return host in self.terceiros

    def validar_url(self, url: str, base: str | None = None) -> ValidacaoURL:
        bruta = str(url or "").strip()
        if base:
            bruta = urljoin(base, bruta)
        v = ValidacaoURL(ok=False, url=bruta)
        try:
            p = urlsplit(bruta)
        except ValueError:
            v.motivos.append("url_invalida")
            return v
        v.esquema = (p.scheme or "").lower()
        if v.esquema not in self.esquemas:
            v.motivos.append(f"esquema_nao_permitido:{v.esquema or 'ausente'}")
        if p.username is not None or p.password is not None:
            v.motivos.append("credenciais_na_url")
        try:
            porta = p.port
        except ValueError:
            v.motivos.append("porta_invalida")
            porta = None
        host, motivo = normalizar_host(p.hostname or "")
        if not host:
            v.motivos.append(f"host_{motivo}")
        else:
            v.host = host
            ok, m = self.host_no_escopo(host)
            if not ok:
                v.motivos.append(m)
        if porta is None and "porta_invalida" not in v.motivos:
            porta = PORTAS_PADRAO.get(v.esquema)
        v.porta = porta
        if porta is not None and porta not in self.portas:
            v.motivos.append(f"porta_nao_permitida:{porta}")
        v.ok = not v.motivos
        return v


def chave_origem(esquema: str, host: str, porta: int | None) -> str:
    return f"{esquema}://{host}:{porta}"


def regex_origem(esquema: str, host: str, porta: int) -> str:
    """Regex de escopo de crawl para uma única origem (esquema + host + porta)."""
    h = re.escape(host)
    if PORTAS_PADRAO.get(esquema) == porta:
        return f"^{esquema}://{h}(:{porta})?(/|\\?|$)"
    return f"^{esquema}://{h}:{porta}(/|\\?|$)"
