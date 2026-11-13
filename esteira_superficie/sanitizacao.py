"""Sanitização de URLs, textos e células CSV.

Relatórios nunca devem conter corpos de resposta, segredos ou valores de
parâmetros. Este módulo concentra as regras para que todas as saídas usem
o mesmo tratamento.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

REDIGIDO = "[REDIGIDO]"

# Padrões que indicam segredo, identificador pessoal ou token.
_PADROES_SENSIVEIS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # chave AWS
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # token GitHub
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # token Slack
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(pass(word)?|senha|pwd|secret|token|api[_-]?key|apikey|chave)\s*[:=]\s*\S+"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # e-mail
    re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),  # CPF formatado
    re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),  # CNPJ formatado
]

# Segmentos de caminho que parecem identificadores ou segredos.
_SEGMENTO_SENSIVEL = [
    re.compile(r"^[0-9a-fA-F]{24,}$"),  # hash/hex longo
    re.compile(r"^[A-Za-z0-9_-]{32,}$"),  # token opaco longo
    re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$"),  # base64
    re.compile(r"^\d{11}$|^\d{14}$"),  # CPF/CNPJ sem máscara
    re.compile(r"^eyJ"),  # JWT
    re.compile(r"^[^@/]+@[^@/]+\.[A-Za-z]{2,}$"),  # e-mail
]

_INICIO_FORMULA = ("=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠")
_CONTROLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitizar_texto(valor, limite: int = 200) -> str:
    """Remove controles e mascara padrões sensíveis em textos curtos (títulos, erros)."""
    if valor is None:
        return ""
    texto = str(valor)
    texto = texto.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    texto = _CONTROLE.sub("", texto)
    for padrao in _PADROES_SENSIVEIS:
        texto = padrao.sub(REDIGIDO, texto)
    texto = re.sub(r"\s{2,}", " ", texto).strip()
    if len(texto) > limite:
        texto = texto[: limite - 1] + "…"
    return texto


def _segmento_sensivel(segmento: str) -> bool:
    if not segmento:
        return False
    return any(p.search(segmento) for p in _SEGMENTO_SENSIVEL)


def sanitizar_caminho(caminho: str) -> str:
    partes = []
    for seg in caminho.split("/"):
        # Parâmetros de matriz (ex.: ;jsessionid=...) são removidos.
        base, _, matriz = seg.partition(";")
        if matriz:
            base = base + ";" + REDIGIDO
        if _segmento_sensivel(base):
            base = REDIGIDO
        partes.append(base)
    return "/".join(partes)


def sanitizar_url(url, preservar: frozenset[str] | set[str] = frozenset()) -> str:
    """Retorna URL sem credenciais, fragmento, valores de parâmetros ou segmentos sensíveis.

    Os nomes dos parâmetros são mantidos; apenas os valores dos nomes listados em
    ``preservar`` são mantidos, e ainda assim só se não parecerem sensíveis.
    """
    if not url:
        return ""
    url = str(url).strip()
    try:
        partes = urlsplit(url)
    except ValueError:
        return sanitizar_texto(url)
    if not partes.scheme and not partes.netloc:
        # URL relativa: trata só caminho e query.
        caminho = sanitizar_caminho(partes.path)
        query = _sanitizar_query(partes.query, preservar)
        return caminho + (("?" + query) if query else "")
    host = partes.hostname or ""
    try:
        porta = partes.port
    except ValueError:
        porta = None
    netloc = host + (f":{porta}" if porta else "")
    caminho = sanitizar_caminho(partes.path)
    query = _sanitizar_query(partes.query, preservar)
    return urlunsplit((partes.scheme.lower(), netloc, caminho, query, ""))


def _sanitizar_query(query: str, preservar) -> str:
    if not query:
        return ""
    pares = parse_qsl(query, keep_blank_values=True)
    if not pares:
        # Query sem formato chave=valor (ex.: ?wsdl). Mantém se for palavra simples.
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,30}", query):
            return query
        return REDIGIDO
    saida = []
    for nome, valor in pares:
        nome_seguro = sanitizar_texto(nome, 60)
        if nome.lower() in preservar and valor and not _segmento_sensivel(valor) and len(valor) <= 40 \
                and sanitizar_texto(valor) == valor:
            saida.append(f"{quote(nome_seguro, safe='')}={quote(valor, safe='')}")
        elif valor == "":
            saida.append(quote(nome_seguro, safe=""))
        else:
            saida.append(f"{quote(nome_seguro, safe='')}={REDIGIDO}")
    return "&".join(saida)


def neutralizar_celula(valor) -> str:
    """Neutraliza injeção de fórmulas em planilhas (CSV injection)."""
    if valor is None:
        return ""
    if isinstance(valor, bool):
        return "sim" if valor else "não"
    if isinstance(valor, (list, tuple, set)):
        valor = "; ".join(str(v) for v in valor)
    texto = str(valor)
    if texto and (texto[0] in _INICIO_FORMULA or texto.lstrip()[:1] in _INICIO_FORMULA):
        return "'" + texto
    return texto
