"""Descoberta de versões, validação de flags e execução controlada das ferramentas externas."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import selectors
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_FLAG_LINHA = re.compile(r"^\s{1,8}(-[A-Za-z][\w-]*)(?:\s*,\s*(-[A-Za-z][\w-]*))?")
_VERSAO = re.compile(r"v?(\d+\.\d+\.\d+)")

# Flags que a esteira usa. "obrigatorias" sustentam limites e segurança: sem elas, a etapa não roda.
# "opcionais" melhoram a coleta; ausentes, são omitidas e registradas no manifesto.
FLAGS = {
    "subfinder": {
        "obrigatorias": ["-d", "-silent", "-o", "-timeout", "-max-time"],
        "opcionais": ["-duc", "-oJ", "-cs", "-nc", "-rl"],
    },
    "httpx": {
        "obrigatorias": ["-l", "-nfs", "-silent", "-sc", "-title", "-server", "-ip", "-cname", "-location",
                         "-ct", "-t", "-rl", "-timeout", "-retries", "-j", "-rstr"],
        "opcionais": ["-td", "-duc", "-probe", "-tls-grab", "-nc", "-H", "-cl", "-ob"],
    },
    "katana": {
        "obrigatorias": ["-u", "-cs", "-dr", "-cos", "-d", "-ct", "-mrs", "-timeout", "-retry", "-c", "-p",
                         "-rl", "-j", "-silent", "-fs"],
        "opcionais": ["-duc", "-or", "-kf", "-jc", "-nc", "-H", "-mdp", "-hrl", "-ndef"],
    },
}

# Flags que nunca podem aparecer: seguir redirecionamentos, preencher formulários,
# validar segredos em provedores, armazenar respostas ou desabilitar escopo.
FLAGS_PROIBIDAS = {
    "httpx": {"-fr", "-follow-redirects", "-fhr", "-follow-host-redirects", "-irr", "-include-response",
              "-sr", "-store-response", "-ss", "-screenshot", "-path", "-ports", "-p"},
    "katana": {"-aff", "-automatic-form-fill", "-kb-validate-secrets", "-ns", "-no-scope", "-sr",
               "-store-response", "-hl", "-headless", "-pc", "-path-climb", "-do", "-display-out-scope",
               "-al", "-auto-login"},
    "subfinder": {"-nW", "-active", "-oI", "-ip", "-up", "-update"},
}


class ErroFerramenta(RuntimeError):
    pass


@dataclass
class InfoFerramenta:
    nome: str
    binario: str
    caminho: str | None = None
    versao: str | None = None
    flags_disponiveis: set[str] = field(default_factory=set)
    faltando_obrigatorias: list[str] = field(default_factory=list)
    faltando_opcionais: list[str] = field(default_factory=list)
    erro: str | None = None

    @property
    def ok(self) -> bool:
        return self.caminho is not None and not self.faltando_obrigatorias and self.erro is None

    def suporta(self, flag: str) -> bool:
        return flag in self.flags_disponiveis

    def resumo(self) -> dict:
        return {"binario": self.binario, "caminho": self.caminho, "versao": self.versao, "ok": self.ok,
                "faltando_obrigatorias": self.faltando_obrigatorias,
                "faltando_opcionais": self.faltando_opcionais, "erro": self.erro}


def extrair_flags(ajuda: str) -> set[str]:
    flags = set()
    for linha in _ANSI.sub("", ajuda).splitlines():
        m = _FLAG_LINHA.match(linha)
        if m:
            flags.update(f for f in m.groups() if f)
    return flags


def extrair_versao(texto: str) -> str | None:
    texto = _ANSI.sub("", texto)
    for linha in texto.splitlines():
        if "version" in linha.lower():
            m = _VERSAO.search(linha)
            if m:
                return m.group(1)
    m = _VERSAO.search(texto)
    return m.group(1) if m else None


def inspecionar(nome: str, binario: str, timeout: int = 30) -> InfoFerramenta:
    """Executa apenas '-version' e '-h' (sem tráfego para alvos) e valida as flags."""
    info = InfoFerramenta(nome=nome, binario=binario)
    caminho = shutil.which(binario)
    if not caminho:
        info.erro = f"binário não encontrado: {binario}"
        return info
    info.caminho = caminho
    try:
        v = subprocess.run([caminho, "-version"], capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        info.versao = extrair_versao((v.stdout or "") + "\n" + (v.stderr or ""))
        h = subprocess.run([caminho, "-h"], capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        info.flags_disponiveis = extrair_flags((h.stdout or "") + "\n" + (h.stderr or ""))
    except (OSError, subprocess.TimeoutExpired) as exc:
        info.erro = f"falha ao inspecionar: {exc}"
        return info
    if not info.flags_disponiveis:
        info.erro = "nenhuma flag reconhecida na saída de -h"
    spec = FLAGS[nome]
    info.faltando_obrigatorias = [f for f in spec["obrigatorias"] if f not in info.flags_disponiveis]
    info.faltando_opcionais = [f for f in spec["opcionais"] if f not in info.flags_disponiveis]
    return info


def inspecionar_todas(cfg: dict, nomes=("subfinder", "httpx", "katana")) -> dict[str, InfoFerramenta]:
    binarios = cfg.get("ferramentas", {})
    return {n: inspecionar(n, binarios.get(n, n)) for n in nomes}


def exigir(info: InfoFerramenta, dry_run: bool) -> None:
    if info.ok:
        return
    msg = info.erro or f"{info.nome} {info.versao}: flags obrigatórias ausentes: {', '.join(info.faltando_obrigatorias)}"
    if dry_run:
        print(f"[aviso] {msg} (dry-run continua; a execução real será bloqueada)")
        return
    raise ErroFerramenta(msg)


class Montador:
    """Monta argv com verificação de suporte: opcionais ausentes são omitidos e anotados."""

    def __init__(self, info: InfoFerramenta):
        self.info = info
        self.argv: list[str] = [info.caminho or info.binario]
        self.omitidas: list[str] = []
        self._validar = bool(info.flags_disponiveis)

    def add(self, flag: str, *valores, opcional: bool = False) -> "Montador":
        proibidas = FLAGS_PROIBIDAS.get(self.info.nome, set())
        if flag in proibidas:
            raise ErroFerramenta(f"flag proibida pela esteira: {self.info.nome} {flag}")
        if self._validar and flag not in self.info.flags_disponiveis:
            if opcional:
                self.omitidas.append(flag)
                return self
            raise ErroFerramenta(f"{self.info.nome} não suporta {flag} (versão {self.info.versao})")
        self.argv.append(flag)
        self.argv.extend(str(v) for v in valores)
        return self


# ------------------------------------------------------------------ execução
@dataclass
class ResultadoExecucao:
    codigo: int | None
    linhas: int
    interrompido: str | None  # None, "cota", "duracao"
    duracao_s: float


def executar_streaming(argv: list[str], destino_jsonl: Path, log: Path, duracao_max_s: float,
                       max_linhas: int | None = None, filtro=None, entrada: Path | None = None) -> ResultadoExecucao:
    """Executa a ferramenta lendo JSONL da saída padrão.

    Cada linha passa por ``filtro`` (que pode remover campos como corpo de resposta)
    antes de ser gravada. O processo é encerrado ao atingir a cota de linhas ou a
    duração máxima; a interrupção é devolvida para registro de cobertura.
    """
    inicio = time.monotonic()
    linhas = 0
    interrompido = None
    stdin = open(entrada, "rb") if entrada else subprocess.DEVNULL
    with open(log, "ab") as flog, open(destino_jsonl, "a", encoding="utf-8") as fout:
        flog.write(f"# {dt.datetime.now(dt.timezone.utc).isoformat()} argv={json.dumps(argv)}\n".encode())
        flog.flush()
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=flog, stdin=stdin,
                                env=os.environ.copy(), start_new_session=True)
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        buffer = b""
        fim = False
        while not fim:
            restante = duracao_max_s - (time.monotonic() - inicio)
            if restante <= 0:
                interrompido = "duracao"
                break
            eventos = sel.select(timeout=min(1.0, restante))
            for _chave, _ in eventos:
                bloco = os.read(proc.stdout.fileno(), 65536)
                if not bloco:
                    fim = True
                    break
                buffer += bloco
                *completas, buffer = buffer.split(b"\n")
                for bruta in completas:
                    linha = bruta.decode("utf-8", errors="replace").strip()
                    if not linha.startswith("{"):
                        continue
                    try:
                        obj = json.loads(linha)
                    except json.JSONDecodeError:
                        continue
                    if filtro:
                        obj = filtro(obj)
                    fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    linhas += 1
                    if max_linhas is not None and linhas >= max_linhas:
                        interrompido = "cota"
                        fim = True
                        break
            if not eventos and proc.poll() is not None:
                # processo terminou; drena o que restar
                resto = proc.stdout.read() or b""
                buffer += resto
                for bruta in buffer.split(b"\n"):
                    linha = bruta.decode("utf-8", errors="replace").strip()
                    if linha.startswith("{"):
                        try:
                            obj = json.loads(linha)
                        except json.JSONDecodeError:
                            continue
                        if filtro:
                            obj = filtro(obj)
                        fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
                        linhas += 1
                buffer = b""
                break
        sel.close()
        if proc.poll() is None:
            _encerrar(proc)
        codigo = proc.wait()
    if entrada:
        stdin.close()
    return ResultadoExecucao(codigo=codigo, linhas=linhas, interrompido=interrompido,
                             duracao_s=round(time.monotonic() - inicio, 2))


def executar_simples(argv: list[str], log: Path, duracao_max_s: float) -> ResultadoExecucao:
    inicio = time.monotonic()
    with open(log, "ab") as flog:
        flog.write(f"# {dt.datetime.now(dt.timezone.utc).isoformat()} argv={json.dumps(argv)}\n".encode())
        flog.flush()
        proc = subprocess.Popen(argv, stdout=flog, stderr=flog, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            codigo = proc.wait(timeout=duracao_max_s)
            interrompido = None
        except subprocess.TimeoutExpired:
            _encerrar(proc)
            codigo = proc.wait()
            interrompido = "duracao"
    return ResultadoExecucao(codigo=codigo, linhas=0, interrompido=interrompido,
                             duracao_s=round(time.monotonic() - inicio, 2))


def _encerrar(proc: subprocess.Popen) -> None:
    import signal
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


class LimitadorTaxa:
    """Limitador simples: no máximo ``por_segundo`` operações por segundo."""

    def __init__(self, por_segundo: float):
        self.intervalo = 1.0 / por_segundo if por_segundo and por_segundo > 0 else 0.0
        self._proximo = 0.0

    def aguardar(self) -> None:
        if not self.intervalo:
            return
        agora = time.monotonic()
        if agora < self._proximo:
            time.sleep(self._proximo - agora)
            agora = self._proximo
        self._proximo = agora + self.intervalo


# ------------------------------------------------------------------ janela
def verificar_janela(janela: str, agora: dt.datetime | None = None) -> tuple[bool, str]:
    """Janela no formato ISO 'inicio/fim' (UTC). Vazia = sem restrição declarada."""
    if not janela:
        return True, "janela não declarada"
    try:
        ini_s, fim_s = janela.split("/", 1)
        ini = _parse_iso(ini_s)
        fim = _parse_iso(fim_s)
    except ValueError:
        return False, f"janela inválida: {janela!r} (use AAAA-MM-DDTHH:MMZ/AAAA-MM-DDTHH:MMZ)"
    agora = agora or dt.datetime.now(dt.timezone.utc)
    if ini <= agora <= fim:
        return True, "dentro da janela"
    return False, f"fora da janela autorizada ({janela}); agora={agora.strftime('%Y-%m-%dT%H:%M:%SZ')}"


def _parse_iso(s: str) -> dt.datetime:
    s = s.strip().replace("Z", "+00:00")
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d
