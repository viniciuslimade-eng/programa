"""Diretório da rodada, manifesto, erros e utilitários de E/S."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
import shutil
import tomllib
from pathlib import Path

from .sanitizacao import neutralizar_celula, sanitizar_texto

ETAPAS = ["ferramentas", "descoberta", "revisao", "sondagem", "rastreamento", "consolidacao"]
SUBDIRS = ["bruto", "descoberta", "revisao", "sondagem", "rastreamento", "relatorios", "entradas"]


def agora_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_arquivo(caminho: Path) -> str:
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


def carregar_config(caminho: Path) -> dict:
    with open(caminho, "rb") as f:
        return tomllib.load(f)


def escrever_json(caminho: Path, dados) -> None:
    tmp = caminho.with_suffix(caminho.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, caminho)


def ler_json(caminho: Path, padrao=None):
    if not caminho.exists():
        return padrao
    with open(caminho, encoding="utf-8") as f:
        return json.load(f)


def escrever_jsonl(caminho: Path, linhas) -> int:
    n = 0
    tmp = caminho.with_suffix(caminho.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for item in linhas:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            n += 1
    os.replace(tmp, caminho)
    return n


def ler_jsonl(caminho: Path) -> list[dict]:
    if not caminho.exists():
        return []
    saida = []
    with open(caminho, encoding="utf-8", errors="replace") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            try:
                saida.append(json.loads(linha))
            except json.JSONDecodeError:
                continue
    return saida


def escrever_csv(caminho: Path, colunas: list[str], linhas: list[dict], bom: bool = True) -> None:
    """CSV UTF-8 com fórmulas neutralizadas em todas as células."""
    tmp = caminho.with_suffix(caminho.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8-sig" if bom else "utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(colunas)
        for linha in linhas:
            w.writerow([neutralizar_celula(linha.get(c)) for c in colunas])
    os.replace(tmp, caminho)


def ler_csv(caminho: Path) -> list[dict]:
    with open(caminho, encoding="utf-8-sig", newline="") as f:
        amostra = f.read(4096)
        f.seek(0)
        try:
            dialeto = csv.Sniffer().sniff(amostra, delimiters=",;\t")
        except csv.Error:
            dialeto = csv.excel
        leitor = csv.DictReader(f, dialect=dialeto)
        return [{(k or "").strip().lower(): (v or "").strip() for k, v in linha.items()} for linha in leitor]


class Rodada:
    """Representa um diretório de rodada. Todas as etapas leem e escrevem aqui."""

    def __init__(self, caminho: Path):
        self.dir = Path(caminho).resolve()
        if not (self.dir / "manifesto.json").exists():
            raise FileNotFoundError(f"rodada sem manifesto: {self.dir} (use o subcomando 'iniciar')")
        self.manifesto = ler_json(self.dir / "manifesto.json")
        self.config = carregar_config(self.dir / "entradas" / "config.toml")

    # ---------------------------------------------------------------- criação
    @classmethod
    def criar(cls, base: Path, config_origem: Path, nome: str | None, ip_saida: str, janela: str,
              operador: str, observacao: str = "") -> "Rodada":
        cfg = carregar_config(config_origem)
        prefixo = cfg.get("rodada", {}).get("prefixo", "inventario")
        nome = nome or f"{prefixo}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        destino = Path(base) / nome
        destino.mkdir(mode=0o700, parents=True, exist_ok=False)
        for s in SUBDIRS:
            (destino / s).mkdir(mode=0o700)
        shutil.copyfile(config_origem, destino / "entradas" / "config.toml")
        manifesto = {
            "rodada": nome,
            "criada_em": agora_utc(),
            "ferramenta": "esteira-superficie",
            "operador": operador,
            "ip_saida_declarado": ip_saida,
            "janela": janela,
            "observacao": observacao,
            "config_sha256": sha256_arquivo(destino / "entradas" / "config.toml"),
            "escopo": cfg.get("escopo", {}),
            "ferramentas": {},
            "entradas": {},
            "etapas": {e: {"estado": "pendente"} for e in ETAPAS},
            "historico": [],
        }
        escrever_json(destino / "manifesto.json", manifesto)
        return cls(destino)

    # -------------------------------------------------------------- manifesto
    def salvar(self) -> None:
        escrever_json(self.dir / "manifesto.json", self.manifesto)

    def etapa(self, nome: str) -> dict:
        return self.manifesto["etapas"].setdefault(nome, {"estado": "pendente"})

    def iniciar_etapa(self, nome: str, dry_run: bool, argv: list[str]) -> None:
        e = self.etapa(nome)
        e.update({"estado": "dry-run" if dry_run else "em_execucao", "inicio": agora_utc(), "fim": None,
                  "comando": argv, "tentativas": e.get("tentativas", 0) + (0 if dry_run else 1)})
        self.manifesto["historico"].append({"etapa": nome, "evento": "inicio", "dry_run": dry_run,
                                            "em": agora_utc()})
        self.salvar()

    def concluir_etapa(self, nome: str, resumo: dict, dry_run: bool = False, estado: str | None = None) -> None:
        e = self.etapa(nome)
        e.update({"estado": estado or ("dry-run" if dry_run else "concluida"), "fim": agora_utc(), "resumo": resumo})
        self.manifesto["historico"].append({"etapa": nome, "evento": e["estado"], "em": agora_utc()})
        self.salvar()

    def falhar_etapa(self, nome: str, motivo: str) -> None:
        e = self.etapa(nome)
        e.update({"estado": "falhou", "fim": agora_utc(), "motivo": sanitizar_texto(motivo, 500)})
        self.manifesto["historico"].append({"etapa": nome, "evento": "falhou", "em": agora_utc()})
        self.salvar()

    def registrar_entrada(self, rotulo: str, caminho: Path, copiar: bool = True) -> Path:
        caminho = Path(caminho)
        destino = self.dir / "entradas" / f"{rotulo}{caminho.suffix}"
        if copiar and caminho.resolve() != destino.resolve():
            shutil.copyfile(caminho, destino)
        self.manifesto["entradas"][rotulo] = {"arquivo_original": str(caminho), "copia": str(destino.relative_to(self.dir)),
                                              "sha256": sha256_arquivo(destino), "registrado_em": agora_utc()}
        self.salvar()
        return destino

    # ------------------------------------------------------------------ erros
    def registrar_erro(self, etapa: str, tipo: str, alvo: str = "", mensagem: str = "") -> None:
        registro = {"em": agora_utc(), "etapa": etapa, "tipo": tipo, "alvo": alvo,
                    "mensagem": sanitizar_texto(mensagem, 400)}
        with open(self.dir / "erros.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(registro, ensure_ascii=False) + "\n")

    def erros(self) -> list[dict]:
        return ler_jsonl(self.dir / "erros.jsonl")

    def p(self, *partes: str) -> Path:
        return self.dir.joinpath(*partes)
