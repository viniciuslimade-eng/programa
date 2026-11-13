import datetime as dt
import os
import unittest

from esteira_superficie.ferramentas import (FLAGS, ErroFerramenta, InfoFerramenta, Montador, extrair_flags,
                                            extrair_versao, inspecionar, verificar_janela)

from .base import FIXTURES, CasoComTmp


class TestFlagsReais(unittest.TestCase):
    """As ajudas em fixtures/ajuda foram capturadas de subfinder v2.17.0, httpx v1.12.0 e katana v1.8.0."""

    def test_flags_usadas_existem_nas_versoes_capturadas(self):
        for nome, spec in FLAGS.items():
            flags = extrair_flags((FIXTURES / "ajuda" / f"{nome}-h.txt").read_text())
            faltando = [f for f in spec["obrigatorias"] + spec["opcionais"] if f not in flags]
            self.assertEqual(faltando, [], f"{nome}: {faltando}")

    def test_alias_longo_reconhecido(self):
        flags = extrair_flags((FIXTURES / "ajuda" / "httpx-h.txt").read_text())
        self.assertIn("-no-fallback-scheme", flags)
        self.assertIn("-follow-redirects", flags)  # existe, mas é proibida pela esteira

    def test_versao(self):
        self.assertEqual(extrair_versao("[\x1b[34mINF\x1b[0m] Current Version: v1.12.0"), "1.12.0")
        self.assertEqual(extrair_versao("[INF] Current version: v1.8.0"), "1.8.0")


class TestInspecao(CasoComTmp):
    def test_ferramenta_falsa_ok(self):
        self.usar_ferramentas_falsas()
        info = inspecionar("httpx", "httpx")
        self.assertTrue(info.ok, info.resumo())
        self.assertEqual(info.versao, "1.12.0")

    def test_flag_obrigatoria_ausente_bloqueia(self):
        self.usar_ferramentas_falsas()
        os.environ["FALSA_REMOVER_FLAGS"] = "-rl,-tls-grab"
        self.addCleanup(os.environ.pop, "FALSA_REMOVER_FLAGS", None)
        info = inspecionar("httpx", "httpx")
        self.assertFalse(info.ok)
        self.assertIn("-rl", info.faltando_obrigatorias)
        self.assertIn("-tls-grab", info.faltando_opcionais)
        m = Montador(InfoFerramenta("httpx", "httpx", "/x", "1", {"-l"}))
        m.add("-tls-grab", opcional=True)
        self.assertEqual(m.omitidas, ["-tls-grab"])
        with self.assertRaises(ErroFerramenta):
            m.add("-rl", 1)

    def test_binario_inexistente(self):
        info = inspecionar("katana", "katana-inexistente-xyz")
        self.assertFalse(info.ok)

    def test_flags_proibidas(self):
        info = InfoFerramenta("httpx", "httpx", "/x", "1", {"-fr", "-l"})
        with self.assertRaises(ErroFerramenta):
            Montador(info).add("-fr")
        info = InfoFerramenta("katana", "katana", "/x", "1", {"-aff", "-ns", "-kb-validate-secrets"})
        for f in ("-aff", "-ns", "-kb-validate-secrets"):
            with self.assertRaises(ErroFerramenta):
                Montador(info).add(f)


class TestJanela(unittest.TestCase):
    def test_janela(self):
        agora = dt.datetime(2026, 11, 20, 23, 0, tzinfo=dt.timezone.utc)
        self.assertTrue(verificar_janela("2026-11-20T22:00Z/2026-11-21T02:00Z", agora)[0])
        self.assertFalse(verificar_janela("2026-11-21T22:00Z/2026-11-22T02:00Z", agora)[0])
        self.assertFalse(verificar_janela("amanhã", agora)[0])
        self.assertTrue(verificar_janela("", agora)[0])


if __name__ == "__main__":
    unittest.main()
