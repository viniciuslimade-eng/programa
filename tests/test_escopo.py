import unittest

from esteira_superficie.escopo import Escopo, normalizar_host, regex_origem
import re

CFG = {"escopo": {"dominios_exatos": ["example.org", "www.example.org"], "sufixos": ["example.org"],
                  "esquemas": ["http", "https"], "portas": [80, 443, 8443], "hosts_excluidos": ["excluido.example.org"]}}


class TestEscopo(unittest.TestCase):
    def setUp(self):
        self.e = Escopo.de_config(CFG)

    def test_normalizacao(self):
        self.assertEqual(normalizar_host("  WWW.Example.Org. ")[0], "www.example.org")
        self.assertEqual(normalizar_host("https://sistemas.example.org/x")[0], "sistemas.example.org")
        self.assertEqual(normalizar_host("*.example.org")[1], "curinga")
        self.assertEqual(normalizar_host("192.0.2.1")[1], "ip_literal")
        self.assertEqual(normalizar_host("in_valido.example.org")[1], "invalido")
        self.assertEqual(normalizar_host("-a.example.org")[1], "invalido")

    def test_dominio_exato_e_sufixo_com_ponto(self):
        self.assertTrue(self.e.host_no_escopo("example.org")[0])
        self.assertTrue(self.e.host_no_escopo("a.b.c.example.org")[0])

    def test_dominios_parecidos_fora_do_escopo(self):
        for h in ("xexample.org", "example.org.evil.com", "example-org.net", "example.orga",
                  "example.net", "wwwexample.org", "exаmple.org"):  # último com 'а' cirílico
            ok, motivo = self.e.host_no_escopo(h)
            self.assertFalse(ok, h)

    def test_host_excluido(self):
        self.assertEqual(self.e.host_no_escopo("excluido.example.org"), (False, "host_excluido"))

    def test_validar_url(self):
        self.assertTrue(self.e.validar_url("https://www.example.org/").ok)
        self.assertTrue(self.e.validar_url("https://sistemas.example.org:8443/x").ok)
        v = self.e.validar_url("https://www.example.org:8080/")
        self.assertIn("porta_nao_permitida:8080", v.motivos)
        self.assertIn("esquema_nao_permitido:ftp", self.e.validar_url("ftp://www.example.org/").motivos)
        self.assertIn("credenciais_na_url", self.e.validar_url("https://u:p@www.example.org/").motivos)
        self.assertIn("fora_do_dominio", self.e.validar_url("https://www.example.org.evil.com/").motivos)
        self.assertIn("porta_invalida", self.e.validar_url("https://www.example.org:99999/").motivos)
        # redirecionamento relativo resolvido contra a base
        self.assertTrue(self.e.validar_url("/sobre", base="https://www.example.org/a").ok)
        self.assertEqual(self.e.validar_url("http://www.example.org/").origem, "http://www.example.org:80")

    def test_regex_origem(self):
        r = re.compile(regex_origem("https", "www.example.org", 443))
        self.assertTrue(r.search("https://www.example.org/x"))
        self.assertTrue(r.search("https://www.example.org:443/x"))
        self.assertTrue(r.search("https://www.example.org"))
        self.assertFalse(r.search("https://www.example.org.evil.com/"))
        self.assertFalse(r.search("http://www.example.org/"))
        self.assertFalse(r.search("https://www.example.org:8443/"))
        self.assertFalse(r.search("https://wwwXexample.org/"))
        r2 = re.compile(regex_origem("https", "sistemas.example.org", 8443))
        self.assertTrue(r2.search("https://sistemas.example.org:8443/"))
        self.assertFalse(r2.search("https://sistemas.example.org/"))

    def test_escopo_vazio(self):
        with self.assertRaises(ValueError):
            Escopo.de_config({"escopo": {}})


if __name__ == "__main__":
    unittest.main()
