import unittest

from esteira_superficie.sanitizacao import REDIGIDO, neutralizar_celula, sanitizar_texto, sanitizar_url


class TestSanitizacao(unittest.TestCase):
    def test_url_remove_credenciais_fragmento_e_valores(self):
        s = sanitizar_url("https://user:senha@www.ex.test:8443/a/b?token=abc&id=5&vazio=#frag")
        self.assertEqual(s, f"https://www.ex.test:8443/a/b?token={REDIGIDO}&id={REDIGIDO}&vazio")
        self.assertNotIn("senha", s)
        self.assertNotIn("abc", s)

    def test_url_preserva_parametro_permitido(self):
        self.assertIn("pagina=2", sanitizar_url("https://ex.test/?pagina=2&q=x", {"pagina"}))
        self.assertIn(f"pagina={REDIGIDO}", sanitizar_url("https://ex.test/?pagina=" + "a" * 40, {"pagina"}))

    def test_url_segmentos_sensiveis(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
        self.assertNotIn("eyJ", sanitizar_url(f"https://ex.test/sessao/{jwt}/x"))
        self.assertIn(REDIGIDO, sanitizar_url("https://ex.test/cpf/12345678901"))
        self.assertIn(REDIGIDO, sanitizar_url("https://ex.test/app;jsessionid=ABCDEF123/x"))
        self.assertEqual(sanitizar_url("https://ex.test/servico.asmx?wsdl"), "https://ex.test/servico.asmx?wsdl")

    def test_texto(self):
        t = sanitizar_texto("Erro: password=abc123 token: zz contato fulano@ex.test\nlinha2 AKIAABCDEFGHIJKLMNOP")
        for proibido in ("abc123", "fulano@", "AKIA", "\n"):
            self.assertNotIn(proibido, t)
        self.assertTrue(len(sanitizar_texto("x" * 1000, 50)) <= 50)

    def test_neutralizar_formula(self):
        for v in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\t=x", " =x", "＝1"):
            self.assertTrue(neutralizar_celula(v).startswith("'"), v)
        self.assertEqual(neutralizar_celula("normal"), "normal")
        self.assertEqual(neutralizar_celula(["a", "=b"]), "a; =b")  # lista vira texto que não começa com fórmula
        self.assertEqual(neutralizar_celula(["=a"]), "'=a")


if __name__ == "__main__":
    unittest.main()
