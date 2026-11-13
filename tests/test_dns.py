import unittest

from esteira_superficie import dns

from .base import FIXTURES


class TestDig(unittest.TestCase):
    def ler(self, nome):
        return (FIXTURES / "dig" / nome).read_text()

    def test_noerror_com_cname(self):
        r = dns.analisar_saida_dig(self.ler("noerror-cname.txt"), 0)
        self.assertEqual(r.status, "NOERROR")
        self.assertEqual(r.registros, {"CNAME": ["lb.example.test"], "A": ["192.0.2.2"]})

    def test_nxdomain_nodata_timeout(self):
        self.assertEqual(dns.analisar_saida_dig(self.ler("nxdomain.txt"), 0).status, "NXDOMAIN")
        nod = dns.analisar_saida_dig(self.ler("nodata.txt"), 0)
        self.assertEqual((nod.status, nod.registros), ("NOERROR", {}))
        self.assertEqual(dns.analisar_saida_dig(self.ler("timeout.txt"), 9).status, "TIMEOUT")

    def test_classificar(self):
        R = dns.RespostaDNS
        self.assertEqual(dns.classificar({"A": R("NOERROR", {"A": ["1.1.1.1"]}), "AAAA": R("NOERROR")}), "resolvido")
        self.assertEqual(dns.classificar({"A": R("NXDOMAIN"), "AAAA": R("NXDOMAIN")}), "nxdomain")
        self.assertEqual(dns.classificar({"A": R("NOERROR"), "AAAA": R("NOERROR")}), "sem_registro")
        self.assertEqual(dns.classificar({"A": R("SERVFAIL"), "AAAA": R("TIMEOUT")}), "erro")

    def test_ramos(self):
        ramos = dns.ramos_para_wildcard(["a.dev.ex.test", "b.dev.ex.test", "www.ex.test"], ["ex.test"], 10)
        self.assertEqual(ramos, ["ex.test", "dev.ex.test"])
        wc = {"ex.test": {"wildcard": False}, "dev.ex.test": {"wildcard": True}}
        self.assertEqual(dns.ramo_wildcard_de("x.y.dev.ex.test", wc), "dev.ex.test")
        self.assertIsNone(dns.ramo_wildcard_de("www.ex.test", wc))

    def test_fixture_wildcard(self):
        r = dns.ResolvedorFixture(FIXTURES / "dns-fixture.json")
        self.assertEqual(r.consultar("zzz.dev.example.test", "A").registros, {"A": ["192.0.2.99"]})
        self.assertEqual(r.consultar("zzz.example.test", "A").status, "NXDOMAIN")
        self.assertEqual(r.consultar("quebrado.example.test", "A").status, "SERVFAIL")


if __name__ == "__main__":
    unittest.main()
