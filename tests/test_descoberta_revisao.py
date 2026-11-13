import json
import shutil

from esteira_superficie.cli import main
from esteira_superficie.rodada import Rodada, ler_csv, ler_jsonl

from .base import FIXTURES, CasoComTmp


class TestDescobertaRevisao(CasoComTmp):
    def iniciar(self):
        self.assertEqual(main(["iniciar", "--config", str(FIXTURES / "config-descoberta.toml"), "--base", str(self.tmp),
                               "--nome", "r1", "--ip-saida", "203.0.113.10", "--operador", "teste"]), 0)
        return self.tmp / "r1"

    def descobrir(self, rd, *extra):
        os_env = {"FALSA_SUBFINDER_FIXTURE": str(FIXTURES / "subfinder-saida.jsonl")}
        import os
        os.environ.update(os_env)
        self.addCleanup(os.environ.pop, "FALSA_SUBFINDER_FIXTURE", None)
        self.usar_ferramentas_falsas()
        return main(["descobrir", "--rodada", str(rd), "--sementes", str(FIXTURES / "sementes.txt"),
                     "--hosts-internos", str(FIXTURES / "hosts-internos.csv"),
                     "--dns-fixture", str(FIXTURES / "dns-fixture.json"), *extra])

    def test_descoberta_completa(self):
        rd = self.iniciar()
        self.assertEqual(self.descobrir(rd), 0)
        cands = {c["host"]: c for c in ler_jsonl(rd / "descoberta" / "candidatos.jsonl")}
        # procedência preservada: www veio de semente, inventário interno e subfinder
        self.assertEqual(set(cands["www.example.test"]["fontes"]), {"semente", "inventario_interno", "subfinder"})
        fontes_sf = [p for p in cands["www.example.test"]["procedencia"] if p["fonte"] == "subfinder"]
        self.assertEqual(fontes_sf[0]["fontes_passivas"], ["alienvault", "crtsh"])
        self.assertEqual(cands["www.example.test"]["dns"]["registros"]["CNAME"], ["lb.example.test"])
        # wildcard simulado
        wc = {w["ramo"]: w for w in ler_jsonl(rd / "descoberta" / "wildcard.jsonl")}
        self.assertTrue(wc["dev.example.test"]["wildcard"])
        self.assertFalse(wc["example.test"]["wildcard"])
        self.assertTrue(cands["qualquer.dev.example.test"]["dns"]["resposta_generica"])
        self.assertFalse(cands["qualquer.dev.example.test"]["manter"])  # só subfinder → descartado
        self.assertTrue(cands["portal.dev.example.test"]["manter"])  # respaldo interno → mantido
        # estados DNS distintos
        self.assertEqual(cands["antigo.example.test"]["dns"]["estado"], "nxdomain")
        self.assertEqual(cands["semdados.example.test"]["dns"]["estado"], "sem_registro")
        self.assertEqual(cands["quebrado.example.test"]["dns"]["estado"], "erro")
        # domínios parecidos e inválidos fora do escopo
        fora = {f.get("host") or f.get("valor"): f["motivo"] for f in ler_jsonl(rd / "descoberta" / "fora-escopo.jsonl")}
        for h in ("example.test.evil.test", "xexample.test", "example-test.example"):
            self.assertEqual(fora[h], "fora_do_dominio")
        self.assertEqual(fora["192.0.2.10"], "ip_literal")
        self.assertEqual(fora["in_valido!.example.test"], "invalido")
        # dependências e curingas
        deps = ler_jsonl(rd / "descoberta" / "dependencias.jsonl")
        self.assertEqual([d["host"] for d in deps], ["parceiro.example.net"])
        self.assertEqual(len(ler_jsonl(rd / "descoberta" / "curingas-declarados.jsonl")), 1)
        self.assertTrue(cands["fornecedor.example.test"]["terceiro"])
        self.assertEqual(cands["sistemas.example.test"]["portas_declaradas"], [443, 8443])
        # erros registrados
        erros = Rodada(rd).erros()
        self.assertTrue(any(e["alvo"] == "quebrado.example.test" for e in erros))
        # sem reexecução
        self.assertEqual(self.descobrir(rd), 0)

    def test_dry_run_nao_consulta(self):
        rd = self.iniciar()
        self.assertEqual(self.descobrir(rd, "--dry-run"), 0)
        self.assertFalse((rd / "descoberta" / "candidatos.jsonl").exists())
        plano = json.loads((rd / "descoberta" / "plano.json").read_text())
        self.assertIn("-duc", plano["comandos"][0]["argv"])
        self.assertTrue(plano["consultas_dns_estimadas"] > 0)
        self.assertFalse(list((rd / "bruto").glob("subfinder-*.jsonl")))

    def test_revisao(self):
        rd = self.iniciar()
        self.descobrir(rd)
        self.assertEqual(main(["revisar", "--rodada", str(rd)]), 0)
        modelo = ler_csv(rd / "revisao" / "modelo-origens.csv")
        self.assertTrue(all(l["sondar"] == "nao" for l in modelo))
        self.assertIn("https://sistemas.example.test:8443/", {l["url"] for l in modelo})
        origens = self.tmp / "origens.csv"
        origens.write_text(
            "url,sondar,rastrear,responsavel,revisado_por,data_revisao,terceiro_confirmado,observacao\n"
            "https://www.example.test/,sim,sim,GTI,SEG,2026-11-13,na,ok\n"
            "https://www.example.test.evil.test/,sim,nao,,SEG,2026-11-13,na,parecido\n"
            "https://www.example.test:8080/,sim,nao,,SEG,2026-11-13,na,porta\n"
            "https://fornecedor.example.test/,sim,nao,,SEG,2026-11-13,pendente,terceiro\n"
            "https://sistemas.example.test/,sim,nao,,,2026-11-13,na,sem revisor\n"
            "https://sistemas.example.test/?token=1,sim,nao,,SEG,2026-11-13,na,query\n"
            "https://naodescoberto.example.test/,sim,nao,,SEG,2026-11-13,na,sem procedencia\n"
            "https://antigo.example.test/,nao,nao,,,,,não selecionado\n", encoding="utf-8")
        self.assertEqual(main(["revisar", "--rodada", str(rd), "--origens", str(origens)]), 0)
        dados = json.loads((rd / "revisao" / "aprovadas.json").read_text())
        aprov = {a["url"] for a in dados["aprovados"]}
        self.assertEqual(aprov, {"https://www.example.test/", "https://naodescoberto.example.test/"})
        motivos = {r["url"]: r["motivos"] for r in dados["rejeitados"]}
        self.assertIn("fora_do_dominio", motivos["https://www.example.test.evil.test/"])
        self.assertIn("porta_nao_permitida:8080", motivos["https://www.example.test:8080/"])
        self.assertIn("terceiro_sem_confirmacao_de_titularidade", motivos["https://fornecedor.example.test/"])
        self.assertIn("revisado_por_ausente", motivos["https://sistemas.example.test/"])
        self.assertIn("query_ou_fragmento_nao_permitidos", motivos["https://sistemas.example.test/?token=1"])
        # exigir procedência
        self.assertEqual(main(["revisar", "--rodada", str(rd), "--origens", str(origens), "--exigir-procedencia"]), 0)
        dados = json.loads((rd / "revisao" / "aprovadas.json").read_text())
        self.assertEqual({a["url"] for a in dados["aprovados"]}, {"https://www.example.test/"})
        # adulteração da lista após aprovação bloqueia a sondagem
        copia = rd / dados["arquivo"]
        with open(copia, "a", encoding="utf-8") as f:
            f.write("https://sombra.example.test/,sim,sim,,SEG,2026-11-13,na,\n")
        self.assertEqual(main(["sondar", "--rodada", str(rd), "--dry-run"]), 2)


class TestSemRevisao(CasoComTmp):
    def test_sondar_sem_origens_revisadas(self):
        main(["iniciar", "--config", str(FIXTURES / "config-descoberta.toml"), "--base", str(self.tmp), "--nome", "r"])
        self.assertEqual(main(["sondar", "--rodada", str(self.tmp / "r"), "--dry-run"]), 2)
        self.assertEqual(main(["rastrear", "--rodada", str(self.tmp / "r"), "--dry-run"]), 2)
        shutil.rmtree(self.tmp / "r")
