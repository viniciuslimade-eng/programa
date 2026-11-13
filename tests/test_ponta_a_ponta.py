"""Pipeline completo contra servidor local.

Por padrão usa as ferramentas falsas (tests/ferramentas_falsas). Com ESTEIRA_BIN_REAIS=<dir>
contendo subfinder/httpx/katana reais, o mesmo teste roda com as ferramentas instaladas.
"""

import csv
import json
import os
import unittest

from esteira_superficie.cli import main
from esteira_superficie.rodada import Rodada, ler_csv, ler_jsonl

from . import servidor_local
from .base import FIXTURES, CasoComTmp

CONFIG = """
[escopo]
dominios_exatos = ["localhost"]
sufixos = []
esquemas = ["http", "https"]
portas = [{porta}]

[identificacao]
user_agent = "Inventario-Teste/0.1"

[ferramentas]
subfinder = "subfinder"
httpx = "httpx"
katana = "katana"

[dns]
taxa_por_segundo = 0
amostras_wildcard = 2

[sondagem]
taxa_por_segundo = 5
concorrencia = 1
timeout_s = 2
max_requisicoes = {max_req}
duracao_max_s = 120
max_bytes_resposta = 65536
max_saltos_redirecionamento = 2
seguir_redirecionamentos_revisados = true

[rastreamento]
profundidade = 3
duracao_max_s = 60
duracao_total_max_s = 120
max_bytes_resposta = 65536
timeout_s = 2
concorrencia = 1
paralelismo = 1
taxa_por_segundo = 20
max_requisicoes = {max_rast}
exclusoes = '(?i)(logout|signout|sair|excluir|delete)'
arquivos_conhecidos = "{kf}"
js_crawl = true

[relatorio]
csv_bom = true
"""


class TestPontaAPonta(CasoComTmp):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.porta = servidor_local.iniciar()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        super().setUp()
        bin_reais = os.environ.get("ESTEIRA_BIN_REAIS")
        if bin_reais:
            os.environ["PATH"] = f"{bin_reais}{os.pathsep}{self._path_original}"
        else:
            self.usar_ferramentas_falsas()
        self.reais = bool(bin_reais)
        self.base = f"http://localhost:{self.porta}"

    def preparar(self, max_req=20, max_rast=200, nome="r"):
        cfg = self.tmp / f"config-{nome}.toml"
        cfg.write_text(CONFIG.format(porta=self.porta, max_req=max_req, max_rast=max_rast,
                                     kf="" if self.reais else "all"), encoding="utf-8")
        dnsfx = self.tmp / "dns.json"
        dnsfx.write_text(json.dumps({"registros": {"localhost": {"A": ["127.0.0.1"]}}}))
        internos = self.tmp / "internos.csv"
        internos.write_text(f"host,fonte,responsavel,portas\nlocalhost,f5,GTI Portal,{self.porta}\n", encoding="utf-8")
        self.assertEqual(main(["iniciar", "--config", str(cfg), "--base", str(self.tmp), "--nome", nome,
                               "--ip-saida", "127.0.0.1", "--operador", "teste"]), 0)
        rd = self.tmp / nome
        self.assertEqual(main(["descobrir", "--rodada", str(rd), "--hosts-internos", str(internos), "--sem-subfinder",
                               "--dns-fixture", str(dnsfx)]), 0)
        origens = self.tmp / "origens.csv"
        linhas = ["url,sondar,rastrear,responsavel,revisado_por,data_revisao,terceiro_confirmado,observacao",
                  f"{self.base}/,sim,sim,GTI,SEG,2026-11-13,na,portal",
                  f"{self.base}/redir-externo,sim,nao,GTI,SEG,2026-11-13,na,redirecionamento externo",
                  f"{self.base}/redir-interno,sim,nao,GTI,SEG,2026-11-13,na,redirecionamento interno",
                  f"{self.base}/redir-porta,sim,nao,GTI,SEG,2026-11-13,na,porta fora do escopo",
                  f"{self.base}/lento,sim,nao,GTI,SEG,2026-11-13,na,timeout",
                  f"{self.base}/restrito,sim,nao,GTI,SEG,2026-11-13,na,waf",
                  "http://localhost.evil.test/,sim,nao,GTI,SEG,2026-11-13,na,parecido"]
        origens.write_text("\n".join(linhas) + "\n", encoding="utf-8")
        self.assertEqual(main(["revisar", "--rodada", str(rd), "--origens", str(origens)]), 0)
        return rd

    def test_pipeline(self):
        rd = self.preparar()
        r = Rodada(rd)
        self.assertEqual(len(json.loads((rd / "revisao" / "aprovadas.json").read_text())["rejeitados"]), 1)

        # dry-run não gera tráfego
        antes = servidor_local.Manipulador.contador
        self.assertEqual(main(["sondar", "--rodada", str(rd), "--dry-run"]), 0)
        self.assertEqual(main(["rastrear", "--rodada", str(rd), "--dry-run"]), 0)
        self.assertEqual(servidor_local.Manipulador.contador, antes)
        plano = json.loads((rd / "sondagem" / "plano.json").read_text())
        argv = plano["comandos"][0]["argv"]
        for f in ("-nfs", "-rl", "-t", "-timeout", "-retries", "-rstr", "-j"):
            self.assertIn(f, argv)
        self.assertNotIn("-fr", argv)
        pk = json.loads((rd / "rastreamento" / "plano.json").read_text())["comandos"][0]["argv"]
        for f in ("-dr", "-cs", "-cos", "-fs", "-mrs", "-ct", "-rl"):
            self.assertIn(f, pk)

        # sondagem
        self.assertEqual(main(["sondar", "--rodada", str(rd)]), 0)
        servicos = {s["alvo"]: s for s in ler_jsonl(rd / "sondagem" / "servicos.jsonl")}
        self.assertEqual(servicos[f"{self.base}/"]["status_code"], 200)
        self.assertEqual(servicos[f"{self.base}/restrito"]["classificacao"], "possivel_bloqueio_waf")
        self.assertIn(servicos[f"{self.base}/lento"]["estado"], ("falha", "sem_resultado"))
        if servicos[f"{self.base}/lento"]["estado"] == "falha":
            self.assertEqual(servicos[f"{self.base}/lento"]["classificacao"], "timeout")
        # redirecionamento interno seguido (origem aprovada), salto 1
        self.assertEqual(servicos[f"{self.base}/sobre"]["salto"], 1)
        redirs = {x["origem"]: x for x in ler_jsonl(rd / "sondagem" / "redirecionamentos.jsonl")}
        ext = redirs[f"{self.base}/redir-externo"]
        self.assertEqual(ext["decisao"], "fora_do_escopo_registrado")
        self.assertNotIn("abc123", ext["destino_sanitizado"])
        self.assertEqual(redirs[f"{self.base}/redir-porta"]["decisao"], "fora_do_escopo_registrado")
        self.assertEqual(redirs[f"{self.base}/redir-interno"]["decisao"], "seguido")
        caminhos = servidor_local.Manipulador.caminhos
        self.assertNotIn("/phish?sessao=abc123", caminhos)

        # rastreamento
        self.assertEqual(main(["rastrear", "--rodada", str(rd)]), 0)
        urls = ler_jsonl(rd / "rastreamento" / "urls.jsonl")
        caminhos_obs = {u["caminho_sanitizado"]: u for u in urls}
        self.assertIn("/sobre", caminhos_obs)
        self.assertEqual(caminhos_obs["/backup/site.bak"]["tipo"], "arquivo_suspeito")
        self.assertEqual(caminhos_obs["/api/docs/openapi.json"]["tipo"], "documentacao_api")
        self.assertNotIn("/logout", caminhos_obs)
        self.assertFalse(any(u["host"] != "localhost" for u in urls))
        self.assertTrue(all("eyJ" not in u["url_sanitizada"] for u in urls))
        self.assertEqual(caminhos_obs["/arquivos/relatorio.pdf"]["tipo"], "documento")
        if True:  # API citada apenas em JavaScript, encontrada via -jc
            self.assertEqual(caminhos_obs["/api/v1/usuarios"]["controle_acesso"], "autenticacao_exigida (validar eficácia)")
        bruto = "".join(p.read_text() for p in (rd / "bruto").glob("katana-*.jsonl"))
        self.assertNotIn("NaoDeveriaAparecer", bruto)  # corpo removido antes de gravar
        self.assertNotIn('"body"', bruto)
        self.assertNotIn("/logout", "".join(caminhos))

        # consolidação
        self.assertEqual(main(["consolidar", "--rodada", str(rd),
                               "--webservices-documentados", str(FIXTURES / "webservices-documentados.csv"),
                               "--tecnologias-confirmadas", str(FIXTURES / "tecnologias-confirmadas.csv")]), 0)
        rel = rd / "relatorios"
        for nome in ("ativos.csv", "urls.csv", "webservices.csv", "achados.csv", "relatorio.md", "ativos.jsonl",
                     "cobertura.json"):
            self.assertTrue((rel / nome).exists(), nome)
        bruto_csv = (rel / "ativos.csv").read_bytes()
        self.assertTrue(bruto_csv.startswith(b"\xef\xbb\xbf"))
        with open(rel / "ativos.csv", encoding="utf-8-sig", newline="") as f:
            ativos = list(csv.DictReader(f))
        titulo = next(a["titulo"] for a in ativos if a["resposta"].startswith("200") and "HYPERLINK" in a["titulo"])
        self.assertTrue(titulo.startswith("'="))
        self.assertTrue(any("ServidorTeste" in a["tecnologia_confirmada"] for a in ativos))
        ws = {w["rota"]: w for w in ler_csv(rel / "webservices.csv")}
        self.assertTrue(ws["/ws/legado.asmx"]["estado"].startswith("apenas_documentado"))
        self.assertTrue(ws["/api/docs/openapi.json"]["documentacao"].startswith("documentação de API pública"))
        self.assertTrue(ws["/servico.asmx"]["documentacao"].startswith("WSDL público"))
        self.assertTrue(ws["/api/v1/usuarios"]["estado"].startswith("controle_observado + documentado"))
        anon = [a for a in ler_csv(rel / "achados.csv") if a["categoria"] == "webservice_acesso_anonimo"]
        self.assertFalse(any("openapi" in a["ativo"] for a in anon))  # documentação não é contada duas vezes
        achados = ler_csv(rel / "achados.csv")
        cats = {a["categoria"] for a in achados}
        for c in ("arquivo_esquecido_ou_backup", "documentacao_api_publica", "redirecionamento_externo",
                  "webservice_documentado_nao_observado", "http_sem_redirecionamento_https"):
            self.assertIn(c, cats)
        self.assertTrue(all(a["prioridade"] == "a validar" for a in achados))
        md = (rel / "relatorio.md").read_text()
        for secao in ("## Escopo", "## Ponto de observação", "## Cobertura por etapa",
                      "## Divergências com o inventário interno", "## Lacunas de cobertura", "## Itens prioritários"):
            self.assertIn(secao, md)
        tudo = "".join(p.read_text(encoding="utf-8-sig") for p in rel.iterdir())
        for proibido in ("NaoDeveriaAparecer", "AKIAABCDEFGHIJKLMNOP", "abc123", "eyJhbGci"):
            self.assertNotIn(proibido, tudo)
        self.assertTrue(all(e["etapa"] for e in r.erros()))
        # permissões restritas
        self.assertEqual(oct((rd / "bruto").stat().st_mode & 0o777), "0o700")

        # comparação com nova rodada sem rastreamento → perda de cobertura, não desaparecimento
        rd2 = self.preparar(nome="r2")
        main(["sondar", "--rodada", str(rd2)])
        main(["consolidar", "--rodada", str(rd2), "--comparar-com", str(rd)])
        comp = json.loads((rd2 / "relatorios" / "comparacao.json").read_text())
        self.assertTrue(comp["urls_removidas"])
        self.assertTrue(all(u["classificacao"].startswith("perda_de_cobertura") for u in comp["urls_removidas"]))

    def test_cota_e_retomada(self):
        rd = self.preparar(max_req=2, max_rast=3, nome="cota")
        self.assertEqual(main(["sondar", "--rodada", str(rd)]), 3)  # parcial
        servicos = ler_jsonl(rd / "sondagem" / "servicos.jsonl")
        self.assertEqual(sum(1 for s in servicos if s["estado"] == "nao_sondado_cota"), 4)
        self.assertEqual(Rodada(rd).etapa("sondagem")["estado"], "parcial")
        # retomada processa só os pendentes (ainda com cota 2 por execução)
        antes = {s["alvo"] for s in servicos if s["estado"] in ("respondeu", "falha")}
        main(["sondar", "--rodada", str(rd), "--retomar"])
        depois = ler_jsonl(rd / "sondagem" / "servicos.jsonl")
        feitos = {s["alvo"] for s in depois if s["estado"] in ("respondeu", "falha")}
        self.assertTrue(antes < feitos)
        # rastreamento limitado por quantidade
        self.assertEqual(main(["rastrear", "--rodada", str(rd)]), 3)
        est = json.loads((rd / "rastreamento" / "estado.json").read_text())
        self.assertEqual(list(est.values())[0]["estado"], "interrompida_cota")
        self.assertLessEqual(len(ler_jsonl(rd / "rastreamento" / "urls.jsonl")), 3)

    def test_janela_bloqueia(self):
        cfg = self.tmp / "c.toml"
        cfg.write_text(CONFIG.format(porta=self.porta, max_req=5, max_rast=5, kf=""), encoding="utf-8")
        main(["iniciar", "--config", str(cfg), "--base", str(self.tmp), "--nome", "jan",
              "--janela", "2000-01-01T00:00Z/2000-01-01T01:00Z"])
        rd = self.tmp / "jan"
        origens = self.tmp / "o.csv"
        origens.write_text("url,sondar,rastrear,responsavel,revisado_por,data_revisao,terceiro_confirmado,observacao\n"
                           f"{self.base}/,sim,sim,,SEG,2026-11-13,na,\n", encoding="utf-8")
        main(["revisar", "--rodada", str(rd), "--origens", str(origens)])
        antes = servidor_local.Manipulador.contador
        self.assertEqual(main(["sondar", "--rodada", str(rd)]), 2)
        self.assertEqual(servidor_local.Manipulador.contador, antes)


if __name__ == "__main__":
    unittest.main()
