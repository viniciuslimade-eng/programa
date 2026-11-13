"""Servidor HTTP local para testes da esteira (nenhum tráfego externo).

Rotas simulam: páginas, anexos, backup esquecido, redirecionamento interno e externo,
timeout, bloqueio de WAF, API citada em JavaScript, documentação OpenAPI/WSDL,
título com fórmula de planilha e link com token em parâmetro.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PAGINA = """<!doctype html><html><head><title>=HYPERLINK("http://x.test","Portal")</title>
<script src="/app.js"></script></head><body>
<a href="/sobre">Sobre</a>
<a href="/arquivos/relatorio.pdf">Relatório</a>
<a href="/backup/site.bak">antigo</a>
<a href="/logout">Sair</a>
<a href="/excluir?id=1">Excluir</a>
<a href="http://example.test.evil.test/phish">parecido</a>
<a href="/redir-externo">externo</a>
<a href="/redir-interno">interno</a>
<a href="/busca?q=teste&token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl">busca</a>
<a href="/api/docs/openapi.json">API</a>
<a href="/servico.asmx?wsdl">WSDL</a>
<a href="/restrito">restrito</a>
</body></html>"""

JS = 'fetch("/api/v1/usuarios").then(r=>r.json()); const SEGREDO="AKIAABCDEFGHIJKLMNOP";'
OPENAPI = json.dumps({"openapi": "3.0.0", "info": {"title": "API de teste", "version": "2"},
                      "paths": {"/api/v2/carteiras": {"get": {}}}})
WSDL = '<?xml version="1.0"?><definitions name="Servico"></definitions>'


class Manipulador(BaseHTTPRequestHandler):
    server_version = "ServidorTeste/1.0"
    contador = 0
    caminhos: list[str] = []
    trava = threading.Lock()

    def log_message(self, *a):  # silencioso
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass  # cliente desistiu (ex.: timeout do teste)

    def _resp(self, status, corpo="", tipo="text/html; charset=utf-8", extra=None):
        dados = corpo.encode()
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(dados)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(dados)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        with Manipulador.trava:
            Manipulador.contador += 1
            Manipulador.caminhos.append(self.path)
        caminho = urlsplit(self.path).path
        q = urlsplit(self.path).query
        porta = self.server.server_address[1]
        if caminho == "/":
            return self._resp(200, PAGINA)
        if caminho == "/sobre":
            return self._resp(200, "<html><head><title>Sobre</title></head><body><a href='/'>início</a></body></html>")
        if caminho == "/arquivos/relatorio.pdf":
            return self._resp(200, "%PDF-1.4 teste", "application/pdf")
        if caminho == "/backup/site.bak":
            return self._resp(200, "senha=NaoDeveriaAparecer", "application/octet-stream")
        if caminho in ("/logout", "/excluir"):
            return self._resp(200, "<title>efeito colateral</title>")
        if caminho == "/redir-externo":
            return self._resp(302, "", extra={"Location": "http://example.test.evil.test/phish?sessao=abc123"})
        if caminho == "/redir-interno":
            return self._resp(301, "", extra={"Location": "/sobre"})
        if caminho == "/redir-porta":
            return self._resp(302, "", extra={"Location": f"http://localhost:1/"})
        if caminho == "/lento":
            time.sleep(4)
            return self._resp(200, "<title>lento</title>")
        if caminho == "/restrito":
            return self._resp(403, "<html><head><title>Request Rejected</title></head></html>")
        if caminho == "/app.js":
            return self._resp(200, JS, "application/javascript")
        if caminho == "/api/v1/usuarios":
            return self._resp(401, '{"erro":"nao autenticado"}', "application/json",
                              {"WWW-Authenticate": "Bearer"})
        if caminho == "/api/docs/openapi.json":
            return self._resp(200, OPENAPI, "application/json")
        if caminho == "/servico.asmx" and q.lower() == "wsdl":
            return self._resp(200, WSDL, "text/xml")
        if caminho == "/busca":
            return self._resp(200, "<title>Busca</title>")
        if caminho == "/robots.txt":
            return self._resp(200, "User-agent: *\nDisallow: /admin-antigo/\n", "text/plain")
        if caminho == "/sitemap.xml":
            return self._resp(200, f'<?xml version="1.0"?><urlset><url><loc>http://localhost:{porta}/sobre</loc></url></urlset>',
                              "application/xml")
        return self._resp(404, "<title>Não encontrado</title>")


def iniciar(porta: int = 0) -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", porta), Manipulador)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


if __name__ == "__main__":
    srv, porta = iniciar(int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
    print(f"servidor local em http://localhost:{porta}/ (Ctrl+C para sair)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
