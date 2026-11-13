# esteira-superficie

CLI local em Python 3 (somente biblioteca padrão, Python ≥ 3.11) que executa a *Esteira de inventário da superfície externa* com Subfinder, dig, httpx e Katana. Cada etapa é um subcomando e grava seus resultados num diretório de rodada. Todas as etapas podem ser executadas em `--dry-run` e retomadas depois de uma interrupção.

```
iniciar → ferramentas → descobrir → revisar → sondar → rastrear → consolidar
                                      ▲          │          │
                                      └── lista de origens revisadas (obrigatória)
```

## Garantias de segurança

| Garantia | Como é aplicada |
|---|---|
| Dry-run sem tráfego | `--dry-run` monta e grava os comandos (`plano.json`) sem executar Subfinder, dig, httpx ou Katana. A única execução local é `-version`/`-h`, que não acessa a rede. Teste: `test_pipeline` confere que o contador do servidor local não muda. |
| Origens revisadas obrigatórias | `sondar` e `rastrear` só aceitam alvos de `revisao/aprovadas.json`. A aprovação guarda o SHA-256 da lista: se o CSV for alterado depois, as etapas recusam até que se rode `revisar` de novo. |
| Escopo | Domínio **exato** ou **sufixo com ponto** (`x.example.org` passa; `xexample.org`, `example.org.evil.com` e homógrafos IDN não passam), esquema e porta permitidos, sem credenciais, query ou fragmento na origem. O escopo é revalidado na saída do Katana. |
| Redirecionamentos | O httpx roda sem `-fr` e o Katana com `-dr`. Cada `Location` é validado e registrado (`redirecionamentos.jsonl`) com a decisão: `fora_do_escopo_registrado`, `no_escopo_origem_nao_revisada_registrado`, `registrado_nao_seguido`, `seguido`, `limite_de_saltos` ou `laco_ou_repetido`. Só é seguido, um salto por vez, quando `seguir_redirecionamentos_revisados = true` **e** o destino é uma origem aprovada. |
| Limites | Taxa, concorrência, timeout, `retries 0`, tamanho de resposta (`-rstr`/`-mrs`), duração por origem e total, e cota de requisições (alvos do httpx; linhas do Katana, com o processo encerrado ao atingir a cota). |
| Flags proibidas | O montador recusa, por exemplo, `-fr`, `-irr` e `-sr` (httpx), e `-aff`, `-ns`, `-hl`, `-kb-validate-secrets` e `-pc` (Katana). |
| Janela | Se `--janela` for informada no `iniciar`, `sondar` e `rastrear` recusam execução fora dela. |
| Sanitização | Corpos e requisições/respostas brutas são descartados **antes** de gravar a saída do Katana/httpx. Nos relatórios: sem credenciais nem fragmento na URL, valores de parâmetros como `[REDIGIDO]`, tokens/JWT/CPF/CNPJ/e-mail mascarados no caminho e no texto. |
| CSV | UTF-8 (com BOM, configurável), e toda célula iniciada por `= + - @ \t \r` recebe o prefixo `'`. |
| Permissões | `umask 077`; a rodada e `bruto/` ficam com modo `0700`. |

Os achados automáticos ficam sempre com `prioridade = a validar`. A coluna `prioridade_revisao` só ordena a fila de revisão humana. A escala crítica/alta/média/baixa do documento é aplicada depois da validação.

## Instalação

```bash
cd esteira-superficie
python3 -m pip install --user -e .
```

Também é possível rodar sem instalar: `python3 -m esteira_superficie ...`. Os binários `subfinder`, `httpx` (ProjectDiscovery) e `katana` precisam estar no `PATH`, ou com caminho definido em `[ferramentas]`, além do `dig` (pacote `dnsutils` ou `bind-utils`).

Atenção: o `httpx` do ProjectDiscovery tem o mesmo nome do cliente Python `httpx`. Confira com `httpx -version`, ou aponte o caminho completo em `[ferramentas] httpx = "/opt/pd/httpx"`.

## Validação de versões e flags

```bash
esteira-superficie ferramentas --config config.toml
```

Esse comando executa apenas `-version` e `-h` e confere cada flag que a esteira usa. As **obrigatórias**, que sustentam limites e escopo, bloqueiam a etapa quando faltam. As **opcionais** são omitidas e registradas como `flags_omitidas` na cobertura. O resultado vai para o manifesto. As etapas repetem a verificação antes de executar.

Validado neste desenvolvimento com **Subfinder v2.17.0, httpx v1.12.0 e Katana v1.8.0**. As saídas de `-h` dessas versões estão em `tests/fixtures/ajuda/`. Comportamentos observados no laboratório:

- **Katana `-ob`** (*omit body*) impede a extração de endpoints em JavaScript (`-jc`) na v1.8.0, por isso não é usado. O corpo é descartado pela esteira antes da gravação.
- **Katana `-kf`** aceita **um** valor (`all`, `robotstxt` ou `sitemapxml`). No servidor de teste, `-kf all` reduziu a cobertura de links HTML. Por isso o exemplo vem com `arquivos_conhecidos = ""`. Compare as duas opções no piloto.
- **Katana sem `-ndef`** omite PDFs e outros estáticos da saída. A esteira usa `-ndef` (`incluir_estaticos = true`) para que anexos entrem no inventário.

## Diretório da rodada

```
<rodada>/
  manifesto.json        escopo, hash da config, IP de saída declarado, janela, operador, versões, estado das etapas
  erros.jsonl           erros e lacunas por etapa (DNS, timeout, cota, sem resultado, origem rejeitada…)
  entradas/             cópias com SHA-256 de config, sementes, inventário interno, origens revisadas…
  bruto/          0700  saídas das ferramentas (sem corpos) e logs — restritas à equipe de segurança
  descoberta/           candidatos.jsonl (procedência), fora-escopo, dependencias, curingas-declarados, wildcard, cobertura
  revisao/              modelo-origens.csv, aprovadas.json (com hash)
  sondagem/             servicos.jsonl, redirecionamentos.jsonl, cobertura.json
  rastreamento/         urls.jsonl, redirecionamentos.jsonl, estado.json (por origem), cobertura.json
  relatorios/           ativos/urls/webservices/achados (.csv e .jsonl), cobertura.json, comparacao.json, relatorio.md
```

Estados mantidos separados: **nome descoberto** (`nome_descoberto`), **DNS resolvido** (`dns_estado`: `resolvido`, `nxdomain`, `sem_registro` = NODATA ou `erro`, além de `resposta_generica` quando coincide com o wildcard do ramo), **serviço observado** (`servico_observado`) e **tecnologia** (`tecnologia_inferida` vem da assinatura do httpx; `tecnologia_confirmada` só vem do CSV fornecido pelo responsável).

## Arquivos de entrada

| Arquivo | Formato | Exemplo |
|---|---|---|
| config | TOML | `config.exemplo.toml` |
| sementes | TXT, um nome por linha | `exemplos/sementes.txt` |
| hosts internos | TXT ou CSV `host,fonte,responsavel,portas,terceiro,observacao` (fonte: `zona_dns`, `f5`, `firewall`, `proxy`, `gateway`, `nuvem`) | `exemplos/hosts-internos.exemplo.csv` |
| origens revisadas | CSV `url,sondar,rastrear,responsavel,revisado_por,data_revisao,terceiro_confirmado,observacao` | `exemplos/origens-revisadas.exemplo.csv` |
| webservices documentados | CSV `host,rota,protocolo,ambiente,versao,documentacao,finalidade,dados_tratados,consumidores,responsavel,fonte` | `exemplos/webservices-documentados.exemplo.csv` |
| tecnologias confirmadas | CSV `host,componente,versao,responsavel,data` | `exemplos/tecnologias-confirmadas.exemplo.csv` |

Regras da revisão: as linhas com `sondar=nao` e `rastrear=nao` são ignoradas. As selecionadas exigem `revisado_por` e uma `data_revisao` ISO. Hosts de terceiros, listados em `escopo.terceiros` ou com `terceiro=sim` no inventário, exigem `terceiro_confirmado=sim`. Um host sem procedência na descoberta gera aviso, ou é rejeitado com `--exigir-procedencia`. Nomes fora do escopo que vêm de fontes internas, como parceiros e fornecedores, são registrados como **dependências** e não são descartados em silêncio.

## Piloto

Execute numa VM Linux ou WSL2 com saída externa conhecida e sem VPN corporativa.

1. Prepare a configuração e confira as ferramentas:

```bash
cp config.exemplo.toml config.toml
```

```bash
esteira-superficie ferramentas --config config.toml
```

2. Crie a rodada, declarando o IP de saída e a janela autorizada (UTC). O comando imprime o caminho da rodada:

```bash
R=$(esteira-superficie iniciar --config config.toml --ip-saida 203.0.113.10 --janela "2026-11-20T22:00Z/2026-11-21T02:00Z" --operador "Segurança - analista")
```

```bash
esteira-superficie ferramentas --rodada "$R"
```

3. Descoberta: veja o plano primeiro e depois execute. O Subfinder consulta fontes passivas de terceiros; o DNS consulta o resolvedor configurado.

```bash
esteira-superficie descobrir --rodada "$R" --sementes exemplos/sementes.txt --hosts-internos hosts-internos.csv --dry-run
```

```bash
esteira-superficie descobrir --rodada "$R" --sementes exemplos/sementes.txt --hosts-internos hosts-internos.csv
```

4. Revisão de escopo: gere o modelo e copie para um CSV de trabalho. Nele, marque `sondar`/`rastrear` = `sim` só para o pequeno conjunto revisado e preencha `revisado_por`, `data_revisao` e, quando for o caso, `terceiro_confirmado`.

```bash
esteira-superficie revisar --rodada "$R"
```

```bash
cp "$R/revisao/modelo-origens.csv" origens-revisadas.csv
```

```bash
esteira-superficie revisar --rodada "$R" --origens origens-revisadas.csv
```

5. Sondagem HTTP. Comece com `taxa_por_segundo = 1`, acompanhe o F5/WAF e interrompa com Ctrl+C diante de degradação:

```bash
esteira-superficie sondar --rodada "$R" --dry-run
```

```bash
esteira-superficie sondar --rodada "$R"
```

6. Rastreamento, começando por uma origem revisada (o primeiro piloto usa só o portal):

```bash
esteira-superficie rastrear --rodada "$R" --dry-run
```

```bash
esteira-superficie rastrear --rodada "$R" --somente https://www.example.org/
```

7. Consolidação, opcionalmente com documentação de webservices (plano de TI, manuais), tecnologias confirmadas e comparação com a rodada anterior:

```bash
esteira-superficie consolidar --rodada "$R" --webservices-documentados webservices-documentados.csv --tecnologias-confirmadas tecnologias-confirmadas.csv
```

```bash
esteira-superficie consolidar --rodada "$R" --comparar-com inventario-20261101T220000Z
```

Na comparação, um ativo ou URL que sumiu é classificado como `desaparecimento_observado` quando foi sondado ou rastreado nesta rodada, e como `perda_de_cobertura` quando não foi.

## Retomar etapas

```bash
esteira-superficie status --rodada "$R"
```

- Uma etapa `concluida` não é refeita sem `--forcar` (descobrir, sondar, rastrear).
- `sondar --retomar` processa apenas os alvos `sem_resultado`, `interrompido` ou `nao_sondado_cota` e mantém os demais resultados. A etapa fica `parcial`, com código de saída 3, enquanto houver pendências.
- `rastrear --retomar` pula as origens `concluida` de `rastreamento/estado.json` e reprocessa as interrompidas (cota, duração ou falha). Use `--somente <url>` para limitar a execução a uma origem.
- Depois de alterar a lista de origens, rode `revisar --origens` de novo. As etapas seguintes usam a nova aprovação.
- `consolidar` pode ser repetido a qualquer momento; ele lê o estado atual das etapas.

```bash
esteira-superficie sondar --rodada "$R" --retomar
```

```bash
esteira-superficie rastrear --rodada "$R" --retomar
```

## Limites (config)

| Seção | Chave | Efeito |
|---|---|---|
| `[dns]` | `taxa_por_segundo`, `timeout_s`, `amostras_wildcard`, `ramos_wildcard_max` | consultas `dig` (A, AAAA, CNAME) e nomes aleatórios por ramo |
| `[sondagem]` | `taxa_por_segundo` (`-rl`), `concorrencia` (`-t`), `timeout_s`, `max_bytes_resposta` (`-rstr`), `max_requisicoes`, `duracao_max_s`, `max_saltos_redirecionamento` | httpx com `-retries 0` e `-nfs` |
| `[rastreamento]` | `profundidade` (`-d`), `duracao_max_s` (`-ct`), `duracao_total_max_s`, `max_bytes_resposta` (`-mrs`), `concorrencia` (`-c`), `paralelismo` (`-p`), `taxa_por_segundo` (`-rl`), `max_requisicoes`, `max_requisicoes_por_origem`, `max_paginas_por_dominio` (`-mdp`), `exclusoes` (`-cos`) | Katana com `-retry 0`, `-dr`, `-fs fqdn` e `-cs` restrito à origem exata |

Inclua em `exclusoes` qualquer rota com efeito colateral via GET. O padrão cobre logout, sair, excluir e delete, entre outras.

## Testes

```bash
python3 -m unittest discover -s tests -t . -v
```

Os testes rodam só em ambiente local: um servidor HTTP em 127.0.0.1 (`tests/servidor_local.py`), um resolvedor DNS simulado (`tests/fixtures/dns-fixture.json`) e ferramentas falsas (`tests/ferramentas_falsas/`), que emulam a interface e a saída JSONL das reais. Cenários cobertos:

- wildcard DNS simulado (`*.dev.example.test`): nome só do Subfinder é descartado; nome com respaldo interno é mantido;
- domínios parecidos (`example.test.evil.test`, `xexample.test`, homógrafo cirílico), IP literal, curinga `*.` e nome inválido;
- redirecionamento externo (registrado e não seguido, com token redigido), redirecionamento para porta fora do escopo, redirecionamento interno seguido salto a salto;
- timeout (`/lento`), bloqueio tipo WAF (`/restrito`, "Request Rejected"), cota de requisições e retomada, janela fora do horário;
- API citada apenas em JavaScript (`/api/v1/usuarios`, 401) e API apenas na documentação (`/ws/legado.asmx`), além de OpenAPI e WSDL públicos;
- título com fórmula (`=HYPERLINK`), corpo com segredo e link com JWT, para checar a neutralização no CSV e a ausência desses dados nos relatórios;
- flags ausentes ou proibidas; lista de origens adulterada após a aprovação; dry-run sem tráfego.

Para rodar o teste ponta a ponta com as ferramentas **reais** contra o servidor local:

```bash
ESTEIRA_BIN_REAIS=/caminho/dos/binarios python3 -m unittest tests.test_ponta_a_ponta -v
```

Para subir o servidor de laboratório manualmente:

```bash
python3 tests/servidor_local.py 8799
```

## Limitações conhecidas

- O IP de saída é **declarado** pelo operador. A esteira não consulta serviços externos para descobri-lo.
- A classificação de erros do httpx depende de `-probe`. Sem essa flag, falhas aparecem como `sem_resultado`.
- A detecção de bloqueio de WAF é heurística (título e servidor) e aparece como lacuna de cobertura, não como achado.
- A análise de anexos (texto, metadados, imagens) é manual e local. A esteira não baixa anexos e só registra a URL, o tipo e o estado.
- TLS: os campos do `-tls-grab` (emissor, validade, nome incompatível) são consolidados, mas não foram exercitados com HTTPS nos testes locais. Valide no piloto com `openssl s_client -servername`.
