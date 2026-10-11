# Voltolini Mobile Decision Core

Código experimental para propostas locais de decisão, com validação de evidências, agregação de casos e painel de consulta. **Release NÃO APROVADO. G0–G8 não estão aprovados (NOT_VERIFIED).** Checks estruturais inválidos podem retornar FAIL; um arquivo existente, hash correto ou teste sintético aprovado não certifica um gate.

Este repositório separa a engenharia verificável da qualidade do modelo. Os testes públicos exercitam contratos, parsing estrito, integridade, denominadores, limites de arquivos e consulta HTTP. Eles não medem qualidade neural, latência de inferência, custo, exportação nativa ou desempenho físico. Esses indicadores globais permanecem indisponíveis.

## Conteúdo e limites

- `evaluation/`: validador estrutural, agregador exato e conversor puro de bundles, com schemas versionados. Erros/timeouts permanecem nos denominadores; precisão sem aceitas é null com motivo. Entradas não podem declarar aprovação.
- `lab/own_v01_runner.py`: auditor de metadados ZIP e referências explicitamente pinadas. Não extrai nem executa código do arquivo; integridade não comprova execução de modelo ou MLflow.
- `model/core.py`: fonte original de modelo próprio Conv/dual encoder sob MIT. **Não é BERT nem um checkpoint pretrained.** Importá-la requer PyTorch; os parâmetros são inicializados quando o chamador cria o modelo. Não há pesos, tokenizer treinado, datasets ou receita de treino publicada neste pacote.
- `server.py`, `preview_adapter.py` e assets: painel local de consulta, sem inferência ou escrita em GET. O config público começa vazio; não mostra resultados privados nem atividade inventada.
- `tests/`: fixtures sintéticas locais e controles negativos. Nenhum teste depende de arquivos privados ou de rótulos de avaliação reais.

A arquitetura original usa texto da pergunta/estado/contexto e descrições das opções. Campos tipados e valores passam por validação, mas não se tornam automaticamente entradas da representação neural. A fonte experimental não garante generalização, compreensão ordinal genérica ou segurança de ações. O Engine produz propostas e não executa ferramentas.

## Consulta sem dependências neurais

Python 3.10+ em sistema POSIX é recomendado. Os utilitários stdlib usam descritores e O_NOFOLLOW para rejeitar symlinks e writes inseguros. O conjunto público também foi verificado com Python 3.9 no macOS; isso não comprova compatibilidade do core neural. Não há passo de instalação para as consultas abaixo.

```sh
python3 -B -m unittest discover -s tests
python3 -B validate_all_gates.py --json
python3 -B lab/own_v01_runner.py audit --help
python3 -B server.py
```

O validador retorna exit 1 enquanto a release não está aprovada; isso é esperado. A CLI lê por padrão o projeto onde está instalada, sem depender do cwd. `--root` e `--evidence-dir` recebem caminhos absolutos sem travessia; `--output` exige destino novo fora do projeto e não sobrescreve arquivos. Sem `--output`, a consulta não grava snapshots.

O servidor imprime a URL `http://127.0.0.1:<porta>/` e usa porta efêmera (`listen_port: 0`). O exemplo `dashboard.config.example.json` tem `sources: []`: valores globais ficam null/NOT_VERIFIED e nenhuma fonte real é inventada. GET `/api/preview` apenas consulta fontes. Métodos de alteração são rejeitados. A atualização periódica fica desativada até clique explícito; não inicia experimentos.

Para usar fontes locais próprias, passe `--config /caminho/absoluto/config.json` com configuração mantida fora do Git. Os contratos do adapter exigem fontes compatíveis; não reutilize recibos ou caminhos de outra máquina. Não exponha o servidor à rede externa. Ctrl+C encerra o processo; iniciar uma consulta não aprova execução ao vivo.

O core neural fica isolado das CLIs e da descoberta de testes. Qualquer uso futuro exige ambiente PyTorch compatível, configuração, vocabulário e pesos próprios externos, além de validação específica. Não há download automático, integração remota ou ensaio neural nos comandos documentados.

## Verificação pública e proveniência

A preparação desta árvore executou 94 testes stdlib, com zero skips, incluindo consulta HTTP loopback efêmera e config vazio. Não foram executados treino, inferência, calibração, SDK de tracking ou testes nativos. Os oráculos são sintéticos: um resultado VALID significa somente a propriedade indicada pelo contrato.

`SOURCE_PROVENANCE.json` registra hashes originais e públicos dos arquivos derivados, sem paths privados, datasets ou resultados. `NOTICE.md` descreve a origem MIT do core e as adaptações de portabilidade. A licença não certifica a cadeia de dependências nem o comportamento do modelo. Revisão de licenças das dependências é exigida antes de qualquer distribuição com runtime neural.

Não versionar pesos, caches, estado, segredos, datasets, rótulos, predições, logits, bancos MLflow, logs, checkpoints ou pacotes recuperados. O `.gitignore` ajuda, mas a publicação exige revisão da lista exata e do diff. Este pacote não importa o histórico privado de desenvolvimento.

## Instalação e rollback local

Manter este repositório em diretório próprio. As consultas stdlib não modificam outros projetos. Use uma cópia externa para qualquer evidência operacional e conserve seus backups privados. Para rollback do painel, encerre seu processo e restaure a versão de código previamente fixada; configurações e resultados externos não são sobrescritos. Publicação de código não substitui os gates integrais nem autoriza ações reais.
