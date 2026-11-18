# slowdos-early

Pipeline de geração, captura e análise de tráfego do ataque **Slowloris**,
com foco em caracterizar o efeito de dois parâmetros do ataque (taxa de
abertura de conexões e intervalo entre envios parciais de cabeçalho) e em
avaliar a **Taxa de Falsos Positivos (FPR)**, utilizado como embasamento
científico para a produção do artigo da matéria Estrutura de Dados Básica II

O projeto cobre todo o fluxo: montagem do testbed isolado, geração e
captura do tráfego (ataque e benigno), extração de features por fluxo, e
treinamento/avaliação de um classificador (Hoeffding Tree).

## Estrutura do repositório

```
slowdos-early/
├─ testbed/                     # ambiente de simulação (Docker)
│  ├─ Dockerfile.server         # Apache alvo (poucos workers)
│  ├─ Dockerfile.attacker       # contêiner do slowhttptest
│  ├─ Dockerfile.benign         # contêiner de clientes benignos simulados
│  ├─ benign_loop.sh            # script dos clientes benignos
│  ├─ orchestrate.sh            # orquestra todo o experimento
│  └─ README.md                 # detalhes da arquitetura do testbed
│
├─ data/
│  ├─ raw/
│  │  ├─ pcaps/                 # capturas (.pcap) — fora do git
│  │  ├─ logs/                  # conexões retidas, relatórios do slowhttptest
│  │  └─ manifest.csv           # índice de todas as execuções (IPs, parâmetros, caminhos)
│  ├─ interim/                  # artefatos intermediários (pacotes extraídos, checks)
│  └─ processed/                # datasets finais de fluxos (ex: flows_n8_v1.csv)
│
├─ src/
│  ├─ features/
│  │  ├─ assemble.py            # monta o dataset de features a partir dos fluxos
│  │  ├─ build_flows.py         # agrupa pacotes em fluxos
│  │  ├─ explore_checks.py      # validações sobre os pcaps (portas, SYN, duplicação...)
│  │  └─ label.py               # rotulagem dos fluxos (ataque/benigno)
│  ├─ config.py                 # configurações centrais do pipeline
│  ├─ pcap_to_packets.py        # extrai pacotes brutos dos pcaps
│  ├─ run_pipeline.py           # executa o pipeline de features ponta a ponta
│  ├─ qa.py                     # checagens de qualidade do dataset final
│  └─ hoeffding_tree_pipeline.py # treino/avaliação do classificador
│
├─ tests/                       # testes automatizados do pipeline
├─ data_dictionary.md           # dicionário de dados (colunas, tipos, significado)
├─ Makefile                     # atalhos para rodar testbed, features e modelo
└─ .gitignore
```

## Pré-requisitos
- Docker e `tcpdump` (para o testbed)
- Python 3.10+ com as dependências do pipeline instaladas
- `sudo` disponível (o `tcpdump` do testbed exige privilégio de captura)

## Instalação do tcpdump:
```bash
sudo apt-get install -y docker.io tcpdump curl coreutils iproute2 # Distro Debian-based
sudo pacman -S docker tcpdump curl coreutils # Distro Arch-based
```

## Como executar

O `Makefile` concentra os três estágios do projeto. Rode nesta ordem:

**1. Gerar os dados (testbed)**

```bash
make testbed
```

Sobe o ambiente isolado (servidor, atacante e cliente benigno em
contêineres com IPs próprios), executa as rodadas de ataque e de baseline
benigno, e grava os pcaps/logs em `data/raw/`. Detalhes da arquitetura em
[`testbed/README.md`](testbed/README.md). Demora pouco mais de 1h com os
parâmetros padrão.

**2. Extrair features dos pcaps**

```bash
make features
```

Executa, em sequência: `pcap_to_packets.py` (extrai pacotes dos pcaps),
`run_pipeline.py` (monta os fluxos e o dataset de features) e `qa.py`
(valida o dataset gerado). O resultado fica em `data/processed/`.

**3. Treinar e avaliar o classificador**

```bash
make hoeffding-tree
```

Treina o modelo Hoeffding Tree sobre `data/processed/flows_n8_v1.csv` e
salva os resultados em `results/hoeffding_tree`.

## Dados e rastreabilidade

Cada execução do testbed é registrada em `data/raw/manifest.csv`, com
parâmetros usados (`-r`, `-i`), IPs de cada papel, ferramenta, timestamps e
caminhos dos artefatos gerados. O significado de cada coluna dos datasets
está documentado em [`data_dictionary.md`](data_dictionary.md).
