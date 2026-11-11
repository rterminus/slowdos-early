# Testbed Slowloris — P1 (Testbed e captura)

Ambiente automatizado para gerar e capturar tráfego de ataque Slowloris
contra um Apache propositalmente limitado, com tráfego benigno em paralelo,
contagem de conexões retidas, e variação dos dois parâmetros que definem o
ataque: a **taxa de abertura de conexões** (`-r`) e a **lentidão de cada
conexão** (`-i`).

## Estrutura esperada no repositório

Este script assume que `testbed/` fica dentro do repositório do projeto, e
grava as saídas em `data/`, um nível acima:

```
repo/
├─ testbed/                  <- esta pasta
│  ├─ Dockerfile
│  ├─ orchestrate.sh
│  └─ README.md
└─ data/
   ├─ raw/
   │  ├─ pcaps/               <- gerado pelo script (NÃO commitar no git)
   │  │  └─ checksums.sha256  <- gerado pelo script (esse sim vai no git)
   │  └─ logs/                 <- gerado pelo script (vai no git, são pequenos)
   └─ manifest.csv             <- gerado pelo script (vai no git, caminhos relativos)
```

Se você ainda não moveu esta pasta pra dentro do repositório, coloque-a lá
como `testbed/` antes de rodar — o script cria `../data/...` automaticamente
a partir de onde ele mesmo está.

**Importante sobre o git:** os `.pcap` costumam ser grandes e não devem ir
pro git. Suba-os para o drive combinado com a equipe, mantendo os mesmos
nomes, e versione só `data/raw/pcaps/checksums.sha256` (gerado
automaticamente) — assim qualquer um confere a integridade do arquivo depois
de baixar, sem precisar versionar o binário.

## Pré-requisitos (instalar no host, não dentro do contêiner)

```bash
sudo apt-get update
sudo apt-get install -y docker.io slowhttptest tcpdump curl iproute2 coreutils
sudo usermod -aG docker $USER   # opcional, evita precisar de sudo pro docker
```

No Arch Linux: `sudo pacman -S docker tcpdump curl iproute2 coreutils` +
`slowhttptest` via AUR.

## Como rodar

```bash
cd testbed
chmod +x orchestrate.sh
sudo ./orchestrate.sh
```

É necessário `sudo` porque o `tcpdump` exige privilégio para capturar pacotes.

## O que o script faz

1. Builda a imagem do Apache (poucos workers → satura rápido), sobe o
   contêiner e descobre seu IP interno (`docker inspect`) para registrar no
   manifesto.

2. **Fase 1 — baseline benigno isolado** (`BENIGN_ONLY_REPETITIONS`
   execuções, por padrão 3): com o Apache limpo e **sem nenhum ataque
   rodando**, simula vários "usuários" fazendo requisições espaçadas
   aleatoriamente. Gera `benigno_only_repN.pcap` + log de conexões. **Esse é
   o conjunto de negativos limpos usado para calcular FPR.**

3. **Fase 2 — varia a TAXA (`-r`)**, com o intervalo (`-i`) **fixo** em
   `FIXED_INTERVAL_FOR_RATE` (padrão: 10s). Testa `RATES` (padrão: 50, 100,
   200, 400 conexões/s) × `REPETITIONS` (padrão: 3) repetições. Gera
   `taxaX_repY.pcap` + log de conexões + relatório do slowhttptest.

4. **Fase 3 — varia o INTERVALO (`-i`)**, com a taxa (`-r`) **fixa** em
   `FIXED_RATE_FOR_INTERVAL` (padrão: 100 conexões/s). Testa `INTERVALS`
   (padrão: 5, 10, 20, 30 segundos) × `INTERVAL_REPETITIONS` (padrão: 3)
   repetições. Gera `intervaloX_repY.pcap` + log de conexões + relatório.
   **Essa fase existe porque a Fase 2 sozinha só varia a velocidade de
   abertura de conexões, não a lentidão de cada conexão individual** — que é
   o parâmetro que mais afeta as features extraídas por fluxo (ponto
   levantado no retorno do P3).

   Em ambas as fases 2 e 3, o tráfego benigno roda **em paralelo** com o
   ataque (cenário realista, mostra o efeito sobre usuários reais durante o
   incidente) — diferente da Fase 1, que é isolada e serve só de baseline de
   FPR.

5. Gera `data/manifest.csv`, juntando **todas** as execuções (benignas, Fase
   2 e Fase 3) num único índice, com caminhos relativos, os parâmetros `r` e
   `i` usados em cada execução, qual deles foi a variável de interesse
   (`param_nome`/`param_valor`), e os IPs do atacante/servidor.

6. Gera `data/raw/pcaps/checksums.sha256` com o hash de cada `.pcap`, e
   encerra.

## Ajustando a escala do experimento

Edite estas variáveis no topo do `orchestrate.sh`:

| Variável | O que controla |
|---|---|
| `RATES` | Taxas de conexão/s testadas na Fase 2 |
| `FIXED_INTERVAL_FOR_RATE` | Intervalo (`-i`) fixo usado durante toda a Fase 2 |
| `REPETITIONS` | Repetições de cada taxa, na Fase 2 |
| `INTERVALS` | Intervalos (s) testados na Fase 3 |
| `FIXED_RATE_FOR_INTERVAL` | Taxa (`-r`) fixa usada durante toda a Fase 3 |
| `INTERVAL_REPETITIONS` | Repetições de cada intervalo, na Fase 3 |
| `ATTACK_DURATION` | Duração de cada execução de ataque (Fases 2 e 3), em segundos |
| `TOTAL_CONNECTIONS` | Total de conexões simultâneas que o slowhttptest abre (`-c`) |
| `BENIGN_CONCURRENT_CLIENTS` | Quantos "usuários" simulados rodam em paralelo |
| `BENIGN_MIN_THINK` / `BENIGN_MAX_THINK` | Faixa de pausa (s) entre requisições de cada usuário simulado |
| `BENIGN_ONLY_REPETITIONS` | Capturas benignas isoladas (baseline de FPR) |
| `BENIGN_ONLY_DURATION` | Duração de cada captura benigna isolada, em segundos |

Com os valores padrão (3 capturas benignas + 12 execuções na Fase 2 + 12
execuções na Fase 3, todas de 120s), o experimento completo leva pouco mais
de **55 minutos**. Pra um teste rápido antes de rodar tudo, reduza
temporariamente `ATTACK_DURATION`, `BENIGN_ONLY_DURATION` e as listas de
repetições.

## O manifesto (`data/manifest.csv`)

Colunas:

| Coluna | Significado |
|---|---|
| `label` | Nome da execução (ex: `taxa200_rep1`, `intervalo30_rep2`, `benigno_only_rep1`) |
| `tipo` | `ataque` ou `benigno` |
| `param_nome` | Qual parâmetro foi variado nesta execução: `r`, `i`, ou `NA` (benigno) |
| `param_valor` | Valor desse parâmetro nesta execução |
| `r` | Valor real de `-r` usado (mesmo quando fixo) |
| `i` | Valor real de `-i` usado (mesmo quando fixo) |
| `duracao_s` | Duração da execução, em segundos |
| `ip_atacante` | IP de onde partiu o ataque/tráfego (host, `127.0.0.1`) |
| `ip_servidor` | IP do Apache (IP interno do contêiner Docker) |
| `pcap_file` | Caminho **relativo** ao pcap (`data/raw/pcaps/...`) |
| `conexoes_log` | Caminho **relativo** ao log de conexões retidas |
| `slowhttptest_report` | Caminho **relativo** ao relatório HTML do slowhttptest (`NA` para benigno) |

Esse arquivo substitui os antigos `resumo_execucoes.csv` e
`resumo_benigno.csv` — agora é um índice único, com caminhos que funcionam em
qualquer máquina (desde que a estrutura `testbed/` + `data/` seja respeitada).

## Observações importantes

- Rode isso **apenas contra o seu próprio Apache em contêiner, na sua máquina
  ou em um ambiente isolado que você controla**. Nunca aponte o `slowhttptest`
  para um host que não seja seu.
- Para calcular FPR: rode seu detector contra os pcaps de `tipo=benigno` no
  manifesto — qualquer alerta disparado aí é, por definição, um falso
  positivo (`FP`); o que não disparar é verdadeiro negativo (`TN`).
  `FPR = FP / (FP + TN)`.
- Se o `tcpdump` não capturar nada com `CAPTURE_IFACE="any"`, troque pela
  interface da bridge do Docker (`ip addr show docker0`) editando essa
  variável no topo do script.
