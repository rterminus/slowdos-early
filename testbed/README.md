# Testbed Slowloris — P1 (Testbed e captura)

Ambiente automatizado para gerar e capturar tráfego de ataque Slowloris
contra um Apache propositalmente limitado, com tráfego benigno em paralelo,
contagem de conexões retidas, e variação dos dois parâmetros que definem o
ataque: a **taxa de abertura de conexões** (`-r`) e a **lentidão de cada
conexão** (`-i`).

## Arquitetura: 3 contêineres, 3 IPs

Servidor, atacante e cliente benigno rodam em **contêineres separados**,
numa rede Docker dedicada, cada um com IP fixo:

| Papel | Contêiner | IP | Ferramenta |
|---|---|---|---|
| Servidor | `apache_slowloris_test` | `172.28.0.10` | Apache (poucos workers) |
| Atacante | `slowloris_attacker_run` (efêmero) | `172.28.0.20` | `slowhttptest` |
| Cliente benigno | `slowloris_benign_client` | `172.28.0.30` | `curl` (vários "usuários" simulados) |

**Por que isso importa:** numa versão anterior deste testbed, atacante e
cliente benigno rodavam os dois no host, batendo em `localhost` — ou seja,
tinham o **mesmo IP de origem** nos pcaps, tornando impossível diferenciá-los
por endereço (qualquer feature ou regra de detecção baseada em IP de origem
ficava inutilizável). Com os 3 contêineres, cada papel tem um IP real e
distinto, e os pcaps refletem isso corretamente.

## Estrutura esperada no repositório

```
repo/
├─ testbed/                   <- esta pasta
│  ├─ Dockerfile.server
│  ├─ Dockerfile.attacker
│  ├─ Dockerfile.benign
│  ├─ benign_loop.sh
│  ├─ orchestrate.sh
│  └─ README.md
└─ data/
   ├─ raw/
   │  ├─ pcaps/                <- gerado pelo script (NÃO commitar no git)
   │  │  └─ checksums.sha256   <- gerado pelo script (esse sim vai no git)
   │  └─ logs/                  <- gerado pelo script (vai no git, são pequenos)
   └─ manifest.csv              <- gerado pelo script (vai no git, caminhos relativos)
```

**Importante sobre o git:** os `.pcap` costumam ser grandes e não devem ir
pro git. Suba-os para o drive combinado com a equipe, mantendo os mesmos
nomes, e versione só `data/raw/pcaps/checksums.sha256` (gerado
automaticamente).

## Pré-requisitos (instalar no host)

```bash
sudo apt-get update
sudo apt-get install -y docker.io tcpdump curl coreutils
sudo usermod -aG docker $USER   # opcional, evita precisar de sudo pro docker
```

No Arch Linux: `sudo pacman -S docker tcpdump curl coreutils`.

**Note:** `slowhttptest` e os clientes benignos **não precisam mais estar
instalados no host** — eles rodam dentro dos contêineres atacante e benigno,
que o próprio script builda.

## Como rodar

```bash
cd testbed
chmod +x orchestrate.sh
sudo ./orchestrate.sh
```

É necessário `sudo` porque o `tcpdump` exige privilégio para capturar pacotes.

## O que o script faz

1. Cria a rede Docker dedicada `slowloris_net` (172.28.0.0/24), se ainda não
   existir, e builda as 3 imagens (servidor, atacante, cliente benigno)
2. Sobe o servidor com IP fixo `172.28.0.10`
3. **Fase 1 — baseline benigno isolado** (`BENIGN_ONLY_REPETITIONS`
   execuções, padrão 3): servidor limpo, **sem ataque**, só o cliente
   benigno rodando. Gera `benigno_only_repN.pcap` + log de conexões. **Esse
   é o conjunto de negativos limpos usado para calcular FPR.**
4. **Fase 2 — varia a TAXA (`-r`)**, intervalo (`-i`) fixo em
   `FIXED_INTERVAL_FOR_RATE` (padrão: 10s). Testa `RATES` (padrão: 50, 100,
   200, 400) × `REPETITIONS` (padrão: 3). Gera `taxaX_repY.pcap` + log +
   relatório do slowhttptest. Cliente benigno roda em paralelo.
5. **Fase 3 — varia o INTERVALO (`-i`)**, taxa (`-r`) fixa em
   `FIXED_RATE_FOR_INTERVAL` (padrão: 100). Testa `INTERVALS` (padrão: 5,
   10, 20, 30s) × `INTERVAL_REPETITIONS` (padrão: 3). Gera
   `intervaloX_repY.pcap` + log + relatório. Cliente benigno roda em
   paralelo. Essa fase cobre o parâmetro que de fato define a "lentidão" de
   cada conexão — a Fase 2 sozinha só varia a velocidade de abertura.
6. Gera `data/manifest.csv` com IPs reais, timestamps de início/fim,
   ferramenta usada, parâmetros e caminhos relativos de tudo
7. Gera `data/raw/pcaps/checksums.sha256` e encerra

## Captura e monitor de conexões — como funcionam agora

- **tcpdump**: continua rodando no **host**, na interface `any`, filtrando
  por `host 172.28.0.10` (o IP do servidor) — assim captura todo o tráfego
  de/para o servidor, venha do atacante ou do cliente benigno, cada um já
  com seu IP de origem real no pacote.
- **Conexões retidas**: como atacante e cliente benigno agora rodam em
  contêineres com namespace de rede próprio, o host não vê mais os sockets
  deles diretamente. O monitor passou a rodar via `docker exec` **dentro do
  contêiner do servidor** (`ss -ant`, filtrando `ESTAB` na porta 80) — o que
  faz sentido mesmo, já que "conexões retidas" é um recurso do servidor
  sendo esgotado, não do atacante.

## Ajustando a escala do experimento

| Variável | O que controla |
|---|---|
| `RATES` | Taxas de conexão/s testadas na Fase 2 |
| `FIXED_INTERVAL_FOR_RATE` | Intervalo (`-i`) fixo usado durante toda a Fase 2 |
| `REPETITIONS` | Repetições de cada taxa, na Fase 2 |
| `INTERVALS` | Intervalos (s) testados na Fase 3 |
| `FIXED_RATE_FOR_INTERVAL` | Taxa (`-r`) fixa usada durante toda a Fase 3 |
| `INTERVAL_REPETITIONS` | Repetições de cada intervalo, na Fase 3 |
| `ATTACK_DURATION` | Duração de cada execução de ataque (`-l`), em segundos |
| `TOTAL_CONNECTIONS` | Total de conexões simultâneas do slowhttptest (`-c`) |
| `BENIGN_CONCURRENT_CLIENTS` | "Usuários" simulados dentro do contêiner benigno |
| `BENIGN_MIN_THINK` / `BENIGN_MAX_THINK` | Faixa de pausa (s) entre requisições de cada usuário |
| `BENIGN_ONLY_REPETITIONS` | Capturas benignas isoladas (baseline de FPR) |
| `BENIGN_ONLY_DURATION` | Duração de cada captura benigna isolada, em segundos |
| `SERVER_IP` / `ATTACKER_IP` / `BENIGN_IP` | IPs fixos de cada papel na rede dedicada |
| `NETWORK_SUBNET` | Sub-rede Docker usada (mude se colidir com outra rede sua) |

Com os valores padrão (3 benignas + 12 execuções Fase 2 + 12 execuções Fase
3, todas de 120s), o experimento completo leva pouco mais de **55 minutos**.

## O manifesto (`data/manifest.csv`)

| Coluna | Significado |
|---|---|
| `label` | Nome da execução (ex: `taxa200_rep1`, `intervalo30_rep2`, `benigno_only_rep1`) |
| `tipo` | `ataque` ou `benigno` |
| `param_nome` | Parâmetro variado nesta execução: `r`, `i`, ou `NA` (benigno) |
| `param_valor` | Valor desse parâmetro nesta execução |
| `r` / `i` | Valores reais de `-r` e `-i` usados (mesmo quando fixos) |
| `duracao_s` | Duração da execução, em segundos |
| `ip_atacante` | IP do contêiner atacante (`NA` nas execuções benignas) |
| `ip_cliente_benigno` | IP do contêiner de cliente benigno |
| `ip_servidor` | IP do contêiner do Apache |
| `pcap_file` / `conexoes_log` / `slowhttptest_report` | Caminhos **relativos** a cada artefato |
| `hora_inicio` / `hora_fim` | Timestamp ISO 8601 de início e fim da execução |
| `ferramenta` | `slowhttptest+curl` (ataque) ou `curl` (benigno) |

## Observações importantes

- Rode isso **apenas no seu próprio ambiente isolado**. Nunca aponte o
  atacante para um host que não seja seu.
- Para calcular FPR: rode seu detector contra os pcaps de `tipo=benigno` no
  manifesto. `FPR = FP / (FP + TN)`.
- Se `172.28.0.0/24` colidir com outra rede já em uso na sua máquina, mude
  `NETWORK_SUBNET` e os três IPs fixos no topo do script.
- Se quiser reaproveitar a rede entre execuções (não precisa recriar toda
  vez), não tem problema — o script já checa se ela existe antes de criar.
