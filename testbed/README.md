# Testbed Slowloris — P1 (Testbed e captura)

Ambiente automatizado para gerar e capturar tráfego de ataque Slowloris
contra um Apache propositalmente limitado, com tráfego benigno em paralelo
e contagem de conexões retidas.

## Estrutura

```
slowloris_testbed/
├── Dockerfile          # Apache com MPM prefork e poucos workers
├── orchestrate.sh      # script que automatiza todo o experimento
├── pcaps/              # saída: um .pcap por (taxa, repetição)
└── logs/               # saída: logs de conexões retidas, relatórios do slowhttptest, resumo.csv
```

## Pré-requisitos (instalar no host, não dentro do contêiner)

```bash
sudo apt-get update
sudo apt-get install -y docker.io slowhttptest tcpdump curl iproute2
sudo usermod -aG docker $USER   # opcional, evita precisar de sudo pro docker
```

No Arch Linux: `sudo pacman -S docker tcpdump curl iproute2` + `slowhttptest` via AUR.

## Como rodar

```bash
chmod +x orchestrate.sh
sudo ./orchestrate.sh
```

É necessário `sudo` porque o `tcpdump` exige privilégio para capturar pacotes.

## O que o script faz

1. Builda a imagem do Apache (poucos workers → satura rápido) e sobe o contêiner

2. **Fase 1 — baseline benigno isolado** (`BENIGN_ONLY_REPETITIONS` execuções,
   por padrão 3): com o Apache limpo e **sem nenhum ataque rodando**, simula
   vários "usuários" fazendo requisições espaçadas aleatoriamente
   (`BENIGN_CONCURRENT_CLIENTS` clientes, pausa entre
   `BENIGN_MIN_THINK`–`BENIGN_MAX_THINK` segundos), gravando um `.pcap` e um
   log de conexões próprios, prefixados `benigno_only_repN`. **Esse é o
   conjunto de negativos limpos usado para calcular FPR** — não tem ataque
   misturado, então qualquer coisa que um detector marcar como "suspeita"
   aqui é, por definição, falso positivo.

3. **Fase 2 — execuções de ataque**: para cada combinação de **taxa**
   (conexões/s) × **repetição**, definidas no topo do script (`RATES` e
   `REPETITIONS`):
   - Reinicia o Apache (estado limpo)
   - Dispara o mesmo tráfego benigno simulado em paralelo com o ataque
     (cenário realista — mostra o efeito do ataque sobre usuários reais,
     mas **não** serve de baseline de FPR, já que está misturado com ataque)
   - Começa a gravar o `.pcap` com `tcpdump`
   - Começa a logar conexões `ESTABLISHED` na porta alvo, 1x por segundo
   - Dispara o ataque com `slowhttptest`
   - Encerra tráfego benigno, captura e log ao fim do ataque

4. Ao final, gera dois arquivos de índice:
   - `logs/resumo_benigno.csv` — aponta para os pcaps/logs da Fase 1 (baseline de FPR)
   - `logs/resumo_execucoes.csv` — aponta para os pcaps/logs da Fase 2 (ataques)

## Ajustando a escala do experimento

Edite estas variáveis no topo do `orchestrate.sh`:

| Variável | O que controla |
|---|---|
| `RATES` | As taxas de conexão/s testadas (ex: 50, 100, 200, 400) |
| `REPETITIONS` | Quantas vezes repetir cada taxa de ataque |
| `ATTACK_DURATION` | Duração de cada ataque, em segundos |
| `TOTAL_CONNECTIONS` | Total de conexões simultâneas que o slowhttptest abre |
| `BENIGN_CONCURRENT_CLIENTS` | Quantos "usuários" simulados rodam em paralelo |
| `BENIGN_MIN_THINK` / `BENIGN_MAX_THINK` | Faixa de pausa (s) entre requisições de cada usuário simulado |
| `BENIGN_ONLY_REPETITIONS` | Quantas capturas benignas isoladas rodar (baseline de FPR) |
| `BENIGN_ONLY_DURATION` | Duração de cada captura benigna isolada, em segundos |

Com os valores padrão (3 capturas benignas de 120s + 4 taxas × 3 repetições de
ataque de 120s), o experimento completo leva pouco mais de **30 minutos**.

## Saídas para usar no artigo

**Ataques (Fase 2):**
- **`pcaps/taxaX_repY.pcap`** — tráfego bruto capturado, pronto para extração
  de features (ex: via CICFlowMeter) ou inspeção no Wireshark
- **`logs/taxaX_repY_conexoes.csv`** — série temporal de conexões retidas
  (o "sintoma" do Slowloris); ótimo para plotar um gráfico de conexões × tempo
- **`logs/taxaX_repY_slowhttptest.html`** — relatório nativo do slowhttptest
  (conexões iniciadas, fechadas, status do serviço)
- **`logs/resumo_execucoes.csv`** — índice de tudo, para automatizar análises
  depois

**Baseline benigno / FPR (Fase 1):**
- **`pcaps/benigno_only_repN.pcap`** — tráfego 100% legítimo, sem ataque
  misturado; é o conjunto de **negativos** para calcular FPR
- **`logs/benigno_only_repN_conexoes.csv`** — conexões retidas durante
  tráfego legítimo (deve ficar baixo e estável — se subir muito aqui, é sinal
  de que o próprio Apache está configurado agressivo demais, não do detector)
- **`logs/resumo_benigno.csv`** — índice das capturas benignas

Para calcular FPR depois: rode seu detector contra os pcaps de
`benigno_only_repN` — qualquer alerta disparado aí é, por definição, um falso
positivo (`FP`); o que não disparar alerta é verdadeiro negativo (`TN`).
`FPR = FP / (FP + TN)`.

## Observações importantes

- Rode isso **apenas contra o seu próprio Apache em contêiner, na sua máquina
  ou em um ambiente isolado que você controla**. Nunca aponte o `slowhttptest`
  para um host que não seja seu.
- Se os valores de `RATES`/`TOTAL_CONNECTIONS` não derrubarem o Apache na sua
  máquina, reduza `MaxRequestWorkers` no `Dockerfile` ou aumente a taxa/duração.
- A interface de captura `any` funciona na maioria dos hosts Linux; se o
  `tcpdump` não capturar nada, troque `CAPTURE_IFACE` por `docker0` ou pela
  interface virtual específica do contêiner (`ip addr` para descobrir).
