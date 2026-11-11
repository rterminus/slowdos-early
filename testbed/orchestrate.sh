#!/usr/bin/env bash
#
# Orquestra o testbed do P1 (Testbed e captura) para o artigo sobre Slowloris.
#
# O que este script faz, em ordem:
#   1. Builda e sobe o Apache em contêiner (poucos workers, fácil de saturar)
#   2. Captura BENIGN_ONLY_REPETITIONS execuções de tráfego 100% benigno,
#      SEM nenhum ataque rodando junto — isso é o baseline "limpo" de
#      negativos, necessário para calcular FPR depois (ver nota abaixo)
#   3. FASE 2 — varia a TAXA de abertura de conexões (-r do slowhttptest),
#      com o intervalo entre envios parciais (-i) FIXO. Para cada combinação
#      de TAXA x REPETIÇÃO:
#        a. Reinicia o Apache (estado limpo a cada teste)
#        b. Dispara tráfego benigno em paralelo (cenário realista, misturado
#           com o ataque — não serve de baseline de FPR, serve pra ver como
#           o ataque afeta usuários reais durante o incidente)
#        c. Inicia o tcpdump, gravando um .pcap nomeado pela taxa/repetição
#        d. Inicia o monitor de conexões retidas (log .csv com timestamp)
#        e. Roda o slowhttptest (o ataque em si) por ATTACK_DURATION segundos
#        f. Encerra tráfego benigno, captura e monitor
#   4. FASE 3 — varia o INTERVALO entre envios parciais (-i do slowhttptest,
#      a "lentidão" de cada conexão), com a TAXA (-r) FIXA. Mesma mecânica da
#      Fase 2, mas variando o parâmetro oposto. Isso cobre o ponto levantado
#      no feedback do P3: a Fase 2 sozinha só varia a velocidade de ABERTURA
#      de conexões, não a lentidão de CADA conexão — que é o que de fato
#      caracteriza o comportamento "sorrateiro" do Slowloris.
#   5. Gera data/manifest.csv, juntando todas as execuções (benignas, Fase 2
#      e Fase 3) com caminhos relativos, parâmetros usados e IPs.
#   6. Gera checksums.sha256 dos pcaps e encerra o Apache.
#
# NOTA SOBRE FPR (False Positive Rate):
#   Para calcular FPR, um detector precisa ser testado contra tráfego 100%
#   legítimo, sem ataque misturado — senão não dá pra saber se uma conexão
#   "suspeita" era de fato um falso positivo ou era o próprio ataque. Por
#   isso a etapa 2 roda ISOLADA, antes de qualquer ataque começar. Os pcaps
#   e logs dela (prefixo "benigno_only_repN") são o seu conjunto de
#   negativos limpos; os pcaps de ataque (prefixo "taxaX_repY" e
#   "intervaloY_repZ") são o seu conjunto de positivos.
#
# Requisitos no host: docker, slowhttptest, tcpdump, curl, iproute2 (para 'ss'),
# sha256sum, e permissão de sudo para tcpdump (captura de pacotes exige
# privilégio).
#
# ESTRUTURA DE PASTAS ESPERADA (ver README):
#   repo/
#   ├─ testbed/          <- este script fica aqui
#   └─ data/raw/pcaps/   <- pcaps vão aqui (fora do git)
#      data/raw/logs/    <- logs/relatórios vão aqui (dentro do git)
#      data/manifest.csv <- índice de tudo, com caminhos relativos
#
# Uso:
#   chmod +x orchestrate.sh
#   sudo ./orchestrate.sh
#
# (precisa de sudo por causa do tcpdump; o resto roda como usuário normal)

set -uo pipefail

# ---------------------------------------------------------------------------
# CONFIGURAÇÃO — ajuste aqui conforme a escala do seu experimento
# ---------------------------------------------------------------------------
CONTAINER_NAME="apache_slowloris_test"
IMAGE_NAME="apache-testbed"
TARGET_HOST="localhost"
TARGET_PORT="8080"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}/"

# --- Fase 2: varia a TAXA (-r), intervalo (-i) fixo ---
RATES=(50 100 200 400)         # conexões novas por segundo que o slowhttptest abre
FIXED_INTERVAL_FOR_RATE=10      # -i fixo usado durante a Fase 2
REPETITIONS=3                   # repetições de cada taxa (para variância estatística)

# --- Fase 3: varia o INTERVALO (-i), taxa (-r) fixa ---
INTERVALS=(5 10 20 30)          # intervalo (s) entre envios parciais de cabeçalho
FIXED_RATE_FOR_INTERVAL=100      # -r fixo usado durante a Fase 3
INTERVAL_REPETITIONS=3          # repetições de cada intervalo

ATTACK_DURATION=120              # duração de cada execução de ataque, em segundos (Fases 2 e 3)
TOTAL_CONNECTIONS=1000           # -c do slowhttptest: total de conexões simultâneas

BENIGN_CONCURRENT_CLIENTS=5      # nº de "usuários" simulados rodando em paralelo
BENIGN_MIN_THINK=1               # tempo mínimo (s) entre requisições de um cliente
BENIGN_MAX_THINK=4               # tempo máximo (s) entre requisições de um cliente

BENIGN_ONLY_REPETITIONS=3        # repetições da captura benigna isolada (baseline de FPR)
BENIGN_ONLY_DURATION=120         # duração de cada captura benigna isolada, em segundos
                                   # (igual a ATTACK_DURATION, pra ter janelas comparáveis)

# ---------------------------------------------------------------------------
# CAMINHOS — testbed/ fica dentro do repo, data/ é irmã de testbed/
# ---------------------------------------------------------------------------
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${BASE_DIR}/.." && pwd)"

PCAP_REL="data/raw/pcaps"
LOG_REL="data/raw/logs"
PCAP_DIR="${REPO_ROOT}/${PCAP_REL}"
LOG_DIR="${REPO_ROOT}/${LOG_REL}"
MANIFEST_FILE="${REPO_ROOT}/data/manifest.csv"
CHECKSUMS_FILE="${PCAP_DIR}/checksums.sha256"

CAPTURE_IFACE="any"              # 'any' funciona na maioria dos hosts Linux
ATTACKER_IP="127.0.0.1"          # slowhttptest/curl rodam no host, contra a porta mapeada
SERVER_IP=""                      # preenchido depois do container subir (docker inspect)

mkdir -p "$PCAP_DIR" "$LOG_DIR" "$(dirname "$MANIFEST_FILE")"

BENIGN_CLIENT_PIDS=()
TCPDUMP_PID=""
MONITOR_PID=""

# Array em memória com uma linha por execução; viram o manifest.csv no final.
# Cada elemento: label|tipo|param_nome|param_valor|r|i|duracao_s|pcap_rel|log_rel|report_rel
MANIFEST_ROWS=()

# ---------------------------------------------------------------------------
# FUNÇÕES AUXILIARES
# ---------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_dependencies() {
    local missing=()
    for cmd in docker slowhttptest tcpdump curl ss sha256sum; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "Faltam dependências no host: ${missing[*]}"
        echo "Instale com algo como:"
        echo "  sudo apt-get update && sudo apt-get install -y docker.io slowhttptest tcpdump curl iproute2 coreutils"
        echo "  (Arch: sudo pacman -S docker tcpdump curl iproute2 coreutils ; slowhttptest via AUR)"
        exit 1
    fi
}

build_and_start_apache() {
    log "Buildando imagem do Apache..."
    docker build -t "$IMAGE_NAME" "$BASE_DIR" || { echo "Build falhou"; exit 1; }

    # remove contêiner antigo se existir
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    log "Subindo contêiner $CONTAINER_NAME na porta $TARGET_PORT..."
    docker run -d --name "$CONTAINER_NAME" -p "${TARGET_PORT}:80" "$IMAGE_NAME" >/dev/null

    # espera o Apache responder antes de seguir
    for i in $(seq 1 15); do
        if curl -s -o /dev/null "$TARGET_URL"; then
            log "Apache está no ar."
            return 0
        fi
        sleep 1
    done
    echo "Apache não respondeu a tempo."
    exit 1
}

detect_server_ip() {
    SERVER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME" 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="desconhecido"
    fi
    log "IP do servidor (contêiner): ${SERVER_IP} | IP do atacante (host): ${ATTACKER_IP}"
}

restart_apache() {
    log "Reiniciando Apache para estado limpo..."
    docker restart "$CONTAINER_NAME" >/dev/null
    for i in $(seq 1 15); do
        if curl -s -o /dev/null "$TARGET_URL"; then
            return 0
        fi
        sleep 1
    done
    echo "Apache não voltou ao ar após restart."
    exit 1
}

start_benign_traffic() {
    log "Iniciando tráfego benigno de fundo (${BENIGN_CONCURRENT_CLIENTS} clientes simulados)..."
    BENIGN_CLIENT_PIDS=()
    for i in $(seq 1 "$BENIGN_CONCURRENT_CLIENTS"); do
        (
            while true; do
                curl -s -o /dev/null "$TARGET_URL"
                # pausa aleatória entre requisições, simulando um usuário real
                # pensando/lendo a página, em vez de bater sem parar
                sleep "$(( (RANDOM % (BENIGN_MAX_THINK - BENIGN_MIN_THINK + 1)) + BENIGN_MIN_THINK ))"
            done
        ) &
        BENIGN_CLIENT_PIDS+=("$!")
    done
}

stop_benign_traffic() {
    if [ ${#BENIGN_CLIENT_PIDS[@]} -gt 0 ]; then
        log "Parando tráfego benigno..."
        for pid in "${BENIGN_CLIENT_PIDS[@]}"; do
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" 2>/dev/null || true
        done
        BENIGN_CLIENT_PIDS=()
    fi
}

start_capture() {
    local pcap_file="$1"
    tcpdump -i "$CAPTURE_IFACE" -w "$pcap_file" "port ${TARGET_PORT}" >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2   # dá tempo do tcpdump abrir o arquivo antes do ataque começar
}

stop_capture() {
    if [ -n "$TCPDUMP_PID" ]; then
        kill -INT "$TCPDUMP_PID" >/dev/null 2>&1 || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
}

start_connection_monitor() {
    local log_file="$1"
    echo "timestamp,conexoes_retidas" > "$log_file"
    (
        while true; do
            count=$(ss -ant 2>/dev/null | awk -v port=":${TARGET_PORT}" '$1=="ESTAB" && $4 ~ port {c++} END{print c+0}')
            echo "$(date +%s),${count}" >> "$log_file"
            sleep 1
        done
    ) &
    MONITOR_PID=$!
}

stop_connection_monitor() {
    if [ -n "$MONITOR_PID" ]; then
        kill "$MONITOR_PID" >/dev/null 2>&1 || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
}

run_attack() {
    local rate="$1"
    local interval="$2"
    local outfile_prefix="$3"
    log "Rodando slowhttptest: -r ${rate} (conexões/s), -i ${interval}s, -c ${TOTAL_CONNECTIONS}, -l ${ATTACK_DURATION}s"
    slowhttptest -c "$TOTAL_CONNECTIONS" -H -i "$interval" -r "$rate" -t GET \
        -u "$TARGET_URL" -p 3 -l "$ATTACK_DURATION" \
        -o "${outfile_prefix}" >/dev/null 2>&1
}

run_benign_only_capture() {
    local label="$1"
    local pcap_file="${PCAP_DIR}/${label}.pcap"
    local conn_log="${LOG_DIR}/${label}_conexoes.csv"

    log "=== Captura benigna isolada: ${label} (sem ataque, ${BENIGN_ONLY_DURATION}s) ==="

    restart_apache
    start_capture "$pcap_file"
    start_connection_monitor "$conn_log"
    start_benign_traffic

    sleep "$BENIGN_ONLY_DURATION"

    stop_benign_traffic
    stop_connection_monitor
    stop_capture

    MANIFEST_ROWS+=("${label}|benigno|NA|NA|NA|NA|${BENIGN_ONLY_DURATION}|${PCAP_REL}/${label}.pcap|${LOG_REL}/${label}_conexoes.csv|NA")
    log "Captura benigna concluída. pcap: ${pcap_file} | log conexões: ${conn_log}"
    sleep 3
}

run_attack_execution() {
    # Executa um ataque com -r e -i dados, e registra a linha do manifesto.
    # param_nome/param_valor indicam qual dos dois foi a variável de interesse
    # desta rodada (o outro ficou fixo) — útil pra análise depois.
    local label="$1"
    local rate="$2"
    local interval="$3"
    local param_nome="$4"
    local param_valor="$5"

    local pcap_file="${PCAP_DIR}/${label}.pcap"
    local conn_log="${LOG_DIR}/${label}_conexoes.csv"
    local report_prefix="${LOG_DIR}/${label}_slowhttptest"

    log "=== Execução: ${label} (r=${rate}, i=${interval}) ==="

    restart_apache
    start_benign_traffic
    start_capture "$pcap_file"
    start_connection_monitor "$conn_log"

    run_attack "$rate" "$interval" "$report_prefix"

    stop_connection_monitor
    stop_capture
    stop_benign_traffic

    MANIFEST_ROWS+=("${label}|ataque|${param_nome}|${param_valor}|${rate}|${interval}|${ATTACK_DURATION}|${PCAP_REL}/${label}.pcap|${LOG_REL}/${label}_conexoes.csv|${LOG_REL}/${label}_slowhttptest.html")
    log "Execução concluída. pcap: ${pcap_file} | log conexões: ${conn_log}"
    sleep 3
}

write_manifest() {
    log "Gerando manifest em ${MANIFEST_FILE}..."
    {
        echo "label,tipo,param_nome,param_valor,r,i,duracao_s,ip_atacante,ip_servidor,pcap_file,conexoes_log,slowhttptest_report"
        for row in "${MANIFEST_ROWS[@]}"; do
            IFS='|' read -r label tipo param_nome param_valor r i dur pcap_rel log_rel report_rel <<< "$row"
            echo "${label},${tipo},${param_nome},${param_valor},${r},${i},${dur},${ATTACKER_IP},${SERVER_IP},${pcap_rel},${log_rel},${report_rel}"
        done
    } > "$MANIFEST_FILE"
}

generate_checksums() {
    log "Gerando checksums dos pcaps em ${CHECKSUMS_FILE}..."
    (cd "$PCAP_DIR" && sha256sum ./*.pcap > "$CHECKSUMS_FILE" 2>/dev/null) || \
        log "Aviso: nenhum pcap encontrado para gerar checksums (ou sha256sum falhou)."
}

cleanup() {
    log "Limpando processos em segundo plano..."
    stop_capture
    stop_connection_monitor
    stop_benign_traffic
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# EXECUÇÃO PRINCIPAL
# ---------------------------------------------------------------------------

check_dependencies
build_and_start_apache
detect_server_ip

# ---------------------------------------------------------------------------
# FASE 1 — baseline benigno isolado (necessário para calcular FPR depois)
# ---------------------------------------------------------------------------
for rep in $(seq 1 "$BENIGN_ONLY_REPETITIONS"); do
    run_benign_only_capture "benigno_only_rep${rep}"
done

# ---------------------------------------------------------------------------
# FASE 2 — varia a TAXA (-r), intervalo (-i) fixo em FIXED_INTERVAL_FOR_RATE
# ---------------------------------------------------------------------------
for rate in "${RATES[@]}"; do
    for rep in $(seq 1 "$REPETITIONS"); do
        label="taxa${rate}_rep${rep}"
        run_attack_execution "$label" "$rate" "$FIXED_INTERVAL_FOR_RATE" "r" "$rate"
    done
done

# ---------------------------------------------------------------------------
# FASE 3 — varia o INTERVALO (-i), taxa (-r) fixa em FIXED_RATE_FOR_INTERVAL
# ---------------------------------------------------------------------------
for interval in "${INTERVALS[@]}"; do
    for rep in $(seq 1 "$INTERVAL_REPETITIONS"); do
        label="intervalo${interval}_rep${rep}"
        run_attack_execution "$label" "$FIXED_RATE_FOR_INTERVAL" "$interval" "i" "$interval"
    done
done

# ---------------------------------------------------------------------------
# FINALIZAÇÃO
# ---------------------------------------------------------------------------
write_manifest
generate_checksums

log "Tudo concluído."
log "Manifesto: ${MANIFEST_FILE}"
log "Checksums: ${CHECKSUMS_FILE}"
log "Pcaps em: ${PCAP_DIR}"
log "Logs/relatórios em: ${LOG_DIR}"
