#!/usr/bin/env bash
#
# Orquestra o testbed do P1 (Testbed e captura) para o artigo sobre Slowloris.
#
# O que este script faz, em ordem:
#   1. Builda e sobe o Apache em contêiner (poucos workers, fácil de saturar)
#   2. Captura BENIGN_ONLY_REPETITIONS execuções de tráfego 100% benigno,
#      SEM nenhum ataque rodando junto — isso é o baseline "limpo" de
#      negativos, necessário para calcular FPR depois (ver nota abaixo)
#   3. Para cada combinação de TAXA x REPETIÇÃO de ataque:
#        a. Reinicia o Apache (estado limpo a cada teste)
#        b. Dispara tráfego benigno em paralelo (cenário realista, misturado
#           com o ataque — não serve de baseline de FPR, serve pra ver como
#           o ataque afeta usuários reais durante o incidente)
#        c. Inicia o tcpdump, gravando um .pcap nomeado pela taxa/repetição
#        d. Inicia o monitor de conexões retidas (log .csv com timestamp)
#        e. Roda o slowhttptest (o ataque em si) por ATTACK_DURATION segundos
#        f. Encerra tráfego benigno, captura e monitor
#   4. Encerra o Apache no final
#
# NOTA SOBRE FPR (False Positive Rate):
#   Para calcular FPR, um detector precisa ser testado contra tráfego 100%
#   legítimo, sem ataque misturado — senão não dá pra saber se uma conexão
#   "suspeita" era de fato um falso positivo ou era o próprio ataque. Por
#   isso a etapa 2 roda ISOLADA, antes de qualquer ataque começar. Os pcaps
#   e logs dela (prefixo "benigno_only_repN") são o seu conjunto de
#   negativos limpos; os pcaps de ataque (prefixo "taxaX_repY") são o seu
#   conjunto de positivos.
#
# Requisitos no host: docker, slowhttptest, tcpdump, curl, iproute2 (para 'ss'),
# e permissão de sudo para tcpdump (captura de pacotes exige privilégio).
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

RATES=(50 100 200 400)      # conexões novas por segundo que o slowhttptest abre
REPETITIONS=3                 # repetições de cada taxa (para variância estatística)
ATTACK_DURATION=120            # duração de cada execução de ataque, em segundos
TOTAL_CONNECTIONS=1000         # -c do slowhttptest: total de conexões simultâneas

BENIGN_CONCURRENT_CLIENTS=5    # nº de "usuários" simulados rodando em paralelo
BENIGN_MIN_THINK=1             # tempo mínimo (s) entre requisições de um cliente
BENIGN_MAX_THINK=4             # tempo máximo (s) entre requisições de um cliente

BENIGN_ONLY_REPETITIONS=3      # repetições da captura benigna isolada (baseline de FPR)
BENIGN_ONLY_DURATION=120       # duração de cada captura benigna isolada, em segundos
                                 # (igual a ATTACK_DURATION, pra ter janelas comparáveis)

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PCAP_DIR="${BASE_DIR}/pcaps"
LOG_DIR="${BASE_DIR}/logs"
CAPTURE_IFACE="any"            # 'any' funciona na maioria dos hosts Linux

mkdir -p "$PCAP_DIR" "$LOG_DIR"

BENIGN_CLIENT_PIDS=()
TCPDUMP_PID=""
MONITOR_PID=""

# ---------------------------------------------------------------------------
# FUNÇÕES AUXILIARES
# ---------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_dependencies() {
    local missing=()
    for cmd in docker slowhttptest tcpdump curl ss; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "Faltam dependências no host: ${missing[*]}"
        echo "Instale com algo como:"
        echo "  sudo apt-get update && sudo apt-get install -y docker.io slowhttptest tcpdump apache2-utils"
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
    local outfile_prefix="$2"
    log "Rodando slowhttptest: taxa=${rate} conexões/s, duração=${ATTACK_DURATION}s"
    slowhttptest -c "$TOTAL_CONNECTIONS" -H -i 10 -r "$rate" -t GET \
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

    echo "${label},${pcap_file},${conn_log},${BENIGN_ONLY_DURATION}" >> "$BENIGN_SUMMARY_FILE"
    log "Captura benigna concluída. pcap: ${pcap_file} | log conexões: ${conn_log}"
    sleep 3
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

# ---------------------------------------------------------------------------
# FASE 1 — baseline benigno isolado (necessário para calcular FPR depois)
# ---------------------------------------------------------------------------
BENIGN_SUMMARY_FILE="${LOG_DIR}/resumo_benigno.csv"
echo "label,pcap_file,conexoes_log,duracao_s" > "$BENIGN_SUMMARY_FILE"

for rep in $(seq 1 "$BENIGN_ONLY_REPETITIONS"); do
    run_benign_only_capture "benigno_only_rep${rep}"
done

# ---------------------------------------------------------------------------
# FASE 2 — execuções de ataque (com tráfego benigno misturado, cenário realista)
# ---------------------------------------------------------------------------
SUMMARY_FILE="${LOG_DIR}/resumo_execucoes.csv"
echo "taxa,repeticao,pcap_file,conexoes_log,slowhttptest_report,duracao_s" > "$SUMMARY_FILE"

for rate in "${RATES[@]}"; do
    for rep in $(seq 1 "$REPETITIONS"); do
        label="taxa${rate}_rep${rep}"
        pcap_file="${PCAP_DIR}/${label}.pcap"
        conn_log="${LOG_DIR}/${label}_conexoes.csv"
        report_prefix="${LOG_DIR}/${label}_slowhttptest"

        log "=== Execução: taxa=${rate}, repetição=${rep} ==="

        restart_apache
        start_benign_traffic
        start_capture "$pcap_file"
        start_connection_monitor "$conn_log"

        run_attack "$rate" "$report_prefix"

        stop_connection_monitor
        stop_capture
        stop_benign_traffic

        echo "${rate},${rep},${pcap_file},${conn_log},${report_prefix}.html,${ATTACK_DURATION}" >> "$SUMMARY_FILE"

        log "Execução concluída. pcap: ${pcap_file} | log conexões: ${conn_log}"
        sleep 3
    done
done

log "Tudo concluído."
log "Baseline benigno (FPR): ${BENIGN_SUMMARY_FILE}"
log "Execuções de ataque: ${SUMMARY_FILE}"
log "Pcaps em: ${PCAP_DIR}"
log "Logs/relatórios em: ${LOG_DIR}"
