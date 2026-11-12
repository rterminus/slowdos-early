#!/usr/bin/env bash
#
# Orquestra o testbed do P1 (Testbed e captura) para o artigo sobre Slowloris.
#
# MUDANÇA IMPORTANTE NESTA VERSÃO: servidor, atacante e cliente benigno agora
# rodam em TRÊS CONTÊINERES SEPARADOS, numa rede Docker dedicada, cada um com
# IP fixo e distinto. Antes, atacante e cliente benigno rodavam ambos no
# host, batendo em "localhost" — ou seja, tinham o MESMO IP de origem, o que
# tornava impossível diferenciá-los por endereço nos pcaps (ponto levantado
# na revisão: "não está com IP diferente"). Agora:
#
#   servidor (Apache)........ SERVER_IP   (ex: 172.28.0.10)
#   atacante (slowhttptest).. ATTACKER_IP (ex: 172.28.0.20)
#   cliente benigno (curl)... BENIGN_IP   (ex: 172.28.0.30)
#
# O que este script faz, em ordem:
#   1. Cria a rede Docker dedicada (se não existir) e builda as 3 imagens
#   2. Sobe o contêiner do servidor com IP fixo
#   3. FASE 1 — baseline benigno isolado (sem ataque), para calcular FPR depois
#   4. FASE 2 — varia a TAXA (-r), intervalo (-i) fixo
#   5. FASE 3 — varia o INTERVALO (-i), taxa (-r) fixa
#      (em ambas, o cliente benigno roda em paralelo, em seu próprio contêiner)
#   6. Gera data/manifest.csv com IPs reais, timestamps de início/fim,
#      ferramenta usada, parâmetros e caminhos relativos
#   7. Gera checksums.sha256 dos pcaps e encerra tudo
#
# NOTA SOBRE O MONITOR DE CONEXÕES RETIDAS:
#   Como atacante e cliente benigno agora rodam em contêineres próprios (com
#   seus próprios namespaces de rede), o host NÃO enxerga mais os sockets
#   internos deles. Por isso o monitor de conexões passou a rodar via
#   'docker exec' DENTRO do contêiner do servidor, que é o único lugar onde
#   faz sentido medir "conexões retidas" mesmo (é o recurso do servidor que
#   está sendo esgotado).
#
# NOTA SOBRE O PONTO DE CAPTURA:
#   O tcpdump continua rodando no HOST, na interface "any" (enxerga o
#   tráfego de todas as interfaces, incluindo a bridge Docker da rede
#   dedicada), filtrando por "host SERVER_IP" — assim captura só o tráfego
#   de/para o servidor, venha ele do atacante ou do cliente benigno,
#   cada um com seu IP de origem real.
#
# Requisitos no host: docker, tcpdump, curl, sha256sum, e permissão de sudo
# para tcpdump (captura de pacotes exige privilégio). O slowhttptest e o
# curl dos "usuários simulados" NÃO precisam estar instalados no host — eles
# rodam dentro dos contêineres atacante/benigno.
#
# ESTRUTURA DE PASTAS ESPERADA (ver README):
#   repo/
#   ├─ testbed/          <- este script e os Dockerfiles ficam aqui
#   └─ data/raw/pcaps/   <- pcaps vão aqui (fora do git)
#      data/raw/logs/    <- logs/relatórios vão aqui (dentro do git)
#      data/manifest.csv <- índice de tudo, com caminhos relativos
#
# Uso:
#   chmod +x orchestrate.sh
#   sudo ./orchestrate.sh
#
# (precisa de sudo por causa do tcpdump; o resto roda como usuário normal,
# mas o usuário precisa estar no grupo 'docker' ou também rodar com sudo)

set -uo pipefail

# ---------------------------------------------------------------------------
# CONFIGURAÇÃO — ajuste aqui conforme a escala do seu experimento
# ---------------------------------------------------------------------------

# --- Rede Docker dedicada, com IPs fixos para cada papel ---
NETWORK_NAME="slowloris_net"
NETWORK_SUBNET="172.28.0.0/24"
SERVER_IP="172.28.0.10"
ATTACKER_IP="172.28.0.20"
BENIGN_IP="172.28.0.30"
TARGET_PORT="80"                 # porta interna do Apache (sem NAT/publish agora)
TARGET_URL="http://${SERVER_IP}:${TARGET_PORT}/"

SERVER_CONTAINER="apache_slowloris_test"
ATTACKER_IMAGE="slowloris-attacker"
BENIGN_IMAGE="slowloris-benign"
SERVER_IMAGE="slowloris-server"
BENIGN_CONTAINER="slowloris_benign_client"

# --- Fase 2: varia a TAXA (-r), intervalo (-i) fixo ---
RATES=(50 100 200 400)          # conexões novas por segundo que o slowhttptest abre
FIXED_INTERVAL_FOR_RATE=10       # -i fixo usado durante a Fase 2
REPETITIONS=3                    # repetições de cada taxa

# --- Fase 3: varia o INTERVALO (-i), taxa (-r) fixa ---
INTERVALS=(5 10 20 30)           # intervalo (s) entre envios parciais de cabeçalho
FIXED_RATE_FOR_INTERVAL=100       # -r fixo usado durante a Fase 3
INTERVAL_REPETITIONS=3           # repetições de cada intervalo

ATTACK_DURATION=120               # duração de cada execução de ataque (-l), em segundos
TOTAL_CONNECTIONS=1000            # -c do slowhttptest: total de conexões simultâneas

BENIGN_CONCURRENT_CLIENTS=5       # nº de "usuários" simulados dentro do contêiner benigno
BENIGN_MIN_THINK=1                # tempo mínimo (s) entre requisições de um cliente
BENIGN_MAX_THINK=4                # tempo máximo (s) entre requisições de um cliente

BENIGN_ONLY_REPETITIONS=3         # repetições da captura benigna isolada (baseline de FPR)
BENIGN_ONLY_DURATION=120          # duração de cada captura benigna isolada, em segundos

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

CAPTURE_IFACE="any"               # 'any' funciona na maioria dos hosts Linux

mkdir -p "$PCAP_DIR" "$LOG_DIR" "$(dirname "$MANIFEST_FILE")"

TCPDUMP_PID=""
MONITOR_PID=""

# Uma linha por execução; vira o manifest.csv no final. Campos:
# label|tipo|param_nome|param_valor|r|i|duracao_s|pcap_rel|log_rel|report_rel|hora_inicio|hora_fim|ferramenta
MANIFEST_ROWS=()

# ---------------------------------------------------------------------------
# FUNÇÕES AUXILIARES
# ---------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

now_iso() {
    date '+%Y-%m-%dT%H:%M:%S%z'
}

check_dependencies() {
    local missing=()
    for cmd in docker tcpdump curl sha256sum; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "Faltam dependências no host: ${missing[*]}"
        echo "Instale com algo como:"
        echo "  sudo apt-get update && sudo apt-get install -y docker.io tcpdump curl coreutils"
        echo "  (Arch: sudo pacman -S docker tcpdump curl coreutils)"
        echo "Note: slowhttptest e os clientes benignos agora rodam DENTRO dos"
        echo "contêineres — não precisam estar instalados no host."
        exit 1
    fi
}

create_network() {
    if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
        log "Criando rede Docker dedicada ${NETWORK_NAME} (${NETWORK_SUBNET})..."
        docker network create --subnet "$NETWORK_SUBNET" "$NETWORK_NAME" >/dev/null
    else
        log "Rede ${NETWORK_NAME} já existe, reaproveitando."
    fi
}

build_images() {
    log "Buildando imagem do servidor..."
    docker build -t "$SERVER_IMAGE" -f "${BASE_DIR}/Dockerfile.server" "$BASE_DIR" || { echo "Build do servidor falhou"; exit 1; }

    log "Buildando imagem do atacante..."
    docker build -t "$ATTACKER_IMAGE" -f "${BASE_DIR}/Dockerfile.attacker" "$BASE_DIR" || { echo "Build do atacante falhou"; exit 1; }

    log "Buildando imagem do cliente benigno..."
    docker build -t "$BENIGN_IMAGE" -f "${BASE_DIR}/Dockerfile.benign" "$BASE_DIR" || { echo "Build do cliente benigno falhou"; exit 1; }
}

start_server() {
    docker rm -f "$SERVER_CONTAINER" >/dev/null 2>&1 || true
    log "Subindo servidor em ${SERVER_IP} (rede ${NETWORK_NAME})..."
    docker run -d --name "$SERVER_CONTAINER" \
        --network "$NETWORK_NAME" --ip "$SERVER_IP" \
        "$SERVER_IMAGE" >/dev/null

    for i in $(seq 1 15); do
        if curl -s -o /dev/null "$TARGET_URL"; then
            log "Servidor está no ar em ${TARGET_URL}"
            return 0
        fi
        sleep 1
    done
    echo "Servidor não respondeu a tempo."
    exit 1
}

restart_server() {
    log "Reiniciando servidor para estado limpo..."
    docker restart "$SERVER_CONTAINER" >/dev/null
    for i in $(seq 1 15); do
        if curl -s -o /dev/null "$TARGET_URL"; then
            return 0
        fi
        sleep 1
    done
    echo "Servidor não voltou ao ar após restart."
    exit 1
}

start_benign_traffic() {
    log "Iniciando cliente benigno em ${BENIGN_IP} (${BENIGN_CONCURRENT_CLIENTS} usuários simulados)..."
    docker rm -f "$BENIGN_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$BENIGN_CONTAINER" \
        --network "$NETWORK_NAME" --ip "$BENIGN_IP" \
        -e TARGET_URL="$TARGET_URL" \
        -e CONCURRENT_CLIENTS="$BENIGN_CONCURRENT_CLIENTS" \
        -e MIN_THINK="$BENIGN_MIN_THINK" \
        -e MAX_THINK="$BENIGN_MAX_THINK" \
        "$BENIGN_IMAGE" >/dev/null
}

stop_benign_traffic() {
    docker rm -f "$BENIGN_CONTAINER" >/dev/null 2>&1 || true
}

start_capture() {
    local pcap_file="$1"
    # Filtra por IP do servidor (não por porta): assim captura tudo que
    # envolve o servidor, venha do atacante ou do cliente benigno, cada um
    # com seu IP de origem real.
    tcpdump -i "$CAPTURE_IFACE" -w "$pcap_file" "host ${SERVER_IP}" >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2   # dá tempo do tcpdump abrir o arquivo antes do tráfego começar
}

stop_capture() {
    if [ -n "$TCPDUMP_PID" ]; then
        kill -INT "$TCPDUMP_PID" >/dev/null 2>&1 || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
}

start_connection_monitor() {
    # Roda DENTRO do contêiner do servidor via 'docker exec': é lá que faz
    # sentido medir "conexões retidas" (é o recurso do servidor sendo
    # esgotado), e é o único lugar onde o host ainda consegue ver esses
    # sockets, já que atacante e cliente benigno têm namespaces próprios.
    local log_file="$1"
    echo "timestamp,conexoes_retidas" > "$log_file"
    (
        while true; do
            count=$(docker exec "$SERVER_CONTAINER" ss -ant 2>/dev/null \
                | awk -v port=":${TARGET_PORT}" '$1=="ESTAB" && $4 ~ port {c++} END{print c+0}')
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
    # Roda o slowhttptest DENTRO do contêiner atacante, com IP próprio
    # (ATTACKER_IP). O contêiner é efêmero (--rm): sobe, ataca por
    # ATTACK_DURATION segundos, e sai sozinho quando o slowhttptest termina.
    local rate="$1"
    local interval="$2"
    local outfile_name="$3"   # só o nome do arquivo, sem caminho
    log "Rodando slowhttptest (contêiner ${ATTACKER_IP}): -r ${rate}, -i ${interval}s, -c ${TOTAL_CONNECTIONS}, -l ${ATTACK_DURATION}s"
    docker run --rm --name "slowloris_attacker_run" \
        --network "$NETWORK_NAME" --ip "$ATTACKER_IP" \
        -v "${LOG_DIR}:/output" \
        "$ATTACKER_IMAGE" \
        -c "$TOTAL_CONNECTIONS" -H -i "$interval" -r "$rate" -t GET \
        -u "$TARGET_URL" -p 3 -l "$ATTACK_DURATION" \
        -o "/output/${outfile_name}" >/dev/null 2>&1
}

cleanup() {
    log "Limpando processos e contêineres..."
    stop_capture
    stop_connection_monitor
    stop_benign_traffic
    docker rm -f "slowloris_attacker_run" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# EXECUÇÕES (benigna isolada / ataque) — cada uma registra sua linha no manifest
# ---------------------------------------------------------------------------

run_benign_only_capture() {
    local label="$1"
    local pcap_file="${PCAP_DIR}/${label}.pcap"
    local conn_log="${LOG_DIR}/${label}_conexoes.csv"
    local t_inicio t_fim

    log "=== Captura benigna isolada: ${label} (sem ataque, ${BENIGN_ONLY_DURATION}s) ==="

    restart_server
    start_capture "$pcap_file"
    start_connection_monitor "$conn_log"
    t_inicio="$(now_iso)"
    start_benign_traffic

    sleep "$BENIGN_ONLY_DURATION"

    stop_benign_traffic
    t_fim="$(now_iso)"
    stop_connection_monitor
    stop_capture

    MANIFEST_ROWS+=("${label}|benigno|NA|NA|NA|NA|${BENIGN_ONLY_DURATION}|${PCAP_REL}/${label}.pcap|${LOG_REL}/${label}_conexoes.csv|NA|${t_inicio}|${t_fim}|curl")
    log "Captura benigna concluída. pcap: ${pcap_file} | log conexões: ${conn_log}"
    sleep 3
}

run_attack_execution() {
    local label="$1"
    local rate="$2"
    local interval="$3"
    local param_nome="$4"
    local param_valor="$5"

    local pcap_file="${PCAP_DIR}/${label}.pcap"
    local conn_log="${LOG_DIR}/${label}_conexoes.csv"
    local report_name="${label}_slowhttptest"
    local t_inicio t_fim

    log "=== Execução: ${label} (r=${rate}, i=${interval}) ==="

    restart_server
    start_capture "$pcap_file"
    start_connection_monitor "$conn_log"
    t_inicio="$(now_iso)"
    start_benign_traffic

    run_attack "$rate" "$interval" "$report_name"

    stop_benign_traffic
    t_fim="$(now_iso)"
    stop_connection_monitor
    stop_capture

    MANIFEST_ROWS+=("${label}|ataque|${param_nome}|${param_valor}|${rate}|${interval}|${ATTACK_DURATION}|${PCAP_REL}/${label}.pcap|${LOG_REL}/${label}_conexoes.csv|${LOG_REL}/${report_name}.html|${t_inicio}|${t_fim}|slowhttptest+curl")
    log "Execução concluída. pcap: ${pcap_file} | log conexões: ${conn_log}"
    sleep 3
}

write_manifest() {
    log "Gerando manifest em ${MANIFEST_FILE}..."
    {
        echo "label,tipo,param_nome,param_valor,r,i,duracao_s,ip_atacante,ip_cliente_benigno,ip_servidor,pcap_file,conexoes_log,slowhttptest_report,hora_inicio,hora_fim,ferramenta"
        for row in "${MANIFEST_ROWS[@]}"; do
            IFS='|' read -r label tipo param_nome param_valor r i dur pcap_rel log_rel report_rel t_inicio t_fim ferramenta <<< "$row"
            local ip_atk="$ATTACKER_IP"
            [ "$tipo" = "benigno" ] && ip_atk="NA"
            echo "${label},${tipo},${param_nome},${param_valor},${r},${i},${dur},${ip_atk},${BENIGN_IP},${SERVER_IP},${pcap_rel},${log_rel},${report_rel},${t_inicio},${t_fim},${ferramenta}"
        done
    } > "$MANIFEST_FILE"
}

generate_checksums() {
    log "Gerando checksums dos pcaps em ${CHECKSUMS_FILE}..."
    (cd "$PCAP_DIR" && sha256sum ./*.pcap > "$CHECKSUMS_FILE" 2>/dev/null) || \
        log "Aviso: nenhum pcap encontrado para gerar checksums (ou sha256sum falhou)."
}

# ---------------------------------------------------------------------------
# EXECUÇÃO PRINCIPAL
# ---------------------------------------------------------------------------

check_dependencies
create_network
build_images
start_server

log "IPs fixos desta execução: servidor=${SERVER_IP} atacante=${ATTACKER_IP} benigno=${BENIGN_IP}"

# FASE 1 — baseline benigno isolado
for rep in $(seq 1 "$BENIGN_ONLY_REPETITIONS"); do
    run_benign_only_capture "benigno_only_rep${rep}"
done

# FASE 2 — varia a TAXA (-r), intervalo (-i) fixo
for rate in "${RATES[@]}"; do
    for rep in $(seq 1 "$REPETITIONS"); do
        label="taxa${rate}_rep${rep}"
        run_attack_execution "$label" "$rate" "$FIXED_INTERVAL_FOR_RATE" "r" "$rate"
    done
done

# FASE 3 — varia o INTERVALO (-i), taxa (-r) fixa
for interval in "${INTERVALS[@]}"; do
    for rep in $(seq 1 "$INTERVAL_REPETITIONS"); do
        label="intervalo${interval}_rep${rep}"
        run_attack_execution "$label" "$FIXED_RATE_FOR_INTERVAL" "$interval" "i" "$interval"
    done
done

write_manifest
generate_checksums

log "Tudo concluído."
log "Manifesto: ${MANIFEST_FILE}"
log "Checksums: ${CHECKSUMS_FILE}"
log "Pcaps em: ${PCAP_DIR}"
log "Logs/relatórios em: ${LOG_DIR}"
