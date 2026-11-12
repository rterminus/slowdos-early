#!/usr/bin/env bash
#
# Simula CONCURRENT_CLIENTS "usuários" fazendo requisições HTTP normais,
# com pausas aleatórias entre MIN_THINK e MAX_THINK segundos (variáveis de
# ambiente), até receber SIGTERM (quando o orchestrate.sh para o contêiner).

set -u

TARGET_URL="${TARGET_URL:-http://localhost/}"
CONCURRENT_CLIENTS="${CONCURRENT_CLIENTS:-5}"
MIN_THINK="${MIN_THINK:-1}"
MAX_THINK="${MAX_THINK:-4}"

client_loop() {
    while true; do
        curl -s -o /dev/null "$TARGET_URL"
        sleep "$(( (RANDOM % (MAX_THINK - MIN_THINK + 1)) + MIN_THINK ))"
    done
}

pids=()
for i in $(seq 1 "$CONCURRENT_CLIENTS"); do
    client_loop &
    pids+=("$!")
done

# encerra os clientes de forma limpa quando o contêiner recebe SIGTERM
trap 'kill "${pids[@]}" 2>/dev/null; exit 0' TERM INT

wait
