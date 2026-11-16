#!/usr/bin/env bash
# NoisyTCP lab liveness monitor.
# Run this FROM THE ATTACKER HOST alongside the PoC. The PoC cannot tell when
# the target kernel panics; this watches reachability and timestamps the drop.
#
#   ./lab/monitor.sh <target-ip> [tcp-port]
#
# A sustained ping loss + TCP connect failure == the target went down (panic).
# Ctrl-C to stop. Logs to stdout and ./lab/monitor.log.
set -uo pipefail

IP="${1:?usage: monitor.sh <target-ip> [tcp-port]}"
PORT="${2:-80}"
LOG="$(dirname "$0")/monitor.log"
INTERVAL=0.5
FAILS=0
THRESH=4          # consecutive failures before declaring DOWN
DOWN=0
START=$(date +%s)

echo "[monitor] watching $IP (tcp/$PORT), interval ${INTERVAL}s, log=$LOG" | tee -a "$LOG"

probe_tcp() {
    timeout 1 bash -c "echo > /dev/tcp/$IP/$PORT" 2>/dev/null
}

while true; do
    if ping -c1 -W1 "$IP" >/dev/null 2>&1; then
        if [ "$DOWN" = 1 ]; then
            echo "[monitor] $(date '+%F %T') TARGET BACK UP (rebooted?)" | tee -a "$LOG"
            DOWN=0
        fi
        FAILS=0
    else
        FAILS=$((FAILS+1))
        if [ "$FAILS" -ge "$THRESH" ] && [ "$DOWN" = 0 ]; then
            # confirm with a TCP probe so a single ICMP blip isn't a false alarm
            if ! probe_tcp; then
                DOWN=1
                EL=$(( $(date +%s) - START ))
                echo "[monitor] $(date '+%F %T') *** TARGET DOWN *** (after ${EL}s) -> likely kernel panic" | tee -a "$LOG"
            fi
        fi
    fi
    sleep "$INTERVAL"
done
