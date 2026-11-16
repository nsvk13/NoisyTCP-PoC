#!/usr/bin/env bash
# NoisyTCP lab TARGET preparation. Run this ON THE TARGET VM (as root).
# It does NOT exploit anything -- it prepares a plain TCP listener and prints
# the configuration that makes the race reachable, plus mitigation toggles.
#
#   sudo ./lab/target-setup.sh [iface] [port]
#
# The bug triggers on ANY plain listen() socket (nginx/apache/ssh/python).
set -uo pipefail

IFACE="${1:-eth0}"
PORT="${2:-80}"

echo "================ NoisyTCP target check ================"
echo "[*] kernel: $(uname -r)"
echo "    Vulnerable if built before fix 4e2b3ef19e0e (2026-11-03)."
echo "    Introduced by 079096f103fa (2015-10-03) -> ~all kernels in between."
echo

echo "[*] SYN cookies (must be 1 for trigger flow #1):"
echo "    net.ipv4.tcp_syncookies = $(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)"
echo "    net.ipv4.tcp_max_syn_backlog = $(cat /proc/sys/net/ipv4/tcp_max_syn_backlog 2>/dev/null)"
echo "    net.core.somaxconn = $(cat /proc/sys/net/core/somaxconn 2>/dev/null)"
echo

echo "[*] RX queues on $IFACE (need >= 2, OR RPS enabled):"
if command -v ethtool >/dev/null 2>&1; then
    ethtool -l "$IFACE" 2>/dev/null | sed 's/^/    /'
fi
echo "    rx queues in sysfs: $(ls -d /sys/class/net/$IFACE/queues/rx-* 2>/dev/null | wc -l)"
echo "    RPS cpus (rx-0): $(cat /sys/class/net/$IFACE/queues/rx-0/rps_cpus 2>/dev/null)"
echo "    NOTE: virtio-net needs multiqueue (queues=N) for >1 RX queue."
echo

echo "[*] Starting a plain TCP listener on :$PORT"
if command -v nginx >/dev/null 2>&1; then
    echo "    using nginx (default config is enough)"
    nginx 2>/dev/null || systemctl start nginx 2>/dev/null || service nginx start 2>/dev/null || true
elif command -v python3 >/dev/null 2>&1; then
    echo "    using python3 http.server (background)"
    nohup python3 -m http.server "$PORT" --bind 0.0.0.0 >/tmp/noisytcp-listener.log 2>&1 &
    echo "    pid=$! log=/tmp/noisytcp-listener.log"
else
    echo "    !! install nginx or python3, or run any TCP listener on :$PORT"
fi
echo

cat <<'EOF'
================ Mitigations (to verify the fix) ================
Apply the patch 4e2b3ef19e0e (priority). Temporary mitigations:

  # 1. Disable SYN cookies (blocks the cookie-request realloc path).
  #    Per-netns: apply in EACH container with its own netns.
  sudo sysctl -w net.ipv4.tcp_syncookies=0

  # 2. Serialize to a single RX queue + disable RPS/RFS (blocks the race).
  sudo ethtool -l <iface> combined 1
  echo 0 | sudo tee /sys/class/net/<iface>/queues/rx-*/rps_cpus

A patched kernel (or either mitigation) should survive the PoC indefinitely.
================================================================
EOF
