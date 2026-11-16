#!/usr/bin/env bash
# NoisyTCP lab VM launcher (QEMU/KVM). TEMPLATE -- edit paths before use.
#
# The advisory reproduces in 5s-2min against VMs (vCPU preemption widens the
# race window). The key requirement is >= 2 RX queues: virtio-net MULTIQUEUE.
# The guest kernel must be UNPATCHED (built before fix 4e2b3ef19e0e).
#
#   1. Put a Linux disk image (unpatched kernel) at $DISK, or an ISO at $ISO.
#   2. ./lab/run-vm.sh
#   3. In the guest: sudo ./lab/target-setup.sh eth0 80
#   4. From the host: ./lab/monitor.sh 127.0.0.1 8080   (hostfwd below)
#      and: sudo ./noisytcp --iface <bridge/tap> --target <guest-ip> --port 80 \
#             --authorize I-OWN-THIS-TARGET
#
# For L2 reachability from the attacker, use a tap/bridge instead of user-mode
# SLIRP (SLIRP NAT may not preserve fragmentation/RX-hash behavior). The
# user-mode block below is a quick start; swap to -netdev tap for real tests.
set -euo pipefail

DISK="${DISK:-./lab/target.qcow2}"   # guest disk with unpatched kernel
ISO="${ISO:-}"                        # optional installer ISO
MEM="${MEM:-2048}"
CPUS="${CPUS:-4}"
QUEUES="${QUEUES:-4}"                 # virtio-net RX/TX queues (>=2 required)
SSH_FWD="${SSH_FWD:-2222}"
HTTP_FWD="${HTTP_FWD:-8080}"

if [[ ! -f "$DISK" && -z "$ISO" ]]; then
    echo "error: set DISK=./lab/target.qcow2 (unpatched kernel) or ISO=..." >&2
    echo "       e.g. DISK=~/images/debian-old-kernel.qcow2 ./lab/run-vm.sh" >&2
    exit 1
fi

ARGS=(
    -enable-kvm -cpu host -smp "$CPUS" -m "$MEM"
    -display none -daemonize -pidfile ./lab/vm.pid
    -serial file:./lab/vm-serial.log
    # virtio-net with MULTIQUEUE: vectors = 2*queues + 2
    -netdev "user,id=n0,hostfwd=tcp::${SSH_FWD}-:22,hostfwd=tcp::${HTTP_FWD}-:80"
    -device "virtio-net-pci,netdev=n0,mq=on,vectors=$((2*QUEUES+2)),queues=${QUEUES}"
)
[[ -f "$DISK" ]] && ARGS+=(-drive "file=$DISK,if=virtio,format=qcow2")
[[ -n "$ISO" ]]  && ARGS+=(-cdrom "$ISO" -boot d)

echo "[*] launching VM: cpus=$CPUS queues=$QUEUES ssh=:$SSH_FWD http=:$HTTP_FWD"
echo "[*] serial log: ./lab/vm-serial.log (watch for the kernel panic here)"
qemu-system-x86_64 "${ARGS[@]}"
echo "[*] VM running (pidfile ./lab/vm.pid). Guest: enable multiqueue with"
echo "    'ethtool -L eth0 combined $QUEUES' if not auto, then target-setup.sh."
