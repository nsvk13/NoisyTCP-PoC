# NoisyTCP-PoC

Proof-of-concept **testing harness** for **NoisyTCP — CVE-2026-99288**, a Linux
kernel TCP pre-authentication remote corruption vulnerability (remote DoS /
kernel panic) disclosed by Hyunwoo Kim (@v4bel).

> ## ⚠️ Authorized lab testing only
> This tool **crashes the target kernel** (a remote denial of service that takes
> down the whole host, including containers). It exists to **validate exposure
> and verify the patch / mitigations** on systems you own or are explicitly
> authorized to test. It sends from a real, attributable source address to a
> **single named target**; it does not scan, spread, spoof, or evade. Running it
> against a system you do not control is illegal. The tool refuses to run without
> `--authorize I-OWN-THIS-TARGET`.

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
sudo ./noisytcp --iface <lab-iface> --target <guest-ip> --port 80 \
                --authorize I-OWN-THIS-TARGET
```

`lab/run-vm.sh` is a template (edit `DISK`/`ISO`). For faithful fragmentation /
RX-hash behavior prefer a **tap/bridge** over user-mode SLIRP NAT.

---

## 6. Usage

```sh
sudo ./noisytcp --iface eth0 --target 10.0.0.2 --port 80 \
                --authorize I-OWN-THIS-TARGET --race-threads 8 --tuples 32 [options]
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
| `--iface IF` | — | egress interface (required) |
| `--target IP` | — | single target IPv4 (required) |
| `--port P` | — | target TCP port (required) |
| `--authorize STR` | — | must equal `I-OWN-THIS-TARGET` (required) |
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
