// SPDX-License-Identifier: GPL-2.0
/*
 * The XDP TCP fast path, driven by a scripted peer.
 *
 * The test is the peer: it writes Ethernet frames into a TAP device, where
 * the XDP program sees them natively, and reads back whatever the stack
 * transmits on that device. It performs the handshake with a listening socket
 * by hand, so every sequence number is known, and then sends segments in any
 * order it likes and checks the ACKs, SACK blocks and responses it gets.
 */
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_tcp.skel.h"
#include "xdp_tcp_hooks.skel.h"

#define NS		"xdp_tcp_ns"
#define DEV		"xdptcp0"
#define UPPER		"xdptcp0mv"	/* a macvlan over DEV, for the stacked case */
#define KERN_MAC	"02:00:00:00:00:01"
#define PEER_MAC	"02:00:00:00:00:02"
#define LOWER_MAC	"02:00:00:00:00:03"	/* DEV's own, when the kernel's addresses are UPPER's */
#define KERN_IP4	"192.168.77.1"
#define PEER_IP4	"192.168.77.2"
#define KERN_IP6	"fd00:77::1"
#define PEER_IP6	"fd00:77::2"
#define PORT		7777
#define PEER_PORT	40000
#define PEER_ISS	0x10000
#define PEER_WIN	65535
#define MSS		1460
#define TIMEOUT_MS	2000

#define FRAME_MAX	2048
#define DATA_MAX	1600
#define OPTS_MAX	40

/* TCP header flags, as the low byte of the flag word. */
#define TH_FIN		0x01
#define TH_SYN		0x02
#define TH_RST		0x04
#define TH_PSH		0x08
#define TH_ACK		0x10

/* TCP option kinds and lengths. */
#define OPT_KIND_EOL		0
#define OPT_KIND_NOP		1
#define OPT_KIND_MSS		2
#define OPT_KIND_SACK_PERM	4
#define OPT_KIND_SACK		5
#define OPT_KIND_TS		8
#define OPT_LEN_MSS		4
#define OPT_LEN_SACK_PERM	2
#define OPT_LEN_TS		10

/* Options to ask for in the SYN. */
#define OPT_SACK	(1 << 0)
#define OPT_TS		(1 << 1)

struct peer {
	int fd;
	int family;
	__u8 kern_mac[ETH_ALEN], peer_mac[ETH_ALEN];
	struct in_addr kern4, peer4;
	struct in6_addr kern6, peer6;
	__u32 snd_nxt;		/* next byte we send */
	__u32 rcv_nxt;		/* next byte we expect from the kernel */
	__u16 win;
	bool ts;		/* timestamps negotiated */
	bool sack;		/* SACK negotiated */
	__u32 tsval, tsecr;
	__u64 segs;		/* segments of the connection received so far */
};

struct seg {
	__u32 seq, ack;
	__u16 flags, win;
	int len;
	__u8 data[DATA_MAX];
	bool has_ts;
	__u32 tsval, tsecr;
	int nr_sack;
	struct {
		__u32 start, end;
	} sack[4];
	__u16 mss;
	bool sack_perm;
};

struct ctx {
	struct netns_obj *ns;
	struct xdp_tcp *skel;
	struct peer peer;
	int ifindex;
	int srv;
	int conn;
};

static bool before(__u32 a, __u32 b)
{
	return (__s32)(a - b) < 0;
}

static __u64 now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void set_flags(struct tcphdr *th, __u16 flags)
{
	th->fin = !!(flags & TH_FIN);
	th->syn = !!(flags & TH_SYN);
	th->rst = !!(flags & TH_RST);
	th->psh = !!(flags & TH_PSH);
	th->ack = !!(flags & TH_ACK);
}

static __u16 get_flags(const struct tcphdr *th)
{
	return (th->fin ? TH_FIN : 0) | (th->syn ? TH_SYN : 0) | (th->rst ? TH_RST : 0) |
	       (th->psh ? TH_PSH : 0) | (th->ack ? TH_ACK : 0);
}

static int parse_mac(const char *s, __u8 *mac)
{
	unsigned int b[ETH_ALEN];
	int i;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != ETH_ALEN)
		return -1;
	for (i = 0; i < ETH_ALEN; i++)
		mac[i] = b[i];
	return 0;
}

static int peer_init(struct peer *p, int fd, int family)
{
	memset(p, 0, sizeof(*p));
	p->fd = fd;
	p->family = family;
	p->win = PEER_WIN;
	p->tsval = 1000;
	if (parse_mac(KERN_MAC, p->kern_mac) || parse_mac(PEER_MAC, p->peer_mac))
		return -1;
	if (inet_pton(AF_INET, KERN_IP4, &p->kern4) != 1 ||
	    inet_pton(AF_INET, PEER_IP4, &p->peer4) != 1 ||
	    inet_pton(AF_INET6, KERN_IP6, &p->kern6) != 1 ||
	    inet_pton(AF_INET6, PEER_IP6, &p->peer6) != 1)
		return -1;
	return 0;
}

static int put_opt(__u8 *o, int off, __u8 kind, __u8 len, const void *val)
{
	o[off] = kind;
	o[off + 1] = len;
	if (len > 2)
		memcpy(o + off + 2, val, len - 2);
	return off + len;
}

/*
 * Build the TCP options: for a SYN whatever was asked for, otherwise the
 * aligned timestamp block that the kernel's fast path recognises.
 */
static int build_opts(struct peer *p, __u8 *o, bool syn, unsigned int ask)
{
	__be32 ts[2] = { htonl(p->tsval), htonl(p->tsecr) };
	int off = 0;

	if (syn) {
		__be16 mss = htons(MSS);

		off = put_opt(o, off, OPT_KIND_MSS, OPT_LEN_MSS, &mss);
		if ((ask & OPT_SACK) && (ask & OPT_TS)) {
			off = put_opt(o, off, OPT_KIND_SACK_PERM, OPT_LEN_SACK_PERM, NULL);
			off = put_opt(o, off, OPT_KIND_TS, OPT_LEN_TS, ts);
		} else if (ask & OPT_TS) {
			o[off++] = OPT_KIND_NOP;
			o[off++] = OPT_KIND_NOP;
			off = put_opt(o, off, OPT_KIND_TS, OPT_LEN_TS, ts);
		} else if (ask & OPT_SACK) {
			o[off++] = OPT_KIND_NOP;
			o[off++] = OPT_KIND_NOP;
			off = put_opt(o, off, OPT_KIND_SACK_PERM, OPT_LEN_SACK_PERM, NULL);
		}
	} else if (p->ts) {
		o[off++] = OPT_KIND_NOP;
		o[off++] = OPT_KIND_NOP;
		off = put_opt(o, off, OPT_KIND_TS, OPT_LEN_TS, ts);
	}
	return off;
}

/* Send one segment with explicit sequence numbers; the peer's cursors are not touched. */
static int peer_send_raw(struct peer *p, __u16 flags, __u32 seq, __u32 ack, const void *data,
			 int len, unsigned int syn_opts)
{
	__u8 frame[FRAME_MAX], opts[OPTS_MAX];
	struct ethhdr *eth = (void *)frame;
	struct tcphdr *th;
	int optlen, tcplen, off, tries;
	ssize_t ret;

	if (len < 0 || len > DATA_MAX)
		return -1;
	optlen = build_opts(p, opts, flags & TH_SYN, syn_opts);
	tcplen = sizeof(*th) + optlen + len;

	memcpy(eth->h_dest, p->kern_mac, ETH_ALEN);
	memcpy(eth->h_source, p->peer_mac, ETH_ALEN);
	off = sizeof(*eth);
	if (p->family == AF_INET) {
		struct iphdr *iph = (void *)(frame + off);

		eth->h_proto = htons(ETH_P_IP);
		memset(iph, 0, sizeof(*iph));
		iph->version = 4;
		iph->ihl = 5;
		iph->tot_len = htons(sizeof(*iph) + tcplen);
		iph->ttl = 64;
		iph->protocol = IPPROTO_TCP;
		iph->saddr = p->peer4.s_addr;
		iph->daddr = p->kern4.s_addr;
		iph->check = build_ip_csum(iph);
		off += sizeof(*iph);
	} else {
		struct ipv6hdr *ip6h = (void *)(frame + off);

		eth->h_proto = htons(ETH_P_IPV6);
		memset(ip6h, 0, sizeof(*ip6h));
		ip6h->version = 6;
		ip6h->payload_len = htons(tcplen);
		ip6h->nexthdr = IPPROTO_TCP;
		ip6h->hop_limit = 64;
		ip6h->saddr = p->peer6;
		ip6h->daddr = p->kern6;
		off += sizeof(*ip6h);
	}
	th = (void *)(frame + off);
	memset(th, 0, sizeof(*th));
	th->source = htons(PEER_PORT);
	th->dest = htons(PORT);
	th->seq = htonl(seq);
	th->ack_seq = htonl(ack);
	th->doff = (sizeof(*th) + optlen) / 4;
	set_flags(th, flags);
	th->window = htons(p->win);
	memcpy(th + 1, opts, optlen);
	memcpy((__u8 *)(th + 1) + optlen, data, len);
	if (p->family == AF_INET)
		th->check = csum_tcpudp_magic(p->peer4.s_addr, p->kern4.s_addr, tcplen,
					      IPPROTO_TCP, csum_partial(th, tcplen, 0));
	else
		th->check = csum_ipv6_magic(&p->peer6, &p->kern6, tcplen, IPPROTO_TCP,
					    csum_partial(th, tcplen, 0));
	off += tcplen;

	for (tries = 0; tries < 100; tries++) {
		ret = write(p->fd, frame, off);
		if (ret == off)
			return 0;
		if (ret < 0 && errno == EAGAIN) {
			usleep(1000);
			continue;
		}
		break;
	}
	PRINT_FAIL("write(tap) returned %zd\n", ret);
	return -1;
}

/* Send the next in-order segment and advance the peer's send cursor. */
static int peer_send(struct peer *p, __u16 flags, const void *data, int len)
{
	int err;

	err = peer_send_raw(p, flags | TH_ACK, p->snd_nxt, p->rcv_nxt, data, len, 0);
	if (!err) {
		p->snd_nxt += len;
		if (flags & (TH_SYN | TH_FIN))
			p->snd_nxt++;
	}
	return err;
}

static void parse_opts(struct seg *s, const __u8 *o, int optlen)
{
	int off = 0;

	while (off < optlen) {
		__u8 kind = o[off], len;

		if (kind == OPT_KIND_EOL)
			return;
		if (kind == OPT_KIND_NOP) {
			off++;
			continue;
		}
		if (off + 1 >= optlen)
			return;
		len = o[off + 1];
		if (len < 2 || off + len > optlen)
			return;
		switch (kind) {
		case OPT_KIND_MSS:
			if (len == OPT_LEN_MSS)
				s->mss = ntohs(*(__be16 *)(o + off + 2));
			break;
		case OPT_KIND_SACK_PERM:
			s->sack_perm = true;
			break;
		case OPT_KIND_TS:
			if (len == OPT_LEN_TS) {
				s->has_ts = true;
				s->tsval = ntohl(*(__be32 *)(o + off + 2));
				s->tsecr = ntohl(*(__be32 *)(o + off + 6));
			}
			break;
		case OPT_KIND_SACK: {
			int i, n = (len - 2) / 8;

			for (i = 0; i < n && i < ARRAY_SIZE(s->sack); i++) {
				s->sack[i].start = ntohl(*(__be32 *)(o + off + 2 + i * 8));
				s->sack[i].end = ntohl(*(__be32 *)(o + off + 6 + i * 8));
			}
			s->nr_sack = i;
			break;
		}
		}
		off += len;
	}
}

/* Parse a frame into @s if it is a segment of our connection. */
static bool parse_frame(struct peer *p, const __u8 *frame, int flen, struct seg *s)
{
	const struct ethhdr *eth = (const void *)frame;
	const struct tcphdr *th;
	int off = sizeof(*eth), tcplen, hlen;

	if (flen < off)
		return false;
	if (p->family == AF_INET) {
		const struct iphdr *iph = (const void *)(frame + off);

		if (eth->h_proto != htons(ETH_P_IP) || flen < off + (int)sizeof(*iph))
			return false;
		if (iph->protocol != IPPROTO_TCP || iph->ihl < 5 ||
		    iph->saddr != p->kern4.s_addr || iph->daddr != p->peer4.s_addr)
			return false;
		/* A refused connection's ACKs are the stack's, options and all. */
		tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
		off += iph->ihl * 4;
	} else {
		const struct ipv6hdr *ip6h = (const void *)(frame + off);

		if (eth->h_proto != htons(ETH_P_IPV6) || flen < off + (int)sizeof(*ip6h))
			return false;
		if (ip6h->nexthdr != IPPROTO_TCP ||
		    memcmp(&ip6h->saddr, &p->kern6, sizeof(p->kern6)) ||
		    memcmp(&ip6h->daddr, &p->peer6, sizeof(p->peer6)))
			return false;
		tcplen = ntohs(ip6h->payload_len);
		off += sizeof(*ip6h);
	}
	if (tcplen < (int)sizeof(*th) || off + tcplen > flen)
		return false;
	th = (const void *)(frame + off);
	if (th->source != htons(PORT) || th->dest != htons(PEER_PORT))
		return false;
	hlen = th->doff * 4;
	if (hlen < (int)sizeof(*th) || hlen > tcplen)
		return false;

	memset(s, 0, sizeof(*s));
	s->seq = ntohl(th->seq);
	s->ack = ntohl(th->ack_seq);
	s->flags = get_flags(th);
	s->win = ntohs(th->window);
	s->len = tcplen - hlen;
	if (s->len > DATA_MAX)
		return false;
	memcpy(s->data, (const __u8 *)th + hlen, s->len);
	parse_opts(s, (const __u8 *)(th + 1), hlen - sizeof(*th));
	if (s->has_ts)
		p->tsecr = s->tsval;
	p->segs++;
	return true;
}

/* Wait up to @timeout_ms for the next segment of the connection. */
static int peer_recv(struct peer *p, struct seg *s, int timeout_ms)
{
	struct pollfd pfd = { .fd = p->fd, .events = POLLIN };
	__u8 frame[FRAME_MAX];
	__u64 deadline = now_ms() + timeout_ms;

	for (;;) {
		__s64 left = (__s64)(deadline - now_ms());
		ssize_t n;

		if (left <= 0)
			return -1;
		if (poll(&pfd, 1, left) <= 0)
			return -1;
		n = read(p->fd, frame, sizeof(frame));
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			return -1;
		}
		if (parse_frame(p, frame, n, s))
			return 0;
	}
}

/* Receive segments until one carries payload, remembering the last ACK seen. */
static int peer_recv_data(struct peer *p, struct seg *s, int timeout_ms)
{
	for (;;) {
		if (peer_recv(p, s, timeout_ms))
			return -1;
		if (s->len)
			return 0;
	}
}

/*
 * Collect @len bytes of in-order payload from the kernel into @buf, ACKing as
 * it arrives. Each segment must continue where the previous one ended.
 */
static int peer_collect(struct peer *p, void *buf, int len)
{
	int got = 0;

	while (got < len) {
		struct seg s;

		if (!ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv data"))
			return -1;
		if (!ASSERT_EQ(s.seq, p->rcv_nxt, "data seq") ||
		    !ASSERT_LE(got + s.len, len, "data len"))
			return -1;
		memcpy(buf + got, s.data, s.len);
		got += s.len;
		p->rcv_nxt += s.len;
		if (peer_send(p, 0, NULL, 0))
			return -1;
	}
	return 0;
}

/*
 * Three-way handshake with the listener. The peer picks its ISS; the kernel's
 * ISS comes back in the SYN-ACK, so both cursors are known afterwards.
 */
static int peer_handshake(struct peer *p, unsigned int opts)
{
	struct seg s;

	p->snd_nxt = PEER_ISS;
	if (!ASSERT_OK(peer_send_raw(p, TH_SYN, PEER_ISS, 0, NULL, 0, opts), "send SYN"))
		return -1;
	p->snd_nxt++;
	if (!ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv SYN-ACK"))
		return -1;
	if (!ASSERT_EQ(s.flags, TH_SYN | TH_ACK, "SYN-ACK flags") ||
	    !ASSERT_EQ(s.ack, p->snd_nxt, "SYN-ACK ack"))
		return -1;
	p->rcv_nxt = s.seq + 1;
	p->ts = (opts & OPT_TS) && s.has_ts;
	p->sack = (opts & OPT_SACK) && s.sack_perm;
	if (!ASSERT_EQ(p->ts, !!(opts & OPT_TS), "timestamps negotiated") ||
	    !ASSERT_EQ(p->sack, !!(opts & OPT_SACK), "SACK negotiated"))
		return -1;
	p->tsval++;
	return ASSERT_OK(peer_send(p, 0, NULL, 0), "send ACK") ? 0 : -1;
}

static int accept_conn(int srv)
{
	struct pollfd pfd = { .fd = srv, .events = POLLIN };
	int fd;

	if (!ASSERT_EQ(poll(&pfd, 1, TIMEOUT_MS), 1, "poll(listener)"))
		return -1;
	fd = accept(srv, NULL, NULL);
	ASSERT_GE(fd, 0, "accept");
	return fd;
}

static void teardown(struct ctx *c)
{
	if (c->conn >= 0)
		close(c->conn);
	if (c->srv >= 0)
		close(c->srv);
	if (c->ifindex > 0)
		bpf_xdp_detach(c->ifindex, XDP_FLAGS_DRV_MODE, NULL);
	xdp_tcp__destroy(c->skel);
	if (c->peer.fd >= 0)
		close(c->peer.fd);
	netns_free(c->ns);
}

/* How the server differs from the plain one. */
#define SERVER_MAPPED	(1 << 0)	/* an IPv6 listener accepts the peer's IPv4 connection */
#define SERVER_STACKED	(1 << 1)	/* the kernel's addresses are on a macvlan over the TAP */

/*
 * @family is the peer's. A mapped server listens on an IPv6 socket for the
 * peer's IPv4 connection: the accepted socket is an IPv6 one sending IPv4. A
 * stacked server's segments cross two devices on the way out.
 */
static int setup_server(struct ctx *c, int family, unsigned int flags)
{
	const char *addr_dev = flags & SERVER_STACKED ? UPPER : DEV;
	int tap, err;

	memset(c, 0, sizeof(*c));
	c->peer.fd = -1;
	c->srv = -1;
	c->conn = -1;

	c->ns = netns_new(NS, true);
	if (!ASSERT_OK_PTR(c->ns, "netns_new"))
		return -1;
	tap = open_tuntap(DEV, true);
	if (!ASSERT_GE(tap, 0, "open_tuntap"))
		goto fail;
	if (peer_init(&c->peer, tap, family)) {
		close(tap);
		goto fail;
	}
	SYS(fail, "sysctl -qw net.ipv6.conf.%s.accept_ra=0", DEV);
	if (flags & SERVER_STACKED) {
		SYS(fail, "ip link set dev %s address %s up", DEV, LOWER_MAC);
		SYS(fail, "ip link add link %s name %s address %s type macvlan mode private",
		    DEV, UPPER, KERN_MAC);
		SYS(fail, "sysctl -qw net.ipv6.conf.%s.accept_ra=0", UPPER);
		SYS(fail, "ip link set dev %s up", UPPER);
	} else {
		SYS(fail, "ip link set dev %s address %s up", DEV, KERN_MAC);
	}
	SYS(fail, "ip addr add %s/24 dev %s", KERN_IP4, addr_dev);
	SYS(fail, "ip -6 addr add %s/64 dev %s nodad", KERN_IP6, addr_dev);
	SYS(fail, "ip neigh add %s lladdr %s dev %s nud permanent", PEER_IP4, PEER_MAC, addr_dev);
	SYS(fail, "ip -6 neigh add %s lladdr %s dev %s nud permanent", PEER_IP6, PEER_MAC,
	    addr_dev);

	c->skel = xdp_tcp__open_and_load();
	if (!ASSERT_OK_PTR(c->skel, "xdp_tcp__open_and_load"))
		goto fail;
	c->ifindex = if_nametoindex(DEV);
	if (!ASSERT_GT(c->ifindex, 0, "if_nametoindex"))
		goto fail;
	err = bpf_xdp_attach(c->ifindex, bpf_program__fd(c->skel->progs.xdp_tcp_echo),
			     XDP_FLAGS_DRV_MODE, NULL);
	if (!ASSERT_OK(err, "bpf_xdp_attach")) {
		c->ifindex = 0;
		goto fail;
	}
	c->srv = start_server(flags & SERVER_MAPPED ? AF_INET6 : family, SOCK_STREAM,
			      flags & SERVER_MAPPED ? "::" : family == AF_INET ? KERN_IP4 : KERN_IP6,
			      PORT, 0);
	if (!ASSERT_GE(c->srv, 0, "start_server"))
		goto fail;
	return 0;
fail:
	teardown(c);
	return -1;
}

static int setup(struct ctx *c, int family)
{
	return setup_server(c, family, 0);
}

/* Connect, then make sure the application sees nothing of what XDP consumes. */
static int connect_peer(struct ctx *c, unsigned int opts)
{
	if (peer_handshake(&c->peer, opts))
		return -1;
	c->conn = accept_conn(c->srv);
	return c->conn < 0 ? -1 : 0;
}

static int app_recv(struct ctx *c, void *buf, int len)
{
	int ret = recv(c->conn, buf, len, MSG_DONTWAIT);

	return ret < 0 ? -errno : ret;
}

/*
 * Keep the extension at the UAPI boundary after tcpi_total_retrans. libc
 * may already include later counters, so sizeof(struct tcp_info) is not
 * a stable prefix length.
 */
struct tcp_info_ext {
	__u8 base[offsetof(struct tcp_info, tcpi_total_retrans) + sizeof(__u32)];
	__u64 tcpi_pacing_rate;
	__u64 tcpi_max_pacing_rate;
	__u64 tcpi_bytes_acked;
	__u64 tcpi_bytes_received;
	__u32 tcpi_segs_out;
	__u32 tcpi_segs_in;
	__u32 tcpi_notsent_bytes;
	__u32 tcpi_min_rtt;
	__u32 tcpi_data_segs_in;
	__u32 tcpi_data_segs_out;
};

static int conn_info(struct ctx *c, struct tcp_info_ext *ti)
{
	socklen_t len = sizeof(*ti);

	memset(ti, 0, sizeof(*ti));
	return getsockopt(c->conn, IPPROTO_TCP, TCP_INFO, ti, &len);
}

/* A TcpExt counter of the test's netns, or -1. */
static long netstat_tcpext(const char *name)
{
	char *hdr = NULL, *val = NULL, *h, *v, *hs, *vs, line[8192];
	long ret = -1;
	FILE *f;

	f = fopen("/proc/net/netstat", "r");
	if (!f)
		return -1;
	while (!val && fgets(line, sizeof(line), f)) {
		if (strncmp(line, "TcpExt:", 7))
			continue;
		if (hdr)
			val = strdup(line);
		else
			hdr = strdup(line);
	}
	fclose(f);
	if (!hdr || !val)
		goto out;
	for (h = strtok_r(hdr + 7, " \n", &hs), v = strtok_r(val + 7, " \n", &vs); h && v;
	     h = strtok_r(NULL, " \n", &hs), v = strtok_r(NULL, " \n", &vs)) {
		if (!strcmp(h, name)) {
			ret = atol(v);
			break;
		}
	}
out:
	free(hdr);
	free(val);
	return ret;
}

/* Send a request, expect its echo, ACK it. */
static int request_echoed(struct ctx *c, const char *req)
{
	struct peer *p = &c->peer;
	int len = strlen(req);
	char buf[DATA_MAX];
	struct seg s;

	if (!ASSERT_OK(peer_send(p, TH_PSH, req, len), "send request"))
		return -1;
	if (!ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv echo"))
		return -1;
	if (!ASSERT_EQ(s.seq, p->rcv_nxt, "echo seq") || !ASSERT_EQ(s.ack, p->snd_nxt, "echo ack") ||
	    !ASSERT_EQ(s.len, len, "echo len") || !ASSERT_MEMEQ(s.data, req, len, "echo data"))
		return -1;
	if (p->ts && !ASSERT_EQ(s.tsecr, p->tsval, "echo tsecr"))
		return -1;
	p->rcv_nxt += s.len;
	p->tsval++;
	if (!ASSERT_OK(peer_send(p, 0, NULL, 0), "ack echo"))
		return -1;
	/* Nothing reached the application. */
	return ASSERT_EQ(app_recv(c, buf, sizeof(buf)), -EAGAIN, "app sees nothing") ? 0 : -1;
}

static void test_echo(int family, unsigned int opts)
{
	struct tcp_info_ext before, after;
	struct ctx c;

	if (setup(&c, family))
		return;
	if (connect_peer(&c, opts) || !ASSERT_OK(conn_info(&c, &before), "tcp_info"))
		goto out;
	if (request_echoed(&c, "hello") || request_echoed(&c, "world!"))
		goto out;
	ASSERT_EQ(c.skel->bss->consumed, 2, "consumed");
	ASSERT_EQ(c.skel->bss->sent, 2, "sent");
	ASSERT_EQ(c.skel->bss->sent_bytes, 11, "sent_bytes");
	ASSERT_EQ(c.skel->bss->consume_errs, 0, "consume_errs");
	ASSERT_EQ(c.skel->bss->send_errs, 0, "send_errs");
	/* Segments taken here count as the stack's do: two with data, then two pure ACKs. */
	if (ASSERT_OK(conn_info(&c, &after), "tcp_info")) {
		ASSERT_EQ(after.tcpi_segs_in - before.tcpi_segs_in, 4, "segs_in");
		ASSERT_EQ(after.tcpi_data_segs_in - before.tcpi_data_segs_in, 2, "data_segs_in");
		ASSERT_EQ(after.tcpi_bytes_received - before.tcpi_bytes_received, 11,
			  "bytes_received");
	}
out:
	teardown(&c);
}

/* After a successful lookup the program may still leave the segment to the stack. */
static void test_declined(void)
{
	char buf[DATA_MAX];
	struct ctx c;
	struct seg s;

	if (setup(&c, AF_INET))
		return;
	if (connect_peer(&c, 0))
		goto out;
	c.skel->bss->decline = 1;
	if (!ASSERT_OK(peer_send(&c.peer, TH_PSH, "hello", 5), "send request"))
		goto out;
	if (!ASSERT_OK(peer_recv(&c.peer, &s, TIMEOUT_MS), "recv ack"))
		goto out;
	ASSERT_EQ(s.ack, c.peer.snd_nxt, "ack");
	ASSERT_EQ(s.len, 0, "no echo");
	ASSERT_EQ(app_recv(&c, buf, sizeof(buf)), 5, "app recv");
	ASSERT_MEMEQ(buf, "hello", 5, "app data");
	ASSERT_EQ(c.skel->bss->lookups, 1, "lookups");
	ASSERT_EQ(c.skel->bss->consumed, 0, "consumed");
out:
	teardown(&c);
}

/*
 * A reply is pushed as it is queued. With an earlier segment of the connection
 * still paced in the qdisc, autocorking would hold a small reply back until
 * that transmission completes, for a merge the fast path never does.
 */
static void test_send_now(void)
{
	__u64 rate = 10000;	/* bytes per second */
	char pattern[3500], buf[sizeof(pattern) + 200 + 5];
	struct ctx c;
	struct peer *p;
	int i, got = 0;

	if (setup(&c, AF_INET))
		return;
	p = &c.peer;
	/* The pacing has to be fq's for a paced segment to sit in the qdisc. */
	SYS(out, "tc qdisc replace dev %s root fq", DEV);
	if (connect_peer(&c, 0))
		goto out;
	/* The stack paces a connection only from its tenth data segment on. */
	for (i = 0; i < 10; i++)
		if (request_echoed(&c, "warm"))
			goto out;
	if (!ASSERT_OK(setsockopt(c.conn, SOL_SOCKET, SO_MAX_PACING_RATE, &rate, sizeof(rate)),
		       "SO_MAX_PACING_RATE"))
		goto out;
	for (i = 0; i < (int)sizeof(pattern); i++)
		pattern[i] = 'a' + i % 26;
	memcpy(c.skel->arena->reply, pattern, sizeof(pattern));
	/*
	 * The first reply leaves at once, as one TSO burst on this short RTT, and
	 * runs the pacing clock 350 ms ahead; the second is stamped there and is
	 * held in fq; the third, queued behind it, is what autocorking would hold.
	 */
	c.skel->bss->reply_len = sizeof(pattern);
	if (!ASSERT_OK(peer_send(p, TH_PSH, "big", 3), "send first request"))
		goto out;
	c.skel->bss->reply_len = 200;
	if (!ASSERT_OK(peer_send(p, TH_PSH, "mid", 3), "send second request"))
		goto out;
	c.skel->bss->reply_len = 0;
	if (!ASSERT_OK(peer_send(p, TH_PSH, "small", 5), "send third request"))
		goto out;
	ASSERT_EQ(netstat_tcpext("TCPAutoCorking"), 0, "no autocorking");
	ASSERT_EQ(c.skel->bss->sent, 13, "sent");
	ASSERT_EQ(c.skel->bss->send_errs, 0, "send_errs");
	/* Everything arrives in order once the pacing lets it. */
	while (got < (int)sizeof(buf)) {
		struct seg s;

		if (!ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv reply") ||
		    !ASSERT_EQ(s.seq, p->rcv_nxt, "reply seq") ||
		    !ASSERT_LE(got + s.len, (int)sizeof(buf), "reply len"))
			goto out;
		memcpy(buf + got, s.data, s.len);
		got += s.len;
		p->rcv_nxt += s.len;
		if (!ASSERT_OK(peer_send(p, 0, NULL, 0), "ack reply"))
			goto out;
	}
	ASSERT_MEMEQ(buf, pattern, sizeof(pattern), "first reply");
	ASSERT_MEMEQ(buf + sizeof(pattern), pattern, 200, "second reply");
	ASSERT_MEMEQ(buf + sizeof(pattern) + 200, "small", 5, "third reply");
out:
	teardown(&c);
}

enum refusal {
	REFUSE_SOCKMAP,
	REFUSE_MD5,
	REFUSE_XFRM,
	REFUSE_XFRM_OUT,
	REFUSE_IP_OPTIONS,
};

/*
 * Sockets the fast path has to leave to the stack: one in a sockmap, whose
 * receive path is BPF's; one with an MD5 key, whose unsigned segments the
 * stack drops; one under an XFRM input policy, which only the stack can
 * evaluate; and two whose segments the send path cannot build, one under an
 * XFRM output policy and one with IP options.
 */
static void test_refused(enum refusal how)
{
	__u8 nops[4] = { IPOPT_NOOP, IPOPT_NOOP, IPOPT_NOOP, IPOPT_NOOP };
	struct tcp_md5sig md5 = {};
	struct sockaddr_in *sin;
	int map = -1, key = 0;
	__u64 fd;
	char buf[DATA_MAX];
	struct ctx c;
	struct seg s;

	if (setup(&c, AF_INET))
		return;
	if (connect_peer(&c, 0))
		goto out;
	switch (how) {
	case REFUSE_SOCKMAP:
		map = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, NULL, sizeof(key), sizeof(fd), 1, NULL);
		fd = c.conn;
		if (!ASSERT_GE(map, 0, "sockmap") ||
		    !ASSERT_OK(bpf_map_update_elem(map, &key, &fd, BPF_ANY), "sockmap update"))
			goto out;
		break;
	case REFUSE_MD5:
		sin = (struct sockaddr_in *)&md5.tcpm_addr;
		sin->sin_family = AF_INET;
		inet_pton(AF_INET, PEER_IP4, &sin->sin_addr);
		md5.tcpm_keylen = 4;
		memcpy(md5.tcpm_key, "abcd", 4);
		if (!ASSERT_OK(setsockopt(c.conn, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5)),
			       "TCP_MD5SIG"))
			goto out;
		break;
	case REFUSE_XFRM:
		SYS(out, "ip xfrm policy add src %s/32 dst %s/32 dir in action allow",
		    PEER_IP4, KERN_IP4);
		break;
	case REFUSE_XFRM_OUT:
		SYS(out, "ip xfrm policy add src %s/32 dst %s/32 dir out action allow",
		    KERN_IP4, PEER_IP4);
		break;
	case REFUSE_IP_OPTIONS:
		if (!ASSERT_OK(setsockopt(c.conn, IPPROTO_IP, IP_OPTIONS, nops, sizeof(nops)),
			       "IP_OPTIONS"))
			goto out;
		break;
	}
	if (!ASSERT_OK(peer_send(&c.peer, TH_PSH, "hello", 5), "send request"))
		goto out;
	ASSERT_EQ(c.skel->bss->consumed, 0, "consumed");
	ASSERT_EQ(c.skel->bss->sent, 0, "sent");
	if (how == REFUSE_MD5) {
		ASSERT_EQ(netstat_tcpext("TCPMD5NotFound"), 1, "dropped by the stack");
		ASSERT_EQ(app_recv(&c, buf, sizeof(buf)), -EAGAIN, "app sees nothing");
		goto out;
	}
	if (!ASSERT_OK(peer_recv(&c.peer, &s, TIMEOUT_MS), "recv ack"))
		goto out;
	ASSERT_EQ(s.ack, c.peer.snd_nxt, "ack");
	ASSERT_EQ(s.len, 0, "no echo");
	ASSERT_EQ(app_recv(&c, buf, sizeof(buf)), 5, "app recv");
	ASSERT_MEMEQ(buf, "hello", 5, "app data");
out:
	if (map >= 0)
		close(map);
	teardown(&c);
}

/* Observers at the hooks on the way out, and the counts they stood at. */
struct hooks {
	struct xdp_tcp_hooks *skel;
	struct bpf_link *nf, *cg, *tcx;
	int cgfd;
	__u64 nf_segs, cgroup_segs, tcx_segs, peer_segs;
};

/*
 * Before the listener is created: an accepted socket is in the listener's
 * cgroup, and the cgroup hook sees the handshake with the listener's.
 */
static int hooks_join(struct hooks *h)
{
	memset(h, 0, sizeof(*h));
	h->cgfd = test__join_cgroup("/xdp_tcp_hooks");
	return ASSERT_GE(h->cgfd, 0, "join cgroup") ? 0 : -1;
}

static int hooks_attach(struct hooks *h, int family, int ifindex)
{
	LIBBPF_OPTS(bpf_netfilter_opts, nfopts,
		    .pf = family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6,
		    .hooknum = NF_INET_LOCAL_OUT,
		    .priority = -128);
	LIBBPF_OPTS(bpf_tcx_opts, tcxopts);

	h->skel = xdp_tcp_hooks__open_and_load();
	if (!ASSERT_OK_PTR(h->skel, "xdp_tcp_hooks__open_and_load"))
		return -1;
	h->skel->bss->port = PORT;
	h->nf = bpf_program__attach_netfilter(h->skel->progs.nf_count, &nfopts);
	h->cg = bpf_program__attach_cgroup(h->skel->progs.cgroup_count, h->cgfd);
	h->tcx = bpf_program__attach_tcx(h->skel->progs.tcx_count, ifindex, &tcxopts);
	if (!ASSERT_OK_PTR(h->nf, "attach netfilter") || !ASSERT_OK_PTR(h->cg, "attach cgroup") ||
	    !ASSERT_OK_PTR(h->tcx, "attach tcx"))
		return -1;
	return 0;
}

static void hooks_detach(struct hooks *h)
{
	bpf_link__destroy(h->tcx);
	bpf_link__destroy(h->cg);
	bpf_link__destroy(h->nf);
	xdp_tcp_hooks__destroy(h->skel);
	if (h->cgfd >= 0)
		close(h->cgfd);
}

/*
 * What each hook saw since the last call, against what the peer received:
 * the cgroup hook sees every segment, the other two as many as @stack says.
 */
static void hooks_expect(struct hooks *h, struct peer *p, const char *what, __u64 stack)
{
	char name[64];

	snprintf(name, sizeof(name), "%s: netfilter", what);
	ASSERT_EQ(h->skel->bss->nf_segs - h->nf_segs, stack, name);
	snprintf(name, sizeof(name), "%s: cgroup egress", what);
	ASSERT_EQ(h->skel->bss->cgroup_segs - h->cgroup_segs, p->segs - h->peer_segs, name);
	snprintf(name, sizeof(name), "%s: tc egress", what);
	ASSERT_EQ(h->skel->bss->tcx_segs - h->tcx_segs, stack, name);
	h->nf_segs = h->skel->bss->nf_segs;
	h->cgroup_segs = h->skel->bss->cgroup_segs;
	h->tcx_segs = h->skel->bss->tcx_segs;
	h->peer_segs = p->segs;
}

/*
 * The way out: a served connection's segments pass the cgroup egress hook
 * and no other on their way to the device, whether sent in reply from XDP,
 * retransmitted by the stack's timer, a pure ACK, or the FIN. The handshake
 * precedes the serving and is the stack's. With @stale the neighbour entry
 * is not in a connected state when the first reply leaves, so that it takes
 * the resolving output path instead of the cached header. The observers sit
 * on the TAP device, which for a stacked server is the lower device the
 * segments reach through the macvlan's own transmit path.
 */
static void test_tx_hooks(int family, unsigned int flags, bool stale)
{
	struct peer *p;
	struct hooks h;
	struct ctx c;
	struct seg s;

	if (hooks_join(&h))
		return;
	if (setup_server(&c, family, flags))
		goto out_hooks;
	p = &c.peer;
	if (hooks_attach(&h, family, c.ifindex))
		goto out;
	if (connect_peer(&c, 0))
		goto out;
	/* The SYN-ACK is the listener's: every hook sees it. */
	hooks_expect(&h, p, "handshake", 1);
	if (stale)
		SYS(out, "ip %s neigh replace %s lladdr %s dev %s nud stale",
		    family == AF_INET ? "-4" : "-6", family == AF_INET ? PEER_IP4 : PEER_IP6,
		    PEER_MAC, flags & SERVER_STACKED ? UPPER : DEV);
	if (request_echoed(&c, "hello") || request_echoed(&c, "world"))
		goto out;
	hooks_expect(&h, p, "replies", 0);
	/* A reply the peer does not acknowledge is sent again by the timer. */
	if (!ASSERT_OK(peer_send(p, TH_PSH, "again", 5), "send request") ||
	    !ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv echo") ||
	    !ASSERT_EQ(s.seq, p->rcv_nxt, "echo seq") ||
	    !ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv retransmit") ||
	    !ASSERT_EQ(s.seq, p->rcv_nxt, "retransmit seq") || !ASSERT_EQ(s.len, 5, "retransmit len"))
		goto out;
	p->rcv_nxt += s.len;
	if (!ASSERT_OK(peer_send(p, 0, NULL, 0), "ack echo"))
		goto out;
	hooks_expect(&h, p, "retransmit", 0);
	/* The FIN, and the ACK of the peer's. */
	if (!ASSERT_OK(shutdown(c.conn, SHUT_WR), "shutdown") ||
	    !ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv FIN") ||
	    !ASSERT_EQ(s.flags & TH_FIN, TH_FIN, "FIN"))
		goto out;
	p->rcv_nxt++;
	if (!ASSERT_OK(peer_send(p, TH_FIN, NULL, 0), "send FIN") ||
	    !ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv ack of FIN") ||
	    !ASSERT_EQ(s.ack, p->snd_nxt, "ack of FIN"))
		goto out;
	hooks_expect(&h, p, "close", 0);
	ASSERT_EQ(c.skel->bss->sent, 3, "sent");
out:
	teardown(&c);
out_hooks:
	hooks_detach(&h);
}

/*
 * An out-of-order segment goes to the stack, which reassembles and queues
 * for the application. The fast path has to stay off until the application
 * has read, even once header prediction is back on.
 */
static void test_ooo_unread(void)
{
	char buf[DATA_MAX];
	struct peer *p;
	struct ctx c;
	struct seg s;
	__u32 base;
	int got;

	if (setup(&c, AF_INET))
		return;
	p = &c.peer;
	if (connect_peer(&c, OPT_SACK))
		goto out;
	base = p->snd_nxt;

	/* Second segment first: a hole, SACKed by the stack. */
	if (!ASSERT_OK(peer_send_raw(p, TH_ACK | TH_PSH, base + 5, p->rcv_nxt,
				     "BBBBB", 5, 0), "send B"))
		goto out;
	if (!ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv dup ack"))
		goto out;
	ASSERT_EQ(s.ack, base, "dup ack");
	if (ASSERT_EQ(s.nr_sack, 1, "sack block")) {
		ASSERT_EQ(s.sack[0].start, base + 5, "sack start");
		ASSERT_EQ(s.sack[0].end, base + 10, "sack end");
	}
	/* The hole: header prediction is off, the stack fills it and queues. */
	if (!ASSERT_OK(peer_send(p, TH_PSH, "AAAAA", 5), "send A"))
		goto out;
	p->snd_nxt += 5;
	if (!ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv ack AB"))
		goto out;
	ASSERT_EQ(s.ack, base + 10, "ack AB");
	/* Header prediction is on again, but the application has not read. */
	if (!ASSERT_OK(peer_send(p, TH_PSH, "CCCCC", 5), "send C"))
		goto out;
	if (!ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv ack ABC"))
		goto out;
	ASSERT_EQ(s.ack, base + 15, "ack ABC");
	ASSERT_EQ(s.len, 0, "no echo of C");
	ASSERT_EQ(c.skel->bss->consumed, 0, "consumed before read");

	for (got = 0; got < 15;) {
		int ret = app_recv(&c, buf + got, sizeof(buf) - got);

		if (!ASSERT_GT(ret, 0, "app recv"))
			goto out;
		got += ret;
	}
	ASSERT_MEMEQ(buf, "AAAAABBBBBCCCCC", 15, "app data");
	ASSERT_EQ(app_recv(&c, buf, sizeof(buf)), -EAGAIN, "app drained");

	/* Drained: the fast path takes the next segment. */
	if (request_echoed(&c, "DDDDD"))
		goto out;
	ASSERT_EQ(c.skel->bss->consumed, 1, "consumed after read");
out:
	teardown(&c);
}

/*
 * A changed window is not a reason to decline: tcp_ack() takes it. With a
 * window of 2000 bytes the stack sends exactly that much of a 3000-byte reply
 * and waits; opening the window releases the rest. The shrink rides on a
 * second request that also acknowledges the first reply: the stack ignores a
 * smaller window announced by a segment that neither acknowledges new data
 * nor moves past the sequence number of the last update.
 */
static void test_window_update(void)
{
	const int len = 3000;
	char *pattern, *buf;
	__u64 deadline;
	struct peer *p;
	struct ctx c;
	struct seg s;
	int i, got;

	if (setup(&c, AF_INET))
		return;
	p = &c.peer;
	pattern = malloc(len);
	buf = malloc(len);
	if (!ASSERT_OK_PTR(pattern, "malloc") || !ASSERT_OK_PTR(buf, "malloc"))
		goto out;
	for (i = 0; i < len; i++)
		pattern[i] = 'A' + i % 26;

	if (connect_peer(&c, 0))
		goto out;
	if (!ASSERT_OK(peer_send(p, TH_PSH, "hello", 5), "send first request") ||
	    !ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv first echo") ||
	    !ASSERT_EQ(s.len, 5, "first echo len"))
		goto out;
	p->rcv_nxt += s.len;
	/* The echo used the arena too; the pattern goes in after it. */
	memcpy(c.skel->arena->reply, pattern, len);
	c.skel->bss->reply_len = len;
	p->win = 2000;
	if (!ASSERT_OK(peer_send(p, TH_PSH, "req", 3), "send request"))
		goto out;
	/* A window's worth arrives without being acknowledged. */
	for (got = 0; got < 2000;) {
		if (!ASSERT_OK(peer_recv_data(p, &s, TIMEOUT_MS), "recv within window") ||
		    !ASSERT_EQ(s.seq, p->rcv_nxt, "seq within window") ||
		    !ASSERT_LE(got + s.len, 2000, "len within window"))
			goto out;
		memcpy(buf + got, s.data, s.len);
		got += s.len;
		p->rcv_nxt += s.len;
	}
	ASSERT_EQ(c.skel->bss->consumed, 2, "consumed");
	/* The rest does not fit; only retransmissions may show up. */
	deadline = now_ms() + 300;
	while (!peer_recv_data(p, &s, deadline - now_ms()))
		if (!ASSERT_TRUE(before(s.seq, p->rcv_nxt), "window holds the rest"))
			goto out;
	p->win = PEER_WIN;
	if (!ASSERT_OK(peer_send(p, 0, NULL, 0), "open window"))
		goto out;
	if (peer_collect(p, buf + got, len - got))
		goto out;
	ASSERT_MEMEQ(buf, pattern, len, "reply data");
out:
	free(pattern);
	free(buf);
	teardown(&c);
}

/* A FIN is not a data segment; the stack handles it and the application sees EOF. */
static void test_fin(void)
{
	char buf[DATA_MAX];
	struct ctx c;
	struct seg s;

	if (setup(&c, AF_INET))
		return;
	if (connect_peer(&c, 0))
		goto out;
	if (request_echoed(&c, "hello"))
		goto out;
	if (!ASSERT_OK(peer_send(&c.peer, TH_FIN, NULL, 0), "send FIN"))
		goto out;
	if (!ASSERT_OK(peer_recv(&c.peer, &s, TIMEOUT_MS), "recv ack of FIN"))
		goto out;
	ASSERT_EQ(s.ack, c.peer.snd_nxt, "ack of FIN");
	ASSERT_EQ(app_recv(&c, buf, sizeof(buf)), 0, "app EOF");
	ASSERT_EQ(c.skel->bss->consumed, 1, "consumed");
out:
	teardown(&c);
}

/* A retransmission of consumed data is old data to the stack: D-SACKed. */
static void test_retransmit(void)
{
	struct peer *p;
	struct ctx c;
	struct seg s;
	__u32 base;

	if (setup(&c, AF_INET))
		return;
	p = &c.peer;
	if (connect_peer(&c, OPT_SACK))
		goto out;
	base = p->snd_nxt;
	if (request_echoed(&c, "hello"))
		goto out;
	if (!ASSERT_OK(peer_send_raw(p, TH_ACK | TH_PSH, base, p->rcv_nxt, "hello", 5, 0),
		       "resend request"))
		goto out;
	if (!ASSERT_OK(peer_recv(p, &s, TIMEOUT_MS), "recv dup ack"))
		goto out;
	ASSERT_EQ(s.ack, p->snd_nxt, "dup ack");
	ASSERT_EQ(s.len, 0, "no second echo");
	if (ASSERT_EQ(s.nr_sack, 1, "dsack block")) {
		ASSERT_EQ(s.sack[0].start, base, "dsack start");
		ASSERT_EQ(s.sack[0].end, base + 5, "dsack end");
	}
	ASSERT_EQ(c.skel->bss->consumed, 1, "consumed");
out:
	teardown(&c);
}

/* A response larger than the MSS is segmented and paced by the stack. */
static void test_large_reply(void)
{
	const int len = 20000;
	char *pattern, *buf;
	struct ctx c;
	int i;

	if (setup(&c, AF_INET))
		return;
	pattern = malloc(len);
	buf = malloc(len);
	if (!ASSERT_OK_PTR(pattern, "malloc") || !ASSERT_OK_PTR(buf, "malloc"))
		goto out;
	for (i = 0; i < len; i++)
		pattern[i] = 'a' + i % 26;
	memcpy(c.skel->arena->reply, pattern, len);
	c.skel->bss->reply_len = len;

	if (connect_peer(&c, OPT_SACK | OPT_TS))
		goto out;
	if (!ASSERT_OK(peer_send(&c.peer, TH_PSH, "req", 3), "send request"))
		goto out;
	if (peer_collect(&c.peer, buf, len))
		goto out;
	ASSERT_MEMEQ(buf, pattern, len, "reply data");
	ASSERT_EQ(c.skel->bss->consumed, 1, "consumed");
	ASSERT_EQ(c.skel->bss->sent_bytes, len, "sent_bytes");
out:
	free(pattern);
	free(buf);
	teardown(&c);
}

void test_xdp_tcp(void)
{
	if (test__start_subtest("echo_v4"))
		test_echo(AF_INET, 0);
	if (test__start_subtest("echo_v6"))
		test_echo(AF_INET6, 0);
	if (test__start_subtest("echo_v4_ts_sack"))
		test_echo(AF_INET, OPT_TS | OPT_SACK);
	if (test__start_subtest("echo_v6_ts_sack"))
		test_echo(AF_INET6, OPT_TS | OPT_SACK);
	if (test__start_subtest("declined"))
		test_declined();
	if (test__start_subtest("send_now"))
		test_send_now();
	if (test__start_subtest("refused_sockmap"))
		test_refused(REFUSE_SOCKMAP);
	if (test__start_subtest("refused_md5"))
		test_refused(REFUSE_MD5);
	if (test__start_subtest("refused_xfrm"))
		test_refused(REFUSE_XFRM);
	if (test__start_subtest("refused_xfrm_out"))
		test_refused(REFUSE_XFRM_OUT);
	if (test__start_subtest("refused_ip_options"))
		test_refused(REFUSE_IP_OPTIONS);
	if (test__start_subtest("tx_hooks_v4"))
		test_tx_hooks(AF_INET, 0, false);
	if (test__start_subtest("tx_hooks_v6"))
		test_tx_hooks(AF_INET6, 0, false);
	if (test__start_subtest("tx_hooks_v6_mapped"))
		test_tx_hooks(AF_INET, SERVER_MAPPED, false);
	if (test__start_subtest("tx_hooks_neigh_stale"))
		test_tx_hooks(AF_INET, 0, true);
	if (test__start_subtest("tx_hooks_stacked"))
		test_tx_hooks(AF_INET, SERVER_STACKED, false);
	if (test__start_subtest("ooo_unread"))
		test_ooo_unread();
	if (test__start_subtest("window_update"))
		test_window_update();
	if (test__start_subtest("fin"))
		test_fin();
	if (test__start_subtest("retransmit"))
		test_retransmit();
	if (test__start_subtest("large_reply"))
		test_large_reply();
}
