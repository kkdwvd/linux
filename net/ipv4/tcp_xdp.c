// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TCP from XDP.
 *
 * An XDP program that serves established TCP connections uses these kfuncs to
 * receive data segments before they become skbs, without the socket's owner
 * being woken. The stack keeps the connection: the handshake, ACK processing,
 * congestion control, retransmission, the window and the segments it sends
 * are its, and every kfunc that touches connection state runs under the
 * socket lock. What is this file's on the sending side is the way a served
 * connection's segments leave the host, see xdp_tcp_adopt().
 *
 *   bpf_xdp_tcp_recv()     finds the connection and, if the segment is the
 *                          next in sequence and nothing is in the way, takes
 *                          it as tcp_rcv_established() would, with the data
 *                          counted as received and read rather than queued.
 *                          Anything else is a status for the program: out of
 *                          order or the socket busy, so pass the frame on; a
 *                          duplicate, acknowledged on the spot; or a segment
 *                          for the stack.
 *   bpf_xdp_tcp_lookup()   split the in-order path in two, for a program that
 *   bpf_xdp_tcp_consume()  inspects a segment before it accepts it
 *   bpf_xdp_tcp_send()     queues a response on the write queue and pushes it
 *                          at once from BH context, or asks the program to
 *                          try again
 *   bpf_xdp_tcp_release()  drops the socket reference
 *
 * tcp_ack() and friends work on an skb; a segment is described to them with a
 * stack skb whose head holds a copy of the headers and whose control block is
 * filled as tcp_v4_fill_cb() would.
 */
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skbuff.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <net/dsfield.h>
#include <net/inet6_connection_sock.h>
#include <net/inet6_hashtables.h>
#include <net/inet_hashtables.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ndisc.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/tcp_ecn.h>
#include <net/xdp.h>
#include <net/xfrm.h>

enum bpf_xdp_tcp_status {
	BPF_XDP_TCP_RECEIVED = 1,	/* taken: the payload range is the program's to read */
	BPF_XDP_TCP_OUT_OF_ORDER,	/* within the window, beyond the cursor: pass it on */
	BPF_XDP_TCP_BUSY,		/* socket owned or unread data in the stack: pass it on */
	BPF_XDP_TCP_DUPLICATE,		/* nothing new, acknowledged: drop it */
	BPF_XDP_TCP_PASS,		/* for the stack: outside the window or unhandled here */
};

enum bpf_xdp_tcp_info_flags {
	BPF_XDP_TCP_FIN		= 1,	/* the segment ends the peer's stream */
};

struct bpf_xdp_tcp_info {
	__u32 payload_off;	/* offset of the TCP payload in the frame */
	__u32 payload_len;
	__u32 seq;		/* sequence number of the payload's first byte */
	__u32 end_seq;		/* past the payload and the FIN */
	__u32 rcv_nxt;		/* the connection's receive cursor afterwards */
	__u32 status;		/* enum bpf_xdp_tcp_status */
	__u32 flags;		/* enum bpf_xdp_tcp_info_flags */
	__u64 cookie;		/* the socket's cookie, a key for per-connection state */
};

struct xdp_tcp_hdrs {
	const struct iphdr *iph;	/* one of the two is set */
	const struct ipv6hdr *ip6h;
	const struct tcphdr *th;
	u32 payload_len;
	u8 dsfield;
};

/*
 * Parse an IPv4 or IPv6 TCP frame with a non-empty payload or a FIN; false for
 * anything else. IP options and extension headers are left to the stack. The
 * checksum is verified unless the caller knows the frame from a verification of
 * its own, as it does a frame it admitted and has kept read-only since.
 */
static bool xdp_tcp_parse(const struct xdp_buff *xdp, struct xdp_tcp_hdrs *h, bool verify_csum)
{
	const void *data = xdp->data, *end = xdp->data_end;
	const struct ethhdr *eth = data;
	const struct tcphdr *th;
	u32 tcp_len, hlen;
	__sum16 csum;

	if (data + sizeof(*eth) > end)
		return false;
	memset(h, 0, sizeof(*h));
	if (eth->h_proto == htons(ETH_P_IP)) {
		const struct iphdr *iph = data + sizeof(*eth);
		u32 tot_len;

		if ((void *)(iph + 1) > end)
			return false;
		if (iph->version != 4 || iph->ihl != 5 || iph->protocol != IPPROTO_TCP ||
		    (iph->frag_off & htons(IP_MF | IP_OFFSET)))
			return false;
		tot_len = ntohs(iph->tot_len);
		if (tot_len < sizeof(*iph) + sizeof(*th) || (void *)iph + tot_len > end)
			return false;
		if (ip_fast_csum(iph, iph->ihl))
			return false;
		th = (const void *)(iph + 1);
		tcp_len = tot_len - sizeof(*iph);
		/* The device does not verify checksums for XDP; do it here. */
		csum = verify_csum ? csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP,
						       csum_partial(th, tcp_len, 0)) : 0;
		h->iph = iph;
		h->dsfield = ipv4_get_dsfield(iph);
	} else if (IS_ENABLED(CONFIG_IPV6) && eth->h_proto == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h = data + sizeof(*eth);

		if ((void *)(ip6h + 1) > end)
			return false;
		if (ip6h->version != 6 || ip6h->nexthdr != IPPROTO_TCP)
			return false;
		tcp_len = ntohs(ip6h->payload_len);
		if (tcp_len < sizeof(*th) || (void *)(ip6h + 1) + tcp_len > end)
			return false;
		th = (const void *)(ip6h + 1);
		csum = verify_csum ? csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, tcp_len, IPPROTO_TCP,
						     csum_partial(th, tcp_len, 0)) : 0;
		h->ip6h = ip6h;
		h->dsfield = ipv6_get_dsfield(ip6h);
	} else {
		return false;
	}
	if (csum)
		return false;
	hlen = th->doff * 4;
	if (hlen < sizeof(*th) || hlen > tcp_len)
		return false;
	h->th = th;
	h->payload_len = tcp_len - hlen;
	return h->payload_len != 0 || th->fin;
}

static struct sock *xdp_tcp_lookup6(struct net *net, const struct xdp_tcp_hdrs *h, int dif)
{
#if IS_ENABLED(CONFIG_IPV6)
	return __inet6_lookup_established(net, &h->ip6h->saddr, h->th->source, &h->ip6h->daddr,
					  ntohs(h->th->dest), dif, 0);
#else
	return NULL;
#endif
}

/*
 * Is the connection the plain stack's? A ULP such as kTLS or MPTCP, and sockmap,
 * replace sendmsg() and recvmsg() and expect every byte to pass through them;
 * the fast path would go around them on both sides. The function pointers are
 * compared, since tcpv6_prot may live in a module.
 */
static bool xdp_tcp_served(const struct sock *sk)
{
	const struct proto *prot = READ_ONCE(sk->sk_prot);

	return !inet_csk(sk)->icsk_ulp_ops && !sk_is_mptcp(sk) &&
	       prot->sendmsg == tcp_sendmsg && prot->recvmsg == tcp_recvmsg;
}

/*
 * What the stack checks on an skb before a segment reaches the socket and
 * cannot be checked here: the signature a key on the socket demands, and an
 * XFRM input policy. Such a socket's segments are the stack's.
 */
static bool xdp_tcp_rx_guarded(const struct sock *sk)
{
#ifdef CONFIG_TCP_MD5SIG
	if (rcu_access_pointer(tcp_sk(sk)->md5sig_info))
		return true;
#endif
#ifdef CONFIG_TCP_AO
	if (rcu_access_pointer(tcp_sk(sk)->ao_info))
		return true;
#endif
#ifdef CONFIG_XFRM
	if (rcu_access_pointer(sk->sk_policy[XFRM_POLICY_IN]) ||
	    READ_ONCE(sock_net(sk)->xfrm.policy_count[XFRM_POLICY_IN]))
		return true;
#endif
	return false;
}

/*
 * The way out.
 *
 * A served connection's segments are the stack's: tcp_write_xmit() builds them
 * and its timers send them again. But they leave the host through a path of
 * this file's. The socket's af_ops are replaced, the first time a kfunc acts
 * on it, by a copy whose queue_xmit builds the IP header from the cached
 * route, runs the cgroup egress hook, resolves the neighbour and queues the
 * segment on the device, with the TC and netfilter egress hooks left out.
 * What ip_queue_xmit() and inet6_csk_xmit() do beyond that, netfilter's
 * LOCAL_OUT and POST_ROUTING, XFRM, L3 master devices, lightweight tunnels, IP
 * options and extension headers, a served connection's segments do not get,
 * as their counterparts on the way in are not applied to what XDP takes. A
 * socket that needs any of them is not served, see xdp_tcp_tx_guarded(). The
 * pacing, TSQ, the qdisc, GSO and checksum offload are below this point and
 * are kept. The ops go back to the stack's when the socket is disconnected
 * for reuse.
 */
static struct inet_connection_sock_af_ops xdp_tcp_v4_ops, xdp_tcp_v6_ops, xdp_tcp_v6_mapped_ops;

static bool xdp_tcp_lean_ops(const struct inet_connection_sock_af_ops *ops)
{
	return ops == &xdp_tcp_v4_ops || ops == &xdp_tcp_v6_ops || ops == &xdp_tcp_v6_mapped_ops;
}

/*
 * The socket's own reasons for the stack's output path: IP options or
 * extension headers to put in every segment, an XFRM output policy to apply.
 * Checked when the socket is adopted, so that one with them is not, and on
 * every segment after, so that one that gains them later sends the stack's
 * way, receive being unaffected.
 */
static bool xdp_tcp_tx_slow(const struct sock *sk)
{
	if (rcu_access_pointer(inet_sk(sk)->inet_opt))
		return true;
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6 && rcu_access_pointer(inet6_sk(sk)->opt))
		return true;
#endif
#ifdef CONFIG_XFRM
	if (rcu_access_pointer(sk->sk_policy[XFRM_POLICY_OUT]) ||
	    READ_ONCE(sock_net(sk)->xfrm.policy_count[XFRM_POLICY_OUT]))
		return true;
#endif
	return false;
}

/* The route's: a transformation, a lightweight tunnel, an L3 master device. */
static bool xdp_tcp_dst_slow(const struct dst_entry *dst)
{
	return dst_xfrm(dst) || dst->lwtstate || netif_is_l3_slave(dst_dev_rcu(dst));
}

/* What keeps a socket from being adopted. */
static bool xdp_tcp_tx_guarded(const struct sock *sk)
{
	const struct dst_entry *dst;
	bool guarded;

	/* The IPv6 path needs the parts of ipv6 that a module keeps to itself. */
	if (!IS_BUILTIN(CONFIG_IPV6) && sk->sk_family == AF_INET6)
		return true;
	if (xdp_tcp_tx_slow(sk))
		return true;
	rcu_read_lock();
	dst = __sk_dst_get(sk);
	guarded = dst && xdp_tcp_dst_slow(dst);
	rcu_read_unlock();
	return guarded;
}

/*
 * Put the socket on the lean transmit path, the first time. Under the socket
 * lock, which __tcp_transmit_skb() holds when it reads the ops; the pointer
 * is swapped whole, so each segment uses one set or the other. Returns false
 * for a socket that is not to be served.
 */
static bool xdp_tcp_adopt(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct inet_connection_sock_af_ops *ops = icsk->icsk_af_ops;

	if (likely(xdp_tcp_lean_ops(ops)))
		return true;
	if (xdp_tcp_tx_guarded(sk))
		return false;
	if (ops == &ipv4_specific)
		ops = &xdp_tcp_v4_ops;
#if IS_BUILTIN(CONFIG_IPV6)
	else if (ops == &ipv6_specific)
		ops = &xdp_tcp_v6_ops;
	else if (sk->sk_family == AF_INET6 && ops->queue_xmit == ip_queue_xmit)
		ops = &xdp_tcp_v6_mapped_ops;	/* ipv6_mapped, private to tcp_ipv6.c */
#endif
	else
		return false;
	/* Paired with the READ_ONCE() in tcp_setsockopt() and tcp_getsockopt(). */
	WRITE_ONCE(icsk->icsk_af_ops, ops);
	return true;
}

/*
 * From tcp_disconnect(), under the socket lock: the socket may be connected
 * again, or listen, and neither the new connection nor the children would be
 * served. The mapped ops go back to ipv6_specific, which tcp_v6_connect()
 * replaces with ipv6_mapped again for a mapped destination.
 */
void tcp_xdp_disconnect(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (!xdp_tcp_lean_ops(icsk->icsk_af_ops))
		return;
	if (icsk->icsk_af_ops == &xdp_tcp_v4_ops)
		WRITE_ONCE(icsk->icsk_af_ops, &ipv4_specific);
#if IS_BUILTIN(CONFIG_IPV6)
	else
		WRITE_ONCE(icsk->icsk_af_ops, &ipv6_specific);
#endif
}

/* The established socket a parsed data segment belongs to, with a reference. */
static struct sock *xdp_tcp_find(const struct xdp_buff *xdp, struct xdp_tcp_hdrs *h)
{
	struct net_device *dev;
	struct sock *sk;

	if (!xdp->rxq || !xdp->rxq->dev || !xdp_tcp_parse(xdp, h, true))
		return NULL;
	dev = xdp->rxq->dev;
	if (h->iph)
		sk = __inet_lookup_established(dev_net(dev), h->iph->saddr, h->th->source,
					       h->iph->daddr, ntohs(h->th->dest), dev->ifindex, 0);
	else
		sk = xdp_tcp_lookup6(dev_net(dev), h, dev->ifindex);
	if (!sk)
		return NULL;
	/* The established hash also holds request and TIME-WAIT sockets. */
	if (!sk_fullsock(sk)) {
		sock_gen_put(sk);
		return NULL;
	}
	if (READ_ONCE(sk->sk_state) != TCP_ESTABLISHED || !xdp_tcp_served(sk) ||
	    xdp_tcp_rx_guarded(sk) || xdp_tcp_tx_guarded(sk)) {
		sock_put(sk);
		return NULL;
	}
	return sk;
}

static void xdp_tcp_info(const struct xdp_buff *xdp, const struct xdp_tcp_hdrs *h,
			 struct sock *sk, struct bpf_xdp_tcp_info *info)
{
	info->payload_off = (const void *)h->th + h->th->doff * 4 - xdp->data;
	info->payload_len = h->payload_len;
	info->seq = ntohl(h->th->seq);
	info->end_seq = info->seq + info->payload_len + h->th->fin;
	info->rcv_nxt = READ_ONCE(tcp_sk(sk)->rcv_nxt);
	info->status = 0;
	info->flags = h->th->fin ? BPF_XDP_TCP_FIN : 0;
	info->cookie = sock_gen_cookie(sk);
}

/*
 * A connection, not a listener: a listener's lifetime is RCU's rather than its
 * reference count's, and bpf_xdp_tcp_release() puts only what is counted.
 */
static bool xdp_tcp_is_sock(const struct sock *sk)
{
	return sk_fullsock(sk) && !sock_flag(sk, SOCK_RCU_FREE) && sk->sk_type == SOCK_STREAM &&
	       sk->sk_protocol == IPPROTO_TCP &&
	       (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) && xdp_tcp_served(sk);
}

/* Is the segment the connection's? A program may hand us any socket and frame. */
static bool xdp_tcp_matches(struct sock *sk, const struct xdp_tcp_hdrs *h)
{
	if (!xdp_tcp_is_sock(sk))
		return false;
	if (inet_sk(sk)->inet_dport != h->th->source || inet_sk(sk)->inet_sport != h->th->dest)
		return false;
	if (h->iph)
		return inet_sk(sk)->inet_daddr == h->iph->saddr &&
		       inet_sk(sk)->inet_rcv_saddr == h->iph->daddr;
#if IS_ENABLED(CONFIG_IPV6)
	return sk->sk_family == AF_INET6 &&
	       ipv6_addr_equal(&sk->sk_v6_daddr, &h->ip6h->saddr) &&
	       ipv6_addr_equal(&sk->sk_v6_rcv_saddr, &h->ip6h->daddr);
#else
	return false;
#endif
}

/* The segment as the stack's helpers want to see it. */
struct xdp_tcp_skb {
	struct sk_buff skb;
	u8 hdr[sizeof(struct ipv6hdr) + 60] __aligned(8);
	struct skb_shared_info shinfo;
};

static void xdp_tcp_build_skb(struct xdp_tcp_skb *fake, const struct xdp_tcp_hdrs *h)
{
	struct sk_buff *skb = &fake->skb;
	u32 iplen = h->iph ? sizeof(*h->iph) : sizeof(*h->ip6h);
	u32 hlen = h->th->doff * 4;

	memset(fake, 0, sizeof(*fake));
	memcpy(fake->hdr, h->iph ? (const void *)h->iph : (const void *)h->ip6h, iplen);
	memcpy(fake->hdr + iplen, h->th, hlen);
	skb->head = fake->hdr;
	skb->data = fake->hdr + iplen + hlen;
	skb_set_end_offset(skb, offsetof(struct xdp_tcp_skb, shinfo) -
				offsetof(struct xdp_tcp_skb, hdr));
	skb_reset_tail_pointer(skb);
	skb->len = h->payload_len;
	skb->truesize = SKB_TRUESIZE(h->payload_len + iplen + hlen);
	skb->network_header = 0;
	skb->transport_header = iplen;
	skb->protocol = h->iph ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
	TCP_SKB_CB(skb)->seq = ntohl(h->th->seq);
	TCP_SKB_CB(skb)->end_seq = ntohl(h->th->seq) + h->payload_len + h->th->fin;
	TCP_SKB_CB(skb)->ack_seq = ntohl(h->th->ack_seq);
	TCP_SKB_CB(skb)->tcp_flags = tcp_flags_ntohs(h->th);
	TCP_SKB_CB(skb)->ip_dsfield = h->dsfield;
}

/*
 * Header prediction compares the flag word under TCP_HP_BITS, as
 * tcp_fast_path_on() encodes it. bpf_xdp_tcp_lookup() uses it as the stack's
 * fast path does, minus the window: a changed window is taken by tcp_ack()
 * when the segment is consumed, and clients change it often enough as their
 * receive buffers autotune.
 *
 * Nothing may be waiting in the receive queue: consuming would move copied_seq
 * past data the application has yet to read, and tcp_recvmsg() would then find
 * segments before its cursor. Header prediction does not cover this, since the
 * stack's fast path can queue behind unread data.
 */
#define XDP_TCP_HP_BITS		(~(TCP_RESERVED_BITS | TCP_FLAG_PSH))

/* What is handled here: a plain header, at most an aligned timestamp, a sane ACK. */
static bool xdp_tcp_rx_ok(const struct tcp_sock *tp, const struct tcphdr *th)
{
	u32 hlen = th->doff * 4, ack = ntohl(th->ack_seq);

	return th->ack && !th->syn && !th->rst && !th->urg && !th->ece && !th->cwr &&
	       !(tcp_flag_word(th) & TCP_RESERVED_BITS) && !tp->urg_data && !tp->repair &&
	       !tcp_ecn_mode_accecn(tp) &&
	       hlen == tp->tcp_header_len &&
	       (hlen == sizeof(*th) || hlen == sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) &&
	       !after(ack, tp->snd_nxt) && !before(ack, tp->snd_una - tp->max_window);
}

/*
 * The checks tcp_validate_incoming() makes before a segment counts: the
 * connection is established, the header is one handled here, and a timestamp,
 * if there is one, does not go backwards. With the socket locked and not owned.
 */
static bool xdp_tcp_validate(struct sock *sk, const struct xdp_tcp_hdrs *h, s32 *ts_delta)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (sk->sk_state != TCP_ESTABLISHED || xdp_tcp_rx_guarded(sk) || !xdp_tcp_rx_ok(tp, h->th))
		return false;
	tp->rx_opt.saw_tstamp = 0;
	tp->rx_opt.accecn = 0;
	*ts_delta = 0;
	if (h->th->doff * 4 == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
		if (!tcp_parse_aligned_timestamp(tp, h->th))
			return false;
		*ts_delta = tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent;
		if (*ts_delta < 0)
			return false;
	}
	tcp_mstamp_refresh_inline(tp);
	/* A D-SACK is reported once, with the ACK of the segment that set it. */
	tp->rx_opt.dsack = 0;
	return true;
}

/* Where a validated segment stands against the connection. */
static u32 xdp_tcp_classify(const struct tcp_sock *tp, u32 seq, u32 end_seq)
{
	u32 window = tcp_receive_window(tp);

	if (!after(end_seq, tp->rcv_nxt))
		return BPF_XDP_TCP_DUPLICATE;
	if (after(seq, tp->rcv_nxt))
		return before(seq, tp->rcv_nxt + window) ? BPF_XDP_TCP_OUT_OF_ORDER :
							   BPF_XDP_TCP_PASS;
	/* In order, perhaps with an old prefix. A closed window is the stack's to probe. */
	if (!window)
		return BPF_XDP_TCP_PASS;
	if (READ_ONCE(tp->copied_seq) != tp->rcv_nxt || !RB_EMPTY_ROOT(&tp->out_of_order_queue))
		return BPF_XDP_TCP_BUSY;
	return BPF_XDP_TCP_RECEIVED;
}

/* The segment's ACK and timestamp count once, when it is first seen. */
static void xdp_tcp_ack(struct sock *sk, const struct xdp_tcp_skb *fake,
			const struct xdp_tcp_hdrs *h, s32 ts_delta)
{
	const struct sk_buff *skb = &fake->skb;
	struct tcp_sock *tp = tcp_sk(sk);
	bool ts_progress = false;

	if (tp->rx_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tp->rcv_wup))
		ts_progress = tcp_xdp_replace_ts_recent(tp, ts_delta);
	/* Nothing new to acknowledge and no window change: the fast path's shortcut. */
	if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una ||
	    ((tcp_flag_word(h->th) ^ tp->pred_flags) & XDP_TCP_HP_BITS))
		tcp_xdp_ack(sk, skb, ts_progress);
	else
		tcp_update_wl(tp, TCP_SKB_CB(skb)->seq);
	tcp_ecn_received_counters(sk, skb, h->payload_len);
}

/*
 * Take the new part of a segment that starts at or before the receive cursor,
 * as tcp_rcv_established() does for one the stack keeps, with the data counted
 * as read instead of queued. With the socket locked and not owned.
 */
static void xdp_tcp_take(struct sock *sk, struct xdp_tcp_skb *fake, const struct xdp_tcp_hdrs *h,
			 struct bpf_xdp_tcp_info *info)
{
	struct sk_buff *skb = &fake->skb;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = TCP_SKB_CB(skb)->seq, end_seq = TCP_SKB_CB(skb)->end_seq, skip = 0;

	/* An old prefix is reported back; the rest is new. */
	if (before(seq, tp->rcv_nxt)) {
		skip = min_t(u32, tp->rcv_nxt - seq, h->payload_len);
		tcp_dsack_extend(sk, seq, tp->rcv_nxt);
	}
	info->payload_off += skip;
	info->payload_len -= skip;
	info->seq += skip;
	tcp_rcv_rtt_measure_ts(sk, skb);
	tcp_event_data_recv(sk, skb);
	/* Received and read by the program; the read side's autotuning runs here. */
	tcp_rcv_nxt_update(tp, end_seq);
	WRITE_ONCE(tp->copied_seq, end_seq);
	inet_csk_schedule_ack(sk);
	if (h->th->fin) {
		inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		tcp_fin(sk);
	}
	tcp_rcv_space_adjust(sk);
	info->rcv_nxt = tp->rcv_nxt;
	info->status = BPF_XDP_TCP_RECEIVED;
}

/* What tcp_v4_rcv() counts for a segment it hands to a socket. */
static void xdp_tcp_count_in(struct sock *sk, const struct xdp_tcp_hdrs *h)
{
	struct tcp_sock *tp = tcp_sk(sk);

	TCP_INC_STATS(sock_net(sk), TCP_MIB_INSEGS);
	WRITE_ONCE(tp->segs_in, tp->segs_in + 1);
	if (h->payload_len)
		WRITE_ONCE(tp->data_segs_in, tp->data_segs_in + 1);
}

/* A duplicate the stack would D-SACK and acknowledge at once. */
static void xdp_tcp_dup(struct sock *sk, u32 seq, u32 end_seq)
{
	tcp_dsack_set(sk, seq, end_seq);
	tcp_send_ack(sk);
}

/*
 * The receive step for a segment still in its XDP buffer, with the socket
 * locked: classify it and, if it is next in line, take it. @commit_dup says
 * whether a duplicate is acknowledged here or left to the stack.
 */
static u32 xdp_tcp_rcv(struct sock *sk, const struct xdp_tcp_hdrs *h, struct xdp_tcp_skb *fake,
		       bool commit_dup, struct bpf_xdp_tcp_info *info)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = TCP_SKB_CB(&fake->skb)->seq, end_seq = TCP_SKB_CB(&fake->skb)->end_seq;
	u32 status;
	s32 ts_delta;

	if (sock_owned_by_user(sk))
		return BPF_XDP_TCP_BUSY;
	if (!xdp_tcp_validate(sk, h, &ts_delta))
		return BPF_XDP_TCP_PASS;
	status = xdp_tcp_classify(tp, seq, end_seq);
	/* The socket is served from the first segment acted on, not from one looked at. */
	if (status == BPF_XDP_TCP_DUPLICATE && commit_dup) {
		if (!xdp_tcp_adopt(sk))
			return BPF_XDP_TCP_PASS;
		xdp_tcp_count_in(sk, h);
		xdp_tcp_dup(sk, seq, end_seq);
	} else if (status == BPF_XDP_TCP_RECEIVED) {
		if (!xdp_tcp_adopt(sk))
			return BPF_XDP_TCP_PASS;
		xdp_tcp_count_in(sk, h);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);
		xdp_tcp_ack(sk, fake, h, ts_delta);
		xdp_tcp_take(sk, fake, h, info);
		__tcp_ack_snd_check(sk, 0);
	}
	return status;
}

__bpf_kfunc_start_defs();

/**
 * bpf_xdp_tcp_recv - receive a data segment on its connection, if it is next
 * @ctx: the frame
 * @info: what happened, and where the payload is
 *
 * Returns the socket, with a reference, when the frame is an IPv4 or IPv6 TCP
 * data segment for an established socket of the receiving netns; NULL
 * otherwise, with nothing done. info->status then says what became of the
 * segment under the socket lock:
 *
 * BPF_XDP_TCP_RECEIVED: the new part of the segment was taken, as
 * tcp_rcv_established()'s fast path takes a segment, except that the data is
 * counted as received and read rather than queued. The payload range in @info
 * is the program's to read; a FIN is flagged. The program answers the segment,
 * or redirects the frame, and returns anything but XDP_PASS.
 *
 * BPF_XDP_TCP_OUT_OF_ORDER: the segment is within the window but beyond the
 * receive cursor. BPF_XDP_TCP_BUSY: the segment is next, but the socket is
 * owned by its user or the stack holds unread data. In both cases nothing was
 * done, and the program passes the frame to the stack.
 *
 * BPF_XDP_TCP_DUPLICATE: nothing new in it; it was D-SACKed and acknowledged,
 * drop it. BPF_XDP_TCP_PASS: outside the window, or something handled here
 * cannot be, pass it to the stack.
 *
 * Segments of one connection are received in sequence whichever CPUs they
 * arrive on, and never twice; what the program does with the payload it
 * serializes itself if it has to.
 */
__bpf_kfunc struct sock *bpf_xdp_tcp_recv(struct xdp_md *ctx, struct bpf_xdp_tcp_info *info)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct xdp_tcp_skb fake;
	struct xdp_tcp_hdrs h;
	struct sock *sk;

	sk = xdp_tcp_find(xdp, &h);
	if (!sk)
		return NULL;
	xdp_tcp_info(xdp, &h, sk, info);
	xdp_tcp_build_skb(&fake, &h);
	bh_lock_sock_nested(sk);
	info->status = xdp_tcp_rcv(sk, &h, &fake, true, info);
	bh_unlock_sock(sk);
	return sk;
}

/**
 * bpf_xdp_tcp_lookup - find the established socket an in-order XDP frame belongs to
 * @ctx: the frame
 * @info: where the payload is, filled in on success
 *
 * The first half of bpf_xdp_tcp_recv(), for a program that inspects a segment
 * before accepting it: returns the socket, with a reference, when the segment
 * is one bpf_xdp_tcp_recv() would take, next in sequence with nothing in the
 * way; NULL otherwise. The checks are made without the socket lock, as a
 * preview: bpf_xdp_tcp_consume() makes them again under it.
 */
__bpf_kfunc struct sock *bpf_xdp_tcp_lookup(struct xdp_md *ctx, struct bpf_xdp_tcp_info *info)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct xdp_tcp_hdrs h;
	struct tcp_sock *tp;
	struct sock *sk;
	u32 seq;

	sk = xdp_tcp_find(xdp, &h);
	if (!sk)
		return NULL;
	tp = tcp_sk(sk);
	seq = ntohl(h.th->seq);
	if (!xdp_tcp_rx_ok(tp, h.th) ||
	    xdp_tcp_classify(tp, seq, seq + h.payload_len + h.th->fin) != BPF_XDP_TCP_RECEIVED) {
		sock_put(sk);
		return NULL;
	}
	xdp_tcp_info(xdp, &h, sk, info);
	return sk;
}

/**
 * bpf_xdp_tcp_consume - apply an in-order data segment to its connection
 * @sk: the socket from bpf_xdp_tcp_lookup()
 * @ctx: the frame
 * @info: as filled by bpf_xdp_tcp_lookup()
 *
 * The second half of bpf_xdp_tcp_recv(): takes the segment under the socket
 * lock, as a BPF_XDP_TCP_RECEIVED status says. Returns 0, and the program
 * answers the segment or redirects the frame, returning anything but
 * XDP_PASS; or -EAGAIN when the segment is no longer
 * next or the socket is busy, with nothing done, and the frame is the stack's
 * (XDP_PASS). -EINVAL says the frame is not the socket's.
 */
__bpf_kfunc int bpf_xdp_tcp_consume(struct sock *sk, struct xdp_md *ctx,
				    struct bpf_xdp_tcp_info *info)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct xdp_tcp_skb fake;
	struct xdp_tcp_hdrs h;
	u32 status;

	if (!xdp_tcp_parse(xdp, &h, true) || !xdp_tcp_matches(sk, &h))
		return -EINVAL;
	xdp_tcp_info(xdp, &h, sk, info);
	xdp_tcp_build_skb(&fake, &h);
	bh_lock_sock_nested(sk);
	status = xdp_tcp_rcv(sk, &h, &fake, false, info);
	bh_unlock_sock(sk);
	return status == BPF_XDP_TCP_RECEIVED ? 0 : -EAGAIN;
}


/*
 * The one hook kept on the way out: cgroup egress, which sees the segment
 * with its IP header on, as ip_finish_output() shows it. Returns the verdict
 * as ip_finish_output() reads it: NET_XMIT_SUCCESS, NET_XMIT_CN for a segment
 * to send while reporting congestion, or an error with the segment freed.
 */
static int xdp_tcp_egress(struct sock *sk, struct sk_buff *skb)
{
	int ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);

	if (unlikely(ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN))
		kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
	return ret;
}

/* The length the IP layer would check against the path MTU. */
static unsigned int xdp_tcp_seglen(const struct sk_buff *skb, unsigned int iphlen)
{
	if (skb_is_gso(skb))
		return iphlen + tcp_hdrlen(skb) + skb_shinfo(skb)->gso_size;
	return iphlen + skb->len;
}

/* ip_skb_dst_mtu() for a full socket, before the segment has its dst. */
static unsigned int xdp_tcp_v4_mtu(const struct sock *sk, const struct rtable *rt,
				   const struct net_device *dev)
{
	if (ip_sk_use_pmtu(sk))
		return ip_dst_mtu_maybe_forward(&rt->dst, false);
	return min(READ_ONCE(dev->mtu), IP_MAX_MTU);
}

/*
 * What ip_queue_xmit() does for a connected TCP socket, less the layers a
 * served connection goes without. The cases it has that this path does not,
 * a segment over the MTU, a device that needs more headroom, a route the
 * socket should not have been adopted with, are handed to it: they are rare,
 * and it does the right thing with them.
 */
static int xdp_tcp_v4_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct flowi4 *fl4 = &fl->u.ip4;
	struct net_device *dev;
	struct neighbour *neigh;
	bool is_v6gw = false;
	struct rtable *rt;
	struct iphdr *iph;
	int ret, err;

	if (unlikely(xdp_tcp_tx_slow(sk)))
		return ip_queue_xmit(sk, skb, fl);
	rcu_read_lock();
	rt = dst_rtable(__sk_dst_check(sk, 0));
	if (unlikely(!rt)) {
		/* As __ip_queue_xmit(): the retransmit timer keeps trying while there is no route. */
		inet_sk_init_flowi4(inet, fl4);
		fl4->flowi4_dscp = inet_dsfield_to_dscp(READ_ONCE(inet->tos));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			rcu_read_unlock();
			IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			kfree_skb_reason(skb, SKB_DROP_REASON_IP_OUTNOROUTES);
			return -EHOSTUNREACH;
		}
		sk_setup_caps(sk, &rt->dst);
	}
	dev = dst_dev_rcu(&rt->dst);
	if (unlikely(xdp_tcp_dst_slow(&rt->dst) ||
		     xdp_tcp_seglen(skb, sizeof(*iph)) > xdp_tcp_v4_mtu(sk, rt, dev) ||
		     (skb_headroom(skb) < sizeof(*iph) + LL_RESERVED_SPACE(dev) && dev->header_ops))) {
		rcu_read_unlock();
		return ip_queue_xmit(sk, skb, fl);
	}
	skb_dst_set_noref(skb, &rt->dst);

	skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (READ_ONCE(inet->tos) & 0xff));
	iph->frag_off = ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df ? htons(IP_DF) : 0;
	iph->ttl = ip_select_ttl(inet, &rt->dst);
	iph->protocol = IPPROTO_TCP;
	iph->saddr = fl4->saddr;
	iph->daddr = fl4->daddr;
	ip_select_ident_segs(net, skb, sk, skb_shinfo(skb)->gso_segs ?: 1);
	iph_set_totlen(iph, skb->len);
	ip_send_check(iph);
	skb->priority = READ_ONCE(sk->sk_priority);
	skb->mark = READ_ONCE(sk->sk_mark);
	skb->protocol = htons(ETH_P_IP);
	skb->dev = dev;
	IP_INC_STATS(net, IPSTATS_MIB_OUTREQUESTS);

	ret = xdp_tcp_egress(sk, skb);
	if (unlikely(ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN)) {
		rcu_read_unlock();
		return ret;
	}
	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
	if (unlikely(IS_ERR(neigh))) {
		rcu_read_unlock();
		kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
		return PTR_ERR(neigh);
	}
	sock_confirm_neigh(skb, neigh);
	skb_set_skip_egress(skb);
	err = neigh_output(neigh, skb, is_v6gw);
	rcu_read_unlock();
	return err ?: ret;
}

#if IS_BUILTIN(CONFIG_IPV6)
/* The same for inet6_csk_xmit() and ip6_xmit(). */
static int xdp_tcp_v6_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct flowi6 *fl6 = &fl->u.ip6;
	struct net *net = sock_net(sk);
	const struct in6_addr *nexthop;
	struct net_device *dev;
	struct neighbour *neigh;
	struct inet6_dev *idev;
	struct dst_entry *dst;
	struct ipv6hdr *hdr;
	unsigned int seg_len;
	int hlimit, ret, err;

	if (unlikely(xdp_tcp_tx_slow(sk)))
		return inet6_csk_xmit(sk, skb, fl);
	dst = __sk_dst_check(sk, np->dst_cookie);
	if (unlikely(!dst)) {
		dst = inet6_csk_route_socket(sk, fl6);
		if (IS_ERR(dst)) {
			WRITE_ONCE(sk->sk_err_soft, -PTR_ERR(dst));
			sk->sk_route_caps = 0;
			sk_skb_reason_drop(sk, skb, SKB_DROP_REASON_IP_OUTNOROUTES);
			return PTR_ERR(dst);
		}
		/* Restore final destination back after routing done */
		fl6->daddr = sk->sk_v6_daddr;
	}
	rcu_read_lock();
	dev = dst_dev_rcu(dst);
	if (unlikely(xdp_tcp_dst_slow(dst) || xdp_tcp_seglen(skb, sizeof(*hdr)) > dst6_mtu(dst) ||
		     skb_headroom(skb) < sizeof(*hdr) + LL_RESERVED_SPACE(dev))) {
		rcu_read_unlock();
		return inet6_csk_xmit(sk, skb, fl);
	}
	skb_dst_set_noref(skb, dst);

	__skb_push(skb, sizeof(*hdr));
	skb_reset_network_header(skb);
	hdr = ipv6_hdr(skb);
	hlimit = READ_ONCE(np->hop_limit);
	if (hlimit < 0)
		hlimit = ip6_dst_hoplimit(dst);
	ip6_flow_hdr(hdr, np->tclass, ip6_make_flowlabel(net, skb, fl6->flowlabel,
							 ip6_autoflowlabel(net, sk), fl6));
	seg_len = skb->len - sizeof(*hdr);
	hdr->payload_len = htons(seg_len > IPV6_MAXPLEN ? 0 : seg_len);
	hdr->nexthdr = IPPROTO_TCP;
	hdr->hop_limit = hlimit;
	hdr->saddr = fl6->saddr;
	hdr->daddr = fl6->daddr;
	skb->protocol = htons(ETH_P_IPV6);
	skb->priority = READ_ONCE(sk->sk_priority);
	skb->mark = READ_ONCE(sk->sk_mark);
	skb->dev = dev;
	idev = ip6_dst_idev(dst);
	IP6_INC_STATS(net, idev, IPSTATS_MIB_OUTREQUESTS);

	ret = xdp_tcp_egress(sk, skb);
	if (unlikely(ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN)) {
		rcu_read_unlock();
		return ret;
	}
	IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_OUT, skb->len);

	nexthop = rt6_nexthop(dst_rt6_info(dst), &hdr->daddr);
	neigh = __ipv6_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh))
		neigh = __neigh_create(&nd_tbl, nexthop, dev, false);
	if (IS_ERR(neigh)) {
		IP6_INC_STATS(net, idev, IPSTATS_MIB_OUTNOROUTES);
		rcu_read_unlock();
		kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
		return -EINVAL;
	}
	sock_confirm_neigh(skb, neigh);
	skb_set_skip_egress(skb);
	err = neigh_output(neigh, skb, false);
	rcu_read_unlock();
	return err ?: ret;
}
#endif

static void xdp_tcp_init_af_ops(void)
{
	xdp_tcp_v4_ops = ipv4_specific;
	xdp_tcp_v4_ops.queue_xmit = xdp_tcp_v4_xmit;
#if IS_BUILTIN(CONFIG_IPV6)
	xdp_tcp_v6_ops = ipv6_specific;
	xdp_tcp_v6_ops.queue_xmit = xdp_tcp_v6_xmit;
	/* ipv6_mapped is ipv6_specific with the IPv4 output side, as MPTCP builds its copy. */
	xdp_tcp_v6_mapped_ops = ipv6_specific;
	xdp_tcp_v6_mapped_ops.queue_xmit = xdp_tcp_v4_xmit;
	xdp_tcp_v6_mapped_ops.rebuild_header = ipv4_specific.rebuild_header;
	xdp_tcp_v6_mapped_ops.sk_rx_dst_set = ipv4_specific.sk_rx_dst_set;
	xdp_tcp_v6_mapped_ops.net_header_len = ipv4_specific.net_header_len;
	xdp_tcp_v6_mapped_ops.mtu_reduced = ipv4_specific.mtu_reduced;
#endif
}

/*
 * tcp_push() without the sendmsg() layer's write batching. Nagle and TCP_CORK
 * are overridden as TCP_NAGLE_PUSH overrides them, and autocorking, which
 * holds a short segment back while an earlier one is still in the qdisc or
 * the driver so that later writes can be merged into it, does not apply: a
 * reply is complete when it is queued and is never merged with a later one,
 * so the hold would only delay it until that transmission completes. The
 * segment is marked pushed as tcp_mark_push() marks it, and the congestion
 * and receive windows, pacing and TSQ decide when it leaves.
 */
static void xdp_tcp_push(struct sock *sk, struct sk_buff *skb, int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);

	TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
	tp->pushed_seq = tp->write_seq;
	__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
}

/*
 * Build a segment for @len bytes of @buf as tcp_sendmsg() would: the headers
 * in the skb, the payload in page fragments, so that the stack can split and
 * coalesce it like any other segment on the write queue. The socket's own
 * page_frag is used, since there is no task to borrow one from in BH context,
 * and the socket lock, held by the caller, serialises its use. The memory for
 * the headers is scheduled by tcp_stream_alloc_skb(); the payload is left to
 * the caller, which has to schedule skb->data_len.
 *
 * @buf is arena memory, rebased into the arena's kernel mapping by the JIT. A
 * page there that is not populated, or that another CPU frees meanwhile,
 * faults into the arena's scratch page and is reported against the program;
 * a copy that runs past the range the arena recovers fails instead.
 */
static struct sk_buff *xdp_tcp_alloc_segment(struct sock *sk, const void *buf, u32 len)
{
	struct page_frag *pfrag = &sk->sk_frag;
	struct sk_buff *skb;
	int err;

	skb = tcp_stream_alloc_skb(sk, GFP_ATOMIC, tcp_rtx_and_write_queues_empty(sk));
	if (!skb)
		return ERR_PTR(-ENOMEM);
	while (len) {
		int i = skb_shinfo(skb)->nr_frags;
		bool merge;
		u32 copy;

		err = -ENOMEM;
		if (!skb_page_frag_refill(32U, pfrag, GFP_ATOMIC))
			goto fail;
		copy = min_t(u32, len, pfrag->size - pfrag->offset);
		merge = skb_can_coalesce(skb, i, pfrag->page, pfrag->offset);
		if (!merge && i >= MAX_SKB_FRAGS)
			goto fail;
		err = -EFAULT;
		if (copy_from_kernel_nofault(page_address(pfrag->page) + pfrag->offset, buf, copy))
			goto fail;
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page, pfrag->offset, copy);
			page_ref_inc(pfrag->page);
		}
		pfrag->offset += copy;
		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		buf += copy;
		len -= copy;
	}
	return skb;
fail:
	__kfree_skb(skb);
	return ERR_PTR(err);
}

/**
 * bpf_xdp_tcp_send - send data on an established socket from BPF
 * @sk: the socket
 * @buf__arena: the data, in arena memory
 * @len: bytes to send, at most 64 KiB
 *
 * Copies the data into a new segment on the write queue and pushes it at
 * once, from BH context: the stack decides when it leaves, the sendmsg()
 * layer's write batching does not. Returns @len, or -EAGAIN when the socket
 * is held by its user or the write queue has no room for the data: the
 * program keeps the data and tries again later, the request having been
 * consumed already. Other errors are final; -EFAULT says the buffer runs
 * past the arena.
 */
__bpf_kfunc int bpf_xdp_tcp_send(struct sock *sk, void *buf__arena, u32 len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int mss_now, err;

	if (!xdp_tcp_is_sock(sk) || !len || len > SZ_64K)
		return -EINVAL;
	/*
	 * An XDP program runs with bottom halves disabled, but its bpf_wq and
	 * bpf_task_work callbacks run in process context and may call this.
	 */
	local_bh_disable();
	bh_lock_sock_nested(sk);
	err = -EAGAIN;
	if (sock_owned_by_user(sk) || !sk_stream_memory_free(sk))
		goto out;
	err = -ENOTCONN;
	if (!((1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)))
		goto out;
	err = -EINVAL;
	if (!xdp_tcp_adopt(sk))
		goto out;
	skb = xdp_tcp_alloc_segment(sk, buf__arena, len);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		goto out;
	}
	if (!sk_wmem_schedule(sk, skb->data_len)) {
		__kfree_skb(skb);
		err = -EAGAIN;
		goto out;
	}
	mss_now = tcp_current_mss(sk);
	tcp_rate_check_app_limited(sk);
	tcp_skb_entail(sk, skb);
	TCP_SKB_CB(skb)->end_seq += len;
	WRITE_ONCE(tp->write_seq, tp->write_seq + len);
	xdp_tcp_push(sk, skb, mss_now);
	err = len;
out:
	bh_unlock_sock(sk);
	local_bh_enable();
	return err;
}

/**
 * bpf_xdp_tcp_release - drop a reference to a connection
 * @sk: the socket, from bpf_xdp_tcp_recv() or bpf_xdp_tcp_lookup()
 *
 * The verifier lets a program hand over any socket it holds a reference to,
 * one found with bpf_sk_lookup_tcp() included, which carries no reference for
 * a listener or a UDP socket: those are put as bpf_sk_release() puts them, not
 * at all.
 */
__bpf_kfunc void bpf_xdp_tcp_release(struct sock *sk)
{
	if (sk_is_refcounted(sk))
		sock_gen_put(sk);
}

__bpf_kfunc_end_defs();

/* With the frame in hand: XDP only. */
BTF_KFUNCS_START(bpf_xdp_tcp_xdp_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdp_tcp_recv, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdp_tcp_lookup, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdp_tcp_consume)
BTF_ID_FLAGS(func, bpf_xdp_tcp_send)
BTF_ID_FLAGS(func, bpf_xdp_tcp_release, KF_RELEASE)
BTF_KFUNCS_END(bpf_xdp_tcp_xdp_kfunc_ids)

static const struct btf_kfunc_id_set bpf_xdp_tcp_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_xdp_tcp_xdp_kfunc_ids,
};

static int __init bpf_xdp_tcp_kfunc_init(void)
{
	xdp_tcp_init_af_ops();
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_xdp_tcp_xdp_kfunc_set);
}
late_initcall(bpf_xdp_tcp_kfunc_init);
