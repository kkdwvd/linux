// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TCP from XDP.
 *
 * An XDP program that serves established TCP connections uses these kfuncs to
 * receive data segments before they become skbs, without the socket's owner
 * being woken. The stack keeps the connection: the handshake, ACK processing,
 * congestion control, retransmission, the window and the whole sending side
 * are its, and every kfunc that touches connection state runs under the
 * socket lock.
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
 *   bpf_xdp_tcp_release()  drops the socket reference
 *
 * tcp_ack() and friends work on an skb; a segment is described to them with a
 * stack skb whose head holds a copy of the headers and whose control block is
 * filled as tcp_v4_fill_cb() would.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skbuff.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <net/dsfield.h>
#include <net/inet6_hashtables.h>
#include <net/inet_hashtables.h>
#include <net/ip6_checksum.h>
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
	    xdp_tcp_rx_guarded(sk)) {
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
	if (status == BPF_XDP_TCP_DUPLICATE && commit_dup) {
		xdp_tcp_count_in(sk, h);
		xdp_tcp_dup(sk, seq, end_seq);
	} else if (status == BPF_XDP_TCP_RECEIVED) {
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
BTF_ID_FLAGS(func, bpf_xdp_tcp_release, KF_RELEASE)
BTF_KFUNCS_END(bpf_xdp_tcp_xdp_kfunc_ids)

static const struct btf_kfunc_id_set bpf_xdp_tcp_xdp_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_xdp_tcp_xdp_kfunc_ids,
};

static int __init bpf_xdp_tcp_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_xdp_tcp_xdp_kfunc_set);
}
late_initcall(bpf_xdp_tcp_kfunc_init);
