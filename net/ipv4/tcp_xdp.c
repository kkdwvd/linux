// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TCP fast path from XDP.
 *
 * An XDP program that implements a request/response service on top of
 * established TCP connections uses these kfuncs to take an in-order data
 * segment off the stack's hands and to answer it later, without the frame
 * ever becoming an skb and without the socket's owner being woken:
 *
 *   bpf_xdp_tcp_lookup()   parses the frame, finds the established socket and
 *                          reports where the payload is, if the segment is
 *                          one the fast path can handle: IPv4, no options,
 *                          header prediction holds, next in sequence
 *   bpf_xdp_tcp_consume()  under the socket lock, re-checks that and applies
 *                          the segment to the connection as
 *                          tcp_rcv_established()'s fast path would, except
 *                          that the data is counted as received and read
 *                          rather than queued: rcv_nxt and copied_seq move,
 *                          the ACK it carries is processed, an ACK of our
 *                          own is scheduled. The program then drops the frame.
 *   bpf_xdp_tcp_send()     queues a response on the write queue and pushes it,
 *                          as a sendmsg() would, from any BH context, or asks
 *                          the program to try again later
 *   bpf_xdp_tcp_release()  drops the socket reference
 *
 * Everything the fast path declines (a busy socket, unread data in the receive
 * queue, out-of-order or option-bearing segments, a shrinking window) is left
 * to XDP_PASS, where the stack and the application behind it handle the
 * segment as usual.
 *
 * tcp_ack() and friends work on an skb; the frame is described to them with
 * a stack skb whose head holds a copy of the TCP header and whose control
 * block is filled as tcp_v4_fill_cb() would.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>
#include <net/inet_ecn.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/tcp_ecn.h>
#include <net/xdp.h>

struct bpf_xdp_tcp_info {
	__u32 payload_off;	/* offset of the TCP payload in the frame */
	__u32 payload_len;
	__u32 seq;		/* sequence number of the payload's first byte */
	__u32 reserved;
};

struct xdp_tcp_hdrs {
	const struct iphdr *iph;
	const struct tcphdr *th;
	u32 payload_len;
};

/* Parse an IPv4/TCP frame with a non-empty payload; false for anything else. */
static bool xdp_tcp_parse(const struct xdp_buff *xdp, struct xdp_tcp_hdrs *h)
{
	const void *data = xdp->data, *end = xdp->data_end;
	const struct ethhdr *eth = data;
	const struct iphdr *iph;
	const struct tcphdr *th;
	u32 tot_len, hlen;

	if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*th) > end)
		return false;
	if (eth->h_proto != htons(ETH_P_IP))
		return false;
	iph = data + sizeof(*eth);
	if (iph->version != 4 || iph->ihl != 5 || iph->protocol != IPPROTO_TCP ||
	    (iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return false;
	tot_len = ntohs(iph->tot_len);
	if (tot_len < sizeof(*iph) + sizeof(*th) || (void *)iph + tot_len > end)
		return false;
	th = (const void *)(iph + 1);
	hlen = th->doff * 4;
	if (hlen < sizeof(*th) || sizeof(*iph) + hlen > tot_len)
		return false;
	if (ip_fast_csum(iph, iph->ihl))
		return false;
	/* The device does not verify checksums for XDP; do it here. */
	if (csum_tcpudp_magic(iph->saddr, iph->daddr, tot_len - sizeof(*iph), IPPROTO_TCP,
			      csum_partial(th, tot_len - sizeof(*iph), 0)))
		return false;
	h->iph = iph;
	h->th = th;
	h->payload_len = tot_len - sizeof(*iph) - hlen;
	return h->payload_len != 0;
}

/*
 * Header prediction compares the flag word under TCP_HP_BITS, as
 * tcp_fast_path_on() encodes it. Does the segment take the header-prediction
 * fast path on this socket? The window field is left out of the comparison:
 * the stack's fast path wants it unchanged so that it can skip window
 * processing, but the consume path below runs tcp_ack() with the slow-path
 * flag and handles a change, which clients make often enough as their
 * receive buffers autotune.
 *
 * Nothing may be waiting in the receive queue: consuming would move
 * copied_seq past data the application has yet to read, and tcp_recvmsg()
 * would then find segments before its cursor. Header prediction does not
 * cover this, since the stack's fast path can queue behind unread data.
 */
#define XDP_TCP_HP_BITS		(~(TCP_RESERVED_BITS | TCP_FLAG_PSH))
#define XDP_TCP_HP_NOWIN_BITS	(XDP_TCP_HP_BITS & ~htonl(0xffff))

static bool xdp_tcp_fast_ok(const struct tcp_sock *tp, const struct tcphdr *th, u32 plen)
{
	u32 seq = ntohl(th->seq), ack_seq = ntohl(th->ack_seq);

	return tp->pred_flags &&
	       ((tcp_flag_word(th) ^ tp->pred_flags) & XDP_TCP_HP_NOWIN_BITS) == 0 &&
	       seq == tp->rcv_nxt && READ_ONCE(tp->copied_seq) == tp->rcv_nxt &&
	       between(ack_seq, tp->snd_una, tp->snd_nxt) &&
	       !after(seq + plen, tp->rcv_nxt + tcp_receive_window(tp));
}

__bpf_kfunc_start_defs();

/**
 * bpf_xdp_tcp_lookup - find the established socket an XDP frame belongs to
 * @ctx: the frame
 * @info: where the payload is, filled in on success
 *
 * Returns the socket, with a reference, when the frame is an IPv4 TCP data
 * segment for an established socket of the receiving netns and header
 * prediction says the stack would take it on its fast path; NULL otherwise.
 * The checks are made without the socket lock: bpf_xdp_tcp_consume()
 * repeats them under it.
 */
__bpf_kfunc struct sock *bpf_xdp_tcp_lookup(struct xdp_md *ctx, struct bpf_xdp_tcp_info *info)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct xdp_tcp_hdrs h;
	struct sock *sk;

	if (!xdp->rxq || !xdp->rxq->dev || !xdp_tcp_parse(xdp, &h))
		return NULL;
	sk = __inet_lookup_established(dev_net(xdp->rxq->dev), h.iph->saddr, h.th->source,
				       h.iph->daddr, ntohs(h.th->dest), xdp->rxq->dev->ifindex, 0);
	if (!sk)
		return NULL;
	/*
	 * The established hash also holds request sockets of handshakes in
	 * progress and TIME-WAIT sockets; each has its own way of being put.
	 */
	if (!sk_fullsock(sk)) {
		if (sk->sk_state == TCP_TIME_WAIT)
			inet_twsk_put(inet_twsk(sk));
		else
			reqsk_put(inet_reqsk(sk));
		return NULL;
	}
	if (sk->sk_state != TCP_ESTABLISHED || !xdp_tcp_fast_ok(tcp_sk(sk), h.th, h.payload_len)) {
		sock_put(sk);
		return NULL;
	}
	info->payload_off = (void *)h.th + h.th->doff * 4 - xdp->data;
	info->payload_len = h.payload_len;
	info->seq = ntohl(h.th->seq);
	info->reserved = 0;
	return sk;
}

/**
 * bpf_xdp_tcp_consume - apply an in-order data segment to its connection
 * @sk: the socket from bpf_xdp_tcp_lookup()
 * @ctx: the frame
 * @info: as filled by bpf_xdp_tcp_lookup()
 *
 * Under the socket lock, takes the segment as tcp_rcv_established()'s fast
 * path would, with the payload counted as received and read rather than
 * queued for the application. The program must then drop the frame and is
 * responsible for answering it. Returns 0, or -EAGAIN when the socket is
 * owned by its user or the segment no longer fits the fast path: the frame
 * then belongs to the stack (XDP_PASS). The response must fit the socket's
 * send buffer: -ENOBUFS says it would not.
 */
__bpf_kfunc int bpf_xdp_tcp_consume(struct sock *sk, struct xdp_md *ctx,
				    struct bpf_xdp_tcp_info *info)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct {
		struct sk_buff skb;
		u8 hdr[64] __aligned(8);
		struct skb_shared_info shinfo;
	} fake;
	struct sk_buff *skb = &fake.skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct xdp_tcp_hdrs h;
	const struct tcphdr *th;
	u32 hlen, seq, end_seq;
	bool ts_progress = false;
	int err = -EAGAIN;
	s32 delta = 0;

	if (!xdp_tcp_parse(xdp, &h))
		return -EINVAL;
	th = h.th;
	hlen = th->doff * 4;
	seq = ntohl(th->seq);
	end_seq = seq + h.payload_len;

	memset(&fake, 0, sizeof(fake));
	memcpy(fake.hdr, th, hlen);
	skb->head = fake.hdr;
	skb->data = fake.hdr + hlen;
	skb->end = offsetof(typeof(fake), shinfo) - offsetof(typeof(fake), hdr);
	skb->tail = hlen;
	skb->len = h.payload_len;
	skb->truesize = SKB_TRUESIZE(h.payload_len + hlen);
	skb_reset_transport_header(skb);
	skb->transport_header = 0;
	skb->protocol = htons(ETH_P_IP);
	TCP_SKB_CB(skb)->seq = seq;
	TCP_SKB_CB(skb)->end_seq = end_seq;
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->tcp_flags = tcp_flags_ntohs(th);
	TCP_SKB_CB(skb)->ip_dsfield = ipv4_get_dsfield(h.iph);
	TCP_SKB_CB(skb)->sacked = 0;

	bh_lock_sock_nested(sk);
	if (sock_owned_by_user(sk) || sk->sk_state != TCP_ESTABLISHED)
		goto out;
	tcp_mstamp_refresh_inline(tp);
	tp->rx_opt.saw_tstamp = 0;
	tp->rx_opt.accecn = 0;
	if (!xdp_tcp_fast_ok(tp, th, h.payload_len))
		goto out;
	if (tp->tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
		if (!tcp_parse_aligned_timestamp(tp, th))
			goto out;
		delta = tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent;
		if (delta < 0)
			goto out;
	}
	/* The answer has to fit, since the segment cannot be handed back later. */
	if (!sk_stream_memory_free(sk)) {
		err = -ENOBUFS;
		goto out;
	}

	if (tp->tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED &&
	    tp->rcv_nxt == tp->rcv_wup)
		ts_progress = tcp_xdp_replace_ts_recent(tp, delta);
	tcp_rcv_rtt_measure_ts(sk, skb);
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);
	tcp_ecn_received_counters(sk, skb, h.payload_len);

	/* Received and read by the program, so nothing is queued. */
	tcp_rcv_nxt_update(tp, end_seq);
	WRITE_ONCE(tp->copied_seq, end_seq);
	tcp_event_data_recv(sk, skb);

	if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una ||
	    (tcp_flag_word(th) & XDP_TCP_HP_BITS) != tp->pred_flags) {
		/* The slow-path flag makes tcp_ack() take a window change. */
		tcp_xdp_ack(sk, skb, ts_progress);
		if (!inet_csk_ack_scheduled(sk))
			goto done;
	} else {
		tcp_update_wl(tp, seq);
	}
	__tcp_ack_snd_check(sk, 0);
done:
	err = 0;
out:
	bh_unlock_sock(sk);
	return err;
}

/* Queue a response on the write queue and push it. The caller holds the socket lock. */
static int xdp_tcp_queue_response(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now, size_goal, len = skb->len;

	if (!((1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))) {
		__kfree_skb(skb);
		return -ENOTCONN;
	}
	if (tcp_write_queue_empty(sk))
		sk_forced_mem_schedule(sk, skb->truesize);
	else if (!sk_stream_memory_free(sk) || !sk_wmem_schedule(sk, skb->truesize)) {
		__kfree_skb(skb);
		return -EAGAIN;
	}
	mss_now = tcp_send_mss(sk, &size_goal, 0);
	/*
	 * The anchor shares its storage with the skb's dst pointer, so it is
	 * set only on a queued skb, which TCP cleans before freeing.
	 */
	TCP_SKB_CB(skb)->sacked = 0;
	INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
	tcp_skb_entail(sk, skb);
	TCP_SKB_CB(skb)->end_seq += len;
	WRITE_ONCE(tp->write_seq, tp->write_seq + len);
	tcp_push(sk, 0, mss_now, TCP_NAGLE_PUSH, size_goal);
	return len;
}

/**
 * bpf_xdp_tcp_send - send data on an established socket from BPF
 * @sk: the socket
 * @buf__arena: the data, in arena memory
 * @len: bytes to send, at most 64 KiB
 * @aux: the calling program (implicit)
 *
 * Copies the data into a new segment on the write queue and pushes it, as
 * a sendmsg() of the owner would, from BH context. Returns @len, or -EAGAIN
 * when the socket is held by its user or the write queue has no room for
 * the data: the program keeps the data and tries again later, the request
 * having been consumed already. Other errors are final.
 */
__bpf_kfunc int bpf_xdp_tcp_send(struct sock *sk, void *buf__arena, u32 len,
				 struct bpf_prog_aux *aux)
{
	u64 start = bpf_arena_get_kern_vm_start(aux->arena), addr = (u64)(long)buf__arena;
	struct sk_buff *skb;
	void *p;
	int err;

	if (!len || len > SZ_64K)
		return -EINVAL;
	if (!aux->arena || addr < start || addr + len > start + SZ_4G)
		return -EFAULT;
	for (p = buf__arena; p < buf__arena + len; p += PAGE_SIZE - offset_in_page(p))
		if (!vmalloc_to_page(p))
			return -EFAULT;

	skb = alloc_skb_fclone(MAX_TCP_HEADER + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
	skb_reserve(skb, MAX_TCP_HEADER);
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb_put_data(skb, buf__arena, len);

	bh_lock_sock_nested(sk);
	if (sock_owned_by_user(sk)) {
		__kfree_skb(skb);
		err = -EAGAIN;
	} else {
		err = xdp_tcp_queue_response(sk, skb);
	}
	bh_unlock_sock(sk);
	return err;
}

/**
 * bpf_xdp_tcp_release - drop the reference bpf_xdp_tcp_lookup() took
 * @sk: the socket
 */
__bpf_kfunc void bpf_xdp_tcp_release(struct sock *sk)
{
	sock_put(sk);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_xdp_tcp_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdp_tcp_lookup, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_xdp_tcp_consume)
BTF_ID_FLAGS(func, bpf_xdp_tcp_send, KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_xdp_tcp_release, KF_RELEASE)
BTF_KFUNCS_END(bpf_xdp_tcp_kfunc_ids)

static const struct btf_kfunc_id_set bpf_xdp_tcp_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_xdp_tcp_kfunc_ids,
};

static int __init bpf_xdp_tcp_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_xdp_tcp_kfunc_set);
}
late_initcall(bpf_xdp_tcp_kfunc_init);
