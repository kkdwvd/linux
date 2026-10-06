// SPDX-License-Identifier: GPL-2.0
/*
 * A request/response service on established TCP connections, served from
 * XDP: every data segment received in order is answered with a copy of its
 * payload, or with reply_len bytes the test placed in the arena. In hold mode
 * the segments that arrive out of order, or while the socket is owned, are
 * kept in per-connection state keyed by the socket cookie and delivered once
 * their turn comes, from XDP or from a timer.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_experimental.h"
#include "bpf_arena_common.h"
#include "bpf_xdp_tcp.h"
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 16); /* pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

#define REPLY_MAX	32768

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC	1
#endif

char __arena_global reply[REPLY_MAX];

/* The test owns the socket from a syscall program while segments arrive. */
int hold_fd;
struct sock_hold_test hold_state;

SEC("syscall")
int xdp_tcp_hold_sock(void *ctx)
{
	return bpf_kfunc_hold_sock(hold_fd, &hold_state);
}

/* Knobs set by the test. */
int decline;		/* inspect every segment and leave it to the stack */
int reply_len;		/* 0: echo the request; otherwise send this much of the arena */
__u16 serve_port;	/* when set, only connections to this port are served */

#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD
#endif

/*
 * The choice of connections is made before anything is received: a receive
 * serves the connection it finds, so a service checks its port first.
 */
static __always_inline bool to_port(struct xdp_md *ctx, __u16 port)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct tcphdr *th;

	if ((void *)(eth + 1) > end)
		return false;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if ((void *)(iph + 1) > end || iph->protocol != IPPROTO_TCP)
			return false;
		th = (void *)iph + iph->ihl * 4;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);

		if ((void *)(ip6h + 1) > end || ip6h->nexthdr != IPPROTO_TCP)
			return false;
		th = (void *)(ip6h + 1);
	} else {
		return false;
	}
	if ((void *)(th + 1) > end)
		return false;
	return th->dest == bpf_htons(port);
}

/* What happened. */
__u64 lookups, consumed, sent, sent_bytes, consume_errs, send_errs;
int last_consume_err, last_send_err;
__u32 last_len;

static __always_inline void respond(struct bpf_xdp_tcp_sock *sock, struct bpf_dynptr *payload)
{
	__u32 len, i;
	int err;

	last_len = bpf_xdp_tcp_sock_len(sock);
	if (reply_len) {
		len = reply_len > REPLY_MAX ? REPLY_MAX : reply_len;
	} else {
		len = last_len > REPLY_MAX ? REPLY_MAX : last_len;
		bpf_for(i, 0, len) {
			char scratch, *p;

			if (i >= REPLY_MAX)
				break;
			p = bpf_dynptr_slice(payload, i, &scratch, sizeof(scratch));
			if (!p)
				break;
			reply[i] = *p;
		}
	}
	err = bpf_xdp_tcp_sock_send(sock, reply, len);
	if (err < 0) {
		send_errs++;
		last_send_err = err;
	} else {
		sent++;
		sent_bytes += err;
	}
}

/* The split path: look, then leave the segment to the stack. */
static __always_inline int inspect(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_sock sock = {};
	struct bpf_dynptr payload;

	if (!bpf_xdp_tcp_sock_lookup(ctx, &sock))
		return XDP_PASS;
	lookups++;
	bpf_xdp_tcp_sock_payload(&sock, ctx, &payload);
	bpf_xdp_tcp_sock_release(&sock);
	return XDP_PASS;
}

/*
 * Hold mode: the stream is copied into the arena as it is received, in
 * order, and echoed if asked. Out-of-order and busy segments are held.
 */
int hold_mode, stream_echo, stream_prune;
__u32 stream_bytes, stream_fin, stream_pruned;
__u64 stream_callbacks, stream_errors;
int stream_last_error;
char __arena_global stream_data[4096];

struct conn_state {
	struct bpf_xdp_tcp_conn conn;
	struct bpf_timer timer;
	__u32 started;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct conn_state);
} conns SEC(".maps");

static __noinline void deliver(struct bpf_xdp_tcp_sock *sock, struct bpf_dynptr *payload, __u32 len)
{
	__u32 offset = stream_bytes;
	int j;

	if (len > 1600 || offset > sizeof(stream_data) - 1600) {
		stream_errors++;
		stream_last_error = -E2BIG;
		return;
	}
	bpf_for(j, 0, len) {
		char byte, *p;

		if (j >= 1600)
			break;
		p = bpf_dynptr_slice(payload, j, &byte, sizeof(byte));
		if (!p)
			break;
		stream_data[offset + j] = *p;
		reply[j] = *p;
	}
	stream_bytes += len;
	consumed++;
	if (stream_echo) {
		int err = bpf_xdp_tcp_sock_send(sock, reply, len);

		if (err < 0) {
			send_errs++;
			last_send_err = err;
		} else {
			sent++;
			sent_bytes += err;
		}
	}
}

/* Held segments whose turn has come, or everything held when the test asks for a prune. */
static __noinline void drain(struct bpf_xdp_tcp_sock *sock, struct conn_state *st)
{
	int i;

	if (stream_prune) {
		if (!bpf_xdp_tcp_sock_purge(sock, &st->conn)) {
			stream_prune = 0;
			stream_pruned++;
		}
		return;
	}
	bpf_for(i, 0, BPF_XDP_TCP_HOLD_MAX) {
		struct bpf_dynptr payload;
		int len;

		len = bpf_xdp_tcp_sock_next(sock, &st->conn, &payload);
		if (len < 0) {
			stream_errors++;
			stream_last_error = len;
			break;
		}
		if (len > 0)
			deliver(sock, &payload, len);
		if (bpf_xdp_tcp_sock_eof(sock))
			stream_fin = 1;
		if (!len)
			break;
	}
}

/*
 * Retries and reaping: every millisecond while frames are held, in case the
 * socket was busy, and every second otherwise, to notice a closed connection.
 */
static int conn_timer(void *map, __u64 *key, struct conn_state *st)
{
	struct bpf_xdp_tcp_sock sock = {};

	stream_callbacks++;
	if (!bpf_xdp_tcp_sock_resume(&st->conn, &sock))
		return 0;
	if (bpf_xdp_tcp_sock_closed(&sock)) {
		bpf_xdp_tcp_sock_release(&sock);
		bpf_xdp_tcp_conn_destroy(&st->conn);
		bpf_map_delete_elem(&conns, key);
		return 0;
	}
	drain(&sock, st);
	bpf_xdp_tcp_sock_release(&sock);
	bpf_timer_start(&st->timer, st->conn.nr_held ? 1000000 : 1000000000ULL, 0);
	return 0;
}

static __always_inline struct conn_state *conn_state(struct bpf_xdp_tcp_sock *sock)
{
	__u64 key = bpf_xdp_tcp_sock_cookie(sock);
	struct conn_state *st;

	st = bpf_map_lookup_elem(&conns, &key);
	if (!st) {
		struct conn_state zero = {};

		bpf_map_update_elem(&conns, &key, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&conns, &key);
		if (!st)
			return NULL;
	}
	if (!st->started && !bpf_timer_init(&st->timer, &conns, CLOCK_MONOTONIC) &&
	    !bpf_timer_set_callback(&st->timer, conn_timer)) {
		st->started = 1;
		bpf_timer_start(&st->timer, 1000000000ULL, 0);
	}
	return st;
}

static __always_inline int hold_input(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_sock sock = {};
	struct bpf_dynptr payload;
	struct conn_state *st;
	int action = XDP_PASS;

	if (!bpf_xdp_tcp_sock_recv(ctx, &sock, &payload))
		return XDP_PASS;
	st = conn_state(&sock);
	if (!st) {
		stream_errors++;
		goto out;
	}
	switch (bpf_xdp_tcp_sock_status(&sock)) {
	case BPF_XDP_TCP_RECEIVED:
		if (bpf_xdp_tcp_sock_len(&sock))
			deliver(&sock, &payload, bpf_xdp_tcp_sock_len(&sock));
		if (bpf_xdp_tcp_sock_eof(&sock))
			stream_fin = 1;
		if (st->conn.nr_held || stream_prune)
			drain(&sock, st);
		action = XDP_DROP;
		break;
	case BPF_XDP_TCP_OUT_OF_ORDER:
	case BPF_XDP_TCP_BUSY:
		action = bpf_xdp_tcp_sock_hold(ctx, &sock, &st->conn);
		if (action == XDP_CONSUME)
			bpf_timer_start(&st->timer, 1000000, 0);
		break;
	case BPF_XDP_TCP_DUPLICATE:
		action = XDP_DROP;
		break;
	default:
		break;
	}
out:
	bpf_xdp_tcp_sock_release(&sock);
	return action;
}

/*
 * Frame replies: the answer goes out of the request's own buffer. A reply the
 * socket cannot take now is kept, frame and connection reference, and retried
 * from a timer until it goes.
 */
int frame_reply;
__u64 frame_sent, frame_deferred, frame_fallback, frame_errors;
int frame_last_error;

#define FRAME_REPLY_MAX	3072

struct retry_state {
	struct xdp_frame __kptr *frame;
	struct sock __kptr *sk;
	struct bpf_timer timer;
	__u32 off;
	__u32 len;
	__u32 armed;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct retry_state);
} retry SEC(".maps");

static int retry_timer(void *map, __u32 *key, struct retry_state *st)
{
	struct bpf_xdp_tcp_info info = {};
	struct xdp_frame *frame;
	struct sock *sk;

	frame = bpf_kptr_xchg(&st->frame, NULL);
	sk = bpf_kptr_xchg(&st->sk, NULL);
	if (!frame || !sk) {
		if (frame)
			bpf_xdp_frame_release(frame);
		if (sk)
			bpf_xdp_tcp_release(sk);
		return 0;
	}
	frame = bpf_xdp_tcp_send_frame(frame, sk, st->off, st->len, &info);
	if (!frame) {
		frame_sent++;
		bpf_xdp_tcp_release(sk);
		return 0;
	}
	if (info.error == -EAGAIN) {
		frame = bpf_kptr_xchg(&st->frame, frame);
		if (frame)
			bpf_xdp_frame_release(frame);
		sk = bpf_kptr_xchg(&st->sk, sk);
		if (sk)
			bpf_xdp_tcp_release(sk);
		bpf_timer_start(&st->timer, 1000000, 0);
		return 0;
	}
	frame_errors++;
	frame_last_error = info.error;
	bpf_xdp_frame_release(frame);
	bpf_xdp_tcp_release(sk);
	return 0;
}

/* Keep a reply the socket could not take, and the connection, for the timer. */
static __always_inline bool defer_reply(struct bpf_xdp_tcp_sock *sock, struct xdp_frame *frame,
					__u32 off, __u32 len)
{
	struct retry_state *st;
	struct sock *ref;
	__u32 zero = 0;

	st = bpf_map_lookup_elem(&retry, &zero);
	if (!st) {
		bpf_xdp_frame_release(frame);
		return false;
	}
	ref = bpf_xdp_tcp_sock_acquire(sock);
	if (!ref) {
		bpf_xdp_frame_release(frame);
		return false;
	}
	st->off = off;
	st->len = len;
	frame = bpf_kptr_xchg(&st->frame, frame);
	if (frame)
		bpf_xdp_frame_release(frame);
	ref = bpf_kptr_xchg(&st->sk, ref);
	if (ref)
		bpf_xdp_tcp_release(ref);
	if (!st->armed && !bpf_timer_init(&st->timer, &retry, CLOCK_MONOTONIC) &&
	    !bpf_timer_set_callback(&st->timer, retry_timer))
		st->armed = 1;
	bpf_timer_start(&st->timer, 1000000, 0);
	return true;
}

/*
 * Answer out of the request's frame: the echo is already there; a longer
 * reply is the test pattern, written after growing the packet.
 */
static __always_inline int reply_in_frame(struct xdp_md *ctx, struct bpf_xdp_tcp_sock *sock)
{
	__u32 off = bpf_xdp_tcp_sock_offset(sock), len = bpf_xdp_tcp_sock_len(sock);
	struct xdp_frame *frame;
	int i, err;

	if (reply_len) {
		__u32 want = reply_len > FRAME_REPLY_MAX ? FRAME_REPLY_MAX : reply_len;

		if (bpf_xdp_adjust_tail(ctx, (int)want - (int)len)) {
			/* No room in this buffer: the arena has the pattern too. */
			frame_fallback++;
			bpf_xdp_tcp_sock_send(sock, reply, want);
			return XDP_DROP;
		}
		len = want;
		bpf_for(i, 0, (FRAME_REPLY_MAX + 63) / 64) {
			char chunk[64];
			__u32 pos = i * 64, n;
			int j;

			if (pos >= len)
				break;
			bpf_for(j, 0, 64)
				chunk[j] = 'a' + (pos + j) % 26;
			/*
			 * pos < len, so 1 <= len - pos; clamp to the chunk and
			 * restate the bound as arithmetic the verifier tracks.
			 */
			n = len - pos;
			if (n > 64)
				n = 64;
			n = ((n - 1) & 63) + 1;
			if (bpf_xdp_store_bytes(ctx, off + pos, chunk, n))
				break;
		}
	}
	frame = bpf_xdp_tcp_sock_send_frame(ctx, sock, off, len);
	err = bpf_xdp_tcp_sock_error(sock);
	if (!frame) {
		if (err) {
			/* The buffer could not be stolen: nothing to consume, the reply is lost. */
			frame_errors++;
			frame_last_error = err;
			return XDP_DROP;
		}
		frame_sent++;
		return XDP_CONSUME;
	}
	if (err == -EAGAIN) {
		if (defer_reply(sock, frame, off, len))
			frame_deferred++;
		return XDP_CONSUME;
	}
	frame_errors++;
	frame_last_error = err;
	bpf_xdp_frame_release(frame);
	return XDP_CONSUME;
}

/* Deliberately bypass the header to exercise what the kernel enforces. */
int raw_mode;
int raw_no_admission, raw_udp_consume, raw_udp_hold, raw_udp_send;
int raw_udp_reset, raw_udp_dup, raw_udp_acquire, raw_hold, raw_hold_again;
int raw_write, raw_writable_slice, raw_dynptr_data, raw_consume, raw_consume_again;
int raw_rehold, raw_readonly, raw_payload_len;
int raw_listener_acquire, raw_listener_release;

static __always_inline int raw_input(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_info info = {};
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *udp, *lsk;
	struct bpf_dynptr ptr;
	struct xdp_frame *frame;
	struct sock *sk, *ref;
	char byte = 0;

	/* The split lookup leaves the segment untouched for the frame operations below. */
	sk = bpf_xdp_tcp_lookup(ctx, &info);
	if (!sk)
		return XDP_PASS;
	tuple.ipv4.saddr = bpf_htonl(0xc0a84d02);
	tuple.ipv4.daddr = bpf_htonl(0xc0a84d01);
	tuple.ipv4.sport = bpf_htons(40000);
	tuple.ipv4.dport = bpf_htons(7777);
	udp = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (udp) {
		raw_udp_consume = bpf_xdp_tcp_consume((void *)udp, ctx, &info);
		raw_udp_send = bpf_xdp_tcp_send((void *)udp, reply, 1);
		raw_udp_reset = bpf_xdp_tcp_ooo_reset((void *)udp);
		raw_udp_dup = bpf_xdp_tcp_dup((void *)udp, 1, 2);
		bpf_xdp_tcp_ack_pending((void *)udp);
		ref = bpf_xdp_tcp_acquire((void *)udp);
		raw_udp_acquire = ref != NULL;
		if (ref)
			bpf_xdp_tcp_release(ref);
	}
	/*
	 * A tuple with no established socket finds the listener, which the
	 * lookup returns without a reference: it is not a connection to acquire,
	 * and a release of it must not put what was never taken.
	 */
	tuple.ipv4.sport = bpf_htons(40001);
	lsk = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (lsk) {
		ref = bpf_xdp_tcp_acquire((void *)lsk);
		raw_listener_acquire = ref != NULL;
		if (ref)
			bpf_xdp_tcp_release(ref);
		bpf_xdp_tcp_release((void *)lsk);
		raw_listener_release++;
	}
	frame = bpf_xdp_frame_steal(ctx);
	if (!frame) {
		if (udp)
			bpf_sk_release(udp);
		bpf_xdp_tcp_release(sk);
		return XDP_PASS;
	}
	if (udp) {
		raw_udp_hold = bpf_xdp_tcp_hold((void *)udp, frame);
		bpf_sk_release(udp);
	}
	raw_no_admission = bpf_xdp_tcp_consume_frame(sk, frame, &info);
	raw_hold = bpf_xdp_tcp_hold(sk, frame);
	if (raw_hold)
		goto out;
	raw_hold_again = bpf_xdp_tcp_hold(sk, frame);
	bpf_dynptr_from_xdp_frame(frame, 0, &ptr);
	raw_readonly = bpf_dynptr_is_rdonly(&ptr);
	raw_write = bpf_dynptr_write(&ptr, 0, &byte, sizeof(byte), 0);
	raw_writable_slice = bpf_dynptr_slice_rdwr(&ptr, 0, &byte, sizeof(byte)) != NULL;
	raw_dynptr_data = bpf_dynptr_data(&ptr, 0, sizeof(byte)) != NULL;
	raw_consume = bpf_xdp_tcp_consume_frame(sk, frame, &info);
	raw_payload_len = info.payload_len;
	raw_consume_again = bpf_xdp_tcp_consume_frame(sk, frame, &info);
	raw_rehold = bpf_xdp_tcp_hold(sk, frame);
	bpf_xdp_tcp_ack_pending(sk);
out:
	bpf_xdp_frame_release(frame);
	bpf_xdp_tcp_release(sk);
	return XDP_CONSUME;
}

SEC("xdp")
int xdp_tcp_echo(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_sock sock = {};
	struct bpf_dynptr payload;
	int action = XDP_PASS;

	if (raw_mode)
		return raw_input(ctx);
	if (serve_port && !to_port(ctx, serve_port))
		return XDP_PASS;
	if (hold_mode)
		return hold_input(ctx);
	if (decline)
		return inspect(ctx);
	if (!bpf_xdp_tcp_sock_recv(ctx, &sock, &payload))
		return XDP_PASS;
	switch (bpf_xdp_tcp_sock_status(&sock)) {
	case BPF_XDP_TCP_RECEIVED:
		action = XDP_DROP;
		if (bpf_xdp_tcp_sock_len(&sock)) {
			consumed++;
			if (frame_reply)
				action = reply_in_frame(ctx, &sock);
			else
				respond(&sock, &payload);
		}
		break;
	case BPF_XDP_TCP_DUPLICATE:
		action = XDP_DROP;
		break;
	default:
		/* Out of order, busy or the stack's: the stack takes it from here. */
		break;
	}
	bpf_xdp_tcp_sock_release(&sock);
	return action;
}

char _license[] SEC("license") = "GPL";
