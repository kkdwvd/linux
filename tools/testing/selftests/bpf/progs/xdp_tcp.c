// SPDX-License-Identifier: GPL-2.0
/*
 * A request/response service on established TCP connections, served from
 * XDP: every in-order data segment the fast path accepts is answered with a
 * copy of its payload, or with reply_len bytes the test placed in the arena.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

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
#define HDRS_MAX	128	/* Ethernet, IPv6 and a TCP header with options */

char __arena_global reply[REPLY_MAX];

/* Knobs set by the test. */
int decline;		/* give every segment to the stack after a successful lookup */
int reply_len;		/* 0: echo the request; otherwise send this much of the arena */

/* What happened. */
__u64 lookups, consumed, sent, sent_bytes, consume_errs, send_errs;
int last_consume_err, last_send_err;
__u32 last_seq, last_len;

extern struct sock *bpf_xdp_tcp_lookup(struct xdp_md *ctx, struct bpf_xdp_tcp_info *info) __ksym;
extern int bpf_xdp_tcp_consume(struct sock *sk, struct xdp_md *ctx,
			       struct bpf_xdp_tcp_info *info) __ksym;
extern int bpf_xdp_tcp_send(struct sock *sk, void *buf, __u32 len) __ksym;
extern void bpf_xdp_tcp_release(struct sock *sk) __ksym;

SEC("xdp")
int xdp_tcp_echo(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;
	struct bpf_xdp_tcp_info info = {};
	__u32 len, off, i;
	struct sock *sk;
	int err;

	sk = bpf_xdp_tcp_lookup(ctx, &info);
	if (!sk)
		return XDP_PASS;
	lookups++;
	/* The verifier knows nothing about what the kfunc wrote; bound it once. */
	off = info.payload_off;
	if (decline || off > HDRS_MAX)
		goto pass;

	err = bpf_xdp_tcp_consume(sk, ctx, &info);
	if (err) {
		consume_errs++;
		last_consume_err = err;
		goto pass;
	}
	consumed++;
	last_seq = info.seq;
	last_len = info.payload_len;

	if (reply_len) {
		len = reply_len > REPLY_MAX ? REPLY_MAX : reply_len;
	} else {
		len = info.payload_len > REPLY_MAX ? REPLY_MAX : info.payload_len;
		bpf_for(i, 0, len) {
			char *p;

			if (i >= REPLY_MAX)
				break;
			p = data + off + i;
			if (p + 1 > data_end)
				break;
			reply[i] = *p;
		}
	}
	err = bpf_xdp_tcp_send(sk, (void *)reply, len);
	if (err < 0) {
		send_errs++;
		last_send_err = err;
	} else {
		sent++;
		sent_bytes += err;
	}
	bpf_xdp_tcp_release(sk);
	return XDP_DROP;
pass:
	bpf_xdp_tcp_release(sk);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
