// SPDX-License-Identifier: GPL-2.0
/*
 * A request/response service on established TCP connections, served from
 * XDP: every data segment received in order is answered with a copy of its
 * payload, or with reply_len bytes the test placed in the arena.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_experimental.h"
#include "bpf_arena_common.h"
#include "bpf_xdp_tcp.h"

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

char __arena_global reply[REPLY_MAX];

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

SEC("xdp")
int xdp_tcp_echo(struct xdp_md *ctx)
{
	struct bpf_xdp_tcp_sock sock = {};
	struct bpf_dynptr payload;
	int action = XDP_PASS;

	if (serve_port && !to_port(ctx, serve_port))
		return XDP_PASS;
	if (decline)
		return inspect(ctx);
	if (!bpf_xdp_tcp_sock_recv(ctx, &sock, &payload))
		return XDP_PASS;
	switch (bpf_xdp_tcp_sock_status(&sock)) {
	case BPF_XDP_TCP_RECEIVED:
		if (bpf_xdp_tcp_sock_len(&sock)) {
			consumed++;
			respond(&sock, &payload);
		}
		action = XDP_DROP;
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
