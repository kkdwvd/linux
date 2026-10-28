// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A socket cast to its struct by a helper carries the reference of the
 * socket a lookup acquired: a site reached with the cast pointer live
 * releases the socket from it.
 */
SEC("tc")
__description("frame_desc: a throw with a socket cast to tcp_sock live")
__success
int sock_cast_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	struct tcp_sock *tp;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		bpf_sk_release(sk);
		return 0;
	}
	if (skb->len > 100)
		bpf_throw(0);
	bpf_sk_release((struct bpf_sock *)tp);
	return 1;
}

/* A throw reads every register and stack slot: the socket is live at it. */
SEC("tc")
__description("frame_desc: a socket read by nothing but the throw")
__success
int sock_dead_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	bpf_throw(0);
	return 1;
}

static __noinline int throw_unconditionally(void)
{
	bpf_throw(0);
	return 0;
}

/*
 * The callee's throw is unconditional, so the caller never reads the socket
 * again and no live location of its frame holds it at the call: the socket
 * is listed from the unique slot of its acquisition, which the statistics
 * count.
 */
SEC("tc")
__description("frame_desc: a socket held in no live location of the caller of a throw")
__success __log_level(5)
__msg("frame descriptors:{{.*}} slots 1 spills")
int sock_dead_in_caller(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

static __noinline struct bpf_sock *lookup_in_subprog(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};

	return bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
}

/*
 * The socket was acquired by a subprog that has returned, so no slot can
 * hold it either: the throw leaks it, and the program is rejected.
 */
SEC("tc")
__description("frame_desc: a socket of a returned subprog held in no live location at a throw")
__failure __msg("is held at no live location and was acquired in a subprog that returned")
int sock_dead_from_subprog(struct __sk_buff *skb)
{
	struct bpf_sock *sk;

	sk = lookup_in_subprog(skb);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

char _license[] SEC("license") = "GPL";
