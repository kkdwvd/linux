// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int runs;
__u8 ulp_name;

/*
 * Loaded without CAP_BPF but with CAP_PERFMON, so the program is not in
 * kallsyms, yet bpf_skc_to_tcp_sock() hands it a pointer whose fields are
 * read with PROBE_MEM loads. icsk_ulp_ops is NULL on a plain TCP socket, so
 * the load of name[0] goes through a user address and must read zero.
 */
SEC("socket")
int probe_mem_fault_unpriv(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	struct tcp_sock *tp;

	if (!sk)
		return skb->len;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return skb->len;
	ulp_name = tp->inet_conn.icsk_ulp_ops->name[0];
	runs++;
	return skb->len;
}
