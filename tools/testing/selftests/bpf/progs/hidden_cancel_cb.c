// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

static __noinline int triple_plus_one(int x)
{
	return x * 3 + 1;
}

/* The call is its only site: nothing cancels it, so it needs no callback. */
SEC("tc")
int only_calls(struct __sk_buff *skb)
{
	return triple_plus_one(skb->len) & 1;
}

/* The may_goto of the loop cancels it: it needs the callback. */
SEC("tc")
int loop_and_call(struct __sk_buff *skb)
{
	__u32 i;

	for (i = 0; i < skb->len; i++)
		cond_break;
	return triple_plus_one(i) & 1;
}
