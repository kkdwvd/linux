// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

/*
 * A may_goto in a program a user without CAP_BPF may load. Such a program
 * may have no loop, so the may_goto stands on its own: still a site, as the
 * slow path of a timed may_goto runs at the first one of an invocation.
 */
SEC("socket")
int may_goto_once(struct __sk_buff *skb)
{
	__u32 n = skb->len;

	asm volatile goto("may_goto %l[out]" : : : : out);
	n += 1;
out:
	return n & 1;
}
