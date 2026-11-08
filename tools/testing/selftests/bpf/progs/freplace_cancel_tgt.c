// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* The global function an extension replaces: what it returns, the program returns. */
__noinline int tc_glob(struct __sk_buff *skb)
{
	return skb->len > 1000;
}

SEC("tc")
int tc_main(struct __sk_buff *skb)
{
	return tc_glob(skb);
}
