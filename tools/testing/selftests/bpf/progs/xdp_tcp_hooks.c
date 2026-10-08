// SPDX-License-Identifier: GPL-2.0
/*
 * Observers on the way out of the host, for the XDP TCP tests: netfilter's
 * LOCAL_OUT hook, the cgroup egress hook and TC egress. Each counts the TCP
 * segments sent from the test's server port, so that a test can tell which
 * hooks a served connection's segments pass and which they do not.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_kfuncs.h"

#define NF_ACCEPT	1
#define ETH_HLEN	14
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD

__u16 port;	/* the server's port, host order; set by the test */
__u64 nf_segs, cgroup_segs, tcx_segs;

/* Count the segment if it is TCP from @port; the IP header is @l3 bytes in. */
static __always_inline void count(struct __sk_buff *skb, __u32 l3, __be16 proto, __u64 *counter)
{
	struct bpf_dynptr ptr;
	struct tcphdr *th;
	__u8 buf[40];
	__u32 l4 = l3;

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
		return;
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = bpf_dynptr_slice(&ptr, l3, buf, sizeof(*iph));

		if (!iph || iph->protocol != IPPROTO_TCP)
			return;
		l4 += iph->ihl * 4;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = bpf_dynptr_slice(&ptr, l3, buf, sizeof(*ip6h));

		if (!ip6h || ip6h->nexthdr != IPPROTO_TCP)
			return;
		l4 += sizeof(*ip6h);
	} else {
		return;
	}
	th = bpf_dynptr_slice(&ptr, l4, buf, sizeof(*th));
	if (th && th->source == bpf_htons(port))
		__sync_fetch_and_add(counter, 1);
}

/* LOCAL_OUT, IPv4 or IPv6 as attached: the packet starts at the IP header. */
SEC("netfilter")
int nf_count(struct bpf_nf_ctx *ctx)
{
	struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;

	count(skb, 0, ctx->skb->protocol, &nf_segs);
	return NF_ACCEPT;
}

/* The cgroup hook sees the packet from its IP header too. */
SEC("cgroup_skb/egress")
int cgroup_count(struct __sk_buff *skb)
{
	count(skb, 0, skb->protocol, &cgroup_segs);
	return 1;
}

/* TC egress runs after the link-layer header has been put on. */
SEC("tcx/egress")
int tcx_count(struct __sk_buff *skb)
{
	count(skb, ETH_HLEN, skb->protocol, &tcx_segs);
	return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
