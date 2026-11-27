// SPDX-License-Identifier: GPL-2.0
/*
 * Sending a frame a program keeps. The XDP program turns a UDP datagram for
 * its port around in place, takes the frame, and has it sent out of the device
 * it arrived on with bpf_xdp_frame_xmit(): in a later invocation, from a kptr
 * field, or by a syscall program from process context, which finds the frames
 * in their fields. In the invocation that took the frame the driver still
 * hands the buffer over, and the call is refused.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

#define NR_SLOTS	8
#define ETH_ALEN	6
#define ETH_P_IP	0x0800

enum {
	MODE_TAKEN,	/* try to send in the invocation that took the frame */
	MODE_KEPT,	/* keep the frame, send the one kept before it */
	MODE_STASH,	/* keep the frames for the syscall program */
};

struct slot {
	struct xdp_frame __kptr *frame;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SLOTS);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

__u32 mode;
__u16 port;		/* host order; a datagram for the next one is counted and dropped */
__u64 xmit_flags;
__u32 xmit_first, xmit_nr, xmit_irqs_off;
__u64 stolen, steal_failed, stashed, synced, sent, send_failed;
__u32 steal_cpu, xmit_cpu;
int last_err;

static void note(int err)
{
	if (err) {
		send_failed++;
		last_err = err;
	} else {
		sent++;
	}
}

/*
 * Swap the addresses of a datagram for the port: both checksums stay what they
 * were. Returns 1 for one, 2 for a datagram for the next port, 0 for the rest.
 */
static int turn_around(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u8 mac[ETH_ALEN];
	__be32 addr;
	__be16 p;

	if ((void *)(udp + 1) > data_end)
		return 0;
	if (eth->h_proto != bpf_htons(ETH_P_IP) || ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
		return 0;
	if (udp->dest == bpf_htons(port + 1))
		return 2;
	if (udp->dest != bpf_htons(port))
		return 0;
	__builtin_memcpy(mac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, mac, ETH_ALEN);
	addr = ip->daddr;
	ip->daddr = ip->saddr;
	ip->saddr = addr;
	p = udp->dest;
	udp->dest = udp->source;
	udp->source = p;
	return 1;
}

static int stash(struct xdp_frame *f, __u32 idx)
{
	struct slot *s = bpf_map_lookup_elem(&slots, &idx);

	if (!s) {
		bpf_xdp_frame_release(f);
		return -1;
	}
	f = bpf_kptr_xchg(&s->frame, f);
	if (f)
		bpf_xdp_frame_release(f);
	return 0;
}

SEC("xdp")
int xdp_frame_echo(struct xdp_md *ctx)
{
	struct xdp_frame *f, *old;
	struct slot *s;
	__u32 zero = 0;

	switch (turn_around(ctx)) {
	case 0:
		return XDP_PASS;
	case 2:
		/*
		 * The driver is done with every frame that arrived before this one: it has
		 * dropped its reference to those the program took.
		 */
		synced++;
		return XDP_DROP;
	}
	f = bpf_xdp_frame_steal(ctx);
	if (!f) {
		steal_failed++;
		return XDP_DROP;
	}
	stolen++;
	steal_cpu = bpf_get_smp_processor_id();
	switch (mode) {
	case MODE_TAKEN:
		/* The driver still refers to it: refused, and the driver gives it back. */
		note(bpf_xdp_frame_xmit(f, xmit_flags));
		break;
	case MODE_KEPT:
		s = bpf_map_lookup_elem(&slots, &zero);
		if (!s) {
			bpf_xdp_frame_release(f);
			break;
		}
		old = bpf_kptr_xchg(&s->frame, f);
		/* The program's reference is the last one: sent here. */
		if (old)
			note(bpf_xdp_frame_xmit(old, xmit_flags));
		break;
	default:
		/* counted once the frame is in its field */
		if (!stash(f, stashed % NR_SLOTS))
			stashed++;
		break;
	}
	return XDP_CONSUME;
}

/* The other end of the pair: a program there has the device take XDP frames. */
SEC("xdp")
int xdp_frame_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/*
 * Send what the XDP program left in @xmit_nr fields from @xmit_first on, from
 * process context, or try to with IRQs off, where no driver can be entered.
 */
SEC("syscall")
int xdp_frame_xmit_stashed(void *ctx)
{
	unsigned long flags;
	__u32 i;

	xmit_cpu = bpf_get_smp_processor_id();
	bpf_for(i, 0, NR_SLOTS) {
		struct xdp_frame *f;
		struct slot *s;
		__u32 idx = i;
		int err;

		if (i < xmit_first || i - xmit_first >= xmit_nr)
			continue;
		s = bpf_map_lookup_elem(&slots, &idx);
		if (!s)
			break;
		f = bpf_kptr_xchg(&s->frame, NULL);
		if (!f)
			continue;
		if (xmit_irqs_off) {
			bpf_local_irq_save(&flags);
			err = bpf_xdp_frame_xmit(f, xmit_flags);
			bpf_local_irq_restore(&flags);
		} else {
			err = bpf_xdp_frame_xmit(f, xmit_flags);
		}
		note(err);
	}
	return 0;
}

/*
 * A live test run has a page pool of its own, which the run asks to go when it
 * ends, in the thread that ran it: what the pool misses then are the frames
 * that the run left with the program. The pool looks again every second until
 * it misses none.
 */
__u32 pool_tid;
__u32 pools_gone;
__s32 pool_inflight;
__u64 pool_ptr;

SEC("tp_btf/page_pool_release")
int BPF_PROG(pool_release, const struct page_pool *pool, s32 inflight)
{
	if (pool_tid && (__u32)bpf_get_current_pid_tgid() == pool_tid) {
		pools_gone++;
		pool_ptr = (__u64)pool;
	} else if ((__u64)pool != pool_ptr) {
		return 0;
	}
	pool_inflight = inflight;
	return 0;
}

char _license[] SEC("license") = "GPL";
