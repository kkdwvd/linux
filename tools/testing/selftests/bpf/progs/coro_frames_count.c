// SPDX-License-Identifier: GPL-2.0
/*
 * What the frame cache of one program does: the frames that it takes from the
 * allocator and gives back, and how often an interrupt found a class taken
 * below it. See prog_tests/coro_frames.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "coro_frames.h"

/* the program: its id is gone when it is freed */
__u64 load_time;
/* its cache, from the first frame that it got */
__u64 cache;
/* frames from the allocator: for an allocation that found none, and by the irq_work */
__u64 made, refilled;
/* frames back to it, and bpf_coro_frames_free() of the program is over */
__u64 freed, gone;
/* an allocation and a free that found the class taken below them, by context */
__u64 busy_alloc[NR_CTX], busy_free[NR_CTX];

static __always_inline int context(void)
{
	if (bpf_in_nmi())
		return CTX_NMI;
	if (bpf_in_hardirq())
		return CTX_HARDIRQ;
	return bpf_in_serving_softirq() ? CTX_SOFTIRQ : CTX_TASK;
}

SEC("fexit/bpf_coro_frame_new")
int BPF_PROG(frame_new, struct bpf_prog_aux *aux, unsigned int class,
	     struct bpf_coro_frame_hdr *hdr)
{
	if (aux->load_time != load_time || !hdr)
		return 0;
	cache = (__u64)hdr->cache;
	__sync_fetch_and_add(&made, 1);
	return 0;
}

SEC("fexit/bpf_coro_frame_class_refill")
int BPF_PROG(refill, struct bpf_coro_frame_cache *c, void *class, unsigned int nr, int ret)
{
	if (c->owner->prog->aux->load_time == load_time)
		__sync_fetch_and_add(&refilled, ret);
	return 0;
}

SEC("fentry/bpf_coro_frames_kfree")
int BPF_PROG(kfree_frames, struct bpf_coro_frames *owner, void *frames, unsigned int nr)
{
	if (owner->prog->aux->load_time == load_time)
		__sync_fetch_and_add(&freed, nr);
	return 0;
}

SEC("fexit/bpf_coro_frames_kfree_list")
int BPF_PROG(kfree_list, struct bpf_coro_frames *owner, void *first, int ret)
{
	if (owner->prog->aux->load_time == load_time)
		__sync_fetch_and_add(&freed, ret);
	return 0;
}

SEC("fexit/bpf_coro_frames_free")
int BPF_PROG(frames_free, struct bpf_prog *prog)
{
	if (prog->aux->load_time == load_time)
		gone++;
	return 0;
}

SEC("fentry/bpf_coro_frame_alloc_slow")
int BPF_PROG(alloc_slow, struct bpf_prog_aux *aux, __u64 size, void *class, bool mine)
{
	if (aux->load_time == load_time && !mine)
		__sync_fetch_and_add(&busy_alloc[context()], 1);
	return 0;
}

/* not for want of room: the class was taken */
SEC("fentry/bpf_coro_frame_free_slow")
int BPF_PROG(free_slow, struct bpf_coro_frame_hdr *hdr, struct bpf_coro_frame_class *class)
{
	if (cache && (__u64)hdr->cache == cache && class->nr != class->cap)
		__sync_fetch_and_add(&busy_free[context()], 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
