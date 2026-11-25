// SPDX-License-Identifier: GPL-2.0
/*
 * A syscall program, which may sleep, parks coroutine frames for the XDP program that is bound
 * to it. See prog_tests/coro_park.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "coro_park.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
	struct bpf_coro_syscall __kptr *sys;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

struct work_elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct work_elem);
} works SEC(".maps");

/* user space writes 1: the callback of the bpf_wq lets go of the frame */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} go SEC(".maps");

__u64 resumed, destroyed;
/* the callback of the bpf_wq has the frame; it has put it back */
__u64 holds, held;
int op;

static __noinline __used void destroy_counts(void *frame)
{
	destroyed += ((__u64 *)frame)[2];
	bpf_coro_frame_free(frame);
}

static __noinline __used void resume_counts(void *frame)
{
	resumed += ((__u64 *)frame)[2];
	bpf_coro_frame_free(frame);
}

/*
 * The callback of a bpf_wq is code of the program that may sleep: it runs in a read section of
 * RCU Tasks Trace, and with no reference to the program once the bpf_wq is gone. It takes the
 * parked frame out of its slot and holds it until user space says go, or for five seconds.
 */
static int wq_holds(void *map, int *key, void *value)
{
	__u64 start = bpf_ktime_get_ns(), *gop;
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;
	bool stop = false;
	int i, j;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return 0;
	holds = 1;
	bpf_for(i, 0, 1000) {
		bpf_for(j, 0, 1000000) {
			gop = bpf_map_lookup_elem(&go, &idx);
			if ((gop && *gop) || bpf_ktime_get_ns() - start > 5000000000ULL) {
				stop = true;
				break;
			}
		}
		if (stop)
			break;
	}
	coro = bpf_kptr_xchg(&s->xdp, coro);
	if (coro)
		bpf_coro_drop_xdp(coro);
	held = 1;
	return 0;
}

static __always_inline int start_wq(void)
{
	struct work_elem init = {}, *w;
	__u32 idx = 0;

	bpf_map_update_elem(&works, &idx, &init, 0);
	w = bpf_map_lookup_elem(&works, &idx);
	if (!w)
		return 4;
	if (bpf_wq_init(&w->wq, &works, 0))
		return 5;
	if (bpf_wq_set_callback(&w->wq, wq_holds, 0))
		return 6;
	return bpf_wq_start(&w->wq, 0) ? 7 : 0;
}

/* A frame for a syscall program, which this one is: it resumes it itself */
static __always_inline int park_sys(__u64 arg)
{
	struct bpf_coro_syscall *coro;
	struct slot *s;
	__u32 idx = 0;
	__u64 *f;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	f = bpf_coro_frame_alloc(24, NULL);
	if (!f)
		return 2;
	f[0] = (__u64)resume_counts;
	f[1] = (__u64)destroy_counts;
	f[2] = arg;
	coro = bpf_kptr_xchg(&s->sys, bpf_coro_park_syscall(f));
	if (coro)
		bpf_coro_drop_syscall(coro);
	return 0;
}

static __always_inline int resume_sys(void)
{
	struct bpf_coro_syscall *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	coro = bpf_kptr_xchg(&s->sys, NULL);
	if (!coro)
		return 2;
	bpf_rcu_read_lock();
	((void (*)(void *))((void **)coro)[0])(coro);
	bpf_rcu_read_unlock();
	return 0;
}

static __always_inline int park(void *resume, __u64 arg)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;
	__u64 *f;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	f = bpf_coro_frame_alloc(24, NULL);
	if (!f)
		return 2;
	f[0] = (__u64)resume;
	f[1] = (__u64)destroy_counts;
	f[2] = arg;
	coro = bpf_kptr_xchg(&s->xdp, bpf_coro_park_xdp(f));
	if (coro)
		bpf_coro_drop_xdp(coro);
	return 0;
}

SEC("syscall")
int sys_owner(void *ctx)
{
	switch (op) {
	case SYS_PARK:
		return park(resume_counts, 7);
	case SYS_PARK_SYS:
		return park_sys(100);
	case SYS_RESUME_SYS:
		return resume_sys();
	case SYS_WQ:
		return start_wq();
	}
	return 3;
}

/* The XDP program that is bound to it resumes what it parked */
SEC("xdp")
int xdp_resumer(struct xdp_md *ctx)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return XDP_ABORTED;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return XDP_DROP;
	((void (*)(void *))((void **)coro)[0])(coro);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
