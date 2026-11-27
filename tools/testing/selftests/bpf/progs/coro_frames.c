// SPDX-License-Identifier: GPL-2.0
/*
 * The frames that a program keeps for its next ones, see "The frame cache" in
 * kernel/bpf/coro.c. One program allocates, parks and frees frames as the test
 * says, on the CPU that the test runs it on, and tells where its frames are.
 * See prog_tests/coro_frames.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "coro_frames.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SLOTS);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_MANY);
	__type(key, __u32);
	__type(value, struct slot);
} many SEC(".maps");

int op, err;
__u32 from, to;
__u64 addr[NR_SLOTS], last, other;
__u64 destroyed, tried, got;

static __noinline __used void destroy_fn(void *frame)
{
	destroyed++;
	bpf_coro_frame_free(frame);
}

/* Does a destroy function get a frame? Not when the kernel calls it for a program that goes. */
static __noinline __used void destroy_allocs(void *frame)
{
	void *f = bpf_coro_frame_alloc(48, NULL);

	tried++;
	if (f) {
		got++;
		bpf_coro_frame_free(f);
	}
	bpf_coro_frame_free(frame);
}

/* Park a new frame in the value of @key, which is free. Evaluates to where the frame is. */
#define PARK(map, key, size, destroy) ({					\
	struct slot *__s = bpf_map_lookup_elem(&(map), &(key));		\
	struct bpf_coro_xdp *__coro;						\
	__u64 *__f, __where = 0;						\
										\
	if (__s) {								\
		__f = bpf_coro_frame_alloc(size, NULL);				\
		if (__f) {							\
			__where = (__u64)__f;					\
			__f[0] = (__u64)(destroy);				\
			__f[1] = (__u64)(destroy);				\
			__f[(size) / 8 - 1] = 0;				\
			__coro = bpf_kptr_xchg(&__s->xdp, bpf_coro_park_xdp(__f)); \
			if (__coro) {						\
				bpf_coro_drop_xdp(__coro);			\
				err = 2;					\
			}							\
		}								\
	}									\
	if (!__where)								\
		err = 1;							\
	__where;								\
})

/* The frame is written from end to end: KASAN has all of it as allocated. */
#define PAIR(size) ({								\
	__u64 *__f = bpf_coro_frame_alloc(size, NULL);				\
										\
	if (__f) {								\
		last = (__u64)__f;						\
		__f[0] = 1;							\
		__f[(size) / 8 - 1] = 2;					\
		bpf_coro_frame_free(__f);					\
	} else {								\
		err = 1;							\
	}									\
})

/*
 * One call for frames of two sizes: the verifier does not tell the kernel their class there,
 * and the kernel finds it.
 */
static __noinline void *any_size(__u64 size)
{
	return bpf_coro_frame_alloc(size, NULL);
}

SEC("xdp")
int frames(struct xdp_md *ctx)
{
	__u32 lo = from, hi = to, key;
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u64 where;
	int i;

	switch (op) {
	case OP_PARK:
		bpf_for(i, lo, hi) {
			key = i;
			where = PARK(slots, key, 48, destroy_fn);
			if (key < NR_SLOTS)
				addr[key] = where;
		}
		break;
	case OP_DESTROY:
		bpf_for(i, lo, hi) {
			key = i;
			s = bpf_map_lookup_elem(&slots, &key);
			if (!s)
				break;
			coro = bpf_kptr_xchg(&s->xdp, NULL);
			if (!coro) {
				err = 3;
				continue;
			}
			((void (*)(void *))((void **)coro)[1])(coro);
		}
		break;
	case OP_PAIR_48:
		PAIR(48);
		break;
	case OP_PAIR_64:
		PAIR(64);
		break;
	case OP_PAIR_200:
		PAIR(200);
		break;
	case OP_PAIR_ANY: {
		__u64 small = 48, large = 200, *f;

		/* the compiler does not know, and makes no copy of the function for each */
		barrier_var(small);
		barrier_var(large);
		f = any_size(small);
		if (f) {
			last = (__u64)f;
			f[5] = 1;
			bpf_coro_frame_free(f);
		} else {
			err = 1;
		}
		f = any_size(large);
		if (f) {
			other = (__u64)f;
			f[24] = 1;
			bpf_coro_frame_free(f);
		} else {
			err = 1;
		}
		break;
	}
	case OP_PARK_ALLOCS:
		key = lo;
		PARK(slots, key, 48, destroy_allocs);
		break;
	case OP_FILL:
		bpf_for(i, lo, hi) {
			key = i;
			if (!PARK(many, key, MANY_SIZE, destroy_fn))
				break;
		}
		break;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
