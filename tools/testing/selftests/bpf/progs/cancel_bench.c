// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bench_bpf_timing.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct node {
	__u64 v;
};

extern void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

__u32 timeouts;

/*
 * Each iteration acquires a reference, passes a cancellation point holding it
 * and releases it. The site is a may_goto whose timeout path only counts, so
 * that the verifier sees the reference released on every path and the
 * compiler keeps the instruction; a timeout cancels the program instead.
 * Loaded with BPF_F_TEST_SPILL_REFS, the reference is kept in a unique slot
 * across the site: a store after the acquisition and a clear before the
 * release are the cost measured against the plain load.
 */
#define HOLD_ACROSS_SITE()						\
	({								\
		if (!can_loop)						\
			timeouts++;					\
	})

SEC("syscall")
int bench_ringbuf(void *ctx)
{
	return BENCH_BPF_LOOP(({
		void *p = bpf_ringbuf_reserve(&ringbuf, 8, 0);

		if (p) {
			HOLD_ACROSS_SITE();
			bpf_ringbuf_discard(p, 0);
		}
		0;
	}), ({}));
}

SEC("syscall")
int bench_obj(void *ctx)
{
	return BENCH_BPF_LOOP(({
		struct node *n = bpf_obj_new_impl(bpf_core_type_id_local(struct node), NULL);

		if (n) {
			HOLD_ACROSS_SITE();
			bpf_obj_drop_impl(n, NULL);
		}
		0;
	}), ({}));
}

char _license[] SEC("license") = "GPL";
