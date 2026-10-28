// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

SEC(".data.A") __hidden __aligned(8) struct bpf_spin_lock frame_lock;
SEC(".data.B") __hidden __aligned(8) struct bpf_res_spin_lock frame_irq_lock;

static __noinline int bounded_spin(int n)
{
	int i = 0;

	while (i < n && can_loop)
		i++;
	return i;
}

/* The shared callee owns no lock on either path. */
SEC("tc")
__description("frame_desc: caller-owned global lock stays out of a shared callee")
__success __retval(3)
int global_lock_owned_by_caller(struct __sk_buff *skb)
{
	int r;

	if (skb->len > 100) {
		bpf_spin_lock(&frame_lock);
		r = bounded_spin(3);
		bpf_spin_unlock(&frame_lock);
	} else {
		r = bounded_spin(3);
	}
	return r;
}

static __noinline int acquire_global_lock(int n)
{
	bpf_spin_lock(&frame_lock);
	return n;
}

SEC("tc")
__description("frame_desc: a returned lock belongs to the caller")
__success __retval(3)
int global_lock_transferred_on_return(struct __sk_buff *skb)
{
	int r;

	if (skb->len > 100) {
		r = acquire_global_lock(3);
		r = bounded_spin(r);
		bpf_spin_unlock(&frame_lock);
	} else {
		r = bounded_spin(3);
	}
	return r;
}

static __noinline int init_caller_iter(struct bpf_iter_num *it)
{
	bpf_iter_num_new(it, 0, 3);
	return bounded_spin(3);
}

SEC("tc")
__description("frame_desc: callee initializes a caller-owned iterator")
__success __retval(3)
int iter_storage_owned_by_caller(void *ctx)
{
	struct bpf_iter_num it;
	int r;

	r = init_caller_iter(&it);
	bpf_iter_num_destroy(&it);
	return r;
}

static __noinline int save_caller_irqs(unsigned long *flags)
{
	bpf_local_irq_save(flags);
	return bounded_spin(3);
}

SEC("tc")
__description("frame_desc: callee saves irq flags in the caller's frame")
__success __retval(3)
int irq_storage_owned_by_caller(void *ctx)
{
	unsigned long flags;
	int r;

	r = save_caller_irqs(&flags);
	bpf_local_irq_restore(&flags);
	return r;
}

static __noinline int lock_with_caller_irqs(unsigned long *flags)
{
	if (bpf_res_spin_lock_irqsave(&frame_irq_lock, flags))
		return -1;
	return bounded_spin(3);
}

SEC("tc")
__description("frame_desc: irqsave lock shares the flags' owning frame")
__success __retval(3)
int irq_lock_storage_owned_by_caller(void *ctx)
{
	unsigned long flags;
	int r;

	r = lock_with_caller_irqs(&flags);
	if (r >= 0)
		bpf_res_spin_unlock_irqrestore(&frame_irq_lock, &flags);
	return r;
}

static __noinline int move_rcu_section(int move)
{
	if (move) {
		bpf_rcu_read_unlock();
		bpf_rcu_read_lock();
	}
	return bounded_spin(3);
}

SEC("tc")
__description("frame_desc: equal RCU totals do not hide different frame owners")
__failure __msg("holds different locks or sections on another path")
int rcu_owners_differ(struct __sk_buff *skb)
{
	int r;

	bpf_rcu_read_lock();
	r = move_rcu_section(skb->len > 100);
	bpf_rcu_read_unlock();
	return r;
}

static __noinline int move_preempt_section(int move)
{
	if (move) {
		bpf_preempt_enable();
		bpf_preempt_disable();
	}
	return bounded_spin(3);
}

SEC("tc")
__description("frame_desc: equal preempt totals do not hide different frame owners")
__failure __msg("holds different locks or sections on another path")
int preempt_owners_differ(struct __sk_buff *skb)
{
	int r;

	bpf_preempt_disable();
	r = move_preempt_section(skb->len > 100);
	bpf_preempt_enable();
	return r;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} callback_ringbuf SEC(".maps");

volatile __u32 callback_loops = 1;
volatile __u64 callback_flags;

static int init_caller_dynptr_cb(__u32 index, void *data)
{
	struct bpf_dynptr *ptr = data;

	bpf_ringbuf_reserve_dynptr(&callback_ringbuf, 16, 0, ptr);
	bounded_spin(3);
	bpf_ringbuf_discard_dynptr(ptr, 0);
	return 0;
}

/*
 * The helper can return without calling the callback. Its caller descriptor
 * cannot describe both uninitialized storage and the callback's reservation.
 */
SEC("tc")
__description("frame_desc: callback cannot hide newly owned caller storage")
__failure __msg("frame_desc:")
int callback_changes_caller_dynptr(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_loop(callback_loops, init_caller_dynptr_cb, &ptr, callback_flags);
	return 0;
}

static int leave_caller_rcu_cb(__u32 index, void *data)
{
	bpf_rcu_read_unlock();
	bounded_spin(3);
	bpf_rcu_read_lock();
	return 0;
}

SEC("tc")
__description("frame_desc: callback cannot hide changed caller sections")
__failure __msg("holds different locks or sections on another path")
int callback_changes_caller_rcu(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_loop(callback_loops, leave_caller_rcu_cb, NULL, callback_flags);
	bpf_rcu_read_unlock();
	return 0;
}

char _license[] SEC("license") = "GPL";
