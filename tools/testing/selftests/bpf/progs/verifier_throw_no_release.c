// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * [WIP] With BPF_F_THROW_NO_RELEASE bpf_throw may leave the program while it
 * holds a lock, IRQs or preemption disabled, the RCU read lock or references.
 * Nothing releases them at run time, so the programs are only loaded, never
 * run. Each one has a twin without the flag that is still refused.
 */

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

struct foo {
	int x;
};

private(A) struct bpf_spin_lock lock;
private(B) struct bpf_res_spin_lock res_lock;

static __always_inline void irq_off_then_throw(void)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	bpf_throw(0);
	bpf_local_irq_restore(&flags);
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int throw_with_irqs_off(void *ctx)
{
	irq_off_then_throw();
	return 0;
}

SEC("?tc")
__failure __msg("bpf_throw cannot be used inside bpf_local_irq_save-ed region")
int throw_with_irqs_off_refused(void *ctx)
{
	irq_off_then_throw();
	return 0;
}

static __always_inline void spin_lock_then_throw(void)
{
	bpf_spin_lock(&lock);
	bpf_throw(0);
	bpf_spin_unlock(&lock);
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int throw_with_spin_lock(void *ctx)
{
	spin_lock_then_throw();
	return 0;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int throw_with_spin_lock_refused(void *ctx)
{
	spin_lock_then_throw();
	return 0;
}

static __always_inline void res_spin_lock_then_throw(void)
{
	if (bpf_res_spin_lock(&res_lock))
		return;
	bpf_throw(0);
	bpf_res_spin_unlock(&res_lock);
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int throw_with_res_spin_lock(void *ctx)
{
	res_spin_lock_then_throw();
	return 0;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int throw_with_res_spin_lock_refused(void *ctx)
{
	res_spin_lock_then_throw();
	return 0;
}

static __always_inline void rcu_lock_then_throw(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	bpf_rcu_read_unlock();
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int throw_with_rcu_read_lock(void *ctx)
{
	rcu_lock_then_throw();
	return 0;
}

SEC("?tc")
__failure __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region")
int throw_with_rcu_read_lock_refused(void *ctx)
{
	rcu_lock_then_throw();
	return 0;
}

static __always_inline void preempt_off_then_throw(void)
{
	bpf_preempt_disable();
	bpf_throw(0);
	bpf_preempt_enable();
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int throw_with_preemption_off(void *ctx)
{
	preempt_off_then_throw();
	return 0;
}

SEC("?tc")
__failure __msg("bpf_throw cannot be used inside bpf_preempt_disable-ed region")
int throw_with_preemption_off_refused(void *ctx)
{
	preempt_off_then_throw();
	return 0;
}

static __always_inline void acquire_then_throw(void)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return;
	bpf_throw(0);
	bpf_obj_drop(f);
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int throw_with_reference(void *ctx)
{
	acquire_then_throw();
	return 0;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int throw_with_reference_refused(void *ctx)
{
	acquire_then_throw();
	return 0;
}

/* Like std::terminate() */
static __noinline void terminate_like(void)
{
	bpf_throw(0);
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int static_terminate_with_spin_lock(void *ctx)
{
	bpf_spin_lock(&lock);
	terminate_like();
	bpf_spin_unlock(&lock);
	return 0;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int static_terminate_with_spin_lock_refused(void *ctx)
{
	bpf_spin_lock(&lock);
	terminate_like();
	bpf_spin_unlock(&lock);
	return 0;
}

/* Doesn't return: the exit after bpf_throw is dead */
__noinline int global_terminate(void)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int global_terminate_with_irqs_off(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	global_terminate();
	bpf_local_irq_restore(&flags);
	return 0;
}

SEC("?tc")
__failure __msg("bpf_throw cannot be used inside bpf_local_irq_save-ed region")
int global_terminate_with_irqs_off_refused(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	global_terminate();
	bpf_local_irq_restore(&flags);
	return 0;
}

__noinline int global_may_throw(struct __sk_buff *ctx)
{
	if (ctx->len)
		bpf_throw(0);
	return 0;
}

/* The reference is dropped on the path where the callee returns */
SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__success
int global_may_throw_with_reference(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	global_may_throw(ctx);
	bpf_obj_drop(f);
	return 0;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int global_may_throw_with_reference_refused(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	global_may_throw(ctx);
	bpf_obj_drop(f);
	return 0;
}

/*
 * The flag only concerns what is held at a throw. The callee of a global call
 * is verified on its own, so the call is still refused under a lock.
 */
SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__failure __msg("global function calls are not allowed while holding a lock")
int global_terminate_with_spin_lock_refused(void *ctx)
{
	bpf_spin_lock(&lock);
	global_terminate();
	bpf_spin_unlock(&lock);
	return 0;
}

static int throwing_loop_cb(u32 i, void *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__flag(BPF_F_THROW_NO_RELEASE)
__failure __msg("cannot be called from callback subprog")
int throw_from_callback_refused(void *ctx)
{
	bpf_loop(1, throwing_loop_cb, NULL, 0);
	return 0;
}

/* The cookie is the return value of the program, which fentry has to be 0 */
SEC("?fentry/bpf_check")
__flag(BPF_F_THROW_NO_RELEASE)
__failure __msg("At program exit the register R1 has smin=1 smax=1 should")
int throw_cookie_out_of_range_refused(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_throw(1);
	bpf_rcu_read_unlock();
	return 0;
}

char _license[] SEC("license") = "GPL";
