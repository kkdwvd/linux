// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;
extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

__noinline void *exception_cb_bad_ret_type1(u64 cookie)
{
	return NULL;
}

__noinline void exception_cb_bad_ret_type2(u64 cookie)
{
}

__noinline int exception_cb_bad_arg_0(void)
{
	return 0;
}

__noinline int exception_cb_bad_arg_2(int a, int b)
{
	return 0;
}

__noinline int exception_cb_ok_arg_small(int a)
{
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_ret_type1)
__failure __msg("Only void, scalar, arena pointer, or a struct/union of scalars and arena pointers up to 16 bytes is supported.")
int reject_exception_cb_type_1(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_arg_0)
__failure __msg("exception cb only supports single integer argument")
int reject_exception_cb_type_2(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_arg_2)
__failure __msg("exception cb only supports single integer argument")
int reject_exception_cb_type_3(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_ok_arg_small)
__success
int reject_exception_cb_type_4(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_ret_type2)
__failure __msg("exception cb cannot return void")
int reject_exception_cb_type_5(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

__noinline int throwing_exception_cb(u64 c)
{
	bpf_throw(0);
	return c;
}

__noinline int exception_cb1(u64 c)
{
	return c;
}

__noinline int exception_cb2(u64 c)
{
	return c;
}

static __noinline int static_func(struct __sk_buff *ctx)
{
	return exception_cb1(ctx->tstamp);
}

__noinline int global_func(struct __sk_buff *ctx)
{
	return exception_cb1(ctx->tstamp);
}

SEC("?tc")
__exception_cb(throwing_exception_cb)
__failure __msg("bpf_throw cannot be called from the exception callback")
int reject_throwing_exception_cb(struct __sk_buff *ctx)
{
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb1)
__failure __msg("cannot call exception cb directly")
int reject_exception_cb_call_global_func(struct __sk_buff *ctx)
{
	return global_func(ctx);
}

SEC("?tc")
__exception_cb(exception_cb1)
__failure __msg("cannot call exception cb directly")
int reject_exception_cb_call_static_func(struct __sk_buff *ctx)
{
	return static_func(ctx);
}

SEC("?tc")
__exception_cb(exception_cb1)
__exception_cb(exception_cb2)
__failure __msg("multiple exception callback tags for main subprog")
int reject_multiple_exception_cb(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 16;
}

__noinline int exception_cb_bad_ret(u64 c)
{
	return c;
}

SEC("?fentry/bpf_check")
__exception_cb(exception_cb_bad_ret)
__failure __msg("At program exit the register R0 has unknown scalar value should")
int reject_set_exception_cb_bad_ret1(void *ctx)
{
	return 0;
}

SEC("?fentry/bpf_check")
__failure __msg("At program exit the register R1 has smin=64 smax=64 should")
int reject_set_exception_cb_bad_ret2(void *ctx)
{
	bpf_throw(64);
	return 0;
}

__weak
void foo(void)
{
	bpf_throw(1);
}

SEC("?fentry/bpf_check")
__failure __msg("At program exit the register R1 has smin=1 smax=1 should")
int reject_out_of_range_global_throw(struct __sk_buff *skb)
{
	foo();

	return 0;
}

char _license[] SEC("license") = "GPL";
