// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * Coroutine transform tests cover:
 * - reg-only and stack-only liveness across suspend calls;
 * - mixed reg+stack spills (compact ordering within the heap window);
 * - multiple suspend points with different live sets;
 * - control flow (branches/loops) across suspension;
 * - iterator loops (suspend outside iterator lifetime);
 * - subprog-local suspension handling;
 * - ambiguous stack offsets forcing conservative spill-all (see coro_libbpf_fail).
 */
#define ITER_HELPERS					\
	__imm(bpf_iter_num_new),			\
	__imm(bpf_iter_num_next),			\
	__imm(bpf_iter_num_destroy)

volatile __u8 coro_heap[1024] SEC(".bss") __attribute__((used));

SEC("?raw_tp")
__description("coro iter extern btf")
__success
int coro_iter_btf_externs(const void *ctx)
{
	/* Ensure BTF for iterator kfuncs referenced only from asm. */
	bpf_repeat(0);
	return 0;
}

SEC("coro/raw_tp")
__description("coro simple await/yield")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r7")
__xlated("r5 = *(u64 *)(r10 -8)")
__xlated("*(u64 *)(r0 +8) = r5")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r5 = *(u64 *)(r1 +8)")
__xlated("*(u64 *)(r10 -8) = r5")
__xlated("r7 = *(u64 *)(r1 +0)")
__xlated("...")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r7")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r7 = *(u64 *)(r1 +0)")
__success
__naked void coro_simple(void)
{
	asm volatile (
	"r7 = 42;"
	"*(u64 *)(r10 - 8) = r7;"
	"call %[bpf_get_prandom_u32];"
	"r8 = *(u64 *)(r10 - 8);"
	"r7 += r8;"
	"call %[bpf_get_current_pid_tgid];"
	"r0 = r7;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_get_current_pid_tgid)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro branch across await")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r7")
__xlated("r5 = *(u64 *)(r10 -8)")
__xlated("*(u64 *)(r0 +8) = r5")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r5 = *(u64 *)(r1 +8)")
__xlated("*(u64 *)(r10 -8) = r5")
__xlated("r7 = *(u64 *)(r1 +0)")
__success
__naked void coro_branch(void)
{
	asm volatile (
	"call %[bpf_get_smp_processor_id];"
	"r7 = r0;"
	"if r7 == 0 goto l0_%=;"
	"*(u64 *)(r10 - 8) = r7;"
	"l0_%=:"
	"call %[bpf_get_prandom_u32];"
	"if r7 == 0 goto l1_%=;"
	"r8 = *(u64 *)(r10 - 8);"
	"r7 += r8;"
	"l1_%=:"
	"r0 = r7;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro looped stack slot")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("r5 = *(u64 *)(r10 -16)")
__xlated("*(u64 *)(r0 +0) = r5")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r5 = *(u64 *)(r1 +0)")
__xlated("*(u64 *)(r10 -16) = r5")
__success
__naked void coro_var_off(void)
{
	asm volatile (
	"r0 = 0;"
	"r2 = 0;"
	"l0_%=:"
	"*(u64 *)(r10 - 160) = r0;"
	"r2 += 1;"
	"if r2 != 20 goto l0_%=;"
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_prandom_u32];"
	"r1 = *(u64 *)(r10 - 16);"
	"r0 = r1;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro reg-only liveness")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r6")
__xlated("*(u64 *)(r0 +8) = r7")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r6 = *(u64 *)(r1 +0)")
__xlated("r7 = *(u64 *)(r1 +8)")
__success
__naked void coro_regs_only(void)
{
	asm volatile (
	"r6 = 1;"
	"r7 = 2;"
	"r8 = 3;"
	"call %[bpf_get_prandom_u32];"
	"r6 += r7;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro stack-only liveness")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("r5 = *(u64 *)(r10 -8)")
__xlated("*(u64 *)(r0 +0) = r5")
__xlated("r5 = *(u64 *)(r10 -16)")
__xlated("*(u64 *)(r0 +8) = r5")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r5 = *(u64 *)(r1 +0)")
__xlated("*(u64 *)(r10 -8) = r5")
__xlated("r5 = *(u64 *)(r1 +8)")
__xlated("*(u64 *)(r10 -16) = r5")
__success
__naked void coro_stack_only(void)
{
	asm volatile (
	"r6 = 11;"
	"*(u64 *)(r10 - 8) = r6;"
	"r6 = 22;"
	"*(u64 *)(r10 - 16) = r6;"
	"call %[bpf_get_prandom_u32];"
	"r6 = *(u64 *)(r10 - 8);"
	"r7 = *(u64 *)(r10 - 16);"
	"r6 += r7;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro mixed reg/stack ordering")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r6")
__xlated("r5 = *(u64 *)(r10 -8)")
__xlated("*(u64 *)(r0 +8) = r5")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r5 = *(u64 *)(r1 +8)")
__xlated("*(u64 *)(r10 -8) = r5")
__xlated("r6 = *(u64 *)(r1 +0)")
__success
__naked void coro_regs_and_stack(void)
{
	asm volatile (
	"r6 = 5;"
	"*(u64 *)(r10 - 8) = r6;"
	"call %[bpf_get_prandom_u32];"
	"r7 = *(u64 *)(r10 - 8);"
	"r6 += r7;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro multi suspend sets")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r6")
__xlated("call unknown")
__xlated("...")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r7")
__xlated("call unknown")
__success
__naked void coro_multi_suspend(void)
{
	asm volatile (
	"r6 = 1;"
	"call %[bpf_get_prandom_u32];"
	"r7 = r6;"
	"r6 = 2;"
	"call %[bpf_get_current_pid_tgid];"
	"r0 = r7;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_get_current_pid_tgid)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro iter loop (suspend after destroy)")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r6")
__xlated("call unknown")
__success
__naked void coro_iter_loop(void)
{
	asm volatile (
	"r6 = 0;"
	"r1 = r10;"
	"r1 += -8;"
	"r2 = 0;"
	"r3 = 3;"
	"call %[bpf_iter_num_new];"
	"l0_%=:"
	"r1 = r10;"
	"r1 += -8;"
	"call %[bpf_iter_num_next];"
	"if r0 == 0 goto l1_%=;"
	"r6 += 1;"
	"goto l0_%=;"
	"l1_%=:"
	"r1 = r10;"
	"r1 += -8;"
	"call %[bpf_iter_num_destroy];"
	"call %[bpf_get_prandom_u32];"
	"r0 = r6;"
	"exit;"
	:
	: ITER_HELPERS,
	  __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("coro/raw_tp")
__description("coro subprog suspend")
__xlated("r0 = r10")
__xlated("r0 += -512")
__xlated("*(u64 *)(r0 +0) = r9")
__xlated("r5 = *(u64 *)(r10 -8)")
__xlated("*(u64 *)(r0 +8) = r5")
__xlated("call unknown")
__xlated("r1 = r10")
__xlated("r1 += -512")
__xlated("r5 = *(u64 *)(r1 +8)")
__xlated("*(u64 *)(r10 -8) = r5")
__xlated("r9 = *(u64 *)(r1 +0)")
__success
__naked void coro_subprog_suspend(void)
{
	asm volatile (
	"call coro_subprog_suspend__1;"
	"r0 = 0;"
	"exit;"
	:
	:
	: __clobber_all);
}

static __naked __noinline __attribute__((used))
void coro_subprog_suspend__1(void)
{
	asm volatile (
	"r9 = 7;"
	"*(u64 *)(r10 - 8) = r9;"
	"call %[bpf_get_prandom_u32];"
	"r8 = *(u64 *)(r10 - 8);"
	"r9 += r8;"
	"r0 = r9;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
