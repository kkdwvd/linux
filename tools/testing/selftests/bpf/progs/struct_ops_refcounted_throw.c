// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

extern void bpf_task_release(struct task_struct *p) __ksym;

/* clang makes no BTF for a kfunc that only asm calls, and libbpf needs it to link the prog */
void __kfunc_btf_root(void)
{
	bpf_task_release(NULL);
	bpf_throw(0);
}

/*
 * The kernel holds a reference for the argument, and a load from the context gets its handle.
 * The prog throws with the handle in r6, which nothing reads behind bpf_throw(): the pad of
 * the prog releases the reference from there, see "Handles" in liveness.c.
 */
SEC("struct_ops/test_refcounted")
__description("struct_ops: a reference of an argument is released when the prog throws")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("exit")
__xlated("*(u64 *)(r10 -{{[0-9]+}}) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -{{[0-9]+}})")
__xlated("exit")
__naked void refcounted_throw(void)
{
	asm volatile (
		"r6 = *(u64 *)(r1 + 8);"
		"r7 = *(u64 *)(r1 + 0);"
		"if r7 != 1 goto 1f;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
	"1:"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_task_release),
		  __imm(bpf_throw)
		: __clobber_all
	);
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_refcounted_throw = {
	.test_refcounted = (void *)refcounted_throw,
};
