// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

/*
 * A prog that unwinds, for a load without CAP_PERFMON. Nothing in a landing pad is hardened against
 * a cpu that mispredicts, so the verifier refuses the prog, with or without the mitigations.
 */
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/* BPF_JMP | BPF_JCOND with BPF_UNWIND_GOTO in src_reg, and BPF_JMP | BPF_EXIT with BPF_UNWIND_EXIT */
#define unwind_goto(label) ".8byte ((((" #label " - .) / 8 - 1) & 0xffff) << 16) | 0x10e5;"
#define unwind_exit ".8byte 0x1095;"

__naked __noinline __used
static unsigned long raises(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		::: __clobber_all);
}

SEC("socket")
__naked void catches(void)
{
	asm volatile (
		"call raises;"
		unwind_goto(1f)
		"r0 = 1;"
		"exit;"
	"1:	r0 = 42;"
		"exit;"
		::: __clobber_all);
}

#else

SEC("socket")
int dummy(void *ctx)
{
	return 0;
}

#endif
