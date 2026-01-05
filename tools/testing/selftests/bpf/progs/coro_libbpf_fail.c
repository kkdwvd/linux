// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * Ambiguous stack offset forces conservative spill-all across suspend.
 * With a 256-byte heap window, this is expected to fail in libbpf.
 */
SEC("coro/raw_tp")
__description("coro ambiguous stack offset spill-all")
__failure
__naked void coro_stack_ambiguous(void)
{
	asm volatile (
	"call %[bpf_get_smp_processor_id];"
	"r3 = r0;"
	"r2 = r10;"
	"r2 += r3;"
	"*(u64 *)(r2 - 8) = r1;"
	"call %[bpf_get_prandom_u32];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id),
	  __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
