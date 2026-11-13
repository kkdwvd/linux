// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* The target is global_spins() in cancel.c, which is cancelled when its loop is out of time */

/* The verifier doesn't know what is in there */
unsigned long one = 1;

int fentry_cnt;

SEC("?fentry/global_spins")
int BPF_PROG(fentry_cancel)
{
	fentry_cnt++;
	return 0;
}

SEC("?fexit/global_spins")
int BPF_PROG(fexit_cancel)
{
	return 0;
}

/*
 * The caller of an extension is the program that it extends, which has no pad for it: the
 * loop is left when it is out of time.
 */
SEC("?freplace/global_spins")
__naked unsigned long freplace_spins(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 7;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
