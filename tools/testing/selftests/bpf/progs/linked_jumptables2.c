// SPDX-License-Identifier: GPL-2.0
/*
 * Linked after linked_jumptables1.c: sub2() lands behind sub1() in .text and
 * jt2() behind jt1() in the section of the programs, so the entries of their
 * jump tables, offsets in the section of the function, have to move.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct simple_ctx {
	__u64 x;
};

__u64 ret2;
__u64 sub_ret2;
__u64 some_var2;

#ifdef __BPF_FEATURE_GOTOX
/* code that the verifier replaces by a different number of insns */
static __always_inline void adjust_insns(__u64 x)
{
	some_var2 ^= x + bpf_jiffies64();
}

/* a subprog in .text, with a jump table of its own */
static __noinline __u64 sub2(__u64 x)
{
	switch (x) {
	case 0:
		adjust_insns(x + 2);
		return 302;
	case 1:
		adjust_insns(x + 4);
		return 312;
	case 2:
		adjust_insns(x + 6);
		return 322;
	case 3:
		adjust_insns(x + 8);
		return 332;
	case 4:
		adjust_insns(x + 10);
		return 342;
	case 5:
		adjust_insns(x + 12);
		return 352;
	case 6:
		adjust_insns(x + 14);
		return 362;
	case 7:
		adjust_insns(x + 16);
		return 372;
	case 8:
		adjust_insns(x + 18);
		return 382;
	case 9:
		adjust_insns(x + 20);
		return 392;
	case 10:
		adjust_insns(x + 22);
		return 402;
	case 11:
		adjust_insns(x + 24);
		return 412;
	case 12:
		adjust_insns(x + 26);
		return 422;
	case 13:
		adjust_insns(x + 28);
		return 432;
	case 14:
		adjust_insns(x + 30);
		return 442;
	case 15:
		adjust_insns(x + 32);
		return 452;
	default:
		adjust_insns(x + 177);
		return 1302;
	}
}

SEC("syscall")
int jt2(struct simple_ctx *ctx)
{
	sub_ret2 = sub2(ctx->x);
	switch (ctx->x) {
	case 0:
		adjust_insns(ctx->x + 2);
		ret2 = 2;
		break;
	case 1:
		adjust_insns(ctx->x + 4);
		ret2 = 12;
		break;
	case 2:
		adjust_insns(ctx->x + 6);
		ret2 = 22;
		break;
	case 3:
		adjust_insns(ctx->x + 8);
		ret2 = 32;
		break;
	case 4:
		adjust_insns(ctx->x + 10);
		ret2 = 42;
		break;
	case 5:
		adjust_insns(ctx->x + 12);
		ret2 = 52;
		break;
	case 6:
		adjust_insns(ctx->x + 14);
		ret2 = 62;
		break;
	case 7:
		adjust_insns(ctx->x + 16);
		ret2 = 72;
		break;
	case 8:
		adjust_insns(ctx->x + 18);
		ret2 = 82;
		break;
	case 9:
		adjust_insns(ctx->x + 20);
		ret2 = 92;
		break;
	case 10:
		adjust_insns(ctx->x + 22);
		ret2 = 102;
		break;
	case 11:
		adjust_insns(ctx->x + 24);
		ret2 = 112;
		break;
	case 12:
		adjust_insns(ctx->x + 26);
		ret2 = 122;
		break;
	case 13:
		adjust_insns(ctx->x + 28);
		ret2 = 132;
		break;
	case 14:
		adjust_insns(ctx->x + 30);
		ret2 = 142;
		break;
	case 15:
		adjust_insns(ctx->x + 32);
		ret2 = 152;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret2 = 1002;
		break;
	}
	return 0;
}
#else
SEC("syscall")
int jt2(struct simple_ctx *ctx)
{
	return 0;
}
#endif

char _license[] SEC("license") = "GPL";
