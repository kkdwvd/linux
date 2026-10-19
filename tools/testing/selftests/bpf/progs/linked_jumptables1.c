// SPDX-License-Identifier: GPL-2.0
/*
 * Jump tables of functions that the static linker moves: those of
 * linked_jumptables2.c land behind these in .text and in the section of
 * the programs, so their entries have to move with the code.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Skip the test if the compiler doesn't support indirect jumps. The functions
 * are then dummies, so that the skeleton looks the same.
 */
#ifdef __BPF_FEATURE_GOTOX
__u64 skip SEC(".data") = 0;
#else
__u64 skip = 1;
#endif

struct simple_ctx {
	__u64 x;
};

__u64 ret1;
__u64 sub_ret1;
__u64 some_var1;

#ifdef __BPF_FEATURE_GOTOX
/* code that the verifier replaces by a different number of insns */
static __always_inline void adjust_insns(__u64 x)
{
	some_var1 ^= x + bpf_jiffies64();
}

/* a subprog in .text, with a jump table of its own */
static __noinline __u64 sub1(__u64 x)
{
	switch (x) {
	case 0:
		adjust_insns(x + 1);
		return 301;
	case 1:
		adjust_insns(x + 3);
		return 311;
	case 2:
		adjust_insns(x + 5);
		return 321;
	case 3:
		adjust_insns(x + 7);
		return 331;
	case 4:
		adjust_insns(x + 9);
		return 341;
	case 5:
		adjust_insns(x + 11);
		return 351;
	case 6:
		adjust_insns(x + 13);
		return 361;
	case 7:
		adjust_insns(x + 15);
		return 371;
	case 8:
		adjust_insns(x + 17);
		return 381;
	case 9:
		adjust_insns(x + 19);
		return 391;
	case 10:
		adjust_insns(x + 21);
		return 401;
	case 11:
		adjust_insns(x + 23);
		return 411;
	case 12:
		adjust_insns(x + 25);
		return 421;
	case 13:
		adjust_insns(x + 27);
		return 431;
	case 14:
		adjust_insns(x + 29);
		return 441;
	case 15:
		adjust_insns(x + 31);
		return 451;
	default:
		adjust_insns(x + 177);
		return 1301;
	}
}

SEC("syscall")
int jt1(struct simple_ctx *ctx)
{
	sub_ret1 = sub1(ctx->x);
	switch (ctx->x) {
	case 0:
		adjust_insns(ctx->x + 1);
		ret1 = 1;
		break;
	case 1:
		adjust_insns(ctx->x + 3);
		ret1 = 11;
		break;
	case 2:
		adjust_insns(ctx->x + 5);
		ret1 = 21;
		break;
	case 3:
		adjust_insns(ctx->x + 7);
		ret1 = 31;
		break;
	case 4:
		adjust_insns(ctx->x + 9);
		ret1 = 41;
		break;
	case 5:
		adjust_insns(ctx->x + 11);
		ret1 = 51;
		break;
	case 6:
		adjust_insns(ctx->x + 13);
		ret1 = 61;
		break;
	case 7:
		adjust_insns(ctx->x + 15);
		ret1 = 71;
		break;
	case 8:
		adjust_insns(ctx->x + 17);
		ret1 = 81;
		break;
	case 9:
		adjust_insns(ctx->x + 19);
		ret1 = 91;
		break;
	case 10:
		adjust_insns(ctx->x + 21);
		ret1 = 101;
		break;
	case 11:
		adjust_insns(ctx->x + 23);
		ret1 = 111;
		break;
	case 12:
		adjust_insns(ctx->x + 25);
		ret1 = 121;
		break;
	case 13:
		adjust_insns(ctx->x + 27);
		ret1 = 131;
		break;
	case 14:
		adjust_insns(ctx->x + 29);
		ret1 = 141;
		break;
	case 15:
		adjust_insns(ctx->x + 31);
		ret1 = 151;
		break;
	default:
		adjust_insns(ctx->x + 177);
		ret1 = 1001;
		break;
	}
	return 0;
}
#else
SEC("syscall")
int jt1(struct simple_ctx *ctx)
{
	return 0;
}
#endif

char _license[] SEC("license") = "GPL";
