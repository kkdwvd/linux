// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * A loop that only may_goto of the verifier ends and a recursion are limited at run time, see
 * verifier_budget.c. When the time slice is over, or the stack has no room for one more frame,
 * the program is cancelled if no frame on its stack holds anything: every frame leaves through
 * a pad that the verifier generated, nothing of the program runs behind that point, and the main
 * program returns the cancel value of its type.
 *
 * "cancel sites S padded P declined ..." in the stats of the verifier: S sites that a
 * cancellation gets to, P of them have a pad, and the rest declines for the reasons that follow.
 *
 * It takes the JIT of x86-64 or arm64, CAP_BPF and CAP_PERFMON. The loops never end on their own.
 */

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;

/* The frames of a recursion that began, and how many times the code behind a call ran */
unsigned long frames;
unsigned long behind;

/*
 * It calls itself until the stack has no room. Every frame counts itself on the way down. The
 * frames have 128 bytes, so that there are tens of them and not hundreds: the report of the stack
 * check lists them all, and a report that doesn't fit into the stream is dropped.
 */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		"r1 = %[frames] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		"r1 = %[behind] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"exit;"
		:
		: __imm_addr(frames),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The sites: the stack check of dives(), its call of itself, and the call in the main program */
SEC("tc")
__description("cancel: a recursion that is out of stack ends a tc program with TC_ACT_SHOT")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: No room in the stack for a call of a recursive function")
__stderr("...")
__stderr("ERROR: Program was cancelled")
__naked void recursion_tc(void)
{
	asm volatile (
		"call dives;"
		"r1 = %[behind] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(behind)
		: __clobber_all
	);
}

SEC("socket")
__description("cancel: a recursion that is out of stack ends a socket filter with 0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0) __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__stderr("ERROR: No room in the stack for a call of a recursive function")
__stderr("...")
__stderr("ERROR: Program was cancelled")
__naked void recursion_socket(void)
{
	asm volatile (
		"call dives;"
		"r1 = %[behind] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(behind)
		: __clobber_all
	);
}

/*
 * Without a pad may_goto ends a main program with 0 as well. That is TC_ACT_OK, and not what
 * a tc program returns when it is cancelled.
 */
SEC("tc")
__description("cancel: a loop in the main program that is out of time ends it with TC_ACT_SHOT")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT) __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__stderr("ERROR: Timeout detected for may_goto instruction")
__stderr("...")
__stderr("ERROR: Program was cancelled")
__naked void loop_in_main(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long spins(void)
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

/* Without pads may_goto leaves the loop, and the program returns the 7 of spins() */
SEC("socket")
__description("cancel: a loop in a subprog that is out of time ends the program")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0) __log_level(4)
__msg("cancel sites 2 padded 2 declined")
__stderr("ERROR: Timeout detected for may_goto instruction")
__stderr("...")
__stderr("ERROR: Program was cancelled")
__naked void loop_in_subprog(void)
{
	asm volatile (
		"call spins;"
		"exit;"
		::: __clobber_all
	);
}

#define CLOCK_MONOTONIC 1

struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} timers SEC(".maps");

static int timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	dives();
	behind++;
	return 0;
}

/*
 * The kernel enters the callback of a timer like a main program: its pad is the last one to
 * run, tells that the program was cancelled and returns 0. The callback runs when this program
 * has returned, so the runner waits for it and reads the stream and the variables.
 */
SEC("socket")
__description("cancel: a recursion that is out of stack ends the callback of a timer")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
int timer_recursion(void *ctx)
{
	struct elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->timer, timer_cb))
		return 3;
	if (bpf_timer_start(&e->timer, 0, 0))
		return 4;
	return 0;
}

/* The target of the progs in cancel_attach.c */
__naked __noinline __used
unsigned long global_spins(void)
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

/* A global subprog is verified on its own. Its pad is like that of any other subprog. */
SEC("tc")
__description("cancel: a loop in a global subprog has a pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 2 padded 2 declined")
__naked void calls_global_spins(void)
{
	asm volatile (
		"call global_spins;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The call is not the first insn: a call that is its own target is what libbpf leaves in place
 * of a call that it could not resolve, and the verifier takes no such call.
 */
__naked __noinline __used
static unsigned long calls_itself(void)
{
	asm volatile (
		"r1 = 0;"
		"call calls_itself;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * What the verifier adds, in the order of the program: cancel_goto behind a call names the pad
 * of the call. The pad of a subprog leaves with cancel_exit, also the one of its stack check,
 * which is in place behind the report of the check. It tells the pad of its call in r2 what the
 * frame released for its caller: nothing here. The pad of the main program tells that the
 * program was cancelled and returns the value of the type.
 */
SEC("tc")
__description("cancel: cancel_goto behind the calls, cancel_exit in the pads of a subprog")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(TC_ACT_SHOT)
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+2")
__xlated("r0 = 1")
__xlated("exit")
__xlated("call unknown")
__xlated("r0 = 2")
__xlated("exit")
__xlated("...")
__xlated("r2 = 0")
__xlated("r0 = 0{{$}}")
__xlated("cancel_exit")
__xlated("r1 = 0")
__xlated("call pc-{{[0-9]+}}")
__xlated("cancel_goto pc+1")
__xlated("exit")
__xlated("r2 = 0")
__xlated("r0 = 0")
__xlated("cancel_exit")
__naked void insns_of_pads(void)
{
	asm volatile (
		"call calls_itself;"
		"r0 = 1;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * A subprog that cannot be cancelled whatever its frames hold has no pads, and neither has what
 * it calls: a callback that a helper calls, an extension, a program that is loaded without
 * CAP_PERFMON. Its sites decline. They do what they do without pads: may_goto leaves the loop,
 * the stack check returns 0 and the callers go on. The programs below return what they return at
 * their end, which is never the cancel value.
 *
 * A frame that can be cancelled and holds something at a site is another matter. Its pad releases
 * that, or the program is not loaded: see cancel_locks.c and cancel_refs.c.
 */

static int spins_in_callback(__u32 i, void *ctx)
{
	volatile unsigned long *go = &one;

	while (*go)
		;
	return 0;
}

/* The helper that calls a callback has no pad: it would go on with what the callback left */
SEC("socket")
__description("cancel: a loop in a callback of bpf_loop() declines")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 1 padded 0 declined refs 0 section 0 cond 0 callback 1")
int loop_in_callback(void *ctx)
{
	bpf_loop(1, spins_in_callback, NULL, zero);
	return 1;
}

static int calls_dives(__u32 i, void *ctx)
{
	dives();
	return 0;
}

/* The callback cannot be cancelled, so its call of dives() has no pad */
SEC("socket")
__description("cancel: a recursion that a callback of bpf_loop() calls declines")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(1) __log_level(4)
__msg("cancel sites 3 padded 0 declined refs 0 section 0 cond 0 callback 1 caller 2")
int recursion_below_callback(void *ctx)
{
	bpf_loop(1, calls_dives, NULL, zero);
	return 1;
}

static int loop_cb(__u32 i, void *ctx);

static __noinline int calls_loop(int x)
{
	bpf_loop(1, loop_cb, NULL, zero);
	return 0;
}

static __noinline int loop_cb(__u32 i, void *ctx)
{
	return calls_loop(i);
}

/*
 * calls_loop() -> bpf_loop() -> loop_cb() -> calls_loop(): both check the stack. The callback
 * declines, and calls_loop() does because the callback calls it. The call in the main program
 * could have a pad, but nothing comes out of calls_loop() for it.
 */
SEC("socket")
__description("cancel: a recursion through a callback of bpf_loop() declines")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(1) __log_level(4)
__msg("cancel sites 3 padded 0 declined refs 0 section 0 cond 0 callback 2 caller 1")
int recursion_through_callback(void *ctx)
{
	calls_loop(0);
	return 1;
}

/*
 * cancel_exit finds the pad of its call through the symbols of the program, and what is behind
 * the call runs speculatively on what the pads left: CAP_BPF alone is not enough. may_goto ends
 * the main program like it does without pads.
 */
SEC("socket")
__description("cancel: a program that is loaded without CAP_PERFMON declines")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success_unpriv __caps_unpriv(CAP_BPF) __log_level(4)
__msg_unpriv("cancel sites 1 padded 0 declined refs 0 section 0 cond 0 callback 0 caller 0 retval 0 jit 1")
__naked void loop_without_perfmon(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
