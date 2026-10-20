// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

struct elem {
	struct bpf_timer t;
	struct bpf_wq w;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

extern int bpf_wq_init(struct bpf_wq *wq, void *p__map, unsigned int flags) __ksym;
extern int bpf_wq_set_callback(struct bpf_wq *wq,
			       int (callback_fn)(void *map, int *key, void *value),
			       unsigned int flags) __ksym;
extern int bpf_wq_start(struct bpf_wq *wq, unsigned int flags) __ksym;

/* How many times the callback ran, and how many times its pad did */
__u64 cb_runs;
__u64 pad_runs;

__naked __noinline __used
static unsigned long always_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/*
 * The callback. What it calls unwinds, and its pad unwinds on with the r0 = 0
 * that the kernel wants from a timer callback. When the kernel called the
 * callback, unwind_exit is exit. When BPF code did, it returns to the pad
 * after the call.
 */
__naked __noinline __used
static int cb(void *map, int *key, void *value)
{
	asm volatile (
		"r1 = %[cb_runs] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"call always_unwinds;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r1 = %[pad_runs] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"r0 = 0;"
		unwind_exit
		:
		: __imm_addr(cb_runs),
		  __imm_addr(pad_runs),
		  __imm_unwind_goto(2),
		  __imm_unwind_exit
	);
}

/* The callback doesn't look at its arguments. The pad returns 2. */
__naked __noinline __used
static unsigned long calls_cb(void)
{
	asm volatile (
		"r1 = 0;"
		"r2 = 0;"
		"r3 = 0;"
		"call cb;"
		unwind_goto(2)
		"r0 = 1;"
		"exit;"
		"r0 = 2;"
		"exit;"
		:
		: __imm_unwind_goto(2)
	);
}

SEC("tc")
int timer_cb_unwinds(void *ctx)
{
	struct elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return 0;
	if (bpf_timer_init(&val->t, &array, 0))
		return 0;
	if (bpf_timer_set_callback(&val->t, (void *)cb))
		return 0;
	if (bpf_timer_start(&val->t, 0, 0))
		return 0;
	return calls_cb();
}

SEC("tc")
int wq_cb_unwinds(void *ctx)
{
	struct elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return 0;
	if (bpf_wq_init(&val->w, &array, 0))
		return 0;
	if (bpf_wq_set_callback(&val->w, cb, 0))
		return 0;
	if (bpf_wq_start(&val->w, 0))
		return 0;
	return calls_cb();
}

char _license[] SEC("license") = "GPL";
