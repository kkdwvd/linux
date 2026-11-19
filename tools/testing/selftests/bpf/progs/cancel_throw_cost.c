// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * Progs that throw from many places, as a C++ prog does whose every allocation can end in
 * std::terminate(). They are for veristat: what it takes to verify a prog depends on what
 * bpf_throw() keeps live for the pads, see "Handles" in liveness.c. The states of two paths
 * that differ in what bpf_throw() reads stay apart on the whole way to it.
 *
 * die() does not return, like std::terminate(): the compiler puts nothing behind the call, so
 * nothing is live there but what bpf_throw() reads.
 */

#define TC_ACT_OK	0

extern void bpf_local_irq_save(unsigned long *) __weak __ksym;
extern void bpf_local_irq_restore(unsigned long *) __weak __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct val {
	u64 a;
	u64 b;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, struct val);
} vals SEC(".maps");

/* The verifier doesn't know what is in there */
unsigned long sel;
unsigned long seed;

static __always_inline __attribute__((noreturn)) void die(u64 c)
{
	bpf_throw(c);
	__builtin_unreachable();
}

/* An object on the stack of the main prog that the subprogs work on, like 'this' */
struct obj {
	u64 sum;
	u64 cnt;
	struct val *last;
	u64 scratch[4];
};

static __always_inline struct val *get(u32 key, u64 c)
{
	struct val *v;

	key &= 15;
	v = bpf_map_lookup_elem(&vals, &key);
	if (!v)
		die(c);
	return v;
}

/*
 * A step leaves a pointer or a number in what it used, which is dead behind it: the value of
 * a map on one path, a number on the other.
 */
#define LEAF(n)								\
static __noinline u64 leaf##n(struct obj *o, u64 x)			\
{									\
	struct val *v;							\
	u64 r = x;							\
									\
	if (x & (1UL << n)) {						\
		v = get(x + n, n);					\
		r += bpf_get_prandom_u32();				\
		o->last = v;						\
		o->scratch[n & 3] = v->a + r;				\
	} else {							\
		r ^= bpf_get_prandom_u32();				\
		o->scratch[n & 3] = n;					\
		o->cnt++;						\
	}								\
	if (o->cnt > 1000)						\
		die(100 + n);						\
	o->sum += r;							\
	return r;							\
}

LEAF(0) LEAF(1) LEAF(2) LEAF(3) LEAF(4) LEAF(5) LEAF(6) LEAF(7)

#define MID(n, a, b, c)							\
static __noinline u64 mid##n(struct obj *o, u64 x)			\
{									\
	u64 r;								\
									\
	r = leaf##a(o, x);						\
	if (!r)								\
		die(200 + n);						\
	r += leaf##b(o, x >> 1);					\
	if (o->sum == seed)						\
		die(300 + n);						\
	r += leaf##c(o, r);						\
	return r;							\
}

MID(0, 0, 1, 2) MID(1, 3, 4, 5) MID(2, 6, 7, 0) MID(3, 1, 3, 5)

static __always_inline int walk(struct obj *o)
{
	u64 r = sel;

	r += mid0(o, r);
	r += mid1(o, r);
	r += mid2(o, r);
	r += mid3(o, r);
	if (r == seed)
		die(1);
	return r & 1;
}

/* Nothing is held */
SEC("tc")
__description("cancel throw cost: many throws, nothing is held")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
int cost_none(struct __sk_buff *ctx)
{
	struct obj o = {};

	return walk(&o) ? TC_ACT_OK : TC_ACT_OK;
}

/* IRQ flags are held: an IrqGuard */
SEC("tc")
__description("cancel throw cost: many throws, IRQ flags are held")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
int cost_irq(struct __sk_buff *ctx)
{
	unsigned long flags;
	struct obj o = {};
	int ret;

	bpf_local_irq_save(&flags);
	ret = walk(&o);
	bpf_local_irq_restore(&flags);
	return ret ? TC_ACT_OK : TC_ACT_OK;
}

/* A reference is held by the main prog, which keeps its handle over the calls */
SEC("tc")
__description("cancel throw cost: many throws, a reference is held")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
int cost_task(struct __sk_buff *ctx)
{
	struct task_struct *task;
	struct obj o = {};
	int ret;

	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return TC_ACT_OK;
	ret = walk(&o);
	bpf_task_release(task);
	return ret ? TC_ACT_OK : TC_ACT_OK;
}

/*
 * Twelve locals, each a pointer on one path and a number on the other, and none is read
 * again. States that differ in such a local have no join, see bpf_states_join(). If the
 * throw at the end kept them live, there would be 2^12 states to tell apart, more than an
 * insn may have. No local may have a handle: the map has no lock in its value. So all are
 * dead where the paths meet.
 */
#define LOCAL(n)							\
	"r1 = %[sel] ll;"						\
	"r1 = *(u64 *)(r1 + 0);"					\
	"r1 &= " #n ";"							\
	"if r1 == 0 goto 1f;"						\
	"r1 = %[vals] ll;"						\
	"r2 = r10;"							\
	"r2 += -4;"							\
	"call %[bpf_map_lookup_elem];"					\
	"if r0 == 0 goto 9f;"						\
	"goto 2f;"							\
"1:"									\
	"r0 = " #n ";"							\
"2:"

SEC("tc")
__description("cancel throw cost: locals that are dead at bpf_throw() are not told apart")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__naked void cost_locals(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u32 *)(r10 - 4) = r0;"
		LOCAL(1)    "*(u64 *)(r10 - 16) = r0;"
		LOCAL(2)    "*(u64 *)(r10 - 24) = r0;"
		LOCAL(4)    "*(u64 *)(r10 - 32) = r0;"
		LOCAL(8)    "*(u64 *)(r10 - 40) = r0;"
		LOCAL(16)   "*(u64 *)(r10 - 48) = r0;"
		LOCAL(32)   "*(u64 *)(r10 - 56) = r0;"
		LOCAL(64)   "*(u64 *)(r10 - 64) = r0;"
		LOCAL(128)  "*(u64 *)(r10 - 72) = r0;"
		LOCAL(256)  "r6 = r0;"
		LOCAL(512)  "r7 = r0;"
		LOCAL(1024) "r8 = r0;"
		LOCAL(2048) "r9 = r0;"
		"r1 = %[seed] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 3f;"
	"9:"
		"r1 = 0;"
		"call %[bpf_throw];"
	"3:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm(bpf_throw),
		  __imm_addr(vals),
		  __imm_addr(sel),
		  __imm_addr(seed)
		: __clobber_all
	);
}

/* It reads the stack of its caller through r1, and throws */
__naked __noinline __used
static unsigned long cost_throws(void)
{
	asm volatile (
		"r2 = *(u64 *)(r1 + 0);"
		"r1 = 0;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_throw)
		: __clobber_all
	);
}

/*
 * The same twelve locals, all in the stack, and the throw is in a callee that has a pointer to
 * that stack. Its bpf_throw() reads the slots of the frame below that may have a handle, and
 * there are none.
 */
SEC("tc")
__description("cancel throw cost: locals of the frame below that are dead at bpf_throw()")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__naked void cost_locals_below(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 8) = r0;"
		LOCAL(1)    "*(u64 *)(r10 - 16) = r0;"
		LOCAL(2)    "*(u64 *)(r10 - 24) = r0;"
		LOCAL(4)    "*(u64 *)(r10 - 32) = r0;"
		LOCAL(8)    "*(u64 *)(r10 - 40) = r0;"
		LOCAL(16)   "*(u64 *)(r10 - 48) = r0;"
		LOCAL(32)   "*(u64 *)(r10 - 56) = r0;"
		LOCAL(64)   "*(u64 *)(r10 - 64) = r0;"
		LOCAL(128)  "*(u64 *)(r10 - 72) = r0;"
		LOCAL(256)  "*(u64 *)(r10 - 80) = r0;"
		LOCAL(512)  "*(u64 *)(r10 - 88) = r0;"
		LOCAL(1024) "*(u64 *)(r10 - 96) = r0;"
		LOCAL(2048) "*(u64 *)(r10 - 104) = r0;"
		"r1 = %[seed] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 3f;"
	"9:"
		"r1 = r10;"
		"r1 += -8;"
		"call cost_throws;"
	"3:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm_addr(vals),
		  __imm_addr(sel),
		  __imm_addr(seed)
		: __clobber_all
	);
}

char _license[] SEC("license") = "GPL";
