// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for callx through a number with an arena: the address of a function
 * stored to arena and loaded back, and a destructor called from a header in
 * arena. They are apart from verifier_callx_scalar.c because libbpf binds the
 * arena of an object to every program in it, and a program with an arena may
 * load through a number under BPF_F_ARENA_SCALAR, which the tests of a
 * callee's arguments there must see refused.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* callx and BPF_F_ARENA_SCALAR need a JIT that supports both */
#if defined(__clang__) && (defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64))

#define __callx_scalar __flag(BPF_F_ARENA_SCALAR) __arch_x86_64 __arch_arm64

void *bpf_arena_alloc_pages(void *map, void *addr, __u32 page_cnt, int node_id,
			    __u64 flags) __ksym;

#ifdef __TARGET_ARCH_arm64
#define ARENA_VM_START (1ull << 32)
#else
#define ARENA_VM_START (1ull << 44)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__ulong(map_extra, ARENA_VM_START);
} arena SEC(".maps");

/* BTF FUNC records are not generated for kfuncs referenced from inline assembly */
void __kfunc_btf_root(void)
{
	bpf_arena_alloc_pages(0, 0, 0, 0, 0);
}

/* add3(x) { return x + 3; } */
__naked __noinline __used
static unsigned long add3(void)
{
	asm volatile (
		"r0 = r1;"
		"r0 += 3;"
		"exit;"
	);
}

/* the address of add3() is stored to arena and loaded back */
SEC("syscall")
__description("callx scalar: address of a function in arena")
__callx_scalar
__success __retval(13)
__naked void callx_scalar_arena(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r2 = 0;"
		"r3 = 1;"
		"r4 = -1;"
		"r5 = 0;"
		"call %[bpf_arena_alloc_pages];"
		"r6 = r0;"
		"r0 = 100;"
		"if r6 == 0 goto 1f;"
		"r1 = %[add3] ll;"
		"*(u64 *)(r6 + 8) = r1;"
		"r2 = *(u64 *)(r6 + 8);"
		"r1 = 10;"
		"callx r2;"
	"1:"
		"exit;"
		:
		: __imm_addr(arena),
		  __imm_addr(add3),
		  __imm(bpf_arena_alloc_pages)
		: __clobber_all);
}

/* The same in C */

/* like the header of a C++ exception, which keeps the destructor of the object */
struct exc {
	void (*dtor)(struct exc *e);
	long val;
};

static __noinline void exc_dtor(struct exc *e)
{
	e->val += 90;
}

/* the destructor is called a frame away from where it's stored */
static __noinline long exc_end(struct exc *e)
{
	if (e->dtor)
		e->dtor(e);
	return e->val;
}

SEC("syscall")
__description("callx scalar: C, destructor in arena")
__callx_scalar
__success __retval(99)
int callx_scalar_c_arena(void *ctx)
{
	struct exc *e;

	e = bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
	if (!e)
		return 1;
	e->dtor = exc_dtor;
	e->val = 9;
	return exc_end(e);
}

#else

SEC("socket")
__success
int dummy(void *ctx)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
