// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * An access to arena through a number, in a prog loaded with BPF_F_ARENA_SCALAR, is an access to
 * arena like any other when it faults: where its function can unwind it ends the prog through the
 * landing pad of the access, and where it cannot it is skipped. The access goes through
 * BPF_REG_AX, which holds the low 32 bits of the number. So the JIT of x86-64 keeps R0 on the
 * stack, not in BPF_REG_AX, around the loop of cmpxchg of a fetching and, or or xor: the handler
 * of the fault puts R0 back and drops the word, for a landing pad and for a skip alike. Were the
 * word left on the stack, the epilogue of the prog would pop the callee-saved registers one word
 * off.
 */
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

#define __arena_scalar __flag(BPF_F_ARENA_SCALAR) __load_if_JITed()

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

/* r8 = a number, an address of the arena that no page backs */
#define NO_PAGE "r1 = %[arena] ll;" "r8 = 0x1000;"

/* @reg = a task, which has to be released */
#define ACQUIRE_TASK(reg)				\
		"r1 = 1;"				\
		"call %[bpf_task_from_pid];"		\
		"if r0 != 0 goto +1;"			\
		"exit;"					\
		#reg " = r0;"
#define RELEASE_TASK(reg) "r1 = " #reg ";" "call %[bpf_task_release];"
#define TASK_IMM __imm_addr(arena), __imm(bpf_task_from_pid), __imm(bpf_task_release)

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_task_release(bpf_task_from_pid(0));
	bpf_arena_free_pages(&arena, bpf_arena_alloc_pages(&arena, 0, 1, -1, 0), 1);
}

/*
 * Nothing is held: the accesses share the landing pad of their function, which ends the prog with
 * -ECANCELED. Each prog returns 7 if the access is skipped.
 */
#define FAULT(name, insns)							\
SEC("syscall")									\
__description("arena_scalar fault: " #name)					\
__arena_scalar __success __retval(-ECANCELED)					\
__naked void name(void)								\
{										\
	asm volatile (NO_PAGE insns "r0 = 7; exit;" :: TASK_IMM : __clobber_all); \
}

FAULT(load, "r2 = *(u32 *)(r8 + 0);")
FAULT(store, "*(u32 *)(r8 + 0) = 1;")
FAULT(store_imm, "*(u64 *)(r8 + 0) = 1;")
FAULT(atomic_add, "r1 = 1; lock *(u64 *)(r8 + 0) += r1;")
FAULT(fetch_or, "r0 = 5; r1 = 1; r1 = atomic_fetch_or((u64 *)(r8 + 0), r1);")
FAULT(fetch_or_r0, "r0 = 1; r0 = atomic_fetch_or((u64 *)(r8 + 0), r0);")
FAULT(fetch_and_32, "r0 = 5; w1 = 1; w1 = atomic_fetch_and((u32 *)(r8 + 0), w1);")
FAULT(cmpxchg, "r0 = 1; r1 = 2; r0 = cmpxchg_64(r8 + 0, r0, r1);")

/*
 * A task is held at the access: it has a landing pad of its own, which releases the task and ends
 * the prog with TC_ACT_SHOT. The fault is at the first native insn of a fetching or, the load in
 * front of the loop, where R0 has been pushed already.
 */
#define FAULT_HELD(name, insns)							\
SEC("tc")									\
__description("arena_scalar fault: " #name)					\
__arena_scalar __success __retval(2)						\
__naked void name(void)								\
{										\
	asm volatile (NO_PAGE insns "r0 = 7; exit;" :: TASK_IMM : __clobber_all); \
}

FAULT_HELD(task_held_load, ACQUIRE_TASK(r6) "r2 = *(u32 *)(r8 + 0);" RELEASE_TASK(r6))
/* R0 is the place of the task, as the program has it in front of the access */
FAULT_HELD(task_in_r0_fetch_or, ACQUIRE_TASK(r0)
	   "r1 = 1; r1 = atomic_fetch_or((u64 *)(r8 + 0), r1);" RELEASE_TASK(r0))
FAULT_HELD(task_held_fetch_or_r0, ACQUIRE_TASK(r6)
	   "r0 = 1; r0 = atomic_fetch_or((u64 *)(r8 + 0), r0);" RELEASE_TASK(r6))
FAULT_HELD(task_held_fetch_xor_32, ACQUIRE_TASK(r6)
	   "w1 = 1; w1 = atomic_fetch_xor((u32 *)(r8 + 0), w1);" RELEASE_TASK(r6))

struct leaf {
	struct bpf_rb_node node;
	long key;
};

/* To free it takes the lock in it: bpf_rbtree_add() must not drop it under the lock of its tree */
struct node_with_tree {
	struct bpf_rb_node node;
	struct bpf_spin_lock lock;
	struct bpf_rb_root root __contains(leaf, node);
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(T) struct bpf_spin_lock tree_lock;
private(T) struct bpf_rb_root tree_root __contains(node_with_tree, node);

/* No code has a leaf: this puts it in BTF, for __contains() above */
struct leaf *__leaf_btf_root SEC(".data.leaf");

/* What the comparator saw behind each access that it skipped */
__u64 freed_page, fetched = -1, r0_kept = -1, fetched_r0 = -1, reread = -1, loaded = -1;
__u64 number_kept = -1, went_on;

/*
 * The comparator of this tree cannot unwind: its accesses are skipped. A fetching or through the
 * number of a page that the prog freed reads 0 into the operand and leaves R0 alone. With R0 as
 * the operand R0 reads 0. Neither writes: reading the address again gives 0, where the arena
 * mapping a zeroed page in place of the freed one would give 1. A load through a number with
 * garbage in its upper half reads 0 and leaves the number as it was.
 */
__naked __noinline __used
static bool less_skips(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r8 = %[freed_page] ll;"
		"r8 = *(u64 *)(r8 + 0);"
		"r0 = 5;"
		"r1 = 1;"
		"r1 = atomic_fetch_or((u64 *)(r8 + 8), r1);"
		"r2 = %[fetched] ll;"
		"*(u64 *)(r2 + 0) = r1;"
		"r2 = %[r0_kept] ll;"
		"*(u64 *)(r2 + 0) = r0;"
		"r0 = 1;"
		"r0 = atomic_fetch_or((u64 *)(r8 + 8), r0);"
		"r2 = %[fetched_r0] ll;"
		"*(u64 *)(r2 + 0) = r0;"
		"r3 = 9;"
		"r3 = *(u64 *)(r8 + 8);"
		"r2 = %[reread] ll;"
		"*(u64 *)(r2 + 0) = r3;"
		"r8 = 0xdeadbeef00001000 ll;"
		"r7 = r8;"
		"r3 = 9;"
		"r3 = *(u64 *)(r8 + 0);"
		"r2 = %[loaded] ll;"
		"*(u64 *)(r2 + 0) = r3;"
		"r3 = 0;"
		"if r8 != r7 goto +1;"
		"r3 = 1;"
		"r2 = %[number_kept] ll;"
		"*(u64 *)(r2 + 0) = r3;"
		"r1 = %[went_on] ll;"
		"r3 = *(u64 *)(r1 + 0);"
		"r3 += 1;"
		"*(u64 *)(r1 + 0) = r3;"
		"r0 = 0;"
		"exit;"
		:: __imm_addr(arena), __imm_addr(freed_page), __imm_addr(fetched),
		   __imm_addr(r0_kept), __imm_addr(fetched_r0), __imm_addr(reread),
		   __imm_addr(loaded), __imm_addr(number_kept), __imm_addr(went_on)
		: __clobber_all);
}

/* A page that was there, as a number: 0x55 at 8 in it until it was freed */
__naked __noinline __used
static __u64 freed_page_number(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r2 = 0;"
		"r3 = 1;"
		"r4 = -1;"
		"r5 = 0;"
		"call %[bpf_arena_alloc_pages];"
		"if r0 == 0 goto 1f;"
		"r6 = r0;"
		"*(u64 *)(r6 + 8) = 0x55;"
		"r1 = %[arena] ll;"
		"r2 = r6;"
		"r3 = 1;"
		"call %[bpf_arena_free_pages];"
		"r0 = r6;"
	"1:"
		"exit;"
		:: __imm_addr(arena), __imm(bpf_arena_alloc_pages), __imm(bpf_arena_free_pages)
		: __clobber_all);
}

/*
 * Two nodes, so that the comparator runs, one time: it goes on behind its accesses, and so does
 * the prog. Returns 1023 then.
 */
SEC("syscall")
__description("arena_scalar fault: skipped in a subprog that cannot unwind")
__arena_scalar __success __retval(1023)
__log_level(2)
__msg("its may_goto jumps, its arena accesses are skipped")
int skipped_in_stuck_comparator(void *ctx)
{
	struct bpf_rb_node *node;
	struct node_with_tree *n;
	int i;

	freed_page = freed_page_number();
	if (!freed_page)
		return 1;
	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return 2;
		bpf_spin_lock(&tree_lock);
		bpf_rbtree_add(&tree_root, &n->node, less_skips);
		bpf_spin_unlock(&tree_lock);
	}
	for (i = 0; i < 2; i++) {
		bpf_spin_lock(&tree_lock);
		node = bpf_rbtree_first(&tree_root);
		node = node ? bpf_rbtree_remove(&tree_root, node) : NULL;
		bpf_spin_unlock(&tree_lock);
		if (!node)
			return 3;
		bpf_obj_drop(container_of(node, struct node_with_tree, node));
	}
	return 7 + (fetched == 0) * 8 + (r0_kept == 5) * 16 + (fetched_r0 == 0) * 32 +
	       (reread == 0) * 64 + (loaded == 0) * 128 + (number_kept == 1) * 256 +
	       (went_on == 1) * 512;
}

#else

SEC("socket")
__description("arena_scalar fault: not on this architecture")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
