// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/*
 * A recursive subprog begins with a check of the stack, and leaves at once
 * when there is no room: the kernel unwinds it, with kexit, which goes to
 * kgoto after each call of it, or with exit where it cannot unwind. A helper
 * that is handed the subprog as its callback calls it too. When the address of
 * the subprog comes from a table of functions, the verifier finds that out
 * where the helper is called, and the helper needs a pad like the one that a
 * callback with unwind_exit asks for.
 *
 * The kernel unwinds the callback, the helper and every frame above it: no
 * landing pad that the prog has after a call is entered, and the prog returns
 * what the kernel says, TC_ACT_SHOT.
 */

#ifdef CAN_USE_CALLX

/* See verifier_unwind_cb.c for the raw words */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
#define unwind_exit ".8byte 0x1095;"				/* BPF_JMP | BPF_EXIT */

#define __str(x) #x
#define str(x) __str(x)

/*
 * The callbacks are named in read-only data alone, see verifier_callx_rodata.c:
 * no insn takes their address.
 */
asm (
	".pushsection .rodata,\"a\",@progbits;"
	".balign 8;"
	"cb_tbl:"
	".quad cb_in_table;"
	".quad cb_in_table_unwinds;"
	".quad ret0;"
	".quad elem_cb_in_table;"
	".quad cb_in_table_returns;"
	".quad less_in_table;"
	".quad vma_cb_in_table;"
	".quad drain_cb_in_table;"
	".type cb_tbl, @object;"
	".size cb_tbl, .-cb_tbl;"
	".popsection;"
);

#define CB_IN_TABLE		0
#define CB_IN_TABLE_UNWINDS	8
#define RET0			16
#define ELEM_CB_IN_TABLE	24
#define CB_IN_TABLE_RETURNS	32
#define LESS_IN_TABLE		40
#define VMA_CB_IN_TABLE		48
#define DRAIN_CB_IN_TABLE	56

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

/* Never set, which the verifier doesn't know */
__u64 never;

/* How many times the body of a callback ran */
__u64 bodies;

/* What goes_down() returned in a callback, see GOES_DOWN() */
__u64 result;

#define count_body()				\
	"r3 = %[bodies] ll;"			\
	"r5 = *(u64 *)(r3 + 0);"		\
	"r5 += 1;"				\
	"*(u64 *)(r3 + 0) = r5;"

__naked __noinline __used
static unsigned long ret0(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
	);
}

/*
 * A callback that calls itself, once and with a pad after the call, so it begins
 * with the check of a recursive subprog. It has no unwind_exit of its own. Every
 * call insn of it has a pad, and its address is in the table only, so when the
 * check finds no room it unwinds. @ctx is the register with the context of the
 * helper, which is 0 in these tests.
 */
#define CB_IN_TABLE_FUNC(name, ctx)			\
__naked __noinline __used				\
static unsigned long name(void)				\
{							\
	asm volatile (					\
		count_body()				\
		"if " #ctx " != 0 goto 1f;"		\
		#ctx " = 1;"				\
		"call " #name ";"			\
		unwind_goto(2)				\
	"1:"						\
		"r0 = 0;"				\
		"exit;"					\
		"r0 = 0;"				\
		"exit;"					\
		:					\
		: __imm_addr(bodies)			\
		: __clobber_all				\
	);						\
}

/* bpf_loop(): r1 = index, r2 = ctx. Also what callx calls below. */
CB_IN_TABLE_FUNC(cb_in_table, r2)
/* bpf_for_each_map_elem(): r1 = map, r2 = key, r3 = value, r4 = ctx */
CB_IN_TABLE_FUNC(elem_cb_in_table, r4)
/* bpf_user_ringbuf_drain(): r1 = dynptr, r2 = ctx */
CB_IN_TABLE_FUNC(drain_cb_in_table, r2)

/* bpf_find_vma(): r1 = task, r2 = vma, r3 = ctx, which count_body() uses */
__naked __noinline __used
static unsigned long vma_cb_in_table(void)
{
	asm volatile (
		"r2 = r3;"
		count_body()
		"if r2 != 0 goto 1f;"
		"r3 = 1;"
		"call vma_cb_in_table;"
		unwind_goto(2)
	"1:"
		"r0 = 0;"
		"exit;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(bodies)
		: __clobber_all
	);
}

/* The same, with an unwind_exit on a path that is never taken */
__naked __noinline __used
static unsigned long cb_in_table_unwinds(void)
{
	asm volatile (
		count_body()
		"r3 = %[never] ll;"
		"r3 = *(u64 *)(r3 + 0);"
		"if r3 != 0 goto 2f;"
		"if r2 != 0 goto 1f;"
		"r2 = 1;"
		"call cb_in_table_unwinds;"
		unwind_goto(2)
	"1:"
		"r0 = 0;"
		"exit;"
		"r0 = 0;"
		"exit;"
	"2:"
		"r0 = 0;"
		unwind_exit
		:
		: __imm_addr(bodies),
		  __imm_addr(never)
		: __clobber_all
	);
}

/* Not recursive: it has no check, and nothing in it unwinds */
__naked __noinline __used
static unsigned long cb_in_table_returns(void)
{
	asm volatile (
		count_body()
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(bodies)
		: __clobber_all
	);
}

/* Recursive, and named by an insn: the helper that gets it is a plain call of it */
__naked __noinline __used
static unsigned long cb_by_insn(void)
{
	asm volatile (
		count_body()
		"if r2 != 0 goto 1f;"
		"r2 = 1;"
		"call cb_by_insn;"
		unwind_goto(2)
	"1:"
		"r0 = 0;"
		"exit;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(bodies)
		: __clobber_all
	);
}

/*
 * Goes down until a check of a recursion finds no room in the stack. The check
 * of a recursive subprog unwinds, it never returns 0 to a caller that goes on:
 * so each frame first calls a helper with a callback that is recursive too, and
 * goes down only when the helper returned. The frame of the callback begins
 * where the next frame of the recursion would begin, or below it when the helper
 * is not inlined: the check of the callback is the first one that finds no
 * room, and the callback leaves before its body ran.
 *
 * It unwinds, the helper is left on that round, and so are the frames above:
 * the pad of the prog after the helper, which would return 7, is for
 * unwind_exit. Had the helper no pad for kexit, the unwinding were lost there:
 * the callback would return to the helper as if nothing had happened, and
 * nothing would warn. So the verifier looks for the pad in the text of the
 * helper when the prog is loaded, and refuses the prog if there is none, see
 * check_cb_pad().
 */
#define GOES_DOWN(name, insns, ...)			\
__naked __noinline __used				\
static unsigned long name(void)				\
{							\
	asm volatile (					\
		insns					\
		unwind_goto(2)				\
		"call " #name ";"			\
		"exit;"					\
		"r0 = 7;"				\
		"exit;"					\
		:					\
		: __imm_addr(bodies), ##__VA_ARGS__	\
		: __clobber_all				\
	);						\
}							\
							\
/* A callback of bpf_loop() cannot be cancelled */	\
__naked __noinline __used				\
static unsigned long name##_cb(void)			\
{							\
	asm volatile (					\
		"call " #name ";"			\
		"r1 = %[result] ll;"			\
		"*(u64 *)(r1 + 0) = r0;"		\
		"r0 = 0;"				\
		"exit;"					\
		:					\
		: __imm_addr(result)			\
		: __clobber_all				\
	);						\
}

/* The callback at @off of the table in r2 */
#define CB(off)					\
	"r2 = cb_tbl ll;"			\
	"r2 = *(u64 *)(r2 + " str(off) ");"

/* Three rounds. The verifier inlines the loop when the flags are a known 0. */
#define LOOP(off, flags)			\
	CB(off)					\
	"r1 = 3;"				\
	"r3 = 0;"				\
	flags					\
	"call %[bpf_loop];"

#define FLAGS_ZERO	"r4 = 0;"
#define FLAGS_UNKNOWN	"r4 = %[never] ll; r4 = *(u64 *)(r4 + 0);"

GOES_DOWN(goes_down_loop, LOOP(CB_IN_TABLE, FLAGS_ZERO), __imm(bpf_loop))
GOES_DOWN(goes_down_loop_cb_unwinds, LOOP(CB_IN_TABLE_UNWINDS, FLAGS_ZERO), __imm(bpf_loop))
GOES_DOWN(goes_down_loop_not_inlined, LOOP(CB_IN_TABLE, FLAGS_UNKNOWN),
	  __imm(bpf_loop), __imm_addr(never))
GOES_DOWN(goes_down_loop_cb_by_insn,
	  "r2 = %[cb_by_insn] ll;"
	  "r1 = 3;"
	  "r3 = 0;"
	  "r4 = 0;"
	  "call %[bpf_loop];",
	  __imm(bpf_loop), __imm_addr(cb_by_insn))
GOES_DOWN(goes_down_for_each,
	  CB(ELEM_CB_IN_TABLE)
	  "r1 = %[array] ll;"
	  "r3 = 0;"
	  "r4 = 0;"
	  "call %[bpf_for_each_map_elem];",
	  __imm(bpf_for_each_map_elem), __imm_addr(array))
GOES_DOWN(goes_down_find_vma,
	  "call %[bpf_get_current_task_btf];"
	  "r1 = *(u64 *)(r0 + %[mm]);"
	  "r2 = *(u64 *)(r1 + %[start_stack]);"
	  "r1 = r0;"
	  "r3 = cb_tbl ll;"
	  "r3 = *(u64 *)(r3 + " str(VMA_CB_IN_TABLE) ");"
	  "r4 = 0;"
	  "r5 = 0;"
	  "call %[bpf_find_vma];",
	  __imm(bpf_get_current_task_btf), __imm(bpf_find_vma),
	  __imm_const(mm, offsetof(struct task_struct, mm)),
	  __imm_const(start_stack, offsetof(struct mm_struct, start_stack)))
GOES_DOWN(goes_down_callx,
	  "r6 = cb_tbl ll;"
	  "r6 = *(u64 *)(r6 + " str(CB_IN_TABLE) ");"
	  "r1 = 0;"
	  "r2 = 0;"
	  "callx r6;")

/*
 * libbpf and the kernel look for pointers to functions in the data of a prog
 * that has callx. A pad follows it: a callx without one could call any function
 * in the table, which then had to return when it has to stop.
 */
#define CALLX_RET0()						\
	"r2 = cb_tbl ll;"					\
	"r2 = *(u64 *)(r2 + " str(RET0) ");"			\
	"callx r2;"						\
	unwind_goto(0)

/*
 * goes_down() in a callback, which returns what it did: where frames can be
 * cancelled, the check of the recursion of goes_down() in the main program
 * would cancel it instead of returning 0.
 */
#define IN_CALLBACK(goes_down)			\
		"r1 = 1;"			\
		"r2 = %[cb] ll;"		\
		"r3 = 0;"			\
		"r4 = 0;"			\
		"call %[bpf_loop];"		\
		"r1 = %[result] ll;"		\
		"r0 = *(u64 *)(r1 + 0);"	\
		"exit;"				\
		:				\
		: [cb] "i"(goes_down##_cb),	\
		  __imm_addr(result),		\
		  __imm(bpf_loop)		\
		: __clobber_all

#define GOES_DOWN_TEST(name, goes_down)		\
__naked int name(void)				\
{						\
	asm volatile (				\
		CALLX_RET0()			\
		IN_CALLBACK(goes_down)		\
	);					\
}

/*
 * The inlined loop needs a pad of its own for the call of the callback, like
 * the one that a callback with unwind_exit gets: kgoto, for kexit of the check.
 * The first one is the loop of the main program: to the verifier the check of
 * goes_down() can unwind too.
 */
SEC("tc")
__description("unwind cb: the check of a recursive callback in a table unwinds out of the inlined bpf_loop")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__xlated("kgoto pc-15")
__xlated("...")
__xlated("kgoto pc-15")
GOES_DOWN_TEST(loop_cb_in_table_no_room, goes_down_loop)

/* The callback has an unwind_exit: the inlined loop has a pad for that too */
SEC("tc")
__description("unwind cb: the check of a recursive callback with unwind_exit unwinds out of the inlined bpf_loop")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__xlated("kgoto pc-15")
__xlated("...")
__xlated("unwind_goto pc-19")
__xlated("kgoto pc-16")
GOES_DOWN_TEST(loop_cb_in_table_unwinds_no_room, goes_down_loop_cb_unwinds)

/* The helper has the pad, and kgoto after its call is where it leaves to */
SEC("tc")
__description("unwind cb: the check of a recursive callback in a table unwinds out of bpf_loop")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
GOES_DOWN_TEST(loop_not_inlined_cb_in_table_no_room, goes_down_loop_not_inlined)

SEC("tc")
__description("unwind cb: the check of a recursive callback in a table unwinds out of bpf_for_each_map_elem")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
GOES_DOWN_TEST(for_each_cb_in_table_no_room, goes_down_for_each)

/* The vma of the stack of the current task: the callback runs under the mmap lock */
SEC("tc")
__description("unwind cb: the check of a recursive callback in a table unwinds out of bpf_find_vma")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
GOES_DOWN_TEST(find_vma_cb_in_table_no_room, goes_down_find_vma)

/* The same subprog, called by callx: the pad is found by the return address */
SEC("tc")
__description("unwind cb: the check of a recursive subprog in a table unwinds out of callx")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
GOES_DOWN_TEST(callx_cb_in_table_no_room, goes_down_callx)

/*
 * A callback that an insn names is no different: the check of a recursive
 * subprog has one way out. It unwinds through the pad of the helper.
 */
SEC("tc")
__description("unwind cb: the check of a recursive callback named by an insn unwinds out of bpf_loop")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__naked int loop_cb_by_insn_no_room(void)
{
	asm volatile (
		IN_CALLBACK(goes_down_loop_cb_by_insn)
	);
}

/*
 * Without unwind_goto after the call of the helper the verifier adds kgoto all
 * the same, and the pad that it goes to. Here the callback has room, and every
 * round returns.
 */
SEC("tc")
__description("unwind cb: no unwind_goto after bpf_loop, the check of its callback in a table unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int loop_cb_in_table_no_pad(void)
{
	asm volatile (
		CALLX_RET0()
		LOOP(CB_IN_TABLE, FLAGS_ZERO)
		"exit;"
		:
		: __imm(bpf_loop)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind cb: no unwind_goto after bpf_for_each_map_elem, the check of its callback in a table unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int for_each_cb_in_table_no_pad(void)
{
	asm volatile (
		CALLX_RET0()
		CB(ELEM_CB_IN_TABLE)
		"r1 = %[array] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		"exit;"
		:
		: __imm(bpf_for_each_map_elem),
		  __imm_addr(array)
		: __clobber_all
	);
}

/*
 * The callback of bpf_user_ringbuf_drain() runs only on samples from user space,
 * and none are here: these load.
 */
SEC("tc")
__description("unwind cb: unwind_goto after bpf_user_ringbuf_drain, the check of its callback in a table unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__naked int drain_cb_in_table_pad(void)
{
	asm volatile (
		CALLX_RET0()
		CB(DRAIN_CB_IN_TABLE)
		"r1 = %[user_ringbuf] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_user_ringbuf_drain];"
		unwind_goto(1)
		"exit;"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_user_ringbuf_drain),
		  __imm_addr(user_ringbuf)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind cb: no unwind_goto after bpf_user_ringbuf_drain, the check of its callback in a table unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__naked int drain_cb_in_table_no_pad(void)
{
	asm volatile (
		CALLX_RET0()
		CB(DRAIN_CB_IN_TABLE)
		"r1 = %[user_ringbuf] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_user_ringbuf_drain];"
		"exit;"
		:
		: __imm(bpf_user_ringbuf_drain),
		  __imm_addr(user_ringbuf)
		: __clobber_all
	);
}

/* A callback in a table that is not recursive has no check: no pad is asked for */
SEC("tc")
__description("unwind cb: no unwind_goto after bpf_loop, its callback in a table is not recursive")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int loop_cb_in_table_returns(void)
{
	asm volatile (
		CALLX_RET0()
		LOOP(CB_IN_TABLE_RETURNS, FLAGS_ZERO)
		"r1 = %[bodies] ll;"
		"r0 = *(u64 *)(r1 + 0);"
		"exit;"
		:
		: __imm(bpf_loop),
		  __imm_addr(bodies)
		: __clobber_all
	);
}

/*
 * The comparator of bpf_rbtree_add(), recursive and in the table. The node that
 * is added is never NULL, and what the comparator calls gets NULL.
 */
__naked __noinline __used
static unsigned long less_in_table(void)
{
	asm volatile (
		"if r1 == 0 goto 1f;"
		"r1 = 0;"
		"r2 = 0;"
		"call less_in_table;"
		unwind_goto(2)
	"1:"
		"r0 = 0;"
		"exit;"
		"r0 = 0;"
		"exit;"
	);
}

/* Outside of the lock of the tree */
__naked __noinline __used
static int callx_ret0(void)
{
	asm volatile (
		CALLX_RET0()
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

/* Only asm calls the kfunc: this puts its prototype in BTF */
void __rbtree_add_btf_root(struct bpf_rb_root *root, struct bpf_rb_node *node)
{
	bpf_rbtree_add(root, node, NULL);
}

/* r1 = root, r2 = node. The verifier fills r4 and r5. */
__naked __noinline __used
static int rbtree_add_less_in_table(void *root, void *node)
{
	asm volatile (
		"r3 = cb_tbl ll;"
		"r3 = *(u64 *)(r3 + " str(LESS_IN_TABLE) ");"
		"call %[bpf_rbtree_add];"
		unwind_goto(1)
		"exit;"
		"r0 += 42;"
		"exit;"
		:
		: __imm(bpf_rbtree_add)
		: __clobber_all
	);
}

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

/* A node with a list in it: its destructor takes the lock of the list */
struct elem {
	long key;
	struct bpf_list_node node;
};

struct node_list {
	long key;
	struct bpf_rb_node node;
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains(elem, node);
};

private(A) struct bpf_spin_lock llock;
private(A) struct bpf_rb_root lroot __contains(node_list, node);

/* No code has an elem: this puts it in BTF, for __contains() above */
void __elem_btf_root(struct elem *e)
{
}

/* A kptr whose destructor is not for NMI context */
struct node_task {
	long key;
	struct bpf_rb_node node;
	struct task_struct __kptr *task;
};

private(B) struct bpf_spin_lock tlock;
private(B) struct bpf_rb_root troot __contains(node_task, node);

/*
 * The pad of bpf_rbtree_add() drops the node when the comparator unwinds, under
 * the lock of the tree. The check of a recursive comparator unwinds like an
 * unwind_exit of its own does, so the same types are refused.
 */
SEC("tc")
__description("unwind cb: the check of a recursive comparator in a table unwinds on a type that takes a lock when freed")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("bpf_rbtree_add with a comparator that unwinds cannot be used on types with a list head, an rb root or a referenced kptr")
int rbtree_less_in_table_lock_on_free(void *ctx)
{
	struct node_list *n;
	int ret;

	callx_ret0();
	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&llock);
	ret = rbtree_add_less_in_table(&lroot, &n->node);
	bpf_spin_unlock(&llock);
	return ret;
}

/*
 * A recursive subprog is refused in a tracing program when the pass is over.
 * The comparator is refused where it is passed, before that.
 */
SEC("tp_btf/task_newtask")
__description("unwind cb: the check of a recursive comparator in a table unwinds in a tracing program on a type with NMI unsafe fields")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("bpf_rbtree_add with a comparator that unwinds cannot be used in tracing programs on types with NMI unsafe fields")
int BPF_PROG(rbtree_less_in_table_nmi_unsafe, struct task_struct *task, u64 clone_flags)
{
	struct node_task *n;
	int ret;

	callx_ret0();
	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&tlock);
	ret = rbtree_add_less_in_table(&troot, &n->node);
	bpf_spin_unlock(&tlock);
	return ret;
}

#endif /* CAN_USE_CALLX */

char _license[] SEC("license") = "GPL";
