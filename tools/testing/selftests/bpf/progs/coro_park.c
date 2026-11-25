// SPDX-License-Identifier: GPL-2.0
/*
 * Parked coroutine frames. A program suspends a frame with bpf_coro_park_xdp()
 * or bpf_coro_park_syscall() and keeps the pointer it gets in a kptr field. A
 * program of the type that the frame was parked for takes it out, loads the
 * resume or the destroy function from the frame and calls it with the frame,
 * as a compiler does for a coroutine handle: the program that parked it, or
 * one that is bound to that program. See prog_tests/coro_park.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "coro_park.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

#define NR_SLOTS	4

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
	struct bpf_coro_syscall __kptr *sys;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SLOTS);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct slot);
} hslots SEC(".maps");

struct coro_obj {
	int data;
};

__u64 resumed, destroyed, yields, returned;
int err;

/* What a compiler emits for a coroutine handle: the function is in the frame. */
static __always_inline void coro_call(void *coro, int slot)
{
	((void (*)(void *))((void **)coro)[slot])(coro);
}

#define coro_resume(coro)	coro_call(coro, 0)
#define coro_destroy(coro)	coro_call(coro, 1)

/* The frame holds an object across the suspension: both functions drop it. */
static __noinline __used void destroy_fn(void *frame)
{
	__u64 *f = frame;

	destroyed += f[2];
	bpf_obj_drop((struct coro_obj *)f[3]);
	bpf_coro_frame_free(frame);
}

static __noinline __used void resume_fn(void *frame)
{
	__u64 *f = frame;

	resumed += f[2];
	bpf_obj_drop((struct coro_obj *)f[3]);
	bpf_coro_frame_free(frame);
}

static __always_inline __u64 *new_frame(void *resume, __u64 arg)
{
	struct coro_obj *obj;
	__u64 *f;

	f = bpf_coro_frame_alloc(32, NULL);
	if (!f)
		return NULL;
	obj = bpf_obj_new(typeof(*obj));
	if (!obj) {
		bpf_coro_frame_free(f);
		return NULL;
	}
	f[0] = (__u64)resume;
	f[1] = (__u64)destroy_fn;
	f[2] = arg;
	f[3] = (__u64)obj;
	return f;
}

static __always_inline int keep_xdp(struct bpf_coro_xdp *coro, __u32 idx)
{
	struct slot *s = bpf_map_lookup_elem(&slots, &idx);

	if (!s) {
		bpf_coro_drop_xdp(coro);
		return -1;
	}
	coro = bpf_kptr_xchg(&s->xdp, coro);
	if (coro)
		bpf_coro_drop_xdp(coro);
	return 0;
}

static __always_inline int keep_sys(struct bpf_coro_syscall *coro, __u32 idx)
{
	struct slot *s = bpf_map_lookup_elem(&slots, &idx);

	if (!s) {
		bpf_coro_drop_syscall(coro);
		return -1;
	}
	coro = bpf_kptr_xchg(&s->sys, coro);
	if (coro)
		bpf_coro_drop_syscall(coro);
	return 0;
}

/* Park a frame for an XDP program, in slot 0, and one for a syscall program, in slot 1 */
static __always_inline int park(void)
{
	__u64 *f;

	f = new_frame(resume_fn, 1);
	if (!f)
		return XDP_ABORTED;
	if (keep_xdp(bpf_coro_park_xdp(f), 0))
		return XDP_ABORTED;
	f = new_frame(resume_fn, 100);
	if (!f)
		return XDP_ABORTED;
	if (keep_sys(bpf_coro_park_syscall(f), 1))
		return XDP_ABORTED;
	return XDP_PASS;
}

/* The program resumes its own frame */
static __always_inline int resume_own(void)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return XDP_ABORTED;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return XDP_DROP;
	coro_resume(coro);
	returned++;
	return XDP_PASS;
}

/*
 * The programs from here on are bound to the one that parks. An XDP program resumes the frame
 * that is parked for one.
 */
SEC("xdp")
int resume_xdp(struct xdp_md *ctx)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return XDP_ABORTED;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return XDP_DROP;
	coro_resume(coro);
	returned++;
	return XDP_PASS;
}

/* The same from a function of the program, which is unwound with the continuation as well */
static __noinline int resume_one(struct bpf_coro_xdp *coro)
{
	coro_resume(coro);
	returned++;
	return 0;
}

SEC("xdp")
int resume_xdp_func(struct xdp_md *ctx)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return XDP_ABORTED;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return XDP_DROP;
	resume_one(coro);
	returned++;
	return XDP_PASS;
}

/* or from the callback of a helper, which the kernel unwinds through its helper */
static int resume_cb(__u64 i, void *ctx)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		coro_resume(coro);
	returned++;
	return 1;
}

SEC("xdp")
int resume_xdp_cb(struct xdp_md *ctx)
{
	bpf_loop(1, resume_cb, NULL, 0);
	returned++;
	return XDP_PASS;
}

#if defined(__TARGET_ARCH_x86)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 64);
} arena SEC(".maps");

/*
 * A function that has a part of its stack in arena calls a parked frame. The continuation is
 * code of a program that has none, and what it calls leaves nothing in the register of that
 * stack: the caller finds its frame again all the same. Compilers don't know r12 yet.
 */
__naked __noinline __used
static long resumes_with_arena_stack(void)
{
	asm volatile (
		".8byte 0x1000000c07;"		/* r12 += 16 */
		".8byte 0x7fff00c7a;"		/* *(u64 *)(r12 - 16) = 7 */
		"r1 = 0;"
		"*(u32 *)(r10 - 4) = r1;"
		"r2 = r10;"
		"r2 += -4;"
		"r1 = %[slots] ll;"
		"call %[bpf_map_lookup_elem];"
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r2 = 0;"
		"call %[bpf_kptr_xchg];"
		"if r0 == 0 goto 1f;"
		"r1 = r0;"
		"r0 = *(u64 *)(r1 + 0);"
		"callx r0;"
	"1:	.8byte 0xfff0c079;"		/* r0 = *(u64 *)(r12 - 16) */
		"exit;"
		:
		: __imm_addr(slots), __imm(bpf_map_lookup_elem), __imm(bpf_kptr_xchg)
		: __clobber_all
	);
}

SEC("xdp")
int resume_xdp_arena(struct xdp_md *ctx)
{
	return resumes_with_arena_stack();
}

#endif

/* and destroys it */
SEC("xdp")
int destroy_xdp(struct xdp_md *ctx)
{
	struct bpf_coro_xdp *coro;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return XDP_ABORTED;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return XDP_DROP;
	coro_destroy(coro);
	returned++;
	return XDP_PASS;
}

/* A syscall program resumes the frame that is parked for one, in a read section of RCU */
SEC("syscall")
int resume_syscall(void *ctx)
{
	struct bpf_coro_syscall *coro;
	struct slot *s;
	__u32 idx = 1;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	coro = bpf_kptr_xchg(&s->sys, NULL);
	if (!coro)
		return 2;
	bpf_rcu_read_lock();
	coro_resume(coro);
	bpf_rcu_read_unlock();
	returned++;
	return 0;
}

/* The kernel destroys what a program drops: both frames, whoever they are parked for */
SEC("syscall")
int drop_both(void *ctx)
{
	struct bpf_coro_syscall *sys;
	struct bpf_coro_xdp *xdp;
	struct slot *s;
	__u32 idx = 0;

	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	xdp = bpf_kptr_xchg(&s->xdp, NULL);
	if (xdp)
		bpf_coro_drop_xdp(xdp);
	idx = 1;
	s = bpf_map_lookup_elem(&slots, &idx);
	if (!s)
		return 1;
	sys = bpf_kptr_xchg(&s->sys, NULL);
	if (sys)
		bpf_coro_drop_syscall(sys);
	return 0;
}

/* A continuation that parks its frame again, until slot 2 has counted to 3 */
static __noinline __used void resume_again(void *frame)
{
	__u64 *f = frame;

	resumed++;
	if (++f[2] < 3) {
		yields++;
		keep_xdp(bpf_coro_park_xdp(frame), 0);
		return;
	}
	bpf_obj_drop((struct coro_obj *)f[3]);
	bpf_coro_frame_free(frame);
}

static __always_inline int park_again(void)
{
	__u64 *f = new_frame(resume_again, 0);

	if (!f)
		return XDP_ABORTED;
	return keep_xdp(bpf_coro_park_xdp(f), 0) ? XDP_ABORTED : XDP_PASS;
}

/* Frames in the nodes of an rbtree and of a list, as a program that orders its work has them */
struct tree_node {
	struct bpf_rb_node rb;
	struct bpf_coro_xdp __kptr *coro;
	__u64 key;
};

struct list_node {
	struct bpf_list_node link;
	struct bpf_coro_xdp __kptr *coro;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock lock;
private(A) struct bpf_rb_root tree __contains(tree_node, rb);
private(A) struct bpf_list_head list __contains(list_node, link);

static bool key_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return container_of(a, struct tree_node, rb)->key < container_of(b, struct tree_node, rb)->key;
}

static __noinline int park_in_tree(__u64 key)
{
	struct bpf_coro_xdp *coro;
	struct tree_node *t;
	__u64 *f;

	t = bpf_obj_new(typeof(*t));
	if (!t)
		return -1;
	f = new_frame(resume_fn, key);
	if (!f) {
		bpf_obj_drop(t);
		return -1;
	}
	t->key = key;
	coro = bpf_kptr_xchg(&t->coro, bpf_coro_park_xdp(f));
	if (coro)
		bpf_coro_drop_xdp(coro);
	bpf_spin_lock(&lock);
	bpf_rbtree_add(&tree, &t->rb, key_less);
	bpf_spin_unlock(&lock);
	return 0;
}

static __noinline int park_in_list(void)
{
	struct bpf_coro_xdp *coro;
	struct list_node *l;
	__u64 *f;

	l = bpf_obj_new(typeof(*l));
	if (!l)
		return -1;
	f = new_frame(resume_fn, 1000);
	if (!f) {
		bpf_obj_drop(l);
		return -1;
	}
	coro = bpf_kptr_xchg(&l->coro, bpf_coro_park_xdp(f));
	if (coro)
		bpf_coro_drop_xdp(coro);
	bpf_spin_lock(&lock);
	bpf_list_push_back(&list, &l->link);
	bpf_spin_unlock(&lock);
	return 0;
}

/* Three frames into the tree, in an order that is not theirs, and three into the list */
static __always_inline int park_nodes(void)
{
	if (park_in_tree(20) || park_in_tree(10) || park_in_tree(30) ||
	    park_in_list() || park_in_list() || park_in_list())
		return XDP_ABORTED;
	return XDP_PASS;
}

__u64 order[3];

/* Resume what the tree has, lowest key first, then what the list has */
SEC("xdp")
int resume_nodes(struct xdp_md *ctx)
{
	struct bpf_coro_xdp *coro;
	struct bpf_list_node *ln;
	struct bpf_rb_node *rb;
	struct tree_node *t;
	struct list_node *l;
	int i;

	for (i = 0; i < 3; i++) {
		bpf_spin_lock(&lock);
		rb = bpf_rbtree_first(&tree);
		if (rb)
			rb = bpf_rbtree_remove(&tree, rb);
		bpf_spin_unlock(&lock);
		if (!rb)
			return XDP_DROP;
		t = container_of(rb, struct tree_node, rb);
		order[i] = t->key;
		coro = bpf_kptr_xchg(&t->coro, NULL);
		bpf_obj_drop(t);
		if (!coro)
			return XDP_DROP;
		coro_resume(coro);
	}
	for (i = 0; i < 3; i++) {
		bpf_spin_lock(&lock);
		ln = bpf_list_pop_front(&list);
		bpf_spin_unlock(&lock);
		if (!ln)
			return XDP_DROP;
		l = container_of(ln, struct list_node, link);
		coro = bpf_kptr_xchg(&l->coro, NULL);
		bpf_obj_drop(l);
		if (!coro)
			return XDP_DROP;
		coro_resume(coro);
	}
	returned++;
	return XDP_PASS;
}

/* The frames of a recursion that began */
unsigned long frames;

/* It calls itself until the stack has no room, which has the kernel unwind the program */
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
		"exit;"
		:
		: __imm_addr(frames)
		: __clobber_all
	);
}

/* A continuation that the kernel unwinds: whoever called it is unwound too */
static __noinline __used void resume_dives(void *frame)
{
	__u64 *f = frame;

	bpf_obj_drop((struct coro_obj *)f[3]);
	bpf_coro_frame_free(frame);
	dives();
	resumed++;
}

static __always_inline int park_dives(void)
{
	__u64 *f;

	f = new_frame(resume_dives, 0);
	if (!f || keep_xdp(bpf_coro_park_xdp(f), 0))
		return XDP_ABORTED;
	f = new_frame(resume_dives, 0);
	if (!f || keep_sys(bpf_coro_park_syscall(f), 1))
		return XDP_ABORTED;
	return XDP_PASS;
}

/* A frame in a value of the hash map */
static __always_inline int park_in_hash(__u32 key)
{
	struct bpf_coro_xdp *coro;
	struct slot init = {}, *s;
	__u64 *f;

	if (bpf_map_update_elem(&hslots, &key, &init, BPF_ANY))
		return -1;
	s = bpf_map_lookup_elem(&hslots, &key);
	if (!s)
		return -1;
	f = new_frame(resume_fn, key * 2000000);
	if (!f)
		return -1;
	coro = bpf_kptr_xchg(&s->xdp, bpf_coro_park_xdp(f));
	if (coro)
		bpf_coro_drop_xdp(coro);
	return 0;
}

/* Two of them, and the element of the second one is deleted: its memory keeps the frame */
static __always_inline int park_hash(void)
{
	__u32 key = 2;

	if (park_in_hash(1) || park_in_hash(2) || bpf_map_delete_elem(&hslots, &key))
		return XDP_ABORTED;
	return XDP_PASS;
}

/*
 * A frame that carries another parked frame. When the kernel destroys it, its destroy function
 * puts the other one where it was itself, in a value that the kernel has looked at, or drops
 * it: the kernel looks again until nothing is left.
 */
static __noinline __used void destroy_carrier(void *frame)
{
	__u64 *f = frame;
	struct bpf_coro_xdp *carried = (struct bpf_coro_xdp *)f[3];

	destroyed += f[2];
	bpf_coro_frame_free(frame);
	keep_xdp(carried, 2);
}

static __noinline __used void destroy_dropper(void *frame)
{
	__u64 *f = frame;
	struct bpf_coro_xdp *carried = (struct bpf_coro_xdp *)f[3];

	destroyed += f[2];
	bpf_coro_frame_free(frame);
	bpf_coro_drop_xdp(carried);
}

static __noinline __used void resume_carrier(void *frame)
{
	__u64 *f = frame;
	struct bpf_coro_xdp *carried = (struct bpf_coro_xdp *)f[3];

	resumed += f[2];
	bpf_coro_frame_free(frame);
	bpf_coro_drop_xdp(carried);
}

static __always_inline int park_carrier(void *destroy, __u64 arg, __u64 carried_arg, __u32 idx)
{
	struct bpf_coro_xdp *carried;
	__u64 *f;

	f = new_frame(resume_fn, carried_arg);
	if (!f)
		return -1;
	carried = bpf_coro_park_xdp(f);
	f = bpf_coro_frame_alloc(32, NULL);
	if (!f) {
		bpf_coro_drop_xdp(carried);
		return -1;
	}
	f[0] = (__u64)resume_carrier;
	f[1] = (__u64)destroy;
	f[2] = arg;
	f[3] = (__u64)carried;
	return keep_xdp(bpf_coro_park_xdp(f), idx);
}

static __always_inline int park_carriers(void)
{
	if (park_carrier(destroy_carrier, 100000, 10000, 2) ||
	    park_carrier(destroy_dropper, 1000000, 20000, 3))
		return XDP_ABORTED;
	return XDP_PASS;
}

/* What the program that parks does in this run */
int op;

int hooked;

/* A function of that program which an extension can replace, see progs/coro_park_ext.c */
__noinline int owner_hook(int what)
{
	hooked++;
	return what;
}

/*
 * The program that parks the frames. The maps that hold them are its own: every other program
 * here is bound to it, and parks none.
 */
SEC("xdp")
int owner(struct xdp_md *ctx)
{
	switch (owner_hook(op)) {
	case OP_PARK:
		return park();
	case OP_PARK_AGAIN:
		return park_again();
	case OP_PARK_NODES:
		return park_nodes();
	case OP_PARK_DIVES:
		return park_dives();
	case OP_RESUME:
		return resume_own();
	case OP_PARK_HASH:
		return park_hash();
	case OP_PARK_CARRIERS:
		return park_carriers();
	}
	return XDP_ABORTED;
}

struct sleeps_args {
	__u64 uaddr;
};

/* It sleeps for as long as user space leaves the page at that address missing. */
SEC("syscall")
int sleeps(struct sleeps_args *ctx)
{
	char c;

	return bpf_copy_from_user(&c, sizeof(c), (void *)ctx->uaddr);
}

/* A program that is bound to another one parks no frame of its own. */
SEC("xdp")
int bound_parks(struct xdp_md *ctx)
{
	return park();
}

char _license[] SEC("license") = "GPL";
