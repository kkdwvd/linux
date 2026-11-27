// SPDX-License-Identifier: GPL-2.0
/* What the verifier refuses of parked coroutine frames, see progs/coro_park.c */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct slot {
	struct bpf_coro_xdp __kptr *xdp;
	struct bpf_coro_syscall __kptr *sys;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct slot);
} slots SEC(".maps");

static __always_inline void coro_call(void *coro, int slot)
{
	((void (*)(void *))((void **)coro)[slot])(coro);
}

static __always_inline struct slot *slot_at(__u32 idx)
{
	return bpf_map_lookup_elem(&slots, &idx);
}

static __always_inline struct slot *the_slot(void)
{
	return slot_at(0);
}

static __noinline __used void free_fn(void *frame)
{
	bpf_coro_frame_free(frame);
}

static __always_inline int park_xdp(void *resume, void *destroy)
{
	struct bpf_coro_xdp *coro;
	struct slot *s = the_slot();
	__u64 *f;

	if (!s)
		return 0;
	f = bpf_coro_frame_alloc(24, NULL);
	if (!f)
		return 0;
	f[0] = (__u64)resume;
	f[1] = (__u64)destroy;
	coro = bpf_kptr_xchg(&s->xdp, bpf_coro_park_xdp(f));
	if (coro)
		bpf_coro_drop_xdp(coro);
	return 0;
}

static __always_inline int park_sys(void *resume)
{
	struct bpf_coro_syscall *coro;
	struct slot *s = the_slot();
	__u64 *f;

	if (!s)
		return 0;
	f = bpf_coro_frame_alloc(24, NULL);
	if (!f)
		return 0;
	f[0] = (__u64)resume;
	f[1] = (__u64)free_fn;
	coro = bpf_kptr_xchg(&s->sys, bpf_coro_park_syscall(f));
	if (coro)
		bpf_coro_drop_syscall(coro);
	return 0;
}

SEC("xdp")
__success
int park_ok(struct xdp_md *ctx)
{
	return park_xdp(free_fn, free_fn);
}

/* A frame is called by a program of the type that it was parked for */
SEC("syscall")
__failure __msg("was parked for another type of program")
int resume_wrong_type(void *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return 0;
	bpf_rcu_read_lock();
	coro_call(coro, 0);
	bpf_rcu_read_unlock();
	return 0;
}

/* in a read section of RCU */
SEC("syscall")
__failure __msg("is called in a read section of RCU")
int resume_no_rcu(void *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_syscall *coro;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->sys, NULL);
	if (coro)
		coro_call(coro, 0);
	return 0;
}

/* Only the pointer that holds the frame is one to load the function through */
SEC("xdp")
__failure __msg("through the pointer that holds the frame")
int resume_loaded_field(struct xdp_md *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s)
		return 0;
	coro = s->xdp;
	if (coro)
		coro_call(coro, 0);
	return 0;
}

/* and nothing else of the frame is read */
SEC("xdp")
__failure __msg("only the function in one of its first two slots is loaded")
int read_parked_frame(struct xdp_md *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;
	__u64 v;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return 0;
	v = ((__u64 *)coro)[2];
	bpf_coro_drop_xdp(coro);
	return v;
}

/*
 * A continuation calls no continuation. Before the main pass the function that callx calls is
 * any whose address is taken, the continuation among them: it is found recursive, and that is
 * refused, before check_coro_callx() and check_coro_calls() get to say the same.
 */
static __noinline __used void resumes_fn(void *frame)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	bpf_coro_frame_free(frame);
	if (!s)
		return;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		coro_call(coro, 0);
}

SEC("xdp")
__failure __msg("coroutine continuation resumes_fn() is recursive")
int resume_in_continuation(struct xdp_md *ctx)
{
	return park_xdp(resumes_fn, free_fn);
}

/* nor does a function that it calls */
static __noinline int resume_one(struct bpf_coro_xdp *coro)
{
	coro_call(coro, 0);
	return 0;
}

static __noinline __used void calls_resume_fn(void *frame)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	bpf_coro_frame_free(frame);
	if (!s)
		return;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		resume_one(coro);
}

SEC("xdp")
__failure __msg("coroutine continuation calls_resume_fn() is recursive")
int resume_below_continuation(struct xdp_md *ctx)
{
	return park_xdp(calls_resume_fn, free_fn);
}

/* The kernel destroys a parked frame that nothing calls: it needs the function */
SEC("xdp")
__failure __msg("parked coro_frame has no destroy function in its second slot")
int park_no_destroy(struct xdp_md *ctx)
{
	return park_xdp(free_fn, (void *)1);
}

/* A sleepable program parks too: the continuation is verified as code that does not sleep, */
SEC("syscall")
__success
int park_sleepable(void *ctx)
{
	return park_sys(free_fn);
}

static __noinline __used void sleeps_fn(void *frame)
{
	char c;

	bpf_coro_frame_free(frame);
	bpf_copy_from_user(&c, sizeof(c), NULL);
}

/* whatever the program may do */
SEC("syscall")
__failure __msg("sleepable helper bpf_copy_from_user")
int park_sleepable_continuation_sleeps(void *ctx)
{
	char c;

	bpf_copy_from_user(&c, sizeof(c), NULL);
	return park_sys(sleeps_fn);
}

struct wq_elem {
	struct bpf_wq w;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wqs SEC(".maps");

static int wq_parks(void *map, int *key, void *value)
{
	return park_xdp(free_fn, free_fn);
}

/* and so does a callback that may sleep */
SEC("tc")
__success
int park_in_sleepable_callback(struct __sk_buff *ctx)
{
	struct wq_elem *e;
	__u32 idx = 0;

	e = bpf_map_lookup_elem(&wqs, &idx);
	if (!e || bpf_wq_init(&e->w, &wqs, 0))
		return 0;
	bpf_wq_set_callback(&e->w, wq_parks, 0);
	return 0;
}

/*
 * A continuation is code of the type of program that its frame is parked for: a helper of XDP
 * is one to call when that is an XDP program, and none for a syscall program.
 */
static __noinline __used void redirects_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	bpf_redirect(1, 0);
}

SEC("xdp")
__success
int park_helper_of_type(struct xdp_md *ctx)
{
	return park_xdp(redirects_fn, free_fn);
}

static __noinline __used void redirects_too_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	bpf_redirect(1, 0);
}

SEC("xdp")
__failure __msg("program of this type cannot use helper bpf_redirect")
int park_helper_of_other_type(struct xdp_md *ctx)
{
	return park_sys(redirects_too_fn);
}

/* So is a function that the continuation calls and that is verified on its own, */
static __noinline int redirect_below(int ifindex)
{
	return bpf_redirect(ifindex, 0);
}

static __noinline __used void calls_redirect_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	redirect_below(1);
}

SEC("xdp")
__success
int park_helper_below_of_type(struct xdp_md *ctx)
{
	return park_xdp(calls_redirect_fn, free_fn);
}

static __noinline __used void calls_redirect_too_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	redirect_below(1);
}

/* once for each type that calls it: the program calls it too, as an XDP program */
SEC("xdp")
__failure __msg("program of this type cannot use helper bpf_redirect")
int park_helper_below_of_other_type(struct xdp_md *ctx)
{
	return redirect_below(2) + park_sys(calls_redirect_too_fn);
}

int global_calls;

/* A global function is verified once, as code of the program's own type */
__noinline int global_fn(int x)
{
	global_calls += x;
	return x + 1;
}

static __noinline __used void calls_global_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	global_fn(1);
}

SEC("xdp")
__success
int park_global_of_type(struct xdp_md *ctx)
{
	return park_xdp(calls_global_fn, free_fn);
}

static __noinline __used void calls_global_too_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	global_fn(1);
}

SEC("xdp")
__failure __msg("global function global_fn() cannot be called from the continuation of a coro_frame that is parked for another type of program")
int park_global_of_other_type(struct xdp_md *ctx)
{
	return park_sys(calls_global_too_fn);
}

/*
 * A call that states of two types get to is the same function for both: the time is, and the
 * redirect of a tc program is not that of an XDP program.
 */
static __noinline __u64 time_at(__u64 *t)
{
	*t = bpf_ktime_get_ns();
	return *t;
}

static __noinline __used void asks_time_fn(void *frame)
{
	__u64 t;

	bpf_coro_frame_free(frame);
	time_at(&t);
}

SEC("tc")
__success
int helper_of_two_types(struct __sk_buff *ctx)
{
	__u64 t;

	time_at(&t);
	return park_xdp(asks_time_fn, free_fn);
}

static __noinline int redirect_at(int *ifindex)
{
	return bpf_redirect(*ifindex, 0);
}

static __noinline __used void redirects_at_fn(void *frame)
{
	int ifindex = 1;

	bpf_coro_frame_free(frame);
	redirect_at(&ifindex);
}

SEC("tc")
__failure __msg("helper bpf_redirect#23 is not the same function for the types of program that this call is verified as")
int helper_differs_by_type(struct __sk_buff *ctx)
{
	int ifindex = 1;

	redirect_at(&ifindex);
	return park_xdp(redirects_at_fn, free_fn);
}

/* The kfuncs are those of the type too: one of syscall programs, in a tc program */
static __noinline __used void kfunc_of_syscall_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	bpf_kfunc_coro_result(0);
}

SEC("tc")
__success
int park_kfunc_of_type(struct __sk_buff *ctx)
{
	return park_sys(kfunc_of_syscall_fn);
}

/* and one of tc programs is none for the continuation of a frame that is parked for XDP */
static __noinline __used void kfunc_of_tc_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	bpf_kfunc_call_test4(1, 2, 3, 4);
}

SEC("tc")
__failure __msg("calling kernel function bpf_kfunc_call_test4 is not allowed")
int park_kfunc_of_other_type(struct __sk_buff *ctx)
{
	bpf_kfunc_call_test4(1, 2, 3, 4);
	return park_xdp(kfunc_of_tc_fn, free_fn);
}

/* The function that was loaded from a frame is called with that frame */
SEC("xdp")
__failure __msg("R1 has to be the pointer that holds the frame")
int resume_other_frame(struct xdp_md *ctx)
{
	struct slot *a = slot_at(0), *b = slot_at(1);
	struct bpf_coro_xdp *one, *two;

	if (!a || !b)
		return 0;
	one = bpf_kptr_xchg(&a->xdp, NULL);
	if (!one)
		return 0;
	two = bpf_kptr_xchg(&b->xdp, NULL);
	if (!two) {
		bpf_coro_drop_xdp(one);
		return 0;
	}
	((void (*)(void *))((void **)one)[0])(two);
	bpf_coro_drop_xdp(one);
	return 0;
}

/* and is gone with it */
SEC("xdp")
__failure __msg("has type scalar, expected func")
int resume_twice(struct xdp_md *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;
	void (*fn)(void *);

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return 0;
	fn = ((void **)coro)[0];
	fn(coro);
	fn(coro);
	return 0;
}

/* The compiler may load the function into the register that has the frame */
__naked __noinline __used
static void resume_same_reg(struct bpf_coro_xdp *coro)
{
	asm volatile (
		"r0 = r1;"
		"r0 = *(u64 *)(r0 + 0);"
		"callx r0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("xdp")
__success
int resume_through_one_reg(struct xdp_md *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		resume_same_reg(coro);
	return 0;
}

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(L) struct bpf_spin_lock lock;

struct res_node {
	struct bpf_list_node link;
	struct bpf_coro_xdp __kptr *coro;
};

struct res_holder {
	struct bpf_res_spin_lock lock;
	struct bpf_list_head head __contains(res_node, link);
};

/*
 * Nothing empties a list that a bpf_res_spin_lock guards when what has it is freed, nor when
 * the program of the frames in it goes: its nodes hold no frames.
 */
SEC("xdp")
__failure __msg("a bpf_list_head whose nodes can hold a parked coro_frame has to be guarded by a bpf_spin_lock")
int park_in_res_locked_list(struct xdp_md *ctx)
{
	struct res_holder *h = bpf_obj_new(typeof(*h));
	struct res_node *n;

	if (!h)
		return 0;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_obj_drop(h);
		return 0;
	}
	if (bpf_res_spin_lock(&h->lock)) {
		bpf_obj_drop(n);
		bpf_obj_drop(h);
		return 0;
	}
	bpf_list_push_back(&h->head, &n->link);
	bpf_res_spin_unlock(&h->lock);
	bpf_obj_drop(h);
	return 0;
}

struct res_tree_node {
	struct bpf_rb_node node;
	struct bpf_coro_xdp __kptr *coro;
};

struct res_tree_holder {
	struct bpf_res_spin_lock lock;
	struct bpf_rb_root root __contains(res_tree_node, node);
};

static bool res_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return a < b;
}

/* .. and nothing empties an rbtree that one guards */
SEC("xdp")
__failure __msg("a bpf_rb_root whose nodes can hold a parked coro_frame has to be guarded by a bpf_spin_lock")
int park_in_res_locked_tree(struct xdp_md *ctx)
{
	struct res_tree_holder *h = bpf_obj_new(typeof(*h));
	struct res_tree_node *n;

	if (!h)
		return 0;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_obj_drop(h);
		return 0;
	}
	if (bpf_res_spin_lock(&h->lock)) {
		bpf_obj_drop(n);
		bpf_obj_drop(h);
		return 0;
	}
	bpf_rbtree_add(&h->root, &n->node, res_less);
	bpf_res_spin_unlock(&h->lock);
	bpf_obj_drop(h);
	return 0;
}

/* The frame is two objects away from the node: the list leads to it all the same */
struct res_far_inner {
	struct bpf_coro_xdp __kptr *coro;
};

struct res_far_mid {
	struct res_far_inner __kptr *inner;
};

struct res_far_node {
	struct bpf_list_node link;
	struct res_far_mid __kptr *mid;
};

struct res_far_holder {
	struct bpf_res_spin_lock lock;
	struct bpf_list_head head __contains(res_far_node, link);
};

SEC("xdp")
__failure __msg("a bpf_list_head whose nodes can hold a parked coro_frame has to be guarded by a bpf_spin_lock")
int park_far_in_res_locked_list(struct xdp_md *ctx)
{
	struct res_far_holder *h = bpf_obj_new(typeof(*h));
	struct res_far_node *n;

	if (!h)
		return 0;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_obj_drop(h);
		return 0;
	}
	if (bpf_res_spin_lock(&h->lock)) {
		bpf_obj_drop(n);
		bpf_obj_drop(h);
		return 0;
	}
	bpf_list_push_back(&h->head, &n->link);
	bpf_res_spin_unlock(&h->lock);
	bpf_obj_drop(h);
	return 0;
}

/*
 * A node whose fields point to more types than a search has room for at first, none of which
 * can hold a frame: a program that has nothing to do with coroutines is not asked to guard its
 * list with a bpf_spin_lock.
 */
#define WIDE_LEAF(n)				\
struct wide_leaf_##n {				\
	long id;				\
	struct bpf_refcount ref;		\
}

WIDE_LEAF(1); WIDE_LEAF(2); WIDE_LEAF(3); WIDE_LEAF(4);
WIDE_LEAF(5); WIDE_LEAF(6); WIDE_LEAF(7); WIDE_LEAF(8);
WIDE_LEAF(9); WIDE_LEAF(10); WIDE_LEAF(11); WIDE_LEAF(12);
WIDE_LEAF(13); WIDE_LEAF(14); WIDE_LEAF(15); WIDE_LEAF(16);
WIDE_LEAF(17); WIDE_LEAF(18); WIDE_LEAF(19); WIDE_LEAF(20);
WIDE_LEAF(21); WIDE_LEAF(22); WIDE_LEAF(23); WIDE_LEAF(24);
WIDE_LEAF(25); WIDE_LEAF(26); WIDE_LEAF(27); WIDE_LEAF(28);
WIDE_LEAF(29); WIDE_LEAF(30); WIDE_LEAF(31); WIDE_LEAF(32);
WIDE_LEAF(33); WIDE_LEAF(34); WIDE_LEAF(35); WIDE_LEAF(36);
WIDE_LEAF(37); WIDE_LEAF(38); WIDE_LEAF(39); WIDE_LEAF(40);

struct wide_node {
	struct bpf_list_node link;
	struct wide_leaf_1 __kptr *p1;
	struct wide_leaf_2 __kptr *p2;
	struct wide_leaf_3 __kptr *p3;
	struct wide_leaf_4 __kptr *p4;
	struct wide_leaf_5 __kptr *p5;
	struct wide_leaf_6 __kptr *p6;
	struct wide_leaf_7 __kptr *p7;
	struct wide_leaf_8 __kptr *p8;
	struct wide_leaf_9 __kptr *p9;
	struct wide_leaf_10 __kptr *p10;
	struct wide_leaf_11 __kptr *p11;
	struct wide_leaf_12 __kptr *p12;
	struct wide_leaf_13 __kptr *p13;
	struct wide_leaf_14 __kptr *p14;
	struct wide_leaf_15 __kptr *p15;
	struct wide_leaf_16 __kptr *p16;
	struct wide_leaf_17 __kptr *p17;
	struct wide_leaf_18 __kptr *p18;
	struct wide_leaf_19 __kptr *p19;
	struct wide_leaf_20 __kptr *p20;
	struct wide_leaf_21 __kptr *p21;
	struct wide_leaf_22 __kptr *p22;
	struct wide_leaf_23 __kptr *p23;
	struct wide_leaf_24 __kptr *p24;
	struct wide_leaf_25 __kptr *p25;
	struct wide_leaf_26 __kptr *p26;
	struct wide_leaf_27 __kptr *p27;
	struct wide_leaf_28 __kptr *p28;
	struct wide_leaf_29 __kptr *p29;
	struct wide_leaf_30 __kptr *p30;
	struct wide_leaf_31 __kptr *p31;
	struct wide_leaf_32 __kptr *p32;
	struct wide_leaf_33 __kptr *p33;
	struct wide_leaf_34 __kptr *p34;
	struct wide_leaf_35 __kptr *p35;
	struct wide_leaf_36 __kptr *p36;
	struct wide_leaf_37 __kptr *p37;
	struct wide_leaf_38 __kptr *p38;
	struct wide_leaf_39 __kptr *p39;
	struct wide_leaf_40 __kptr *p40;
};

struct wide_holder {
	struct bpf_res_spin_lock lock;
	struct bpf_list_head head __contains(wide_node, link);
};

SEC("xdp")
__success
int many_types_in_res_locked_list(struct xdp_md *ctx)
{
	struct wide_holder *h = bpf_obj_new(typeof(*h));
	struct wide_node *n;

	if (!h)
		return 0;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_obj_drop(h);
		return 0;
	}
	if (bpf_res_spin_lock(&h->lock)) {
		bpf_obj_drop(n);
		bpf_obj_drop(h);
		return 0;
	}
	bpf_list_push_back(&h->head, &n->link);
	bpf_res_spin_unlock(&h->lock);
	bpf_obj_drop(h);
	return 0;
}

/* The same with a frame in the last of them: found, however many types come first */
struct wide_leaf_coro {
	long id;
	struct bpf_coro_xdp __kptr *coro;
};

struct wide_coro_node {
	struct bpf_list_node link;
	struct wide_leaf_1 __kptr *p1;
	struct wide_leaf_2 __kptr *p2;
	struct wide_leaf_3 __kptr *p3;
	struct wide_leaf_4 __kptr *p4;
	struct wide_leaf_5 __kptr *p5;
	struct wide_leaf_6 __kptr *p6;
	struct wide_leaf_7 __kptr *p7;
	struct wide_leaf_8 __kptr *p8;
	struct wide_leaf_9 __kptr *p9;
	struct wide_leaf_10 __kptr *p10;
	struct wide_leaf_11 __kptr *p11;
	struct wide_leaf_12 __kptr *p12;
	struct wide_leaf_13 __kptr *p13;
	struct wide_leaf_14 __kptr *p14;
	struct wide_leaf_15 __kptr *p15;
	struct wide_leaf_16 __kptr *p16;
	struct wide_leaf_17 __kptr *p17;
	struct wide_leaf_18 __kptr *p18;
	struct wide_leaf_19 __kptr *p19;
	struct wide_leaf_20 __kptr *p20;
	struct wide_leaf_21 __kptr *p21;
	struct wide_leaf_22 __kptr *p22;
	struct wide_leaf_23 __kptr *p23;
	struct wide_leaf_24 __kptr *p24;
	struct wide_leaf_25 __kptr *p25;
	struct wide_leaf_26 __kptr *p26;
	struct wide_leaf_27 __kptr *p27;
	struct wide_leaf_28 __kptr *p28;
	struct wide_leaf_29 __kptr *p29;
	struct wide_leaf_30 __kptr *p30;
	struct wide_leaf_31 __kptr *p31;
	struct wide_leaf_32 __kptr *p32;
	struct wide_leaf_33 __kptr *p33;
	struct wide_leaf_34 __kptr *p34;
	struct wide_leaf_35 __kptr *p35;
	struct wide_leaf_36 __kptr *p36;
	struct wide_leaf_37 __kptr *p37;
	struct wide_leaf_38 __kptr *p38;
	struct wide_leaf_39 __kptr *p39;
	struct wide_leaf_coro __kptr *p40;
};

struct wide_coro_holder {
	struct bpf_res_spin_lock lock;
	struct bpf_list_head head __contains(wide_coro_node, link);
};

SEC("xdp")
__failure __msg("a bpf_list_head whose nodes can hold a parked coro_frame has to be guarded by a bpf_spin_lock")
int many_types_and_a_frame_in_res_locked_list(struct xdp_md *ctx)
{
	struct wide_coro_holder *h = bpf_obj_new(typeof(*h));
	struct wide_coro_node *n;

	if (!h)
		return 0;
	n = bpf_obj_new(typeof(*n));
	if (!n) {
		bpf_obj_drop(h);
		return 0;
	}
	if (bpf_res_spin_lock(&h->lock)) {
		bpf_obj_drop(n);
		bpf_obj_drop(h);
		return 0;
	}
	bpf_list_push_back(&h->head, &n->link);
	bpf_res_spin_unlock(&h->lock);
	bpf_obj_drop(h);
	return 0;
}

/* No function is called under a lock, and helpers only with IRQs off */
SEC("xdp")
__failure __msg("a parked coro_frame cannot be called with a lock held or with IRQs off")
int resume_under_lock(struct xdp_md *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return 0;
	bpf_spin_lock(&lock);
	coro_call(coro, 0);
	bpf_spin_unlock(&lock);
	return 0;
}

SEC("xdp")
__failure __msg("a parked coro_frame cannot be called with a lock held or with IRQs off")
int resume_with_irqs_off(struct xdp_md *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;
	unsigned long flags;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (!coro)
		return 0;
	bpf_local_irq_save(&flags);
	coro_call(coro, 0);
	bpf_local_irq_restore(&flags);
	return 0;
}

struct timer_elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct timer_elem);
} timers SEC(".maps");

static int timer_resumes(void *map, int *key, struct bpf_timer *timer)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		coro_call(coro, 0);
	return 0;
}

/* The callback of a timer of an XDP program has no network context */
SEC("xdp")
__failure __msg("for a context that this code does not run in")
int resume_in_timer(struct xdp_md *ctx)
{
	struct timer_elem *e;
	__u32 idx = 0;

	e = bpf_map_lookup_elem(&timers, &idx);
	if (!e)
		return 0;
	bpf_timer_init(&e->t, &timers, 1 /* CLOCK_MONOTONIC */);
	bpf_timer_set_callback(&e->t, timer_resumes);
	return 0;
}

static __always_inline int park_with_cb(void *resume, void *cb)
{
	struct bpf_coro_xdp *coro;
	struct slot *s = the_slot();
	__u64 *f;

	if (!s)
		return 0;
	f = bpf_coro_frame_alloc(24, NULL);
	if (!f)
		return 0;
	f[0] = (__u64)resume;
	f[1] = (__u64)free_fn;
	f[2] = (__u64)cb;
	coro = bpf_kptr_xchg(&s->xdp, bpf_coro_park_xdp(f));
	if (coro)
		bpf_coro_drop_xdp(coro);
	return 0;
}

/*
 * A continuation that calls a parked frame in the callback of a helper, whose address its
 * frame carries: no call in its text leads there, and it is not found recursive.
 */
static int loop_resumes(__u64 i, void *ctx)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s)
		return 1;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		coro_call(coro, 0);
	return 1;
}

static __noinline __used void loops_fn(void *frame)
{
	void *cb = (void *)((__u64 *)frame)[2];

	bpf_coro_frame_free(frame);
	bpf_loop(1, cb, NULL, 0);
}

SEC("xdp")
__failure __msg("a coroutine continuation cannot call a parked coro_frame")
int resume_in_callback_of_continuation(struct xdp_md *ctx)
{
	return park_with_cb(loops_fn, loop_resumes);
}

/* The callback of a helper calls a parked frame like any code of the program */
SEC("xdp")
__success
int resume_in_callback(struct xdp_md *ctx)
{
	bpf_loop(1, loop_resumes, NULL, 0);
	return 0;
}

/* and in a function that such a callback calls, which is verified on its own */
static __noinline int resume_slot(__u32 idx)
{
	struct slot *s = slot_at(idx);
	struct bpf_coro_xdp *coro;

	if (!s)
		return 0;
	coro = bpf_kptr_xchg(&s->xdp, NULL);
	if (coro)
		coro_call(coro, 0);
	return 0;
}

static int loop_calls_resume(__u64 i, void *ctx)
{
	resume_slot(i);
	return 1;
}

static __noinline __used void loops_below_fn(void *frame)
{
	void *cb = (void *)((__u64 *)frame)[2];

	bpf_coro_frame_free(frame);
	bpf_loop(1, cb, NULL, 0);
}

SEC("xdp")
__failure __msg("calls a parked coro_frame, and a coroutine continuation gets to it")
int resume_below_callback_of_continuation(struct xdp_md *ctx)
{
	return park_with_cb(loops_below_fn, loop_calls_resume);
}

#define unwind_exit ".8byte 0x1095;"	/* BPF_JMP | BPF_EXIT, src_reg 1 */

/* unwind_exit of a continuation would unwind the program that calls it: its own, */
__naked __noinline __used
static void unwinds_fn(void *frame)
{
	asm volatile (
		"call %[bpf_coro_frame_free];"
		"r0 = 3;"
		unwind_exit
		:
		: __imm(bpf_coro_frame_free)
		: __clobber_all
	);
}

SEC("xdp")
__failure __msg("has unwind_exit, which would unwind into the program that calls a parked coro_frame")
int park_unwinds(struct xdp_md *ctx)
{
	return park_xdp(unwinds_fn, free_fn);
}

/* and that of a function which it calls and has no landing pad for */
__naked __noinline __used
static int unwinds(void)
{
	asm volatile (
		"r0 = 3;"
		unwind_exit
		::: __clobber_all
	);
}

static __noinline __used void passes_unwind_on_fn(void *frame)
{
	bpf_coro_frame_free(frame);
	unwinds();
}

SEC("xdp")
__failure __msg("is left by an unwinding of the program")
int park_passes_unwind_on(struct xdp_md *ctx)
{
	return park_xdp(passes_unwind_on_fn, free_fn);
}

/* The destroy function ends the coroutine: the kernel waits for that when the program goes */
static __noinline __used void destroy_parks_fn(void *frame)
{
	struct slot *s = the_slot();
	struct bpf_coro_xdp *coro;

	if (!s) {
		bpf_coro_frame_free(frame);
		return;
	}
	coro = bpf_kptr_xchg(&s->xdp, bpf_coro_park_xdp(frame));
	if (coro)
		bpf_coro_drop_xdp(coro);
}

SEC("xdp")
__failure __msg("the destroy function of a parked coro_frame cannot suspend a coro_frame")
int park_destroy_suspends(struct xdp_md *ctx)
{
	return park_xdp(free_fn, destroy_parks_fn);
}

char _license[] SEC("license") = "GPL";
