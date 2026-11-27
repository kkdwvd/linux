// SPDX-License-Identifier: GPL-2.0
/*
 * The tests of timed_may_goto.c that need help from user space. A prog whose time is up is
 * unwound: tc returns 2, TC_ACT_SHOT, then, and a syscall prog -ECANCELED.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define TRIES 4
#define CLOCK_MONOTONIC 1

int zero;

/* Return 1 if the loop went on until the time was up. */
static __always_inline int spin(void)
{
	__u64 t0 = bpf_ktime_get_ns();

	while (can_loop)
		;
	return bpf_ktime_get_ns() - t0 > 100 * 1000 * 1000;
}

static __noinline int spins(void)
{
	return spin();
}

static __noinline int counts_to_1000(void)
{
	int i, cnt = zero;

	for (i = zero; i < 1000 && can_loop; i++)
		cnt++;
	return cnt;
}

/* What a short loop counts before the time is up: user space sees that it got to its end */
int normal_cnt, tail_callee_cnt;

/* Nothing special: the loops go on, then the time is up and the prog is unwound. */
SEC("tc")
int normal_prog(void *ctx)
{
	int i, n = 10;

	normal_cnt = counts_to_1000();
	if (normal_cnt != 1000)
		return 100;
	for (i = 0; i < TRIES; i++)
		n += spins();
	return n;
}

/*
 * A subprog that cannot unwind: the comparator of bpf_rbtree_add() for a node that takes a lock
 * when it is freed. There may_goto jumps where the program says when the time is up, and the prog
 * goes on, see timed_may_goto.c.
 */
struct item {
	struct bpf_list_node link;
};

struct stuck_node {
	struct bpf_rb_node rb;
	struct bpf_spin_lock lock;
	struct bpf_list_head items __contains(item, link);
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(S) struct bpf_spin_lock stuck_lock;
private(S) struct bpf_rb_root stuck_root __contains(stuck_node, rb);

/* No code has an item: this puts it in BTF, for __contains() above */
void __item_btf_root(struct item *i)
{
}

long stuck_spun;

static bool less_uses_up_time(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	long n = zero;

	/* no helpers under the lock */
	while (can_loop)
		n++;
	stuck_spun = n > 1000 * 1000;
	return false;
}

/* Use up the time of the invocation, the prog goes on. Returns 0. */
static __always_inline int time_is_up(void)
{
	struct bpf_rb_node *rb;
	struct stuck_node *n;
	int i;

	stuck_spun = 0;
	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return 100;
		bpf_spin_lock(&stuck_lock);
		bpf_rbtree_add(&stuck_root, &n->rb, less_uses_up_time);
		bpf_spin_unlock(&stuck_lock);
	}
	for (i = 0; i < 2; i++) {
		bpf_spin_lock(&stuck_lock);
		rb = bpf_rbtree_first(&stuck_root);
		rb = rb ? bpf_rbtree_remove(&stuck_root, rb) : NULL;
		bpf_spin_unlock(&stuck_lock);
		if (!rb)
			return 101;
		bpf_obj_drop(container_of(rb, struct stuck_node, rb));
	}
	return !stuck_spun;
}

/*
 * Async callbacks
 */
struct elem {
	struct bpf_timer timer;
	struct bpf_wq wq;
	struct bpf_task_work tw;
	struct bpf_rcu_head rcu;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} async SEC(".maps");

int timer_cnt, wq_cnt, tw_cnt, rcu_cnt, rcu_trace_cnt;

static int timer_cb(void *map, int *key, struct elem *e)
{
	timer_cnt = counts_to_1000();
	return 0;
}

static int wq_cb(void *map, int *key, void *val)
{
	wq_cnt = counts_to_1000();
	return 0;
}

static int tw_cb(struct bpf_map *map, void *key, void *val)
{
	tw_cnt = counts_to_1000();
	return 0;
}

static int rcu_cb(struct bpf_map *map, void *key, void *val)
{
	rcu_cnt = counts_to_1000();
	return 0;
}

static int rcu_trace_cb(struct bpf_map *map, void *key, void *val)
{
	rcu_trace_cnt = counts_to_1000();
	return 0;
}

/*
 * The time of this prog is up when it starts the callbacks: a comparator has used it. User space
 * keeps the task on the cpu, so the callbacks find what it has left. Each call of a callback is an
 * invocation of its own.
 */
SEC("syscall")
int async_after_timeout(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct elem *e, *e1;
	int key = 0, key1 = 1;

	e = bpf_map_lookup_elem(&async, &key);
	e1 = bpf_map_lookup_elem(&async, &key1);
	if (!e || !e1)
		return 100;
	if (bpf_timer_init(&e->timer, &async, CLOCK_MONOTONIC) ||
	    bpf_timer_set_callback(&e->timer, timer_cb))
		return 101;
	if (bpf_wq_init(&e->wq, &async, 0) || bpf_wq_set_callback(&e->wq, wq_cb, 0))
		return 102;
	if (time_is_up())
		return 103;
	if (bpf_timer_start(&e->timer, 0, BPF_F_TIMER_CPU_PIN))
		return 104;
	if (bpf_wq_start(&e->wq, 0))
		return 105;
	if (bpf_task_work_schedule_resume(task, &e->tw, &async, tw_cb))
		return 106;
	if (bpf_call_rcu(&e->rcu, &async, rcu_cb))
		return 107;
	if (bpf_call_rcu_tasks_trace(&e1->rcu, &async, rcu_trace_cb))
		return 108;
	/* control: the time is up, the prog is unwound here and returns -ECANCELED */
	return 109 + counts_to_1000();
}

int ticks;

static int tick_cb(void *map, int *key, struct elem *e)
{
	if (counts_to_1000() != 1000)
		ticks = 1000;
	if (++ticks < 100)
		bpf_timer_start(&e->timer, 20 * 1000 * 1000, BPF_F_TIMER_CPU_PIN);
	return 0;
}

/*
 * A callback of the prog interrupts it, on the same cpu, each 20 ms. It has its own time. That
 * doesn't give more time to the prog: it is unwound when its own time is up. User space sees how
 * long that took.
 */
SEC("syscall")
int spin_under_timer(void *ctx)
{
	struct elem *e;
	int key = 1;

	e = bpf_map_lookup_elem(&async, &key);
	if (!e)
		return 100;
	if (bpf_timer_init(&e->timer, &async, CLOCK_MONOTONIC) ||
	    bpf_timer_set_callback(&e->timer, tick_cb) ||
	    bpf_timer_start(&e->timer, 20 * 1000 * 1000, BPF_F_TIMER_CPU_PIN))
		return 101;
	while (can_loop)
		;
	return 102;
}

/*
 * An async callback that uses up its own time. The kernel called its frame: it is unwound to its
 * exit, and does not get behind its loop. The prog that starts it has returned by then: a prog
 * that is still running on the cpu would share the count with the callback while the two take
 * turns there.
 */
struct spin_elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct spin_elem);
} async_spin SEC(".maps");

int wq_spins, wq_went_on;

static int wq_spin_cb(void *map, int *key, void *val)
{
	wq_spins = 1;
	wq_went_on = spins() + 1;
	return 0;
}

SEC("syscall")
int async_spins(void *ctx)
{
	struct spin_elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&async_spin, &key);
	if (!e)
		return 100;
	if (bpf_wq_init(&e->wq, &async_spin, 0) || bpf_wq_set_callback(&e->wq, wq_spin_cb, 0))
		return 101;
	return bpf_wq_start(&e->wq, 0) ? 102 : 0;
}

/*
 * Extension prog. A function that can unwind cannot be replaced: an extension ends in its main
 * prog. With a loop that may_goto stops that is replaced_global(). plain_global() cannot unwind.
 */
__noinline int replaced_global(int i)
{
	return spin() + i;
}

SEC("tc")
int freplace_target(void *ctx)
{
	int i, n = 10;

	for (i = 0; i < TRIES; i++)
		n += replaced_global(zero);
	return n;
}

int plain_global_calls;

/* It counts its calls: the compiler must not make one call of the calls in a loop */
__noinline int plain_global(int i)
{
	plain_global_calls++;
	return i + zero;
}

SEC("tc")
int freplace_plain_target(void *ctx)
{
	int i, n = 10;

	for (i = 0; i < TRIES; i++)
		n += plain_global(zero);
	return n;
}

/*
 * Tail calls
 */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} jmp_table SEC(".maps");

int tail_callee_runs;

/* It has its own time: the prog that makes the tail call may have none left */
SEC("tc")
int tail_callee(struct __sk_buff *skb)
{
	int i, n = 10;

	tail_callee_runs++;
	tail_callee_cnt = counts_to_1000();
	if (tail_callee_cnt != 1000)
		return 100;
	for (i = 0; i < TRIES; i++)
		n += spins();
	return n;
}

static __noinline int tail_calls(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &jmp_table, 0);
	return zero + 100;
}

/*
 * The target of the tail call is another prog. It is unwound when its time is up, and that ends
 * at its own exit: it returns 2 to this function, which goes on with the time that it has.
 */
SEC("tc")
int tail_call_in_subprog(struct __sk_buff *skb)
{
	int n;

	n = tail_calls(skb);
	if (counts_to_1000() != 1000)
		return 101;
	return 10 + n;
}

SEC("tc")
int tail_call_after_timeout(struct __sk_buff *skb)
{
	if (time_is_up())
		return 101;
	bpf_tail_call(skb, &jmp_table, 0);
	return 100;
}

static __noinline int throws(void)
{
	bpf_throw(7);
	return 0;
}

SEC("tc")
int throw_after_timeout(void *ctx)
{
	if (time_is_up())
		return 101;
	return throws();
}

/*
 * bpf_user_ringbuf_drain()
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

static long drain_cb(struct bpf_dynptr *dynptr, int *spun)
{
	*spun += spin();
	return 0;
}

/*
 * The callback is unwound, and the helper and the prog with it: -ECANCELED. The helper has taken
 * the sample of that call out of the buffer. With no sample left the prog returns 100.
 */
SEC("syscall")
int drain(void *ctx)
{
	int spun = 0;

	return 100 + bpf_user_ringbuf_drain(&user_ringbuf, drain_cb, &spun, 0) * 10 + spun;
}

/*
 * The count and the timestamp of may_goto are per prog and per cpu, the time is that of the wall
 * clock, and only the callers of async callbacks keep what another invocation has there. So an
 * invocation that is preempted shares them with the one that runs in its place: this prog, with
 * 'spin', uses up its time while the one without waits for the cpu. That one finds the count at 0
 * when it runs again and is unwound, with 60 ms of its own at most.
 */
struct shares_clock_args {
	int spin;
};

int victim_started, victim_done;
__u64 victim_ns;

/* The victim has to be preempted while it is in the prog: that takes a kernel which does that */
extern bool CONFIG_PREEMPT __kconfig __weak;
extern bool CONFIG_PREEMPT_LAZY __kconfig __weak;
extern bool CONFIG_PREEMPT_RT __kconfig __weak;
bool kernel_preempts;

SEC("syscall")
int shares_clock(struct shares_clock_args *args)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u64 start = task->se.sum_exec_runtime;

	kernel_preempts = CONFIG_PREEMPT || CONFIG_PREEMPT_LAZY || CONFIG_PREEMPT_RT;
	if (args->spin) {
		while (can_loop)
			;
		return 8;
	}
	victim_done = 0;
	victim_started = 1;
	/* 60 ms of this task on the cpu, whatever else runs there */
	while (can_loop) {
		victim_ns = task->se.sum_exec_runtime - start;
		if (victim_ns >= 60 * 1000 * 1000)
			break;
	}
	victim_done = 1;
	return 7;
}

/*
 * A tracing prog with large frames: they are in a private stack.
 */
int priv_stack_runs, priv_stack_spun, priv_stack_cb_spun;

static __noinline int spins_with_stack(void)
{
	volatile char buf[128] = {};

	return spin() + buf[zero & 127];
}

static int priv_stack_cb(__u64 i, int *spun)
{
	volatile char buf[128] = {};

	*spun += spin() + buf[zero & 127];
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(priv_stack)
{
	volatile char buf[128] = {};
	int i, n = buf[zero & 127], spun = 0;

	/* the first call is unwound in each run: the frames in the private stack are left */
	priv_stack_runs++;
	for (i = 0; i < TRIES; i++)
		n += spins_with_stack();
	bpf_loop(TRIES, priv_stack_cb, &spun, zero);
	priv_stack_spun = n;
	priv_stack_cb_spun = spun;
	return 0;
}
