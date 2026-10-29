// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions_cleanup.skel.h"

/* bpf_find_vma() in the test program looks this up in the test process. */
static int vma_target;

/*
 * Run @prog and check what the unwinder released against what the program
 * recorded acquiring: @released of the @acquired resources, the last acquired
 * first when @ordered, and @sections RCU or preemption sections. @hook is a
 * tracing program that records releases the unwinder does not perform, attached
 * for this run, or NULL.
 */
static void run_prog(struct exceptions_cleanup *skel, struct bpf_program *prog,
		     struct bpf_program *hook, int acquired, int released, int sections,
		     bool ordered, int retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct bpf_link *link = NULL, *hook_link = NULL;
	int ret, i;

	skel->bss->acquired_cnt = 0;
	skel->bss->released_cnt = 0;
	skel->bss->sections_cnt = 0;
	memset(skel->bss->acquired, 0, sizeof(skel->bss->acquired));
	memset(skel->bss->released, 0, sizeof(skel->bss->released));
	skel->bss->vma_addr = (__u64)(long)&vma_target;

	/*
	 * A tracing program runs on its hook and a syscall program on nothing:
	 * no input. The hook of a tracing program fires for every test run of a
	 * tracing program in the system, so it is attached for this run only.
	 */
	if (bpf_program__type(prog) == BPF_PROG_TYPE_TRACING ||
	    bpf_program__type(prog) == BPF_PROG_TYPE_SYSCALL) {
		ropts.data_in = NULL;
		ropts.data_size_in = 0;
	}
	if (bpf_program__type(prog) == BPF_PROG_TYPE_TRACING) {
		link = bpf_program__attach(prog);
		if (!ASSERT_OK_PTR(link, "attach"))
			return;
	}
	if (hook) {
		hook_link = bpf_program__attach(hook);
		if (!ASSERT_OK_PTR(hook_link, "attach hook")) {
			bpf_link__destroy(link);
			return;
		}
	}
	/* A syscall program is run once, without a repeat count. */
	if (bpf_program__type(prog) == BPF_PROG_TYPE_SYSCALL)
		ropts.repeat = 0;
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &ropts);
	bpf_link__destroy(hook_link);
	bpf_link__destroy(link);
	if (!ASSERT_OK(ret, "test_run"))
		return;
	ASSERT_EQ(ropts.retval, retval, "retval");
	ASSERT_EQ(skel->bss->acquired_cnt, acquired, "acquired");
	ASSERT_EQ(skel->bss->released_cnt, released, "released");
	ASSERT_EQ(skel->bss->sections_cnt, sections, "sections");
	for (i = 0; i < released; i++) {
		ASSERT_NEQ(skel->bss->released[i], 0, "released ptr");
		if (ordered)
			ASSERT_EQ(skel->bss->released[i], skel->bss->acquired[acquired - 1 - i],
				  "release order");
	}
}

/* The timer callback runs once the program returned: wait for its cancellation. */
static void run_timer(struct exceptions_cleanup *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int i;

	skel->bss->acquired_cnt = 0;
	skel->bss->released_cnt = 0;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.cancel_may_goto_timer),
					      &ropts), "test_run"))
		return;
	ASSERT_EQ(ropts.retval, 0, "retval");
	for (i = 0; i < 300 && skel->bss->released_cnt < 1; i++)
		usleep(10000);
	ASSERT_EQ(skel->bss->acquired_cnt, 1, "timer acquired");
	ASSERT_EQ(skel->bss->released_cnt, 1, "timer released");
	ASSERT_EQ(skel->bss->released[0], skel->bss->acquired[0], "timer released ptr");
}

/* Run every program; @prefix names the pass in the subtest names. */
static void run_suite(const char *prefix)
{
	struct exceptions_cleanup *skel;
	int server = -1;
	char name[64];

	skel = exceptions_cleanup__open();
	if (!ASSERT_OK_PTR(skel, "exceptions_cleanup__open"))
		return;
	/* Attached by their runs only, see run_prog(). */
	bpf_program__set_autoattach(skel->progs.cancel_may_goto_priv_stack, false);
	bpf_program__set_autoload(skel->progs.drop_hook, true);
	bpf_program__set_autoattach(skel->progs.drop_hook, false);
	if (!ASSERT_OK(exceptions_cleanup__load(skel), "exceptions_cleanup__load"))
		goto out;
	if (!ASSERT_OK(exceptions_cleanup__attach(skel), "attach"))
		goto out;
	/* The listener throw_sock_cast looks up, on an ephemeral port. */
	server = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_OK_FD(server, "start_server"))
		goto out;
	skel->bss->server_port = get_socket_local_port(server);

#define RUN_HOOK(pname, hook, n, released, sections, ordered, retval) do {	\
	snprintf(name, sizeof(name), "%s%s", prefix, #pname);			\
	if (test__start_subtest(name))						\
		run_prog(skel, skel->progs.pname, hook, n, released, sections, ordered, \
			 retval);						\
} while (0)
#define RUN(pname, n, released, sections, ordered, retval) \
	RUN_HOOK(pname, NULL, n, released, sections, ordered, retval)
#define THROW(name, n) RUN(name, n, n, 0, false, 0xeB9F)
	THROW(throw_obj_reg, 1);
	THROW(throw_obj_two, 2);
	THROW(throw_ringbuf, 1);
	THROW(throw_task, 1);
	THROW(throw_sock_cast, 1);
	THROW(throw_iter, 1);
	THROW(throw_obj_maybe, 1);
	THROW(throw_obj_caller, 1);
	THROW(throw_obj_callx_caller, 1);
	THROW(throw_obj_unconditional, 1);
	THROW(throw_obj_dead_caller, 1);
	THROW(throw_obj_subprog, 1);
	THROW(throw_obj_global_caller, 1);
	THROW(throw_slot, 1);
	/* The kernel resumed the continuation: the program completes after the throw in it. */
	RUN(throw_coro_cont, 2, 2, 0, true, 0);
	RUN(throw_spin_lock, 2, 2, 0, true, 0xeB9F);
	RUN(throw_rcu, 1, 1, 1, true, 0xeB9F);
	RUN(throw_irq, 1, 1, 1, true, 0xeB9F);
	/* A cancelled tc program returns TC_ACT_SHOT. */
#define CANCEL(name, n, sections) RUN(name, n, n, sections, true, 2)
	CANCEL(cancel_may_goto_obj, 1, 0);
	CANCEL(cancel_may_goto_caller, 1, 0);
	CANCEL(cancel_may_goto_slot, 1, 0);
	CANCEL(cancel_may_goto_rcu, 1, 1);
	CANCEL(cancel_may_goto_rcu_shared, 1, 1);
	CANCEL(cancel_may_goto_preempt, 0, 3);
	CANCEL(cancel_may_goto_spin_lock, 2, 0);
	CANCEL(cancel_may_goto_obj_lock, 2, 0);
	CANCEL(cancel_may_goto_lock_caller, 2, 0);
	CANCEL(cancel_may_goto_res_lock, 1, 0);
	CANCEL(cancel_may_goto_res_lock_irq, 2, 0);
	CANCEL(cancel_may_goto_irq, 1, 0);
	CANCEL(cancel_may_goto_irq_shared, 2, 0);
	CANCEL(cancel_may_goto_nested, 4, 1);
	CANCEL(cancel_may_goto_global, 1, 0);
	CANCEL(cancel_may_goto_global_chain, 1, 0);
	/* Released locks can be taken again: a leaked resilient lock fails instead of hanging. */
	CANCEL(cancel_may_goto_res_lock, 1, 0);
	CANCEL(cancel_may_goto_res_lock_irq, 2, 0);
	/* Sites in callbacks: the callback is unwound and the cancellation goes on from the call. */
	CANCEL(cancel_may_goto_loop, 1, 0);
	CANCEL(cancel_may_goto_loop_helper, 1, 0);
	CANCEL(cancel_may_goto_global_callback, 1, 0);
	CANCEL(cancel_may_goto_shared_subprog, 1, 0);
	CANCEL(cancel_may_goto_for_each_array, 1, 0);
	CANCEL(cancel_may_goto_for_each_hash, 1, 0);
	CANCEL(cancel_may_goto_for_each_helper, 1, 0);
	/* The kfunc drops the node it was adding before the unwinder releases the lock. */
	RUN_HOOK(cancel_may_goto_rbtree_less, skel->progs.drop_hook, 2, 2, 0, false, 2);
	CANCEL(cancel_may_goto_exception_cb, 1, 0);
	RUN(cancel_may_goto_coro_cont, 2, 2, 0, true, 0);
	/* A cancelled syscall or tracing program returns 0. */
	RUN(cancel_may_goto_find_vma, 1, 1, 0, true, 0);
	RUN(cancel_may_goto_priv_stack, 1, 1, 0, true, 0);
	snprintf(name, sizeof(name), "%scancel_may_goto_timer", prefix);
	if (test__start_subtest(name))
		run_timer(skel);
	/* An arena page fault cancels the program as a may_goto timeout does. */
	CANCEL(cancel_arena_read, 1, 0);
	CANCEL(cancel_arena_write, 1, 0);
	CANCEL(cancel_arena_caller, 1, 0);
	CANCEL(cancel_arena_global, 1, 0);
	CANCEL(cancel_arena_fetch_r0, 1, 0);
	CANCEL(cancel_arena_loop, 1, 0);
	CANCEL(cancel_arena_loop_helper, 1, 0);
#undef CANCEL
#undef THROW
#undef RUN
#undef RUN_HOOK
out:
	if (server >= 0)
		close(server);
	exceptions_cleanup__destroy(skel);
}

void test_exceptions_cleanup(void)
{
	run_suite("");
	/* Constant blinding rewrites the program after the descriptors are keyed. */
	if (!ASSERT_OK(write_sysctl("/proc/sys/net/core/bpf_jit_harden", "2"), "bpf_jit_harden"))
		return;
	run_suite("harden_");
	write_sysctl("/proc/sys/net/core/bpf_jit_harden", "0");
}
