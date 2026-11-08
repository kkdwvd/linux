// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions_cleanup.skel.h"

/* The cookie the programs throw. */
#define THROWN		0xeB9F

/*
 * What a run of a program has to show: its return value, the number of
 * resources the program recorded acquiring, and the releases observed, in
 * order, as a string: a digit names the acquired resource released at that
 * point, 's' an RCU or preemption section, '?' any acquired resource not
 * named elsewhere. @param is a choice the program reads.
 */
struct expect {
	int retval;
	int acquired;
	const char *released;
	__u32 param;
};

static void check_releases(struct exceptions_cleanup *skel, const struct expect *e)
{
	bool matched[ARRAY_SIZE(skel->bss->acquired)] = {};
	int n = strlen(e->released), i, j;

	ASSERT_EQ(skel->bss->acquired_cnt, e->acquired, "acquired");
	if (!ASSERT_EQ(skel->bss->released_cnt, n, "released"))
		return;
	for (i = 0; i < n; i++) {
		__u64 handle = skel->bss->released[i];
		char c = e->released[i];

		if (c == 's') {
			ASSERT_TRUE(skel->bss->released_section[i], "section");
			continue;
		}
		if (!ASSERT_FALSE(skel->bss->released_section[i], "not a section"))
			continue;
		if (c == '?') {
			for (j = 0; j < e->acquired; j++)
				if (!matched[j] && handle == skel->bss->acquired[j])
					break;
			if (ASSERT_LT(j, e->acquired, "released an acquired resource"))
				matched[j] = true;
			continue;
		}
		j = c - '0';
		if (ASSERT_EQ(handle, skel->bss->acquired[j], "release order"))
			matched[j] = true;
	}
}

static void reset(struct exceptions_cleanup *skel, __u32 param)
{
	skel->bss->acquired_cnt = 0;
	skel->bss->released_cnt = 0;
	memset(skel->bss->acquired, 0, sizeof(skel->bss->acquired));
	memset(skel->bss->released, 0, sizeof(skel->bss->released));
	memset(skel->bss->released_section, 0, sizeof(skel->bss->released_section));
	skel->bss->param = param;
	skel->bss->test_pid = getpid();
}

/* Run @prog once and check what it returned and what was released against @e. */
static void run_prog(struct exceptions_cleanup *skel, struct bpf_program *prog,
		     const struct expect *e)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int ret;

	reset(skel, e->param);
	/* A syscall program runs on nothing: no input, and once, without a repeat count. */
	if (bpf_program__type(prog) == BPF_PROG_TYPE_SYSCALL) {
		ropts.data_in = NULL;
		ropts.data_size_in = 0;
		ropts.repeat = 0;
	}
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &ropts);
	if (!ASSERT_OK(ret, "test_run"))
		return;
	ASSERT_EQ(ropts.retval, e->retval, "retval");
	check_releases(skel, e);
}

/* Run every program; @prefix names the pass in the subtest names. */
static void run_suite(const char *prefix)
{
	struct exceptions_cleanup *skel;
	int server = -1;
	char name[64];

	skel = exceptions_cleanup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "exceptions_cleanup__open_and_load"))
		return;
	if (!ASSERT_OK(exceptions_cleanup__attach(skel), "attach"))
		goto out;
	/* The listener throw_sock_cast looks up, on an ephemeral port. */
	server = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_OK_FD(server, "start_server"))
		goto out;
	skel->bss->server_port = get_socket_local_port(server);

/* Run program @pname as subtest @sname, expecting @ret, @n acquisitions and the releases @rel. */
#define RUN_AS(pname, sname, ret, n, rel, ...) do {				\
	struct expect e = { .retval = ret, .acquired = n, .released = rel, ##__VA_ARGS__ }; \
										\
	snprintf(name, sizeof(name), "%s%s", prefix, sname);			\
	if (test__start_subtest(name))						\
		run_prog(skel, skel->progs.pname, &e);				\
} while (0)
#define RUN(pname, ret, n, rel, ...) RUN_AS(pname, #pname, ret, n, rel, ##__VA_ARGS__)
#define THROW(pname, n, rel, ...) RUN(pname, THROWN, n, rel, ##__VA_ARGS__)
	THROW(throw_obj_reg, 1, "0");
	THROW(throw_obj_two, 2, "??");
	THROW(throw_ringbuf, 1, "0");
	THROW(throw_task, 1, "0");
	THROW(throw_sock_cast, 1, "0");
	THROW(throw_iter, 1, "0");
	THROW(throw_obj_maybe, 1, "0");
	THROW(throw_obj_caller, 1, "0");
	THROW(throw_obj_callx_caller, 1, "0");
	RUN_AS(throw_obj_callx_targets_disagree, "throw_obj_callx_targets_disagree_kept", THROWN, 1,
	       "0", .param = 0);
	RUN_AS(throw_obj_callx_targets_disagree, "throw_obj_callx_targets_disagree_dropped", THROWN,
	       1, "", .param = 1);
	THROW(throw_obj_origin_after_guard, 1, "0");
	THROW(throw_obj_unconditional, 1, "0");
	THROW(throw_obj_dead_caller, 1, "0");
	THROW(throw_obj_subprog, 1, "0");
	THROW(throw_obj_global_caller, 1, "0");
	/* Locks and IRQ flags go first, sections next, objects last. */
	THROW(throw_spin_lock, 2, "10");
	THROW(throw_rcu, 1, "s0");
	THROW(throw_irq, 1, "0s");
	THROW(throw_obj_after_caller_lock, 2, "01");
	THROW(throw_sleeping_dtor_after_section, 1, "s0");
	/* Mirrors: references no location of the frame holds on every path. */
	THROW(throw_mirror_conflict, 1, "0");
	THROW(throw_mirror_dead, 1, "0");
	THROW(throw_mirror_lock_two_locations, 2, "01");
	RUN_AS(throw_mirror_shared_release, "throw_mirror_shared_release_first", THROWN, 2, "1",
	       .param = 0);
	RUN_AS(throw_mirror_shared_release, "throw_mirror_shared_release_second", THROWN, 2, "0",
	       .param = 1);
	RUN_AS(throw_refcount_shared_release, "throw_refcount_shared_release_first", THROWN, 1, "0",
	       .param = 0);
	RUN_AS(throw_refcount_shared_release, "throw_refcount_shared_release_second", THROWN, 1, "0",
	       .param = 1);
	RUN_AS(throw_mirror_refresh, "throw_mirror_refresh_kept", THROWN, 1, "0", .param = 0);
	RUN_AS(throw_mirror_refresh, "throw_mirror_refresh_discarded", THROWN, 1, "", .param = 1);
	RUN_AS(throw_mirror_pad_before_call, "throw_mirror_pad_before_call_returned", THROWN, 1, "0",
	       .param = 0);
	RUN_AS(throw_mirror_pad_before_call, "throw_mirror_pad_before_call_unwound", 42, 0, "",
	       .param = 1);
	/* The transfer: what a callee releases of its caller's, the callee lists and the call omits. */
	THROW(throw_callee_drops_obj, 2, "1");
	THROW(throw_callee_unlocks, 2, "0");
	THROW(throw_callee_destroys_iter, 2, "1");
	THROW(throw_callee_restores_irq, 2, "1");
	THROW(throw_iter_by_callee, 1, "0");
	/* Chains: what a callee releases under one chain of calls and not under another. */
	RUN_AS(throw_release_if, "throw_release_if_callee", THROWN, 1, "", .param = 0);
	RUN_AS(throw_release_if, "throw_release_if_caller", THROWN, 1, "0", .param = 1);
	RUN_AS(throw_irq_order, "throw_irq_order_enabled_first", THROWN, 2, "10s", .param = 1);
	RUN_AS(throw_irq_order, "throw_irq_order_enabled_last", THROWN, 2, "01", .param = 0);
	/* The register a callee lists under one chain holds what the caller lists under another. */
	RUN_AS(throw_arrival_listed_by_one_chain, "throw_arrival_listed_by_one_chain_caller", THROWN, 1,
	       "0", .param = 0);
	RUN_AS(throw_arrival_listed_by_one_chain, "throw_arrival_listed_by_one_chain_callee", THROWN, 1,
	       "0", .param = 1);
	RUN_AS(throw_arrival_listed_by_one_chain, "throw_arrival_listed_by_one_chain_discarded", THROWN,
	       1, "", .param = 3);
	/* A record arriving in a register under one chain and by a load under another, discarded by a callee. */
	RUN_AS(throw_mirror_arrives_two_ways, "throw_mirror_arrives_two_ways_reg_kept", THROWN, 1, "0",
	       .param = 0);
	RUN_AS(throw_mirror_arrives_two_ways, "throw_mirror_arrives_two_ways_reg_discarded", THROWN, 1,
	       "", .param = 1);
	RUN_AS(throw_mirror_arrives_two_ways, "throw_mirror_arrives_two_ways_load_kept", THROWN, 1, "0",
	       .param = 2);
	RUN_AS(throw_mirror_arrives_two_ways, "throw_mirror_arrives_two_ways_load_discarded", THROWN, 1,
	       "", .param = 3);
	/* A recursive subprog holding an object per frame: each frame owns its own. */
	THROW(throw_recursion_holding, 4, "3210");
#undef THROW
#undef RUN
#undef RUN_AS
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
