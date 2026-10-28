// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "exceptions_cleanup.skel.h"

/*
 * Run @prog and check what the unwinder released against what the program
 * recorded acquiring: @released of the @acquired resources, the last acquired
 * first when @ordered, and @sections RCU or preemption sections.
 */
static void run_prog(struct exceptions_cleanup *skel, struct bpf_program *prog, int acquired,
		     int released, int sections, bool ordered, int retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, ropts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int ret, i;

	skel->bss->acquired_cnt = 0;
	skel->bss->released_cnt = 0;
	skel->bss->sections_cnt = 0;
	memset(skel->bss->acquired, 0, sizeof(skel->bss->acquired));
	memset(skel->bss->released, 0, sizeof(skel->bss->released));

	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &ropts);
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

/* Run every program; @prefix names the pass in the subtest names. */
static void run_suite(const char *prefix)
{
	struct exceptions_cleanup *skel;
	char name[64];

	skel = exceptions_cleanup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "exceptions_cleanup__open_and_load"))
		return;
	if (!ASSERT_OK(exceptions_cleanup__attach(skel), "attach"))
		goto out;

#define RUN(pname, n, released, sections, ordered, retval) do {			\
	snprintf(name, sizeof(name), "%s%s", prefix, #pname);			\
	if (test__start_subtest(name))						\
		run_prog(skel, skel->progs.pname, n, released, sections, ordered, retval); \
} while (0)
#define THROW(name, n) RUN(name, n, n, 0, false, 0xeB9F)
	THROW(throw_obj_reg, 1);
	THROW(throw_obj_two, 2);
	THROW(throw_ringbuf, 1);
	THROW(throw_task, 1);
	THROW(throw_iter, 1);
	THROW(throw_obj_maybe, 1);
	THROW(throw_obj_caller, 1);
	THROW(throw_obj_unconditional, 1);
	THROW(throw_obj_subprog, 1);
	THROW(throw_obj_global_caller, 1);
	THROW(throw_slot, 1);
	RUN(throw_spin_lock, 2, 2, 0, true, 0xeB9F);
	RUN(throw_rcu, 1, 1, 1, true, 0xeB9F);
	RUN(throw_irq, 1, 1, 1, true, 0xeB9F);
#undef THROW
#undef RUN
out:
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
