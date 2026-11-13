// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "cancel.skel.h"
#include "cancel_attach.skel.h"

static char log_buf[16 * 1024];
static char stream[64 * 1024];

static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

/*
 * The frames of the recursion count themselves on the way down, and what is behind a call
 * counts too. The test loader checks the return value and the stream of the same progs,
 * but it cannot read their variables.
 */
static void test_nothing_behind(struct cancel *skel, struct bpf_program *prog, int retval)
{
	skel->bss->frames = 0;
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), retval, "retval");
	ASSERT_GT(skel->bss->frames, 8, "frames");
	ASSERT_EQ(skel->bss->behind, 0, "behind");
}

/*
 * The callback of the timer runs when the prog that armed it has returned. The last thing
 * that it does is the line that its pad writes to the stream: wait for it.
 */
static void test_timer(struct cancel *skel)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int fd = bpf_program__fd(skel->progs.timer_recursion);
	const char *report, *cancelled = NULL;
	int i, n, len = 0;

	skel->bss->frames = 0;
	skel->bss->behind = 0;
	if (!ASSERT_EQ(run(skel->progs.timer_recursion), 0, "retval"))
		return;
	for (i = 0; i < 500 && !cancelled; i++) {
		n = bpf_prog_stream_read(fd, BPF_STREAM_STDERR, stream + len,
					 sizeof(stream) - len - 1, &ropts);
		if (n > 0)
			len += n;
		stream[len] = 0;
		cancelled = strstr(stream, "ERROR: Program was cancelled");
		if (!cancelled)
			usleep(10000);
	}
	if (!ASSERT_TRUE(cancelled != NULL, "cancelled"))
		return;
	report = strstr(stream, "ERROR: No room in the stack for a call of a recursive function");
	ASSERT_TRUE(report && report < cancelled, "report of the stack check");
	ASSERT_GT(skel->bss->frames, 8, "frames");
	ASSERT_EQ(skel->bss->behind, 0, "behind");
}

/*
 * Load prog @name of cancel_attach.c for global_spins() of @tgt. Returns the skeleton, with
 * what the load returned in @err and what the verifier said in log_buf.
 */
static struct cancel_attach *load_for_target(struct bpf_program *tgt, const char *name, int *err)
{
	struct cancel_attach *skel;
	struct bpf_program *prog;

	skel = cancel_attach__open();
	if (!ASSERT_OK_PTR(skel, "cancel_attach__open"))
		return NULL;
	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto err;
	bpf_program__set_autoload(prog, true);
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	/* the stats */
	bpf_program__set_log_level(prog, 4);
	if (!ASSERT_OK(bpf_program__set_attach_target(prog, bpf_program__fd(tgt), "global_spins"),
		       "set_attach_target"))
		goto err;
	*err = cancel_attach__load(skel);
	return skel;
err:
	cancel_attach__destroy(skel);
	return NULL;
}

/* The loop of the extension declines: the caller of its frame has no pad for it */
static const char freplace_stats[] =
	"cancel sites 1 padded 0 declined refs 0 section 0 cond 0 callback 0 caller 1";

static void test_attach(struct cancel *tgt)
{
	struct bpf_program *tgt_prog = tgt->progs.calls_global_spins;
	struct cancel_attach *skel;
	struct bpf_link *link;
	int err;

	/* cancel_exit of the target would return to the trampoline, which returns to the caller */
	skel = load_for_target(tgt_prog, "fexit_cancel", &err);
	if (!skel)
		return;
	ASSERT_ERR(err, "fexit_cancel");
	ASSERT_HAS_SUBSTR(log_buf, "Only fentry can attach to global_spins, which can be cancelled",
			  "fexit_cancel");
	cancel_attach__destroy(skel);

	/*
	 * The trampoline of fentry returns into the target, and the target to the pad of its
	 * call. The loop spins until the time slice is over.
	 */
	skel = load_for_target(tgt_prog, "fentry_cancel", &err);
	if (!skel)
		return;
	link = NULL;
	if (ASSERT_OK(err, "fentry_cancel"))
		link = bpf_program__attach(skel->progs.fentry_cancel);
	if (!err && ASSERT_OK_PTR(link, "attach")) {
		ASSERT_EQ(run(tgt_prog), TC_ACT_SHOT, "retval");
		ASSERT_EQ(skel->bss->fentry_cnt, 1, "fentry_cnt");
	}
	bpf_link__destroy(link);
	cancel_attach__destroy(skel);

	/* An extension can replace the target. It is not cancelled itself. */
	skel = load_for_target(tgt_prog, "freplace_spins", &err);
	if (!skel)
		return;
	if (ASSERT_OK(err, "freplace_spins"))
		ASSERT_HAS_SUBSTR(log_buf, freplace_stats, "freplace_spins");
	cancel_attach__destroy(skel);
}

/*
 * Serial: some progs spin for 250 ms in an RCU read-side critical section, see
 * timed_may_goto.c.
 */
void serial_test_cancel(void)
{
	struct bpf_program *prog;
	struct cancel *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	RUN_TESTS(cancel);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = cancel__open();
	if (!ASSERT_OK_PTR(skel, "cancel__open"))
		return;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, prog == skel->progs.recursion_tc ||
						prog == skel->progs.recursion_socket ||
						prog == skel->progs.timer_recursion ||
						prog == skel->progs.calls_global_spins);
	if (!ASSERT_OK(cancel__load(skel), "cancel__load"))
		goto out;

	if (test__start_subtest("nothing_behind")) {
		test_nothing_behind(skel, skel->progs.recursion_tc, TC_ACT_SHOT);
		test_nothing_behind(skel, skel->progs.recursion_socket, 0);
	}
	if (test__start_subtest("timer"))
		test_timer(skel);
	if (test__start_subtest("attach"))
		test_attach(skel);
out:
	cancel__destroy(skel);
}
