// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>

/* The skeleton names the type of before and after and leaves it to us, see progs/cancel_throw.c */
struct held_state {
	int preempt;
	int rcu;
	int irq;
	int users;
	int spin;
	int res;
};

#include "cancel_throw.skel.h"
#include "cancel_throw_cost.skel.h"

/* What thrown() of progs/cancel_throw.c adds to the cookie */
#define THROWN	100

static char stream[64 * 1024];

/* Run @prog once. Returns what it returned, below 0 if the run failed. */
static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts),
		       bpf_program__name(prog)))
		return -1;
	return opts.retval;
}

/* What @prog wrote to its stderr stream since this was called last */
static const char *read_stream(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int fd = bpf_program__fd(prog), max = sizeof(stream) - 1, len = 0, n;

	do {
		n = bpf_prog_stream_read(fd, BPF_STREAM_STDERR, stream + len, max - len, &ropts);
		if (n > 0)
			len += n;
	} while (n > 0 && len < max);
	stream[len] = 0;
	return stream;
}

/* "@prog @of", to tell which prog an assertion is about */
static const char *what(struct bpf_program *prog, const char *of)
{
	static char buf[128];

	snprintf(buf, sizeof(buf), "%s %s", bpf_program__name(prog), of);
	return buf;
}

/*
 * The frames of @prog are gone and nothing of it ran behind the point. What they held is
 * released: the prog was entered in what it left, see note() in progs/cancel_throw.c.
 */
static void released(struct cancel_throw *skel, struct bpf_program *prog)
{
	struct held_state *b = &skel->bss->before, *a = &skel->bss->after;

	ASSERT_EQ(skel->bss->behind, 0, what(prog, "behind"));
	ASSERT_EQ(a->preempt, b->preempt, what(prog, "preempt count"));
	ASSERT_EQ(a->rcu, b->rcu, what(prog, "RCU nesting"));
	ASSERT_EQ(a->irq, b->irq, what(prog, "interrupts"));
	ASSERT_EQ(a->users, b->users, what(prog, "references to the task"));
	ASSERT_EQ(a->spin, 0, what(prog, "bpf_spin_lock"));
	ASSERT_EQ(a->res, 0, what(prog, "bpf_res_spin_lock"));
}

static void reset(struct cancel_throw *skel)
{
	skel->bss->behind = 0;
	skel->bss->callbacks = 0;
	skel->bss->cookie = ~0UL;
	memset(&skel->bss->before, -1, sizeof(skel->bss->before));
	memset(&skel->bss->after, -1, sizeof(skel->bss->after));
}

/*
 * @prog throws @cookie: its exception callback ran once, behind the pads, with the cookie, and
 * the prog returned what the callback returned. A throw is no cancellation: nothing is
 * reported.
 */
static void throws(struct cancel_throw *skel, struct bpf_program *prog, int cookie)
{
	reset(skel);
	ASSERT_EQ(run(prog), cookie + THROWN, what(prog, "retval"));
	ASSERT_EQ(skel->bss->callbacks, 1, what(prog, "callbacks"));
	ASSERT_EQ(skel->bss->cookie, cookie, what(prog, "cookie"));
	ASSERT_STREQ(read_stream(prog), "", what(prog, "stream"));
	released(skel, prog);
}

/* @prog is cancelled where it could have thrown: the callback does not run, and look() notes */
static void cancelled(struct cancel_throw *skel, struct bpf_program *prog)
{
	reset(skel);
	skel->bss->dive = 1;
	ASSERT_EQ(run(prog), TC_ACT_SHOT, what(prog, "retval"));
	skel->bss->dive = 0;
	ASSERT_EQ(skel->bss->callbacks, 0, what(prog, "callbacks"));
	ASSERT_HAS_SUBSTR(read_stream(prog), "ERROR: Program was cancelled", what(prog, "stream"));
	run(skel->progs.look);
	released(skel, prog);
}

static int on_record(void *ctx, void *data, size_t size)
{
	(*(int *)ctx)++;
	return 0;
}

/*
 * The record that @prog reserved is discarded: the consumer finds nothing, and nothing that
 * stops it. A record that was neither submitted nor discarded stays in front of it for good.
 */
static void discarded(struct cancel_throw *skel, struct bpf_program *prog)
{
	struct ring_buffer *rb;
	int records = 0;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), on_record, &records, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		return;
	ring_buffer__consume(rb);
	ASSERT_EQ(records, 0, what(prog, "records"));
	ASSERT_EQ(ring__avail_data_size(ring_buffer__ring(rb, 0)), 0, what(prog, "ringbuf"));
	ring_buffer__free(rb);
}

void test_cancel_throw(void)
{
	struct bpf_program *prog;
	struct cancel_throw *skel;
	int path;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs, and what those return that always do the same */
	RUN_TESTS(cancel_throw);
	/* and that what bpf_throw() keeps live for the pads leaves them few states */
	RUN_TESTS(cancel_throw_cost);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = cancel_throw__open();
	if (!ASSERT_OK_PTR(skel, "cancel_throw__open"))
		return;
	/* the ones that are rejected */
	bpf_program__set_autoload(skel->progs.handle_gone, false);
	bpf_program__set_autoload(skel->progs.handle_in_r2, false);
	bpf_program__set_autoload(skel->progs.handle_in_one_of_two_slots, false);
	if (!ASSERT_OK(cancel_throw__load(skel), "cancel_throw__load"))
		goto out;

	if (test__start_subtest("locks")) {
		throws(skel, skel->progs.irq_and_lock_in_main, 1);
		throws(skel, skel->progs.locks_in_two_frames, 2);
	}
	if (test__start_subtest("references")) {
		throws(skel, skel->progs.task_in_main, 3);
		throws(skel, skel->progs.task_in_r0, 4);
		throws(skel, skel->progs.iter_and_task_in_main, 5);
	}
	if (test__start_subtest("frames")) {
		throws(skel, skel->progs.holds_through_frames, 6);
		throws(skel, skel->progs.holds_through_global, 7);
	}
	if (test__start_subtest("cancelled or thrown")) {
		throws(skel, skel->progs.cancelled_or_thrown, 8);
		cancelled(skel, skel->progs.cancelled_or_thrown);
		throws(skel, skel->progs.passed_on, 9);
		cancelled(skel, skel->progs.passed_on);
	}
	/* nothing behind bpf_throw() reads the handle: the pad finds it where bpf_throw() reads */
	if (test__start_subtest("places")) {
		throws(skel, skel->progs.handle_in_r6, 11);
		throws(skel, skel->progs.handle_in_slot, 12);
		throws(skel, skel->progs.handle_filled, 26);
		throws(skel, skel->progs.handle_through_pointer, 13);
		throws(skel, skel->progs.handle_returned, 14);
		throws(skel, skel->progs.handle_given_to_callee, 15);
		throws(skel, skel->progs.handle_stored_by_callee, 16);
		throws(skel, skel->progs.handle_in_slot_below, 17);
		throws(skel, skel->progs.lock_in_map_value, 18);
		throws(skel, skel->progs.lock_pointer_from_callback, 28);
		/* where the compiler and the JIT have callx */
		prog = bpf_object__find_program_by_name(skel->obj, "handle_given_through_callx");
		if (prog)
			throws(skel, prog, 27);
		throws(skel, skel->progs.iter_in_callee, 23);
		throws(skel, skel->progs.ringbuf_record_in_r6, 24);
		discarded(skel, skel->progs.ringbuf_record_in_r6);
	}
	/* the states of two paths are apart at bpf_throw(), and one pad is right for both */
	if (test__start_subtest("two paths")) {
		for (path = 0; path < 2; path++) {
			skel->bss->path = path;
			throws(skel, skel->progs.lock_chosen_at_run_time, 19);
			throws(skel, skel->progs.handle_in_slot_or_reg, 21);
			throws(skel, skel->progs.held_on_one_path, 22);
		}
		skel->bss->path = 0;
	}
	if (test__start_subtest("no callback")) {
		reset(skel);
		ASSERT_EQ(run(skel->progs.no_callback), 10, "no_callback retval");
		ASSERT_EQ(skel->bss->callbacks, 0, "no_callback callbacks");
		run(skel->progs.look);
		released(skel, skel->progs.no_callback);
	}
out:
	cancel_throw__destroy(skel);
}
