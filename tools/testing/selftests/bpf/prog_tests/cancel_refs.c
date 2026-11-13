// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "cancel_refs.skel.h"

static char stream[64 * 1024];

/* Run @prog once. Returns what it returned. */
static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	/* a syscall prog takes no packet */
	if (bpf_program__type(prog) != BPF_PROG_TYPE_SYSCALL) {
		opts.data_in = data;
		opts.data_size_in = sizeof(data);
		opts.repeat = 1;
	}
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

static bool is_tc(struct bpf_program *prog)
{
	return bpf_program__type(prog) == BPF_PROG_TYPE_SCHED_CLS;
}

/*
 * @prog is cancelled: it returns the cancel value of its type where its last insn returns
 * something else, its pad says so in the stream, and nothing ran behind a call of the
 * recursion.
 */
static void cancelled(struct cancel_refs *skel, struct bpf_program *prog)
{
	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), is_tc(prog) ? TC_ACT_SHOT : 0, what(prog, "retval"));
	ASSERT_EQ(skel->bss->behind, 0, what(prog, "behind"));
	ASSERT_HAS_SUBSTR(read_stream(prog), "ERROR: Program was cancelled", what(prog, "stream"));
}

static int records;

static int on_record(void *ctx, void *data, size_t size)
{
	records++;
	return 0;
}

/*
 * A record that was neither submitted nor discarded stops the consumer in front of it for
 * good. The ring buffer of the progs has no such record and none that was submitted: it is
 * empty, and a record that is submitted now gets to the consumer.
 */
static void ringbuf_is_clean(struct cancel_refs *skel, struct ring_buffer *rb, const char *name)
{
	records = 0;
	ring_buffer__consume(rb);
	ASSERT_EQ(records, 0, name);
	ASSERT_EQ(ring__avail_data_size(ring_buffer__ring(rb, 0)), 0, name);
	run(skel->progs.ringbuf_submit);
	ring_buffer__consume(rb);
	ASSERT_EQ(records, 1, name);
}

static void test_iters(struct cancel_refs *skel)
{
	/* bpf_iter_num and the iterator of the module leave nothing behind that could be found */
	cancelled(skel, skel->progs.num_iter_at_call);
	cancelled(skel, skel->progs.testmod_iter_at_call);
	/* a prog that returns to user space inside of an RCU section draws a splat */
	cancelled(skel, skel->progs.task_iter_in_rcu);
}

/* The references to the task that runs the progs, and the users of its mm */
static void current_users(struct cancel_refs *skel, int *usage, int *mm_users)
{
	run(skel->progs.probe_current);
	*usage = skel->bss->cur_usage;
	*mm_users = skel->bss->cur_mm_users;
}

static void test_dynptrs(struct cancel_refs *skel, struct ring_buffer *rb)
{
	int usage, mm_users, usage_now, mm_users_now, i;

	cancelled(skel, skel->progs.ringbuf_dynptr_at_call);
	ringbuf_is_clean(skel, rb, "ringbuf_dynptr_at_call");
	cancelled(skel, skel->progs.dynptr_clone_at_call);
	ringbuf_is_clean(skel, rb, "dynptr_clone_at_call");

	/*
	 * bpf_iter_task_vma holds the task and its mm until it is destroyed. Nothing tells
	 * whether the reader of the file was freed in front of that.
	 */
	current_users(skel, &usage, &mm_users);
	cancelled(skel, skel->progs.file_dynptr_in_vma_loop);
	/* anything may hold the task for a moment. What a pad did not release stays. */
	for (i = 0; i < 100; i++) {
		current_users(skel, &usage_now, &mm_users_now);
		if (usage_now == usage && mm_users_now == mm_users)
			break;
		usleep(10000);
	}
	ASSERT_EQ(usage_now, usage, "file_dynptr_in_vma_loop task");
	ASSERT_EQ(mm_users_now, mm_users, "file_dynptr_in_vma_loop mm");
}

void serial_test_cancel_refs(void)
{
	struct ring_buffer *rb = NULL;
	struct cancel_refs *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs. They run below, where their globals are set. */
	RUN_TESTS(cancel_refs);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = cancel_refs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cancel_refs__open_and_load"))
		return;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), on_record, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;

	if (test__start_subtest("iterators"))
		test_iters(skel);
	if (test__start_subtest("dynptrs"))
		test_dynptrs(skel, rb);
out:
	ring_buffer__free(rb);
	cancel_refs__destroy(skel);
}
