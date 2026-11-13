// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "cgroup_helpers.h"
#include "cancel_refs.skel.h"

#define CGROUP	"/cancel_refs"

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

struct child {
	pid_t pid;
	int wfd;
};

/* A task for the progs to take. It sleeps until the runner closes the pipe. */
static bool start_child(struct child *child)
{
	int fds[2];
	char c;

	if (!ASSERT_OK(pipe(fds), "pipe"))
		return false;
	child->pid = fork();
	if (child->pid == 0) {
		close(fds[1]);
		if (read(fds[0], &c, 1) < 0)
			_exit(1);
		_exit(0);
	}
	close(fds[0]);
	child->wfd = fds[1];
	if (!ASSERT_GT(child->pid, 0, "fork")) {
		close(fds[1]);
		return false;
	}
	return true;
}

static void stop_child(struct child *child)
{
	close(child->wfd);
	waitpid(child->pid, NULL, 0);
}

/* The references to the task that the progs take, as probe_task() counts them */
static int task_users(struct cancel_refs *skel)
{
	skel->bss->task_rcu_users = -1;
	run(skel->progs.probe_task);
	return skel->bss->task_rcu_users;
}

static void test_tasks(struct cancel_refs *skel)
{
	struct child child;
	int users;

	if (!start_child(&child))
		return;
	skel->bss->pid = child.pid;
	users = task_users(skel);
	if (!ASSERT_GT(users, 0, "task_users"))
		goto out;

	cancelled(skel, skel->progs.task_at_call);
	ASSERT_EQ(task_users(skel), users, "task_at_call");
	cancelled(skel, skel->progs.tasks_in_two_frames);
	ASSERT_EQ(task_users(skel), users, "tasks_in_two_frames");
	cancelled(skel, skel->progs.task_maybe_null_in_reg);
	ASSERT_EQ(task_users(skel), users, "task_maybe_null_in_reg");
	cancelled(skel, skel->progs.task_maybe_null_spilled);
	ASSERT_EQ(task_users(skel), users, "task_maybe_null_spilled");
	cancelled(skel, skel->progs.tasks_in_regs_and_slots);
	ASSERT_EQ(task_users(skel), users, "tasks_in_regs_and_slots");

	/* No task has this pid: the handles are NULL, and the pads call nothing with them. */
	skel->bss->pid = -1;
	cancelled(skel, skel->progs.task_maybe_null_in_reg);
	cancelled(skel, skel->progs.task_maybe_null_spilled);
	cancelled(skel, skel->progs.tasks_in_regs_and_slots);
out:
	stop_child(&child);
}

/*
 * A cgroup that was removed is released when the last reference to it is gone, and never if
 * a pad left one behind.
 */
static void test_cgroup(struct cancel_refs *skel)
{
	struct bpf_link *link;
	int fd, i;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;
	fd = create_and_get_cgroup(CGROUP);
	if (!ASSERT_GE(fd, 0, "create_and_get_cgroup"))
		goto out;
	close(fd);
	skel->bss->cgid = get_cgroup_id(CGROUP);
	skel->bss->cgroup_released = 0;
	link = bpf_program__attach(skel->progs.on_cgroup_release);
	if (!ASSERT_OK_PTR(link, "attach")) {
		remove_cgroup(CGROUP);
		goto out;
	}

	cancelled(skel, skel->progs.cgroup_at_call);
	remove_cgroup(CGROUP);
	for (i = 0; i < 1000 && !skel->bss->cgroup_released; i++)
		usleep(10000);
	ASSERT_EQ(skel->bss->cgroup_released, 1, "cgroup_at_call");
	bpf_link__destroy(link);
out:
	cleanup_cgroup_environment();
}

static void test_cpumask(struct cancel_refs *skel)
{
	cancelled(skel, skel->progs.cpumask_at_call);
	/* the map has a reference, which the probe takes. The one of the prog is gone. */
	skel->bss->cpumask_usage = -1;
	ASSERT_EQ(run(skel->progs.probe_cpumask), 0, "probe_cpumask");
	ASSERT_EQ(skel->bss->cpumask_usage, 1, "cpumask_at_call");
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
	if (test__start_subtest("tasks"))
		test_tasks(skel);
	if (test__start_subtest("cgroup"))
		test_cgroup(skel);
	if (test__start_subtest("cpumask"))
		test_cpumask(skel);
out:
	ring_buffer__free(rb);
	cancel_refs__destroy(skel);
}
