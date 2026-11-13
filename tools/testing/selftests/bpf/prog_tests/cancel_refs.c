// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
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

/*
 * The callee was given the task in a stack argument and releases it. The prog is there when
 * the compiler has stack arguments.
 */
static void test_only_copy_in_stack_arg(struct cancel_refs *skel, int users)
{
	struct bpf_program *prog;

	prog = bpf_object__find_program_by_name(skel->obj, "only_copy_in_stack_arg");
	if (!prog)
		return;
	cancelled(skel, prog);
	ASSERT_EQ(task_users(skel), users, "only_copy_in_stack_arg");
}

/*
 * @name keeps a copy of a task that a callee may release, and passes the task in a stack
 * argument. It is cancelled in front of the release and behind it, and returns both ways.
 * The prog is there when the compiler has stack arguments.
 */
static void test_stack_arg_released(struct cancel_refs *skel, const char *name, int users)
{
	struct bpf_program *prog;

	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!prog)
		return;
	skel->bss->give = 1;
	skel->bss->late = 0;
	cancelled(skel, prog);
	ASSERT_EQ(task_users(skel), users, what(prog, "in front of the release"));
	skel->bss->late = 1;
	cancelled(skel, prog);
	ASSERT_EQ(task_users(skel), users, what(prog, "behind the release"));
	skel->bss->late = 2;
	ASSERT_EQ(run(prog), TC_ACT_OK, what(prog, "returns"));
	ASSERT_EQ(task_users(skel), users, what(prog, "released by the callee"));
	skel->bss->give = 0;
	ASSERT_EQ(run(prog), TC_ACT_OK, what(prog, "returns"));
	ASSERT_EQ(task_users(skel), users, what(prog, "released by the caller"));
	skel->bss->late = 0;
}

static void test_tasks(struct cancel_refs *skel)
{
	struct child child;
	int users, self;

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
	/* the callee that was given the task releases it */
	cancelled(skel, skel->progs.only_copy_in_arg);
	ASSERT_EQ(task_users(skel), users, "only_copy_in_arg");
	/* and so does the one that was given it in a stack argument */
	test_only_copy_in_stack_arg(skel, users);
	/* the callee has a pointer to the stack of the caller, whose pad reads a slot there */
	cancelled(skel, skel->progs.stack_pointer_at_call);
	ASSERT_EQ(task_users(skel), users, "stack_pointer_at_call");
	cancelled(skel, skel->progs.callee_writes_to_one_slot);
	ASSERT_EQ(task_users(skel), users, "callee_writes_to_one_slot");
	cancelled(skel, skel->progs.callee_tests_task);
	ASSERT_EQ(task_users(skel), users, "callee_tests_task");
	cancelled(skel, skel->progs.callee_tests_task_spilled);
	ASSERT_EQ(task_users(skel), users, "callee_tests_task_spilled");
	cancelled(skel, skel->progs.callee_tests_and_writes);
	ASSERT_EQ(task_users(skel), users, "callee_tests_and_writes");

	/* the path that holds the task: its drop flag is set, and the pad releases the task */
	skel->bss->zero = 0;
	cancelled(skel, skel->progs.held_on_one_path);
	ASSERT_EQ(task_users(skel), users, "held_on_one_path");
	/*
	 * The other path has the task that runs the prog in the place of the handle, and
	 * holds nothing: the pad finds the flag clear and leaves that task alone.
	 */
	skel->bss->pid = sys_gettid();
	self = task_users(skel);
	skel->bss->zero = 1;
	cancelled(skel, skel->progs.held_on_one_path);
	ASSERT_EQ(task_users(skel), self, "held_on_one_path without the task");
	cancelled(skel, skel->progs.returned_on_one_path);
	ASSERT_EQ(task_users(skel), self, "returned_on_one_path without the task");
	skel->bss->zero = 0;

	/* the callee returns with the task, and the path that calls it holds the task */
	skel->bss->pid = child.pid;
	cancelled(skel, skel->progs.returned_on_one_path);
	ASSERT_EQ(task_users(skel), users, "returned_on_one_path");
	/*
	 * The frame that is cancelled has the task that runs the prog where its handle would
	 * be, and its flag is where the frame before it left one set.
	 */
	cancelled(skel, skel->progs.flag_of_second_frame);
	ASSERT_EQ(task_users(skel), users, "flag_of_second_frame");
	skel->bss->pid = sys_gettid();
	ASSERT_EQ(task_users(skel), self, "flag_of_second_frame: the task that runs it");

	/* the pad releases the task from the slot, whether r6 has it as well or not */
	skel->bss->pid = child.pid;
	cancelled(skel, skel->progs.two_places_on_one_path);
	ASSERT_EQ(task_users(skel), users, "two_places_on_one_path: in r6 too");
	skel->bss->zero = 1;
	cancelled(skel, skel->progs.two_places_on_one_path);
	ASSERT_EQ(task_users(skel), users, "two_places_on_one_path: in the slot only");
	skel->bss->zero = 0;

	/*
	 * The path that holds one task has it in r6 and in the slot, and releases it once.
	 * The other path holds the task that runs the prog as well, in r6: each of the two
	 * is released once.
	 */
	skel->bss->pid2 = sys_gettid();
	cancelled(skel, skel->progs.two_places_and_another_task);
	ASSERT_EQ(task_users(skel), users, "two_places_and_another_task: one task");
	cancelled(skel, skel->progs.another_task_and_two_places);
	ASSERT_EQ(task_users(skel), users, "another_task_and_two_places: one task");
	skel->bss->zero = 1;
	cancelled(skel, skel->progs.two_places_and_another_task);
	ASSERT_EQ(task_users(skel), users, "two_places_and_another_task: the first task");
	cancelled(skel, skel->progs.another_task_and_two_places);
	ASSERT_EQ(task_users(skel), users, "another_task_and_two_places: the first task");
	skel->bss->zero = 0;
	skel->bss->pid = sys_gettid();
	ASSERT_EQ(task_users(skel), self, "two_places_and_another_task: the other task");
	/*
	 * The frame gives the task to a callee, and the call that moves it clears the flag. The
	 * prog is cancelled in front of that call, with the task and without it,
	 */
	skel->bss->pid = child.pid;
	cancelled(skel, skel->progs.held_on_one_path_given_away);
	ASSERT_EQ(task_users(skel), users, "held_on_one_path_given_away");
	skel->bss->pid = sys_gettid();
	skel->bss->zero = 1;
	cancelled(skel, skel->progs.held_on_one_path_given_away);
	ASSERT_EQ(task_users(skel), self, "held_on_one_path_given_away without the task");
	skel->bss->zero = 0;
	/* and in the callee, behind the move: the pad of the callee releases the task, once */
	skel->bss->pid = child.pid;
	skel->bss->late = 1;
	cancelled(skel, skel->progs.held_on_one_path_given_away);
	ASSERT_EQ(task_users(skel), users, "held_on_one_path_given_away in the callee");
	skel->bss->late = 0;

	/*
	 * The callee releases the task and returns, and the frame is cancelled behind that. It
	 * has the task that runs the prog where the handle was, and its flag is clear.
	 */
	skel->bss->give = 1;
	cancelled(skel, skel->progs.given_away_on_one_path);
	ASSERT_EQ(task_users(skel), users, "given_away_on_one_path");
	skel->bss->pid = sys_gettid();
	ASSERT_EQ(task_users(skel), self, "given_away_on_one_path: the task that runs it");
	/* the path that keeps the task holds it there */
	skel->bss->pid = child.pid;
	skel->bss->give = 0;
	cancelled(skel, skel->progs.given_away_on_one_path);
	ASSERT_EQ(task_users(skel), users, "given_away_on_one_path with the task");

	/* both paths get to the call that moves the task, one of them with NULL and nothing held */
	cancelled(skel, skel->progs.null_or_task_given_away);
	ASSERT_EQ(task_users(skel), users, "null_or_task_given_away");
	skel->bss->zero = 1;
	cancelled(skel, skel->progs.null_or_task_given_away);
	ASSERT_EQ(task_users(skel), users, "null_or_task_given_away with NULL");
	skel->bss->zero = 0;

	/*
	 * The callee may release the task that its caller keeps a copy of. The prog is cancelled
	 * in the callee in front of the release: the pad of the call releases the task.
	 */
	skel->bss->give = 1;
	cancelled(skel, skel->progs.callee_may_release);
	ASSERT_EQ(task_users(skel), users, "callee_may_release in front of the release");
	/* and behind the release: the pad of the callee tells, and the task is left alone */
	skel->bss->late = 1;
	cancelled(skel, skel->progs.callee_may_release);
	ASSERT_EQ(task_users(skel), users, "callee_may_release behind the release");
	/* nothing tells where the callee returns: the prog releases the task there, or doesn't */
	skel->bss->late = 2;
	ASSERT_EQ(run(skel->progs.callee_may_release), TC_ACT_OK, "callee_may_release returns");
	ASSERT_EQ(task_users(skel), users, "callee_may_release released by the callee");
	skel->bss->give = 0;
	ASSERT_EQ(run(skel->progs.callee_may_release), TC_ACT_OK, "callee_may_release returns");
	ASSERT_EQ(task_users(skel), users, "callee_may_release released by the caller");

	/*
	 * The task goes through two calls. The prog is cancelled in the frame that released it,
	 * and the two pads below pass on what that one tells,
	 */
	skel->bss->give = 1;
	skel->bss->late = 0;
	cancelled(skel, skel->progs.callee_of_callee_may_release);
	ASSERT_EQ(task_users(skel), users, "callee_of_callee_may_release in the last frame");
	/* and in the frame between, when the one that released has returned */
	skel->bss->late = 1;
	cancelled(skel, skel->progs.callee_of_callee_may_release);
	ASSERT_EQ(task_users(skel), users, "callee_of_callee_may_release in the frame between");
	skel->bss->give = 0;
	ASSERT_EQ(run(skel->progs.callee_of_callee_may_release), TC_ACT_OK,
		  "callee_of_callee_may_release returns");
	ASSERT_EQ(task_users(skel), users, "callee_of_callee_may_release released by the caller");
	skel->bss->late = 0;
	/* the callee gets the task in a stack argument, and tells by that */
	test_stack_arg_released(skel, "callee_may_release_stack_arg", users);
	/* and the frame between passes it on in a register */
	test_stack_arg_released(skel, "stack_arg_goes_on", users);
	/* the callee that releases the task never returns, and is verified without its caller */
	cancelled(skel, skel->progs.callee_releases_and_throws);
	ASSERT_EQ(task_users(skel), users, "callee_releases_and_throws");
	/* the callee tests the task for NULL as well: it finds one and leaves it to its caller, */
	cancelled(skel, skel->progs.callee_tests_and_may_release);
	ASSERT_EQ(task_users(skel), users, "callee_tests_and_may_release with the task");
	/* or releases it */
	skel->bss->give = 1;
	cancelled(skel, skel->progs.callee_tests_and_may_release);
	ASSERT_EQ(task_users(skel), users, "callee_tests_and_may_release released");
	skel->bss->give = 0;

	/* No task has this pid: the handles are NULL, and the pads call nothing with them. */
	skel->bss->pid = -1;
	cancelled(skel, skel->progs.callee_tests_task);
	cancelled(skel, skel->progs.callee_tests_task_spilled);
	cancelled(skel, skel->progs.callee_tests_and_may_release);
	/* the slot has what the callee wrote, and the pad leaves it alone */
	cancelled(skel, skel->progs.callee_tests_and_writes);
	cancelled(skel, skel->progs.task_maybe_null_in_reg);
	cancelled(skel, skel->progs.task_maybe_null_spilled);
	cancelled(skel, skel->progs.tasks_in_regs_and_slots);
out:
	stop_child(&child);
}

/*
 * A cgroup that was removed is released when the last reference to it is gone, and never if
 * a pad left one behind. A reference to its memory cgroup keeps it as well, and it has one:
 * setup_cgroup_environment() enables every controller. @prog takes the one or the other.
 */
static void test_cgroup(struct cancel_refs *skel, struct bpf_program *prog)
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

	cancelled(skel, prog);
	remove_cgroup(CGROUP);
	for (i = 0; i < 1000 && !skel->bss->cgroup_released; i++)
		usleep(10000);
	ASSERT_EQ(skel->bss->cgroup_released, 1, bpf_program__name(prog));
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

/* The references to the socket that the progs look up, as probe_sock() counts them */
static int sock_users(struct cancel_refs *skel)
{
	skel->bss->sock_refcnt = -1;
	run(skel->progs.probe_sock);
	return skel->bss->sock_refcnt;
}

static void test_sockets(struct cancel_refs *skel, struct ring_buffer *rb)
{
	int srv, cli = -1, acc = -1, users;

	/*
	 * A lookup takes no reference to a socket that listens. It takes one to the socket of
	 * a connection: the one that accept() returns, which gets what the client sends.
	 */
	srv = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_OK_FD(srv, "start_server"))
		return;
	cli = connect_to_fd(srv, 0);
	if (!ASSERT_OK_FD(cli, "connect_to_fd"))
		goto out;
	acc = accept(srv, NULL, NULL);
	if (!ASSERT_OK_FD(acc, "accept"))
		goto out;
	skel->bss->tuple_saddr = htonl(INADDR_LOOPBACK);
	skel->bss->tuple_daddr = htonl(INADDR_LOOPBACK);
	skel->bss->tuple_sport = get_socket_local_port(cli);
	skel->bss->tuple_dport = get_socket_local_port(srv);
	users = sock_users(skel);
	if (!ASSERT_GT(users, 0, "sock_users"))
		goto out;

	cancelled(skel, skel->progs.sock_at_call);
	ASSERT_EQ(sock_users(skel), users, "sock_at_call");
	cancelled(skel, skel->progs.skc_at_call);
	ASSERT_EQ(sock_users(skel), users, "skc_at_call");

	/* Nothing has port 0: the handle is NULL, and the pad calls nothing with it. */
	skel->bss->tuple_dport = 0;
	cancelled(skel, skel->progs.sock_at_call);
out:
	if (acc >= 0)
		close(acc);
	if (cli >= 0)
		close(cli);
	close(srv);
}

static void test_ringbuf(struct cancel_refs *skel, struct ring_buffer *rb)
{
	cancelled(skel, skel->progs.ringbuf_at_call);
	ringbuf_is_clean(skel, rb, "ringbuf_at_call");
}

/* The references to the object of the test kfuncs, as probe_test_ref() counts them */
static int test_ref_users(struct cancel_refs *skel)
{
	skel->bss->test_ref_cnt = -1;
	run(skel->progs.probe_test_ref);
	return skel->bss->test_ref_cnt;
}

static void test_test_ref(struct cancel_refs *skel)
{
	int users = test_ref_users(skel);

	if (!ASSERT_GT(users, 0, "test_ref_users"))
		return;
	cancelled(skel, skel->progs.test_ref_at_call);
	ASSERT_EQ(test_ref_users(skel), users, "test_ref_at_call");
}

/* The references to the file that this task was executed from, as probe_exe_file() counts them */
static long exe_file_users(struct cancel_refs *skel)
{
	skel->bss->exe_file_refs = -1;
	run(skel->progs.probe_exe_file);
	return skel->bss->exe_file_refs;
}

/*
 * An LSM prog has no test run. It is attached to the hook of setpriority(), which this thread
 * calls: the prog is cancelled, and the hook refuses with the cancel value of an LSM prog.
 */
static void test_file(struct cancel_refs *skel)
{
	struct bpf_program *prog = skel->progs.file_at_call;
	long users, users_now = -1;
	struct bpf_link *link;
	int err, i;

	users = exe_file_users(skel);
	if (!ASSERT_GE(users, 0, "exe_file_users"))
		return;
	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "attach"))
		return;
	skel->bss->tid = sys_gettid();
	skel->bss->behind = 0;
	errno = 0;
	err = setpriority(PRIO_PROCESS, 0, 0);
	ASSERT_EQ(err, -1, "file_at_call setpriority");
	ASSERT_EQ(errno, EPERM, "file_at_call errno");
	bpf_link__destroy(link);
	ASSERT_EQ(skel->bss->behind, 0, "file_at_call behind");
	ASSERT_HAS_SUBSTR(read_stream(prog), "ERROR: Program was cancelled", "file_at_call stream");

	/* a mapping of the file that comes or goes changes the count. What a pad left stays. */
	for (i = 0; i < 100; i++) {
		users_now = exe_file_users(skel);
		if (users_now == users)
			break;
		usleep(10000);
	}
	ASSERT_EQ(users_now, users, "file_at_call");
}

static void test_ksock(struct cancel_refs *skel)
{
	cancelled(skel, skel->progs.ksock_at_call);
	/* the map has a reference, which the probe takes. The one of the prog is gone. */
	skel->bss->ksock_usage = -1;
	ASSERT_EQ(run(skel->progs.probe_ksock), 0, "probe_ksock");
	ASSERT_EQ(skel->bss->ksock_usage, 1, "ksock_at_call");
}

/* The references to the conntrack entry of the progs, as probe_ct() counts them */
static int ct_users(struct cancel_refs *skel)
{
	skel->bss->ct_use = -1;
	run(skel->progs.probe_ct);
	return skel->bss->ct_use;
}

/* The references to the xfrm state of the progs, as probe_xfrm_state() counts them */
static int xfrm_state_users(struct cancel_refs *skel)
{
	skel->bss->xfrm_refcnt = -1;
	run(skel->progs.probe_xfrm_state);
	return skel->bss->xfrm_refcnt;
}

#define NETNS		"cancel_refs"
#define XFRM_SRC	"198.51.100.1"
#define XFRM_DST	"198.51.100.2"
#define XFRM_SPI	0x1234
#define XFRM_AUTH	"0x1111111111111111111111111111111111111111"
#define XFRM_ENC	"0x22222222222222222222222222222222"

/*
 * A conntrack entry and an xfrm state, in a network namespace that takes them with it. A test
 * run has the loopback device of the namespace that the runner is in.
 */
static void test_net(struct cancel_refs *skel)
{
	struct netns_obj *ns;
	int users;

	ns = netns_new(NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		return;

	inet_pton(AF_INET, XFRM_SRC, &skel->bss->tuple_saddr);
	inet_pton(AF_INET, XFRM_DST, &skel->bss->tuple_daddr);
	skel->bss->tuple_sport = htons(7);
	skel->bss->tuple_dport = htons(9);
	run(skel->progs.ct_insert);
	users = ct_users(skel);
	if (ASSERT_GT(users, 0, "ct_users")) {
		cancelled(skel, skel->progs.ct_at_call);
		ASSERT_EQ(ct_users(skel), users, "ct_at_call");
	}

	SYS(out, "ip xfrm state add src %s dst %s proto esp spi %d mode tunnel "
		 "auth-trunc 'hmac(sha1)' %s 96 enc 'cbc(aes)' %s",
	    XFRM_SRC, XFRM_DST, XFRM_SPI, XFRM_AUTH, XFRM_ENC);
	inet_pton(AF_INET, XFRM_DST, &skel->bss->xfrm_daddr);
	skel->bss->xfrm_spi = htonl(XFRM_SPI);
	users = xfrm_state_users(skel);
	if (ASSERT_GT(users, 0, "xfrm_state_users")) {
		cancelled(skel, skel->progs.xfrm_state_at_call);
		ASSERT_EQ(xfrm_state_users(skel), users, "xfrm_state_at_call");
	}
out:
	netns_free(ns);
}

/*
 * Removing a wakeup source waits for every holder of the lock. An epoll instance has one for
 * itself and one for an EPOLLWAKEUP entry, and close() removes them. A child does that:
 * nothing would end its wait for a lock that a pad left held.
 */
static bool wakeup_sources_go(void)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLWAKEUP };
	int fds[2], ep, status, i;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		ep = epoll_create1(0);
		if (ep < 0 || pipe(fds) || epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev))
			_exit(1);
		close(ep);
		_exit(0);
	}
	if (!ASSERT_GT(pid, 0, "fork"))
		return false;
	for (i = 0; i < 1000; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			return WIFEXITED(status) && !WEXITSTATUS(status);
		usleep(10000);
	}
	return false;
}

static void test_wakeup_sources(struct cancel_refs *skel)
{
	if (!ASSERT_TRUE(wakeup_sources_go(), "wakeup_sources_go"))
		return;
	cancelled(skel, skel->progs.ws_lock_at_call);
	ASSERT_TRUE(wakeup_sources_go(), "ws_lock_at_call");
}

/*
 * The objects keep a reference to the task in a kptr. It is released when the last reference
 * to the object is dropped, so the references to the task tell whether a pad dropped its own.
 */
static void test_objects(struct cancel_refs *skel)
{
	struct child child;
	int users;

	if (!start_child(&child))
		return;
	skel->bss->pid = child.pid;
	users = task_users(skel);
	if (!ASSERT_GT(users, 0, "task_users"))
		goto out;

	cancelled(skel, skel->progs.obj_at_call);
	ASSERT_EQ(task_users(skel), users, "obj_at_call");

	/* the map has the other reference to the object: it goes with that one */
	cancelled(skel, skel->progs.refcounted_at_call);
	ASSERT_EQ(task_users(skel), users + 1, "refcounted_at_call");
	run(skel->progs.drop_stashed);
	ASSERT_EQ(task_users(skel), users, "drop_stashed");

	run(skel->progs.list_push);
	ASSERT_EQ(task_users(skel), users + 1, "list_push");
	cancelled(skel, skel->progs.list_node_at_call);
	ASSERT_EQ(task_users(skel), users, "list_node_at_call");
	/* the list is empty: the handle is NULL, and the pad drops nothing */
	cancelled(skel, skel->progs.list_node_at_call);

	/* the pad has the pointer to the node and drops the object that the node is in */
	run(skel->progs.tail_push);
	ASSERT_EQ(task_users(skel), users + 1, "tail_push");
	cancelled(skel, skel->progs.list_node_not_first);
	ASSERT_EQ(task_users(skel), users, "list_node_not_first");
	cancelled(skel, skel->progs.list_node_not_first);
	run(skel->progs.tail_push);
	ASSERT_EQ(task_users(skel), users + 1, "tail_push");
	cancelled(skel, skel->progs.list_node_spilled);
	ASSERT_EQ(task_users(skel), users, "list_node_spilled");
	cancelled(skel, skel->progs.list_node_spilled);

	/* a per-CPU object leaves nothing behind that could be found */
	cancelled(skel, skel->progs.percpu_obj_at_call);
out:
	stop_child(&child);
}

static void test_several(struct cancel_refs *skel, struct ring_buffer *rb)
{
	struct child child;
	int users;

	if (!start_child(&child))
		return;
	skel->bss->pid = child.pid;
	users = task_users(skel);
	if (!ASSERT_GT(users, 0, "task_users"))
		goto out;

	cancelled(skel, skel->progs.several_kinds_at_call);
	ASSERT_EQ(task_users(skel), users, "several_kinds_at_call task");
	ringbuf_is_clean(skel, rb, "several_kinds_at_call ringbuf");
out:
	stop_child(&child);
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
		test_cgroup(skel, skel->progs.cgroup_at_call);
	if (test__start_subtest("cpumask"))
		test_cpumask(skel);
	if (test__start_subtest("test kfunc"))
		test_test_ref(skel);
	if (test__start_subtest("memcg"))
		test_cgroup(skel, skel->progs.memcg_at_call);
	if (test__start_subtest("file"))
		test_file(skel);
	if (test__start_subtest("ksock"))
		test_ksock(skel);
	if (test__start_subtest("net"))
		test_net(skel);
	if (test__start_subtest("wakeup sources"))
		test_wakeup_sources(skel);
	if (test__start_subtest("sockets"))
		test_sockets(skel, rb);
	if (test__start_subtest("ringbuf"))
		test_ringbuf(skel, rb);
	if (test__start_subtest("objects"))
		test_objects(skel);
	if (test__start_subtest("several"))
		test_several(skel, rb);
out:
	ring_buffer__free(rb);
	cancel_refs__destroy(skel);
}
