// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"
#include <asm/unistd_64.h>
#include <errno.h>

/*
 * BPF io threads, system calls run from them, and coroutine frames parked
 * on file readiness.
 */
char _license[] SEC("license") = "GPL";

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct elem {
	struct bpf_kthread kthread;
	struct bpf_waitq waitq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct elem);
} elems SEC(".maps");

#define EPOLLIN_BIT 1
#define FRAME_MARK 0xc0ffeeULL

/* Set by the test. */
int pipe_fd;
__u64 scratch_uaddr;
/* Recorded by the io thread's callback. */
__u32 cb_runs;
__s64 exec_getppid;
__s64 exec_getpid;
__s64 exec_refused;
__s64 exec_read;
/* Results of the park tests. */
__u64 unparked_mark;
__u32 seq_sample;

static struct elem *elem0(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&elems, &key);
}

static int io_cb(void *map, int *key, void *value)
{
	struct elem *e = value;
	__u64 args[6] = {};

	__sync_fetch_and_add(&cb_runs, 1);
	exec_getppid = bpf_sys_exec(&e->kthread, __NR_getppid, args, sizeof(args));
	exec_getpid = bpf_sys_exec(&e->kthread, __NR_getpid, args, sizeof(args));
	/* Not on the allowlist. */
	exec_refused = bpf_sys_exec(&e->kthread, __NR_exit, args, sizeof(args));
	/* A user pointer of the process: the thread shares its address space. */
	args[0] = pipe_fd;
	args[1] = scratch_uaddr;
	args[2] = 8;
	exec_read = bpf_sys_exec(&e->kthread, __NR_read, args, sizeof(args));
	return 1;
}

SEC("syscall")
int start_io_thread(void *ctx)
{
	struct elem *e = elem0();
	int ret;

	if (!e)
		return -1;
	ret = bpf_waitq_init(&e->waitq, &elems, 0);
	if (ret)
		return ret;
	ret = bpf_kthread_create_io(&e->kthread, &elems, io_cb);
	if (ret)
		return ret;
	return bpf_kthread_start(&e->kthread, 0);
}

SEC("syscall")
int stop_io_thread(void *ctx)
{
	struct elem *e = elem0();

	if (!e)
		return -1;
	return bpf_kthread_stop(&e->kthread, 0);
}

/* The calling task is not the io thread: refused. */
SEC("syscall")
int exec_from_task(void *ctx)
{
	struct elem *e = elem0();
	__u64 args[6] = {};

	if (!e)
		return -1;
	return bpf_sys_exec(&e->kthread, __NR_getppid, args, sizeof(args));
}

SEC("syscall")
int park_on_pipe(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;

	if (!e)
		return -1;
	frame = bpf_coro_frame_alloc(64, NULL);
	if (!frame)
		return -ENOMEM;
	frame[0] = FRAME_MARK;
	return bpf_coro_park_file(frame, pipe_fd, EPOLLIN_BIT, &e->waitq);
}

/* A descriptor that cannot be waited for makes the frame ready at once. */
SEC("syscall")
int park_on_bad_fd(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;

	if (!e)
		return -1;
	frame = bpf_coro_frame_alloc(64, NULL);
	if (!frame)
		return -ENOMEM;
	frame[0] = FRAME_MARK + 1;
	return bpf_coro_park_file(frame, -1, EPOLLIN_BIT, &e->waitq);
}

SEC("syscall")
int park_yield(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;

	if (!e)
		return -1;
	frame = bpf_coro_frame_alloc(64, NULL);
	if (!frame)
		return -ENOMEM;
	frame[0] = FRAME_MARK + 2;
	return bpf_coro_park(frame, &e->waitq);
}

/* Take a ready frame back and read what was stored before the park. */
SEC("syscall")
int unpark_one(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;

	if (!e)
		return -1;
	frame = bpf_coro_unpark(&e->waitq, 64);
	if (!frame)
		return -ENOENT;
	unparked_mark = frame[0];
	frame[1] = 1;	/* writable like any frame */
	bpf_coro_frame_free(frame);
	return 0;
}

/* Asking for more than the allocation behind a frame drops that frame. */
SEC("syscall")
int unpark_too_large(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;

	if (!e)
		return -1;
	frame = bpf_coro_unpark(&e->waitq, 512);
	if (!frame)
		return -ENOENT;
	bpf_coro_frame_free(frame);
	return 0;
}

SEC("syscall")
int sample_sequence(void *ctx)
{
	struct elem *e = elem0();

	if (!e)
		return -1;
	seq_sample = bpf_waitq_sequence(&e->waitq);
	return 0;
}

/*
 * Wait against the sequence sampled before the test wrote to the pipe: the
 * readiness wake bumped it, so this returns -EAGAIN at once rather than
 * sleeping; 2 s bounds a wake that did not happen.
 */
SEC("syscall")
int wait_for_ready(void *ctx)
{
	struct elem *e = elem0();

	if (!e)
		return -1;
	return bpf_waitq_wait_event(&e->waitq, seq_sample, 2000000000ULL);
}
