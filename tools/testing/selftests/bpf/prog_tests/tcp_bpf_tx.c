// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Assign the two ends of a loopback TCP connection to a xmit queue that a BPF
 * kthread serves and check who sends their data: the thread while it polls,
 * the watchdog's work item once the thread has left the sockets waiting, and
 * the sockets themselves when the queue has no thread, because it was never
 * bound, was unbound, or its thread is gone.
 */
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "tcp_bpf_tx.skel.h"

#define CG_NAME "/tcp_bpf_tx"
#define QUEUE 5

/* Mirrors struct tx_args in progs/tcp_bpf_tx.c. */
struct tx_args {
	__u32 queue;
	__u32 pad;
	__u64 flags;
};

static int run_prog(struct bpf_program *prog, __u32 queue, __u64 flags)
{
	struct tx_args args = { .queue = queue, .flags = flags };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, bpf_program__name(prog)))
		return err;
	return (int)opts.retval;
}

/* Send one byte; returns whether it arrived within @timeout_ms. */
static bool ping(int tx, int rx, int timeout_ms)
{
	char c = 'x';

	if (!ASSERT_OK(settimeo(rx, timeout_ms), "settimeo") ||
	    !ASSERT_EQ(send(tx, &c, 1, 0), 1, "send"))
		return false;
	return recv(rx, &c, 1, 0) == 1;
}

/*
 * The byte arrives while the thread is still transmitting, before the thread
 * has counted the socket, so give the counter a moment to pass @before.
 */
static bool xmits_past(struct tcp_bpf_tx *skel, __u64 before)
{
	int i;

	for (i = 0; i < 1000 && skel->bss->xmits <= before; i++)
		usleep(1000);
	return skel->bss->xmits > before;
}

/* Mirror the kernel's enum in net/tcp.h. */
enum { TX_WAKE, TX_QUEUE, TX_INLINE };

/* Have the worker set @mode, and wait until it has. */
static bool set_mode(struct tcp_bpf_tx *skel, __u32 mode)
{
	int i;

	skel->bss->mode_applied = 0;
	skel->bss->mode = mode;
	if (!ASSERT_GE(run_prog(skel->progs.wake_worker, 0, 0), 0, "wake_worker"))
		return false;
	for (i = 0; i < 1000 && skel->bss->mode_applied != mode + 1; i++)
		usleep(1000);
	return skel->bss->mode_applied == mode + 1;
}

void test_tcp_bpf_tx(void)
{
	int cg_fd, listen_fd = -1, client = -1, server = -1;
	struct bpf_link *link = NULL;
	struct tcp_bpf_tx *skel;
	__u64 before;
	char c;

	cg_fd = test__join_cgroup(CG_NAME);
	if (!ASSERT_GE(cg_fd, 0, "join_cgroup"))
		return;
	skel = tcp_bpf_tx__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;
	skel->bss->queue = QUEUE;

	ASSERT_EQ(run_prog(skel->progs.bind_queue_to_current, QUEUE, 0), -ESRCH,
		  "bind_to_user_task");
	ASSERT_EQ(run_prog(skel->progs.poll_queue, QUEUE, 0), -EPERM, "poll_unbound");
	ASSERT_EQ(run_prog(skel->progs.poll_queue, 1 << 20, 0), -EINVAL, "poll_bad_queue");
	ASSERT_EQ(run_prog(skel->progs.unbind_queue, QUEUE, 0), 0, "unbind_unbound");
	ASSERT_EQ(run_prog(skel->progs.unbind_queue, 1 << 20, 0), -EINVAL, "unbind_bad_queue");

	if (!ASSERT_OK(run_prog(skel->progs.create_worker, 0, 0), "create_worker"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.bind_queue, QUEUE, 1), -EINVAL, "bind_bad_flags");
	ASSERT_EQ(run_prog(skel->progs.bind_queue, 1 << 20, 0), -EINVAL, "bind_bad_queue");

	link = bpf_program__attach_cgroup(skel->progs.assign_sock, cg_fd);
	if (!ASSERT_OK_PTR(link, "attach_sockops"))
		goto out;
	listen_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(listen_fd, 0, "start_server"))
		goto out;
	client = connect_to_fd(listen_fd, 0);
	if (!ASSERT_GE(client, 0, "connect"))
		goto out;
	server = accept(listen_fd, NULL, NULL);
	if (!ASSERT_GE(server, 0, "accept"))
		goto out;
	ASSERT_EQ(skel->bss->assigned, 2, "socks_assigned");
	ASSERT_OK(skel->bss->assign_ret, "assign_ret");

	/* Assigned to a queue without a thread, the sockets transmit for themselves. */
	ASSERT_TRUE(ping(client, server, 300), "ping_no_thread");
	ASSERT_EQ(skel->bss->xmits, 0, "no_xmit_by_thread");

	/* The thread transmits for both ends. */
	if (!ASSERT_OK(run_prog(skel->progs.bind_queue, QUEUE, 0), "bind_queue"))
		goto out;
	ASSERT_TRUE(ping(client, server, 300), "ping_thread");
	ASSERT_TRUE(xmits_past(skel, 0), "thread_xmit");
	before = skel->bss->xmits;
	ASSERT_TRUE(ping(server, client, 300), "ping_thread_reverse");
	ASSERT_TRUE(xmits_past(skel, before), "thread_xmit_reverse");
	ASSERT_EQ(run_prog(skel->progs.poll_queue, QUEUE, 0), -EPERM, "poll_by_other_task");
	ASSERT_EQ(run_prog(skel->progs.set_queue_mode, QUEUE, TX_INLINE), -EPERM,
		  "set_mode_by_other_task");
	ASSERT_EQ(run_prog(skel->progs.set_queue_mode, QUEUE, 3), -EINVAL, "set_bad_mode");

	/* In the inline mode the senders transmit and the thread sees nothing. */
	if (!ASSERT_TRUE(set_mode(skel, TX_INLINE), "set_mode_inline"))
		goto out;
	before = skel->bss->xmits;
	ASSERT_TRUE(ping(client, server, 300), "ping_inline");
	ASSERT_EQ(skel->bss->xmits, before, "no_xmit_inline");

	/*
	 * In the queueing mode nobody wakes the thread: the byte waits until
	 * the thread looks, which here is when the test wakes it.
	 */
	if (!ASSERT_TRUE(set_mode(skel, TX_QUEUE), "set_mode_queue"))
		goto out;
	before = skel->bss->xmits;
	ASSERT_FALSE(ping(client, server, 300), "ping_waits_for_thread");
	ASSERT_GE(run_prog(skel->progs.wake_worker, 0, 0), 0, "wake_worker");
	ASSERT_EQ(recv(server, &c, 1, 0), 1, "recv_after_wake");
	ASSERT_TRUE(xmits_past(skel, before), "thread_xmit_queued");

	/* Back in the first mode a send wakes the thread again. */
	if (!ASSERT_TRUE(set_mode(skel, TX_WAKE), "set_mode_wake"))
		goto out;
	before = skel->bss->xmits;
	ASSERT_TRUE(ping(client, server, 300), "ping_wake_mode");
	ASSERT_TRUE(xmits_past(skel, before), "thread_xmit_wake_mode");

	/*
	 * A thread that stops polling leaves the byte in the write queue,
	 * until the queue is unbound over it after about a second and the
	 * waiting socket is served. Later sends are the socket's own again.
	 */
	skel->bss->paused = 1;
	ASSERT_FALSE(ping(client, server, 300), "ping_waits_for_poll");
	ASSERT_OK(settimeo(server, 5000), "settimeo");
	ASSERT_EQ(recv(server, &c, 1, 0), 1, "recv_after_watchdog");
	ASSERT_TRUE(ping(client, server, 300), "ping_after_watchdog");

	/* A new bind puts the queue back in service. */
	skel->bss->paused = 0;
	if (!ASSERT_OK(run_prog(skel->progs.bind_queue, QUEUE, 0), "bind_after_watchdog"))
		goto out;
	before = skel->bss->xmits;
	ASSERT_TRUE(ping(client, server, 300), "ping_after_rebind");
	ASSERT_TRUE(xmits_past(skel, before), "thread_xmit_after_rebind");

	/* A thread that exits gives the queue up. */
	ASSERT_EQ(run_prog(skel->progs.stop_worker, 0, 0), 0, "stop_worker");
	ASSERT_EQ(run_prog(skel->progs.poll_queue, QUEUE, 0), -EPERM, "poll_after_thread_exit");
	ASSERT_TRUE(ping(client, server, 300), "ping_after_thread_exit");
out:
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	if (listen_fd >= 0)
		close(listen_fd);
	bpf_link__destroy(link);
	tcp_bpf_tx__destroy(skel);
	close(cg_fd);
}
