// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Bind the receive NAPI of a veth device to BPF kthreads and check that its
 * packets are delivered by whoever is supposed to poll it: the test itself
 * while no thread polls, a thread that sleeps between interrupts, a thread
 * that keeps the interrupt masked, the thread the NAPI is moved to, and
 * softirq again once the thread stops polling, exits, or the device takes the
 * NAPI back. The veth ends live in two namespaces so that datagrams cross the
 * pair instead of taking loopback.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "bpf_napi.skel.h"

#define NS_SRC "bpf_napi_src"
#define NS_DST "bpf_napi_dst"
#define SRC_IP "10.99.0.1"
#define DST_IP "10.99.0.2"
#define PORT 7777

/* Mirror the kernel's enums next to the NAPI state bits in linux/netdevice.h. */
#define BPF_NAPI_POLL_WORK_MASK 0xffff
#define BPF_NAPI_POLL_MORE (1 << 16)
#define BPF_NAPI_POLL_F_BUSY 1

/* Mirrors struct napi_args in progs/bpf_napi.c. */
struct napi_args {
	__u32 idx;
	__u32 napi_id;
	__u64 flags;
};

static __u32 napi_id;

static int run_prog(struct bpf_program *prog, __u32 idx, __u32 id, __u64 flags)
{
	struct napi_args args = { .idx = idx, .napi_id = id, .flags = flags };
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

static void set_rcvtimeo(int fd, int ms)
{
	struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int udp_socket(const char *ip, bool bind_it)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	int fd;

	inet_pton(AF_INET, ip, &addr.sin_addr);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!ASSERT_GE(fd, 0, "socket"))
		return -1;
	set_rcvtimeo(fd, 300);
	if (bind_it) {
		if (!ASSERT_OK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), "bind")) {
			close(fd);
			return -1;
		}
	} else if (!ASSERT_OK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), "connect")) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Send one datagram; returns whether it arrived within the receive timeout. */
static bool ping(int tx, int rx)
{
	char buf[16] = "napi";

	if (!ASSERT_EQ(send(tx, buf, sizeof(buf), 0), sizeof(buf), "send"))
		return false;
	return recv(rx, buf, sizeof(buf), 0) == sizeof(buf);
}

/*
 * A datagram is delivered from inside the thread's poll, before the thread has
 * counted the poll, so give the counter a moment to pass @before.
 */
static bool polled_past(struct bpf_napi *skel, int idx, __u64 before)
{
	int i;

	for (i = 0; i < 1000 && skel->bss->polls[idx] <= before; i++)
		usleep(1000);
	return skel->bss->polls[idx] > before;
}

/* ip netns exec remounts sysfs for the namespace, our own /sys does not. */
static int set_threaded(int val)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd),
		 "ip netns exec " NS_DST " sh -c 'echo %d > /sys/class/net/veth_dst/threaded'", val);
	return system(cmd);
}

void test_bpf_napi(void)
{
	struct nstoken *tok = NULL;
	socklen_t len = sizeof(napi_id);
	struct bpf_napi *skel;
	int tx = -1, rx = -1, err, ret;
	__u64 before;
	char buf[16];

	skel = bpf_napi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	SYS(out, "ip netns add " NS_SRC);
	SYS(out, "ip netns add " NS_DST);
	SYS(out, "ip link add veth_src netns " NS_SRC " type veth peer name veth_dst netns " NS_DST);
	SYS(out, "ip -n " NS_SRC " addr add dev veth_src " SRC_IP "/24");
	SYS(out, "ip -n " NS_DST " addr add dev veth_dst " DST_IP "/24");
	SYS(out, "ip -n " NS_SRC " link set dev veth_src up");
	SYS(out, "ip -n " NS_DST " link set dev veth_dst up");
	/*
	 * GRO puts veth receive on a NAPI, which is what SO_INCOMING_NAPI_ID
	 * reports; veth only creates it for a device that is already up, and
	 * only uses it for frames from a sender without TSO features.
	 */
	SYS(out, "ip netns exec " NS_DST " ethtool -K veth_dst gro on");
	SYS(out, "ip netns exec " NS_SRC " ethtool -K veth_src tso off");

	/* The sender's socket keeps its namespace; everything else runs in the receiver's. */
	tok = open_netns(NS_SRC);
	if (!ASSERT_OK_PTR(tok, "open_netns_src"))
		goto out;
	tx = udp_socket(DST_IP, false);
	close_netns(tok);
	tok = open_netns(NS_DST);
	if (!ASSERT_OK_PTR(tok, "open_netns_dst"))
		goto out;
	rx = udp_socket(DST_IP, true);
	if (rx < 0 || tx < 0)
		goto out;
	if (!ASSERT_TRUE(ping(tx, rx), "softirq_ping"))
		goto out;
	err = getsockopt(rx, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &len);
	if (!ASSERT_OK(err, "SO_INCOMING_NAPI_ID") || !ASSERT_GT(napi_id, 0, "napi_id"))
		goto out;
	skel->bss->napi_id = napi_id;

	/* Two pollers, neither of which polls until told to. */
	skel->bss->paused[0] = 1;
	skel->bss->paused[1] = 1;
	if (!ASSERT_OK(run_prog(skel->progs.create_poller, 0, 0, 0), "create_poller_0") ||
	    !ASSERT_OK(run_prog(skel->progs.create_poller, 1, 0, 0), "create_poller_1"))
		goto out;

	ASSERT_EQ(run_prog(skel->progs.bind_napi, 0, napi_id, 1), -EINVAL, "bind_bad_flags");
	ASSERT_EQ(run_prog(skel->progs.bind_napi, 0, 0x7fffffff, 0), -ENOENT, "bind_unknown_napi");
	ASSERT_EQ(run_prog(skel->progs.bind_napi_to_current, 0, napi_id, 0), -ESRCH,
		  "bind_to_user_task");
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -ENOENT, "poll_unbound");
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 2), -EINVAL, "poll_bad_flags");
	ASSERT_EQ(run_prog(skel->progs.unbind_napi, 0, napi_id, 0), 0, "unbind_unbound");

	/* A NAPI with a kernel thread cannot be bound. */
	if (!ASSERT_OK(set_threaded(1), "threaded_on"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.bind_napi, 0, napi_id, 0), -EBUSY, "bind_threaded");
	if (!ASSERT_OK(set_threaded(0), "threaded_off"))
		goto out;

	/*
	 * Bound with nobody polling: the packet waits in the NAPI until we
	 * poll. The poll may also find the namespace's IPv6 multicast chatter.
	 */
	if (!ASSERT_OK(run_prog(skel->progs.bind_napi, 0, napi_id, 0), "bind_napi"))
		goto out;
	ASSERT_FALSE(ping(tx, rx), "ping_waits_for_poll");
	ret = run_prog(skel->progs.poll_napi, 0, napi_id, 0);
	ASSERT_GE(ret & BPF_NAPI_POLL_WORK_MASK, 1, "poll_work");
	ASSERT_EQ(ret & BPF_NAPI_POLL_MORE, 0, "poll_completes");
	if (!ASSERT_EQ(recv(rx, buf, sizeof(buf), 0), sizeof(buf), "recv_after_poll"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -EAGAIN, "poll_idle");

	/* A busy poll takes the idle NAPI and leaves it scheduled; a plain one completes it. */
	ret = run_prog(skel->progs.poll_napi, 0, napi_id, BPF_NAPI_POLL_F_BUSY);
	ASSERT_EQ(ret & BPF_NAPI_POLL_MORE, BPF_NAPI_POLL_MORE, "busy_poll_keeps_napi");
	ret = run_prog(skel->progs.poll_napi, 0, napi_id, 0);
	ASSERT_EQ(ret & BPF_NAPI_POLL_MORE, 0, "plain_poll_completes");

	/* The thread polls on every schedule. */
	skel->bss->paused[0] = 0;
	ASSERT_GE(run_prog(skel->progs.wake_poller, 0, 0, 0), 0, "wake_poller_0");
	ASSERT_TRUE(ping(tx, rx), "ping_thread");
	before = skel->bss->polls[0];
	ASSERT_TRUE(ping(tx, rx), "ping_thread_2");
	ASSERT_TRUE(polled_past(skel, 0, before), "thread_polled");
	ASSERT_GE(skel->bss->work[0], 2, "thread_work");

	/* The thread keeps the interrupt masked and polls every millisecond. */
	skel->bss->busy[0] = 1;
	ASSERT_GE(run_prog(skel->progs.wake_poller, 0, 0, 0), 0, "wake_poller_0_busy");
	ASSERT_TRUE(ping(tx, rx), "ping_busy_thread");
	ASSERT_TRUE(ping(tx, rx), "ping_busy_thread_2");
	skel->bss->busy[0] = 0;
	ASSERT_TRUE(ping(tx, rx), "ping_thread_after_busy");

	/* The NAPI moves to the second thread. */
	skel->bss->paused[1] = 0;
	if (!ASSERT_OK(run_prog(skel->progs.bind_napi, 1, napi_id, 0), "move_napi"))
		goto out;
	before = skel->bss->polls[1];
	ASSERT_TRUE(ping(tx, rx), "ping_second_thread");
	ASSERT_TRUE(polled_past(skel, 1, before), "second_thread_polled");

	/*
	 * Suspended, the NAPI is softirq's while it stays bound: datagrams
	 * arrive without the thread, polls are refused, and after the two
	 * packets it asked for the thread is woken and finds that out. Resumed,
	 * the thread polls again.
	 */
	ASSERT_EQ(run_prog(skel->progs.suspend_napi, 0, 0x7fffffff, 0), -ENOENT, "suspend_unknown_napi");
	ASSERT_EQ(run_prog(skel->progs.resume_napi, 0, 0x7fffffff, 0), -ENOENT, "resume_unknown_napi");
	skel->bss->last_err[1] = 0;
	if (!ASSERT_OK(run_prog(skel->progs.suspend_napi, 0, napi_id, 2), "suspend_napi"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -ECANCELED, "poll_suspended");
	ASSERT_TRUE(ping(tx, rx), "ping_softirq_while_suspended");
	ASSERT_TRUE(ping(tx, rx), "ping_softirq_while_suspended_2");
	for (ret = 0; ret < 1000 && skel->bss->last_err[1] != -ECANCELED; ret++)
		usleep(1000);
	ASSERT_EQ(skel->bss->last_err[1], -ECANCELED, "thread_woken_after_count");
	if (!ASSERT_OK(run_prog(skel->progs.resume_napi, 0, napi_id, 0), "resume_napi"))
		goto out;
	before = skel->bss->polls[1];
	ASSERT_TRUE(ping(tx, rx), "ping_after_resume");
	ASSERT_TRUE(polled_past(skel, 1, before), "resumed_thread_polled");

	/* A write of the threaded setting ends the binding. */
	if (!ASSERT_OK(set_threaded(0), "threaded_write_while_bound"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -ENOENT, "poll_after_threaded_write");
	ASSERT_TRUE(ping(tx, rx), "ping_softirq_after_threaded_write");

	/*
	 * A thread that stops polling loses the NAPI's scheduling after about
	 * a second: softirq delivers the packet, polls are refused, and a
	 * resume puts the thread back in charge.
	 */
	skel->bss->paused[1] = 1;
	if (!ASSERT_OK(run_prog(skel->progs.bind_napi, 1, napi_id, 0), "bind_paused"))
		goto out;
	set_rcvtimeo(rx, 5000);
	ASSERT_TRUE(ping(tx, rx), "ping_watchdog");
	set_rcvtimeo(rx, 300);
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -ECANCELED, "poll_after_watchdog");
	ASSERT_TRUE(ping(tx, rx), "ping_softirq_after_watchdog");
	skel->bss->paused[1] = 0;
	if (!ASSERT_OK(run_prog(skel->progs.resume_napi, 0, napi_id, 0), "resume_after_watchdog"))
		goto out;
	before = skel->bss->polls[1];
	ASSERT_TRUE(ping(tx, rx), "ping_after_rebind");
	ASSERT_TRUE(polled_past(skel, 1, before), "rebound_thread_polled");

	/* A thread that exits gives its NAPI back. */
	ASSERT_EQ(run_prog(skel->progs.stop_poller, 1, 0, 0), 0, "stop_poller_1");
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -ENOENT, "poll_after_thread_exit");
	ASSERT_TRUE(ping(tx, rx), "ping_softirq_after_thread_exit");

	/* The device takes the NAPI down with the binding and brings it back without. */
	if (!ASSERT_OK(run_prog(skel->progs.bind_napi, 0, napi_id, 0), "bind_before_down"))
		goto out;
	SYS(out, "ip link set dev veth_dst down");
	ASSERT_EQ(run_prog(skel->progs.poll_napi, 0, napi_id, 0), -ENOENT, "poll_after_down");
	SYS(out, "ip link set dev veth_dst up");
	ASSERT_TRUE(ping(tx, rx), "ping_softirq_after_up");

	ASSERT_EQ(run_prog(skel->progs.stop_poller, 0, 0, 0), 0, "stop_poller_0");
out:
	if (tx >= 0)
		close(tx);
	if (rx >= 0)
		close(rx);
	if (tok)
		close_netns(tok);
	SYS_NOFAIL("ip netns del " NS_SRC);
	SYS_NOFAIL("ip netns del " NS_DST);
	bpf_napi__destroy(skel);
}
