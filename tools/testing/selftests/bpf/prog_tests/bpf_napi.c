// SPDX-License-Identifier: GPL-2.0
/*
 * Hand a veth NAPI to a BPF kthread and check that packets only flow while
 * the poller runs, that the wait queue wakes it, and that unbinding, device
 * down and the threaded-mode exclusion behave. The veth ends live in two
 * namespaces so that datagrams cross the pair instead of taking loopback.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "bpf_napi.skel.h"

#define NS_SRC "bpf_napi_src"
#define NS_DST "bpf_napi_dst"
/* Mirrors the enum next to the NAPI state bits in linux/netdevice.h. */
#define BPF_NAPI_POLL_WORK_MASK 0xffff
#define BPF_NAPI_POLL_MORE (1 << 16)
#define SRC_IP "10.99.0.1"
#define DST_IP "10.99.0.2"
#define PORT 7777

/* Mirrors struct poller in progs/bpf_napi.c; the kernel fields are opaque here. */
struct poller {
	__u64 kthread[2];
	__u64 waitq[2];
	__u64 rounds;
	__u64 polls;
	__u64 work;
	__u64 unbound;
};

static int run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, bpf_program__name(prog)))
		return err;
	return (int)opts.retval;
}

static int udp_socket(const char *ip, bool bind_it)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	struct timeval tv = { .tv_usec = 300 * 1000 };
	int fd;

	inet_pton(AF_INET, ip, &addr.sin_addr);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!ASSERT_GE(fd, 0, "socket"))
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

static int read_poller(struct bpf_napi *skel, struct poller *p)
{
	__u32 key = 0;

	return bpf_map__lookup_elem(skel->maps.poller_map, &key, sizeof(key), p, sizeof(*p), 0);
}

/* Wait for the poller to notice that its NAPI is gone. */
static bool wait_unbound(struct bpf_napi *skel, struct poller *p)
{
	int i;

	for (i = 0; i < 1000; i++) {
		if (read_poller(skel, p) || p->unbound)
			return !!p->unbound;
		usleep(1000);
	}
	return false;
}

void test_bpf_napi(void)
{
	struct nstoken *tok = NULL;
	struct bpf_napi *skel;
	struct poller p;
	__u32 napi_id = 0;
	socklen_t len = sizeof(napi_id);
	int tx = -1, rx = -1, err, ret;
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
	if (!ASSERT_TRUE(ping(tx, rx), "native_ping"))
		goto out;
	err = getsockopt(rx, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &len);
	if (!ASSERT_OK(err, "SO_INCOMING_NAPI_ID") || !ASSERT_GT(napi_id, 0, "napi_id"))
		goto out;
	skel->bss->napi_id = napi_id;
	skel->bss->other_napi_id = 0x7fffffff;

	ASSERT_EQ(run_prog(skel->progs.init_waitq), 0, "init_waitq");
	ASSERT_EQ(run_prog(skel->progs.bind_bad_flags), -EINVAL, "bind_bad_flags");
	ASSERT_EQ(run_prog(skel->progs.bind_other_napi), -ENOENT, "bind_unknown_napi");
	ASSERT_EQ(run_prog(skel->progs.poll_napi), -ENOENT, "poll_unbound");
	ASSERT_EQ(run_prog(skel->progs.unbind_napi), 0, "unbind_unbound");

	/*
	 * A threaded NAPI cannot be bound, and a bound one cannot go threaded.
	 * ip netns exec remounts sysfs for the namespace, our own /sys does not.
	 */
	SYS(out, "ip netns exec " NS_DST " sh -c 'echo 1 > /sys/class/net/veth_dst/threaded'");
	ASSERT_EQ(run_prog(skel->progs.bind_napi), -EBUSY, "bind_threaded");
	SYS(out, "ip netns exec " NS_DST " sh -c 'echo 0 > /sys/class/net/veth_dst/threaded'");
	ASSERT_EQ(run_prog(skel->progs.bind_napi), 0, "bind_napi");
	ASSERT_NEQ(system("ip netns exec " NS_DST " sh -c 'echo 1 > /sys/class/net/veth_dst/threaded' "
			  "2>/dev/null"), 0, "threaded_while_bound");

	/*
	 * Bound with nobody polling: the packet waits in the NAPI until we poll.
	 * The poll may also find the namespace's IPv6 multicast chatter.
	 */
	ASSERT_FALSE(ping(tx, rx), "ping_stalls_without_poller");
	ret = run_prog(skel->progs.poll_napi);
	ASSERT_GE(ret & BPF_NAPI_POLL_WORK_MASK, 1, "poll_pending_work");
	ASSERT_EQ(ret & BPF_NAPI_POLL_MORE, 0, "poll_pending_done");
	if (!ASSERT_EQ(recv(rx, buf, sizeof(buf), 0), sizeof(buf), "recv_after_poll"))
		goto out;
	ASSERT_EQ(run_prog(skel->progs.poll_napi), -EAGAIN, "poll_idle");

	/* With a poller, packets flow and each schedule wakes it. */
	ASSERT_EQ(run_prog(skel->progs.start_poller), 0, "start_poller");
	ASSERT_TRUE(ping(tx, rx), "ping_with_poller");
	ASSERT_TRUE(ping(tx, rx), "ping_with_poller_2");
	ASSERT_OK(read_poller(skel, &p), "lookup_poller");
	ASSERT_GE(p.rounds, 2, "poller_rounds");
	ASSERT_GE(p.work, 2, "poller_work");
	ASSERT_EQ(p.unbound, 0, "poller_unbound");

	/*
	 * Unbinding returns the NAPI to softirq. The poller sleeps on until
	 * something wakes it, and then finds its NAPI gone.
	 */
	ASSERT_EQ(run_prog(skel->progs.unbind_napi), 0, "unbind_napi");
	ASSERT_TRUE(ping(tx, rx), "ping_native_again");
	ASSERT_EQ(run_prog(skel->progs.poll_napi), -ENOENT, "poll_after_unbind");
	ASSERT_EQ(run_prog(skel->progs.wake_poller), 1, "wake_poller");
	ASSERT_TRUE(wait_unbound(skel, &p), "poller_saw_unbind");

	/* Device down unbinds; the ID is gone until the device comes back. */
	ASSERT_EQ(run_prog(skel->progs.bind_napi), 0, "rebind_napi");
	SYS(out, "ip link set dev veth_dst down");
	ASSERT_EQ(run_prog(skel->progs.poll_napi), -ENOENT, "poll_after_down");
	SYS(out, "ip link set dev veth_dst up");
	ASSERT_TRUE(ping(tx, rx), "ping_after_up");

	ASSERT_EQ(run_prog(skel->progs.stop_poller), 0, "stop_poller");
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
