// SPDX-License-Identifier: GPL-2.0
/*
 * Sending a frame a program keeps, over a veth pair: a UDP client in one
 * namespace, and in the other an XDP program that turns each datagram around,
 * takes the frame and has it sent out of the device it arrived on. The client
 * gets its datagrams back when the frame is sent in a later invocation, and by
 * a syscall program from process context, also on another CPU. In the
 * invocation that took the frame the call is refused. A frame that is not sent
 * is given back, and the call says why.
 *
 * The frames of a datagram from the client are pages that nothing counts. A
 * live test run on the device brings frames from a page pool of its own, which
 * a program on the pool's tracepoint watches: it tells whether every frame
 * that was not sent, and every one that was, came back.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include "xdp_frame_xmit.skel.h"

#define NS_SRV		"xdp_fx_srv"
#define NS_CLI		"xdp_fx_cli"
#define DEV_SRV		"fxsrv"
#define DEV_CLI		"fxcli"
#define MAC_SRV		"02:00:00:00:78:01"
#define MAC_CLI		"02:00:00:00:78:02"
#define IP_SRV		"192.168.78.1"
#define IP_CLI		"192.168.78.2"
#define PORT		7778
#define NR_SLOTS	8
#define FRAME_LEN	128
#define FRAME_BIG	1200	/* over an MTU of 1000 */
#define TIMEOUT_MS	2000

enum {
	MODE_TAKEN,
	MODE_KEPT,
	MODE_STASH,
};

struct ctx {
	struct xdp_frame_xmit *skel;
	struct netns_obj *ns_srv, *ns_cli;
	int ifindex_srv, ifindex_cli;
	int fd, fd_sync;
};

static void cleanup(struct ctx *c)
{
	if (c->fd >= 0)
		close(c->fd);
	if (c->fd_sync >= 0)
		close(c->fd_sync);
	/* The devices go with their namespaces, and the programs with the devices. */
	netns_free(c->ns_cli);
	netns_free(c->ns_srv);
	xdp_frame_xmit__destroy(c->skel);
}

static int attach(const char *ns, const char *dev, struct bpf_program *prog)
{
	struct nstoken *tok = open_netns(ns);
	int ifindex, err;

	if (!ASSERT_OK_PTR(tok, "open_netns"))
		return -1;
	ifindex = if_nametoindex(dev);
	err = bpf_xdp_attach(ifindex, prog ? bpf_program__fd(prog) : -1, XDP_FLAGS_DRV_MODE, NULL);
	close_netns(tok);
	if (!ASSERT_GT(ifindex, 0, "if_nametoindex") || !ASSERT_OK(err, "bpf_xdp_attach"))
		return -1;
	return ifindex;
}

static int open_client(int port)
{
	struct timeval tv = { .tv_sec = TIMEOUT_MS / 1000 };
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	struct nstoken *tok;
	int fd, one = 1;

	tok = open_netns(NS_CLI);
	if (!ASSERT_OK_PTR(tok, "open_netns cli"))
		return -1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	close_netns(tok);
	if (!ASSERT_GE(fd, 0, "socket"))
		return -1;
	/*
	 * No checksum: the device would leave it to its peer, and the frame comes back as the
	 * program got it.
	 */
	inet_pton(AF_INET, IP_SRV, &addr.sin_addr);
	if (!ASSERT_OK(setsockopt(fd, SOL_SOCKET, SO_NO_CHECK, &one, sizeof(one)), "SO_NO_CHECK") ||
	    !ASSERT_OK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), "SO_RCVTIMEO") ||
	    !ASSERT_OK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), "connect")) {
		close(fd);
		return -1;
	}
	return fd;
}

static int setup(struct ctx *c)
{
	memset(c, 0, sizeof(*c));
	c->fd = c->fd_sync = -1;
	c->skel = xdp_frame_xmit__open_and_load();
	if (!ASSERT_OK_PTR(c->skel, "xdp_frame_xmit__open_and_load"))
		return -1;
	c->skel->bss->port = PORT;
	c->skel->bss->xmit_nr = NR_SLOTS;
	c->skel->links.pool_release = bpf_program__attach(c->skel->progs.pool_release);
	if (!ASSERT_OK_PTR(c->skel->links.pool_release, "attach pool_release"))
		goto fail;
	c->ns_srv = netns_new(NS_SRV, false);
	c->ns_cli = netns_new(NS_CLI, false);
	if (!ASSERT_OK_PTR(c->ns_srv, "netns_new srv") || !ASSERT_OK_PTR(c->ns_cli, "netns_new cli"))
		goto fail;
	SYS(fail, "ip link add %s address %s netns %s type veth peer name %s address %s netns %s",
	    DEV_SRV, MAC_SRV, NS_SRV, DEV_CLI, MAC_CLI, NS_CLI);

	/* A program on the client's end has the server's end take XDP frames for it. */
	c->ifindex_cli = attach(NS_CLI, DEV_CLI, c->skel->progs.xdp_frame_pass);
	if (c->ifindex_cli < 0)
		goto fail;
	SYS(fail, "ip -n %s addr add %s/24 dev %s", NS_CLI, IP_CLI, DEV_CLI);
	SYS(fail, "ip -n %s link set dev %s up", NS_CLI, DEV_CLI);
	SYS(fail, "ip -n %s link set dev %s up", NS_SRV, DEV_SRV);
	SYS(fail, "ip -n %s neigh add %s lladdr %s dev %s nud permanent", NS_CLI, IP_SRV, MAC_SRV,
	    DEV_CLI);
	c->ifindex_srv = attach(NS_SRV, DEV_SRV, c->skel->progs.xdp_frame_echo);
	if (c->ifindex_srv < 0)
		goto fail;
	c->fd = open_client(PORT);
	c->fd_sync = open_client(PORT + 1);
	if (c->fd < 0 || c->fd_sync < 0)
		goto fail;
	return 0;
fail:
	cleanup(c);
	return -1;
}

static bool wait_for(__u64 *counter, __u64 want)
{
	int i;

	for (i = 0; i < TIMEOUT_MS && READ_ONCE(*counter) < want; i++)
		usleep(1000);
	return ASSERT_EQ(READ_ONCE(*counter), want, "counter");
}

static int send_seq(struct ctx *c, int first, int nr)
{
	char buf[32];
	int i, len;

	for (i = first; i < first + nr; i++) {
		len = snprintf(buf, sizeof(buf), "frame %d", i);
		if (!ASSERT_EQ(send(c->fd, buf, len, 0), len, "send"))
			return -1;
	}
	return 0;
}

/*
 * The device's receive runs behind the send, and the driver drops its reference to a frame
 * only after the program has returned. A datagram that the program counts and drops says
 * that the driver is done with all that arrived before it.
 */
static int sync_rx(struct ctx *c)
{
	__u64 want = READ_ONCE(c->skel->bss->synced) + 1;

	if (!ASSERT_EQ(send(c->fd_sync, "sync", 4, 0), 4, "send sync"))
		return -1;
	return wait_for(&c->skel->bss->synced, want) ? 0 : -1;
}

/* The datagrams come back as they were sent, from the address they went to. */
static void recv_seq(struct ctx *c, int first, int nr)
{
	char buf[32], want[32];
	int i, len, n;

	for (i = first; i < first + nr; i++) {
		len = snprintf(want, sizeof(want), "frame %d", i);
		n = recv(c->fd, buf, sizeof(buf), 0);
		if (!ASSERT_EQ(n, len, "recv") || !ASSERT_MEMEQ(buf, want, len, "payload"))
			return;
	}
}

static void recv_none(struct ctx *c)
{
	char buf[32];

	ASSERT_EQ(recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT), -1, "recv nothing");
	ASSERT_EQ(errno, EAGAIN, "errno");
}

static __u16 ip_csum(const struct iphdr *ip)
{
	const __u16 *p = (const __u16 *)ip;
	__u32 sum = 0;
	int i;

	for (i = 0; i < sizeof(*ip) / 2; i++)
		sum += p[i];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

/*
 * Run the XDP program with @nr live frames of @len bytes: a datagram "frame 0" from the
 * client to the port, as it arrives on the server's device when @c is given, and on loopback,
 * where no NAPI instance polls, when it isn't. The run has a page pool of its own and asks it
 * to go when it ends: the program on the tracepoint tells how many pages it misses then.
 */
static int run_live(struct xdp_frame_xmit *skel, struct ctx *c, int nr, int len)
{
	struct {
		struct ethhdr eth;
		struct iphdr ip;
		struct udphdr udp;
		char data[FRAME_BIG];
	} __attribute__((packed)) frame = {
		.eth.h_proto = htons(ETH_P_IP),
		.ip.version = 4,
		.ip.ihl = 5,
		.ip.ttl = 64,
		.ip.protocol = IPPROTO_UDP,
		.udp.dest = htons(PORT),
		.data = "frame 0",
	};
	int hdrs = sizeof(frame) - sizeof(frame.data), payload = len ? len - hdrs : 7;
	struct xdp_md md = { .data_end = hdrs + payload };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &frame,
		    .data_size_in = hdrs + payload,
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    .repeat = nr,
		    .batch_size = nr);
	__u64 stolen = skel->bss->stolen;
	struct nstoken *tok = NULL;
	int err;

	frame.ip.tot_len = htons(sizeof(frame.ip) + sizeof(frame.udp) + payload);
	frame.udp.len = htons(sizeof(frame.udp) + payload);
	if (c) {
		struct sockaddr_in addr;
		socklen_t alen = sizeof(addr);

		if (!ASSERT_OK(getsockname(c->fd, (struct sockaddr *)&addr, &alen), "getsockname"))
			return -1;
		frame.udp.source = addr.sin_port;
		inet_pton(AF_INET, IP_CLI, &frame.ip.saddr);
		inet_pton(AF_INET, IP_SRV, &frame.ip.daddr);
		sscanf(MAC_SRV, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &frame.eth.h_dest[0],
		       &frame.eth.h_dest[1], &frame.eth.h_dest[2], &frame.eth.h_dest[3],
		       &frame.eth.h_dest[4], &frame.eth.h_dest[5]);
		sscanf(MAC_CLI, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &frame.eth.h_source[0],
		       &frame.eth.h_source[1], &frame.eth.h_source[2], &frame.eth.h_source[3],
		       &frame.eth.h_source[4], &frame.eth.h_source[5]);
		md.ingress_ifindex = c->ifindex_srv;
		opts.ctx_in = &md;
		opts.ctx_size_in = sizeof(md);
		tok = open_netns(NS_SRV);
		if (!ASSERT_OK_PTR(tok, "open_netns srv"))
			return -1;
	}
	frame.ip.check = ip_csum(&frame.ip);
	skel->bss->pools_gone = 0;
	skel->bss->pool_tid = sys_gettid();
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_frame_echo), &opts);
	skel->bss->pool_tid = 0;
	if (tok)
		close_netns(tok);
	if (!ASSERT_OK(err, "test_run live") ||
	    !ASSERT_EQ(skel->bss->stolen - stolen, nr, "stolen") ||
	    !ASSERT_EQ(skel->bss->pools_gone, 1, "pools_gone"))
		return -1;
	return 0;
}

/* The pool of the last live run looks again every second: wait until it misses nothing. */
static void pool_gets_all_back(struct xdp_frame_xmit *skel)
{
	int i;

	for (i = 0; i < 5000 && READ_ONCE(skel->bss->pool_inflight); i++)
		usleep(1000);
	ASSERT_EQ(READ_ONCE(skel->bss->pool_inflight), 0, "pool_inflight");
}

/* Have the syscall program send @nr of the kept frames from @first on. */
static int xmit(struct xdp_frame_xmit *skel, int first, int nr)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	skel->bss->xmit_first = first;
	skel->bss->xmit_nr = nr;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_frame_xmit_stashed), &opts);
	if (!ASSERT_OK(err, "test_run xmit") || !ASSERT_EQ(opts.retval, 0, "retval"))
		return -1;
	return 0;
}

static void reset(struct xdp_frame_xmit__bss *bss)
{
	bss->sent = bss->send_failed = 0;
	bss->last_err = 0;
}

/*
 * In the invocation that took the frame the driver still hands the buffer over: the call is
 * refused and nothing is sent. The driver gives the frames back, also when the call fails
 * before it looks at the references: the pool of a live test run misses no page.
 */
static void test_taken(void)
{
	struct xdp_frame_xmit__bss *bss;
	struct ctx c;

	if (setup(&c))
		return;
	bss = c.skel->bss;
	bss->mode = MODE_TAKEN;
	if (send_seq(&c, 0, NR_SLOTS) || sync_rx(&c))
		goto out;
	ASSERT_EQ(bss->stolen, NR_SLOTS, "stolen");
	ASSERT_EQ(bss->send_failed, NR_SLOTS, "send_failed");
	ASSERT_EQ(bss->sent, 0, "sent");
	ASSERT_EQ(bss->last_err, -EBUSY, "last_err");
	recv_none(&c);

	reset(bss);
	if (run_live(c.skel, &c, NR_SLOTS, 0))
		goto out;
	ASSERT_EQ(bss->send_failed, NR_SLOTS, "send_failed, live");
	ASSERT_EQ(bss->last_err, -EBUSY, "last_err, live");
	ASSERT_EQ(bss->pool_inflight, 0, "pool_inflight");

	reset(bss);
	bss->xmit_flags = 1;
	if (run_live(c.skel, &c, NR_SLOTS, 0))
		goto out;
	ASSERT_EQ(bss->send_failed, NR_SLOTS, "send_failed, flags");
	ASSERT_EQ(bss->last_err, -EINVAL, "last_err, flags");
	ASSERT_EQ(bss->pool_inflight, 0, "pool_inflight, flags");
	ASSERT_EQ(bss->sent, 0, "sent, live");
	recv_none(&c);
out:
	cleanup(&c);
}

/* Sent from a kptr field in a later invocation, in softirq: one datagram behind. */
static void test_kept(void)
{
	struct ctx c;

	if (setup(&c))
		return;
	c.skel->bss->mode = MODE_KEPT;
	if (send_seq(&c, 0, NR_SLOTS))
		goto out;
	recv_seq(&c, 0, NR_SLOTS - 1);
	recv_none(&c);
	ASSERT_EQ(c.skel->bss->stolen, NR_SLOTS, "stolen");
	ASSERT_EQ(c.skel->bss->sent, NR_SLOTS - 1, "sent");
	ASSERT_EQ(c.skel->bss->send_failed, 0, "send_failed");
out:
	/* The last frame is still in its field: the destructor gives it back. */
	cleanup(&c);
}

static int pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * Sent by a syscall program from process context, on another CPU than the one the frames
 * arrived on when there are two. Then frames of a live test run, which the client gets as
 * well, and which the pool gets back once the client has read them.
 */
static void test_process(void)
{
	struct xdp_frame_xmit__bss *bss;
	cpu_set_t old;
	bool two_cpus;
	struct ctx c;
	char buf[32];
	int i;

	if (!ASSERT_OK(sched_getaffinity(0, sizeof(old), &old), "sched_getaffinity"))
		return;
	two_cpus = CPU_ISSET(0, &old) && CPU_ISSET(1, &old);
	if (setup(&c))
		return;
	bss = c.skel->bss;
	bss->mode = MODE_STASH;
	if (two_cpus && !ASSERT_OK(pin(0), "pin to CPU 0"))
		goto out;
	if (send_seq(&c, 0, NR_SLOTS) || sync_rx(&c))
		goto out;
	ASSERT_EQ(bss->stashed, NR_SLOTS, "stashed");
	recv_none(&c);
	if (two_cpus && !ASSERT_OK(pin(1), "pin to CPU 1"))
		goto out;
	if (xmit(c.skel, 0, NR_SLOTS))
		goto out;
	ASSERT_EQ(bss->sent, NR_SLOTS, "sent");
	ASSERT_EQ(bss->send_failed, 0, "send_failed");
	if (two_cpus) {
		ASSERT_EQ(bss->steal_cpu, 0, "steal_cpu");
		ASSERT_EQ(bss->xmit_cpu, 1, "xmit_cpu");
	}
	recv_seq(&c, 0, NR_SLOTS);

	reset(bss);
	if (run_live(c.skel, &c, NR_SLOTS, 0))
		goto out;
	ASSERT_EQ(bss->pool_inflight, NR_SLOTS, "pool_inflight, kept");
	if (xmit(c.skel, 0, NR_SLOTS))
		goto out;
	ASSERT_EQ(bss->sent, NR_SLOTS, "sent, live");
	ASSERT_EQ(bss->send_failed, 0, "send_failed, live");
	for (i = 0; i < NR_SLOTS; i++)
		if (!ASSERT_EQ(recv(c.fd, buf, sizeof(buf), 0), 7, "recv, live") ||
		    !ASSERT_MEMEQ(buf, "frame 0", 7, "payload, live"))
			break;
	pool_gets_all_back(c.skel);
out:
	sched_setaffinity(0, sizeof(old), &old);
	cleanup(&c);
}

/*
 * One round of frames that are not sent: each invocation of a live test run keeps its frame
 * and tries to send the one before, which fails with @err and is given back, so the pool
 * misses the one frame that is still kept when the run ends.
 */
static void fail_kept(struct ctx *c, int len, int err, const char *what)
{
	struct xdp_frame_xmit__bss *bss = c->skel->bss;

	reset(bss);
	bss->mode = MODE_KEPT;
	if (run_live(c->skel, c, NR_SLOTS, len))
		return;
	ASSERT_EQ(bss->send_failed, NR_SLOTS - 1, what);
	ASSERT_EQ(bss->sent, 0, what);
	ASSERT_EQ(bss->last_err, err, what);
	ASSERT_EQ(bss->pool_inflight, 1, what);
	/* the one that is left fails the same way */
	if (!xmit(c->skel, 0, 1))
		ASSERT_EQ(bss->last_err, err, what);
}

/* Frames that cannot be sent are given back, and the call says why. */
static void test_errors(void)
{
	struct xdp_frame_xmit__bss *bss;
	struct ctx c;

	if (setup(&c))
		return;
	bss = c.skel->bss;

	bss->xmit_flags = 1;
	fail_kept(&c, 0, -EINVAL, "flags");
	bss->xmit_flags = 0;

	/* the frame exceeds the MTU of the peer, whose driver takes nothing and says nothing */
	SYS(out, "ip -n %s link set dev %s mtu 1000", NS_CLI, DEV_CLI);
	fail_kept(&c, FRAME_BIG, -ENOBUFS, "peer MTU");
	/* and that of the device */
	SYS(out, "ip -n %s link set dev %s mtu 1000", NS_SRV, DEV_SRV);
	fail_kept(&c, FRAME_BIG, -EMSGSIZE, "MTU");
	SYS(out, "ip -n %s link set dev %s mtu 1500", NS_SRV, DEV_SRV);
	SYS(out, "ip -n %s link set dev %s mtu 1500", NS_CLI, DEV_CLI);

	/* the other end is down, with its NAPI instances off */
	SYS(out, "ip -n %s link set dev %s down", NS_CLI, DEV_CLI);
	fail_kept(&c, 0, -ENXIO, "peer down");
	SYS(out, "ip -n %s link set dev %s up", NS_CLI, DEV_CLI);

	/* IRQs off: no driver can be entered, and a work item gives the frames back */
	reset(bss);
	bss->mode = MODE_STASH;
	bss->xmit_irqs_off = 1;
	if (run_live(c.skel, &c, NR_SLOTS, 0) || xmit(c.skel, 0, NR_SLOTS))
		goto out;
	ASSERT_EQ(bss->send_failed, NR_SLOTS, "send_failed, IRQs off");
	ASSERT_EQ(bss->last_err, -EOPNOTSUPP, "last_err, IRQs off");
	pool_gets_all_back(c.skel);

	ASSERT_EQ(bss->sent, 0, "sent");
	recv_none(&c);
out:
	cleanup(&c);
}

/*
 * A frame finds its device by the NAPI instance it arrived through, which goes when the
 * program is detached, when the device is closed, and with the device. A frame that is kept
 * across any of that is not sent, also when the device has a new instance by then, and is
 * given back. Each time the frames are of the instance that the device has at that point.
 */
static void test_lifetime(void)
{
	struct xdp_frame_xmit__bss *bss;
	struct ctx c;

	if (setup(&c))
		return;
	bss = c.skel->bss;
	bss->mode = MODE_STASH;

	/* the program is detached: the device has no NAPI instance */
	if (run_live(c.skel, &c, 4, 0))
		goto out;
	ASSERT_EQ(bss->pool_inflight, 4, "pool_inflight, kept");
	if (attach(NS_SRV, DEV_SRV, NULL) < 0 || xmit(c.skel, 0, 2))
		goto out;
	ASSERT_EQ(bss->send_failed, 2, "send_failed, detached");
	ASSERT_EQ(bss->last_err, -ENODEV, "last_err, detached");
	/* and attached again: a new instance, which is not the frames' */
	if (attach(NS_SRV, DEV_SRV, c.skel->progs.xdp_frame_echo) < 0 || xmit(c.skel, 2, 2))
		goto out;
	ASSERT_EQ(bss->send_failed, 4, "send_failed, attached again");
	pool_gets_all_back(c.skel);

	/* a frame that arrives through the new one is sent */
	bss->mode = MODE_KEPT;
	if (send_seq(&c, 0, 2))
		goto out;
	recv_seq(&c, 0, 1);
	ASSERT_EQ(bss->sent, 1, "sent, new instance");
	bss->mode = MODE_STASH;

	/* the device is closed and opened */
	if (run_live(c.skel, &c, 2, 0))
		goto out;
	SYS(out, "ip -n %s link set dev %s down", NS_SRV, DEV_SRV);
	SYS(out, "ip -n %s link set dev %s up", NS_SRV, DEV_SRV);
	if (xmit(c.skel, 4, 2))
		goto out;
	ASSERT_EQ(bss->send_failed, 6, "send_failed, closed and opened");
	ASSERT_EQ(bss->last_err, -ENODEV, "last_err, closed and opened");
	pool_gets_all_back(c.skel);

	/* the device is gone, and its peer with it */
	if (run_live(c.skel, &c, 2, 0))
		goto out;
	SYS(out, "ip -n %s link del dev %s", NS_SRV, DEV_SRV);
	if (xmit(c.skel, 6, 2))
		goto out;
	ASSERT_EQ(bss->send_failed, 8, "send_failed, gone");
	ASSERT_EQ(bss->last_err, -ENODEV, "last_err, gone");
	ASSERT_EQ(bss->sent, 1, "sent");
	pool_gets_all_back(c.skel);
out:
	cleanup(&c);
}

/*
 * A frame of a queue whose NAPI instance is not known has no device to go out of: the frames
 * of a live test run on loopback.
 */
static void test_no_napi(void)
{
	struct xdp_frame_xmit *skel;

	skel = xdp_frame_xmit__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_frame_xmit__open_and_load"))
		return;
	skel->links.pool_release = bpf_program__attach(skel->progs.pool_release);
	if (!ASSERT_OK_PTR(skel->links.pool_release, "attach pool_release"))
		goto out;
	skel->bss->port = PORT;
	skel->bss->mode = MODE_STASH;
	if (run_live(skel, NULL, NR_SLOTS, 0))
		goto out;
	ASSERT_EQ(skel->bss->pool_inflight, NR_SLOTS, "pool_inflight, kept");
	if (xmit(skel, 0, NR_SLOTS))
		goto out;
	ASSERT_EQ(skel->bss->sent, 0, "sent");
	ASSERT_EQ(skel->bss->send_failed, NR_SLOTS, "send_failed");
	ASSERT_EQ(skel->bss->last_err, -ENODEV, "last_err");
	pool_gets_all_back(skel);
out:
	xdp_frame_xmit__destroy(skel);
}

void test_xdp_frame_xmit(void)
{
	if (test__start_subtest("taken"))
		test_taken();
	if (test__start_subtest("kept"))
		test_kept();
	if (test__start_subtest("process"))
		test_process();
	if (test__start_subtest("errors"))
		test_errors();
	if (test__start_subtest("lifetime"))
		test_lifetime();
	if (test__start_subtest("no_napi"))
		test_no_napi();
}
