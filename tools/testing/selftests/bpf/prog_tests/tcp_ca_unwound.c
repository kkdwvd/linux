// SPDX-License-Identifier: GPL-2.0

#include <netinet/tcp.h>
#include <test_progs.h>

#include "network_helpers.h"
#include "tcp_ca_unwound.skel.h"

#define LO_IFINDEX 1

/* as in progs/tcp_ca_unwound.c */
enum {
	DROP_NONE,
	DROP_ACK,
	DROP_DATA,
};

struct conn {
	int lfd, cfd, afd;
};

struct sock_opts {
	const char *cc;
	int mss;
};

static int sock_cb(int fd, void *opts)
{
	struct sock_opts *o = opts;

	if (o->mss && setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &o->mss, sizeof(o->mss)))
		return -1;
	return setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, o->cc, strlen(o->cc));
}

/* Each subtest starts from zero */
static void reset(struct tcp_ca_unwound *skel)
{
	memset(skel->bss, 0, sizeof(*skel->bss));
}

static void conn_close(struct conn *c)
{
	if (c->afd >= 0)
		close(c->afd);
	if (c->cfd >= 0)
		close(c->cfd);
	if (c->lfd >= 0)
		close(c->lfd);
}

/* The client sends with congestion control @cc and with segments of @mss bytes, if not 0 */
static bool conn_open(struct conn *c, struct tcp_ca_unwound *skel, const char *cc, int mss)
{
	struct sock_opts sock_opts = { .cc = cc, .mss = mss };
	struct network_helper_opts opts = {
		.post_socket_cb = sock_cb,
		.cb_opts = &sock_opts,
	};
	int one = 1;

	c->cfd = c->afd = -1;
	c->lfd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_OK_FD(c->lfd, "start_server"))
		return false;
	c->cfd = connect_to_fd_opts(c->lfd, &opts);
	if (!ASSERT_OK_FD(c->cfd, "connect_to_fd_opts"))
		goto err;
	c->afd = accept(c->lfd, NULL, NULL);
	if (!ASSERT_OK_FD(c->afd, "accept"))
		goto err;
	/* an ACK for each segment, at once */
	if (!ASSERT_OK(setsockopt(c->afd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one)),
		       "TCP_QUICKACK"))
		goto err;
	if (!ASSERT_OK(settimeo(c->afd, 5000), "settimeo"))
		goto err;
	/* in network byte order */
	skel->bss->srv_port = get_socket_local_port(c->lfd);
	skel->bss->cli_port = get_socket_local_port(c->cfd);
	return true;
err:
	conn_close(c);
	return false;
}

/* The client writes @len bytes and the server reads them */
static bool transfer(struct conn *c, int len)
{
	char buf[16384] = {};
	int n, got = 0;

	if (!ASSERT_LE(len, (int)sizeof(buf), "len") ||
	    !ASSERT_EQ(send(c->cfd, buf, len, 0), len, "send"))
		return false;
	while (got < len) {
		n = recv(c->afd, buf, sizeof(buf), 0);
		if (!ASSERT_GT(n, 0, "recv"))
			return false;
		got += n;
	}
	return true;
}

static bool wait_for(const int *val, int want)
{
	int i;

	for (i = 0; i < 500 && *val < want; i++)
		usleep(10000);
	return *val >= want;
}

static __u32 snd_cwnd(int fd)
{
	struct tcp_info info = {};
	socklen_t len = sizeof(info);

	if (!ASSERT_OK(getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len), "TCP_INFO"))
		return 0;
	return info.tcpi_snd_cwnd;
}

/*
 * The ACK of a segment is lost. The retransmission timer of the client fires, and the server
 * answers the copy with a DSACK: the client learns that the timeout was spurious and takes the
 * loss back, with the window that ->undo_cwnd() returns. The kernel unwinds that call.
 */
static void test_undo_cwnd(struct tcp_ca_unwound *skel)
{
	struct conn c;

	reset(skel);
	if (!conn_open(&c, skel, "bpf_unwound", 0))
		return;
	if (!transfer(&c, 1))
		goto out;

	skel->bss->unwind_undo_cwnd = true;
	skel->bss->drop = DROP_ACK;
	if (!transfer(&c, 1))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->dropped, 1), "dropped") ||
	    !ASSERT_TRUE(wait_for(&skel->bss->undos, 1), "the loss was taken back"))
		goto out;
	skel->bss->unwind_undo_cwnd = false;

	ASSERT_EQ(skel->bss->dropped, 1, "dropped");
	ASSERT_EQ(skel->bss->undo_cwnd_went_down, 1, "undo_cwnd_went_down");
	ASSERT_EQ(skel->bss->undo_cwnd_went_on, 0, "undo_cwnd_went_on");
	/* a window of one segment, see bpf_tcp_ca_unwound_retval(): 0 is no window */
	ASSERT_EQ(skel->bss->cwnd_after_undo, 1, "cwnd_after_undo");
	ASSERT_GE(snd_cwnd(c.cfd), 1, "snd_cwnd");

	/* the connection works as before */
	transfer(&c, 16384);
out:
	skel->bss->unwind_undo_cwnd = false;
	skel->bss->drop = DROP_NONE;
	conn_close(&c);
}

/*
 * The first segment of a write is lost. The ACKs of the segments behind it take the client into
 * a fast recovery, with the slow start threshold that ->ssthresh() returns. The kernel unwinds
 * that call. When the recovery is over TCP sets the window to that threshold.
 * If the guest stalls for longer than the retransmission timeout, about 200 ms, before the
 * retransmitted segment is acknowledged, the timeout takes the connection from the recovery into
 * the loss state. It keeps the threshold there, and no recovery is completed: the window is not
 * set to the threshold, it starts from one segment. The test takes both ways.
 */
static void test_ssthresh(struct tcp_ca_unwound *skel)
{
	struct conn c;

	reset(skel);
	if (!conn_open(&c, skel, "bpf_unwound", 1000))
		return;
	if (!transfer(&c, 1))
		goto out;

	skel->bss->unwind_ssthresh = true;
	skel->bss->drop = DROP_DATA;
	if (!transfer(&c, 16384))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->dropped, 1), "dropped") ||
	    !ASSERT_TRUE(wait_for(&skel->bss->recovered, 1), "the recovery is over"))
		goto out;
	skel->bss->unwind_ssthresh = false;

	ASSERT_EQ(skel->bss->dropped, 1, "dropped");
	ASSERT_EQ(skel->bss->ssthresh_went_on, 0, "ssthresh_went_on");
	/* the least threshold of reno, see bpf_tcp_ca_unwound_retval(): 0 is no window later on */
	ASSERT_EQ(skel->bss->ssthresh_in_recovery, 2, "ssthresh_in_recovery");
	if (!skel->bss->losses) {
		ASSERT_EQ(skel->bss->ssthresh_went_down, 1, "ssthresh_went_down");
		ASSERT_EQ(skel->bss->recoveries, 1, "recoveries");
		ASSERT_EQ(skel->bss->cwnd_after_recovery, 2, "cwnd_after_recovery");
	} else {
		/* a timeout in the recovery: TCP goes on with the threshold of the unwound call */
		ASSERT_GE(skel->bss->ssthresh_went_down, 1, "ssthresh_went_down");
		ASSERT_EQ(skel->bss->ssthresh_in_loss, 2, "ssthresh_in_loss");
	}
	ASSERT_GE(snd_cwnd(c.cfd), 1, "snd_cwnd");

	/* the connection works as before */
	transfer(&c, 16384);
out:
	skel->bss->unwind_ssthresh = false;
	skel->bss->drop = DROP_NONE;
	conn_close(&c);
}

/*
 * Each segment of a write asks ->tso_segs(), and the kernel unwinds each of the calls. TCP makes
 * one segment for a packet of what an unwound call returns, 1, and it would make the same of 0:
 * tcp_tso_segs() clamps. So this does not show the value. It shows that the unwound calls do not
 * stop the write: every byte arrives, each call got to the recursion and none went on behind it.
 */
static void test_tso_segs(struct tcp_ca_unwound *skel)
{
	struct conn c;

	reset(skel);
	if (!conn_open(&c, skel, "bpf_unwound", 1000))
		return;
	skel->bss->unwind_tso_segs = true;
	ASSERT_TRUE(transfer(&c, 16384), "the write arrives");
	skel->bss->unwind_tso_segs = false;
	ASSERT_GT(skel->bss->tso_segs_went_down, 0, "tso_segs_went_down");
	ASSERT_EQ(skel->bss->tso_segs_went_on, 0, "tso_segs_went_on");
	conn_close(&c);
}

static int sndbuf(int fd)
{
	socklen_t len = sizeof(int);
	int val = 0;

	ASSERT_OK(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &len), "SO_SNDBUF");
	return val;
}

/*
 * TCP sizes the send buffer when the connection is set up, with the factor that
 * ->sndbuf_expand() returns. Unwound, it returns the factor that TCP takes for a congestion
 * control without the operator, like reno. With 0 the buffer would never grow.
 */
static void test_sndbuf_expand(struct tcp_ca_unwound *skel)
{
	struct conn c, reno;

	reset(skel);
	skel->bss->unwind_sndbuf_expand = true;
	if (!conn_open(&c, skel, "bpf_unwound", 0))
		goto out;
	if (!conn_open(&reno, skel, "reno", 0))
		goto close;
	ASSERT_GT(skel->bss->sndbuf_expand_went_down, 0, "sndbuf_expand_went_down");
	ASSERT_EQ(skel->bss->sndbuf_expand_went_on, 0, "sndbuf_expand_went_on");
	ASSERT_EQ(sndbuf(c.cfd), sndbuf(reno.cfd), "send buffer, as with reno");
	conn_close(&reno);
close:
	conn_close(&c);
out:
	skel->bss->unwind_sndbuf_expand = false;
}

void test_ns_tcp_ca_unwound(void)
{
	struct tcp_ca_unwound *skel;
	struct bpf_link *link, *tcx;

	skel = tcp_ca_unwound__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tcp_ca_unwound__open_and_load"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.unwound);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;
	tcx = bpf_program__attach_tcx(skel->progs.drops_one, LO_IFINDEX, NULL);
	if (!ASSERT_OK_PTR(tcx, "bpf_program__attach_tcx"))
		goto unlink;
	/* no tail loss probe: the retransmission timer is what finds the lost ACK */
	if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/tcp_early_retrans", "0"),
		       "tcp_early_retrans"))
		goto untcx;

	if (test__start_subtest("undo_cwnd"))
		test_undo_cwnd(skel);
	if (test__start_subtest("ssthresh"))
		test_ssthresh(skel);
	if (test__start_subtest("tso_segs"))
		test_tso_segs(skel);
	if (test__start_subtest("sndbuf_expand"))
		test_sndbuf_expand(skel);
untcx:
	bpf_link__destroy(tcx);
unlink:
	bpf_link__destroy(link);
out:
	tcp_ca_unwound__destroy(skel);
}
