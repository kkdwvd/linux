// SPDX-License-Identifier: GPL-2.0
/*
 * An extension at the step where a NAPI is scheduled, on the receive NAPI of a veth device,
 * see progs/napi_ext.c: every poll of the NAPI passes the extension, which defers it to
 * softirq or to the BPF kthread that the NAPI is bound to, and the kernel resumes the
 * continuation that polls. The kernel polls by itself where it takes the NAPI back from a
 * thread or from the extension, and where a continuation or an entry is unwound. Extensions
 * that could keep a NAPI from being polled are not loaded. What a driver does with its NAPIs
 * beside the poll is on the NAPI of bpf_testmod.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "bpf_napi.skel.h"
#include "napi_ext.skel.h"
#include "napi_ext_fail.skel.h"
#include "napi_ext_null.skel.h"
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "../progs/napi_ext.h"

#define NS_SRC "napi_ext_src"
#define NS_DST "napi_ext_dst"
#define SRC_IP "10.98.0.1"
#define DST_IP "10.98.0.2"
#define PORT 7778

/* Mirror the kernel's enums in linux/netdevice.h. */
#define BPF_NAPI_POLL_F_BUSY 1
#define BPF_NAPI_OPS_F_INDIRECT 1
enum { BPF_NAPI_SCHEDULE, BPF_NAPI_REPOLL, BPF_NAPI_AGAIN };
enum { BPF_NAPI_SOFTIRQ, BPF_NAPI_THREAD };

/* Mirrors the @op of bpf_kfunc_napi_test_ctl() in test_kmods/bpf_testmod.c. */
enum {
	NAPI_TEST_DEL,
	NAPI_TEST_ADD,
	NAPI_TEST_ADD_ZEROED,
	NAPI_TEST_MISS,
	NAPI_TEST_NO_MISS,
	NAPI_TEST_POLLS,
	NAPI_TEST_MORE,
};

/* The polls beside the one that completes, in a row whose schedules are polled more than once */
#define MORE 16

/* Mirrors struct napi_args in progs/bpf_napi.c. */
struct napi_args {
	__u32 idx;
	__u32 napi_id;
	__u64 flags;
};

static char log_buf[1 << 20];

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

static bool wait_ge(__u64 *counter, __u64 want, const char *what)
{
	int i;

	for (i = 0; i < 2000 && READ_ONCE(*counter) < want; i++)
		usleep(1000);
	return ASSERT_GE(READ_ONCE(*counter), want, what);
}

/* Load the extension in map @name of progs/napi_ext_fail.c: the verifier says @msg */
static void refused(const char *name, const char *prog_name, const char *msg)
{
	struct napi_ext_fail *skel = napi_ext_fail__open();
	struct bpf_program *prog;
	struct bpf_map *map;

	if (!ASSERT_OK_PTR(skel, "napi_ext_fail__open"))
		return;
	bpf_object__for_each_map(map, skel->obj)
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS)
			bpf_map__set_autocreate(map, !strcmp(bpf_map__name(map), name));
	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, prog_name))
		goto out;
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	if (ASSERT_ERR(napi_ext_fail__load(skel), name) && !strstr(log_buf, msg)) {
		PRINT_FAIL("%s: the log does not say '%s'\n", name, msg);
		fprintf(stderr, "%s\n", log_buf + (strlen(log_buf) > 2000 ? strlen(log_buf) - 2000 : 0));
	}
out:
	napi_ext_fail__destroy(skel);
}

static void test_refused(void)
{
	refused("ext_keeps", "keeps", "Unreleased reference");
	refused("ext_polls", "polls", "calling kernel function bpf_napi_poll_run is not allowed");
	refused("ext_again_native", "again_native",
		"calling kernel function bpf_napi_poll_native is not allowed");
	refused("ext_cont_keeps", "cont_keeps", "Unreleased reference");
	refused("ext_cont_reads", "cont_reads", "invalid mem access 'scalar'");
	refused("ext_too_big", "too_big", "coro_frame of 64 bytes does not fit in its host");
	refused("ext_no_host", "no_host", "which is in none of its slots");
	refused("ext_holds", "holds", "deferred coro_frame holds a reference besides its host");
	refused("ext_cached", "cached", "deferred coro_frame is not in memory of a host");
}

static struct napi_ext *ext;
static struct bpf_napi *pool;
static struct bpf_link *ext_link;
static int tx = -1, rx = -1;
static __u32 napi_id;

static bool attach(void)
{
	ext_link = bpf_map__attach_struct_ops(ext->maps.napi_ext);
	return ASSERT_OK_PTR(ext_link, "attach_struct_ops");
}

static void detach(void)
{
	bpf_link__destroy(ext_link);
	ext_link = NULL;
}

/* Softirq: every poll passes the entry and is resumed where net_rx_action() polls */
static void softirq(void)
{
	__u64 deferred, resumed, polled, native, hardirq;
	int i;

	ext->bss->mode = MODE_DEFER;
	ext->bss->where = BPF_NAPI_SOFTIRQ;
	deferred = ext->bss->deferred;
	if (!ASSERT_TRUE(ping(tx, rx), "ping, softirq"))
		return;
	ASSERT_GT(ext->bss->deferred, deferred, "deferred");
	ASSERT_GT(ext->bss->entries[BPF_NAPI_SCHEDULE], 0, "entries, schedule");
	ASSERT_EQ(ext->bss->napi_id, napi_id, "napi_id");
	ASSERT_GT(ext->bss->frame_off, 0, "frame_off");
	ASSERT_EQ(ext->bss->no_frame, 0, "no_frame");
	/* each one that was deferred was resumed, and polled */
	wait_ge(&ext->bss->resumed, ext->bss->deferred, "resumed");
	ASSERT_EQ(ext->bss->polled, ext->bss->resumed, "polled");

	/*
	 * the timer of interrupt deferral schedules the NAPI like an interrupt, in hard
	 * interrupt context, and passes the entry
	 */
	hardirq = ext->bss->hardirq;
	SYS_NOFAIL("ip netns exec " NS_DST " sh -c 'echo 2 > /sys/class/net/veth_dst/napi_defer_hard_irqs; echo 200000 > /sys/class/net/veth_dst/gro_flush_timeout'");
	for (i = 0; i < 5; i++)
		ASSERT_TRUE(ping(tx, rx), "ping, timer");
	wait_ge(&ext->bss->hardirq, hardirq + 1, "entries in hard interrupt context");
	SYS_NOFAIL("ip netns exec " NS_DST " sh -c 'echo 0 > /sys/class/net/veth_dst/napi_defer_hard_irqs; echo 0 > /sys/class/net/veth_dst/gro_flush_timeout'");
	usleep(50000);
	wait_ge(&ext->bss->resumed, ext->bss->deferred, "resumed, timer");

	/* the kernel's own step, with no frame */
	ext->bss->mode = MODE_NATIVE;
	usleep(50000);
	resumed = ext->bss->resumed;
	polled = ext->bss->polled;
	native = ext->bss->native;
	ASSERT_TRUE(ping(tx, rx), "ping, native");
	ASSERT_GT(ext->bss->native, native, "native");
	ASSERT_EQ(ext->bss->resumed, resumed, "resumed, native");
	ASSERT_EQ(ext->bss->polled, polled, "polled, native");
	ext->bss->mode = MODE_DEFER;
}

/* The kernel unwinds the continuation before its poll, and the entry with the frame in hand */
static void unwound(void)
{
	__u64 polled, deferred;
	unsigned long frames;

	ext->bss->where = BPF_NAPI_SOFTIRQ;
	usleep(50000);
	ext->bss->mode = MODE_DIVES;
	polled = ext->bss->polled;
	frames = ext->bss->frames;
	ASSERT_TRUE(ping(tx, rx), "ping, continuation unwound");
	ASSERT_GT(ext->bss->frames, frames, "frames");
	ASSERT_EQ(ext->bss->polled, polled, "polled, continuation unwound");
	ext->bss->mode = MODE_ENTRY_DIVES;
	usleep(50000);
	deferred = ext->bss->deferred;
	frames = ext->bss->frames;
	ASSERT_TRUE(ping(tx, rx), "ping, entry unwound");
	ASSERT_GT(ext->bss->frames, frames, "frames, entry");
	ASSERT_EQ(ext->bss->deferred, deferred, "deferred, entry unwound");
	ext->bss->mode = MODE_DEFER;
	usleep(50000);
	ASSERT_TRUE(ping(tx, rx), "ping, after");
}

/* The thread that the NAPI is bound to: the poll waits for its bpf_napi_poll() */
static void thread(void)
{
	__u64 polls, resumed, deferred, again;

	pool->bss->napi_id = napi_id;
	pool->bss->paused[0] = 0;
	if (!ASSERT_OK(run_prog(pool->progs.create_poller, 0, 0, 0), "create_poller") ||
	    !ASSERT_OK(run_prog(pool->progs.bind_napi, 0, napi_id, 0), "bind_napi"))
		return;
	ext->bss->mode = MODE_DEFER;
	ext->bss->where = BPF_NAPI_THREAD;
	usleep(50000);
	polls = pool->bss->polls[0];
	resumed = ext->bss->resumed;
	ASSERT_TRUE(ping(tx, rx), "ping, thread");
	ASSERT_GT(pool->bss->polls[0], polls, "polls of the thread");
	ASSERT_GT(ext->bss->resumed, resumed, "resumed, thread");

	/* bound, and softirq all the same: the entry chooses per schedule */
	ext->bss->where = BPF_NAPI_SOFTIRQ;
	usleep(50000);
	polls = pool->bss->polls[0];
	ASSERT_TRUE(ping(tx, rx), "ping, bound and softirq");
	ASSERT_EQ(pool->bss->polls[0], polls, "polls of the thread, softirq");

	/* a thread that takes the idle NAPI enters by itself, and polls there */
	ext->bss->where = BPF_NAPI_THREAD;
	again = ext->bss->entries[BPF_NAPI_AGAIN];
	pool->bss->busy[0] = 1;
	wait_ge(&ext->bss->entries[BPF_NAPI_AGAIN], again + 3, "entries, again");
	ASSERT_TRUE(ping(tx, rx), "ping, busy thread");
	/* or defers once more, to itself and to softirq */
	deferred = ext->bss->deferred;
	ext->bss->again_defers = 1;
	wait_ge(&ext->bss->deferred, deferred + 3, "deferred, again");
	ASSERT_TRUE(ping(tx, rx), "ping, again defers to the thread");
	ext->bss->where = BPF_NAPI_SOFTIRQ;
	deferred = ext->bss->deferred;
	wait_ge(&ext->bss->deferred, deferred + 3, "deferred, again to softirq");
	ASSERT_TRUE(ping(tx, rx), "ping, again defers to softirq");
	ext->bss->again_defers = 0;
	pool->bss->busy[0] = 0;
	usleep(50000);
	ASSERT_TRUE(ping(tx, rx), "ping, thread again");
}

/* The kernel takes the NAPI back with a poll pending for a thread that does not poll */
static void taken_back(void)
{
	char buf[16] = "napi";
	__u64 resumed, repolls;
	int i, got = 0;

	ext->bss->mode = MODE_DEFER;
	ext->bss->where = BPF_NAPI_THREAD;
	pool->bss->paused[0] = 1;
	usleep(100000);
	resumed = ext->bss->resumed;
	/* the watchdog, after a second */
	ASSERT_FALSE(ping(tx, rx), "ping waits for the thread");
	set_rcvtimeo(rx, 3000);
	ASSERT_EQ(recv(rx, buf, sizeof(buf), 0), sizeof(buf), "recv after the watchdog");
	set_rcvtimeo(rx, 300);
	ASSERT_EQ(ext->bss->resumed, resumed, "resumed, watchdog");
	/* softirq has the NAPI until a new bind; then an unbind */
	ASSERT_TRUE(ping(tx, rx), "ping, taken away");
	if (!ASSERT_OK(run_prog(pool->progs.bind_napi, 0, napi_id, 0), "bind again"))
		return;
	resumed = ext->bss->resumed;
	repolls = ext->bss->entries[BPF_NAPI_REPOLL];
	ASSERT_FALSE(ping(tx, rx), "ping waits for the thread, again");
	/* more than a poll takes: softirq polls again, and enters for that in its round */
	for (i = 0; i < 200; i++)
		send(tx, buf, sizeof(buf), MSG_DONTWAIT);
	ASSERT_OK(run_prog(pool->progs.unbind_napi, 0, napi_id, 0), "unbind");
	while (recv(rx, buf, sizeof(buf), 0) == sizeof(buf))
		got++;
	ASSERT_EQ(got, 201, "received after the unbind");
	ASSERT_GT(ext->bss->entries[BPF_NAPI_REPOLL], repolls, "entries, repoll");
	/* the first poll was the kernel's, the ones behind it the extension's again */
	wait_ge(&ext->bss->resumed, resumed + 1, "resumed, repoll");
	/* and a detach */
	if (!ASSERT_OK(run_prog(pool->progs.bind_napi, 0, napi_id, 0), "bind once more"))
		return;
	ASSERT_FALSE(ping(tx, rx), "ping waits for the thread, once more");
	resumed = ext->bss->resumed;
	detach();
	/* the thread has it natively now, and does not poll: the watchdog once more */
	set_rcvtimeo(rx, 3000);
	ASSERT_EQ(recv(rx, buf, sizeof(buf), 0), sizeof(buf), "recv after the detach");
	set_rcvtimeo(rx, 300);
	ASSERT_EQ(ext->bss->resumed, resumed, "resumed, detach");
	ASSERT_OK(run_prog(pool->progs.unbind_napi, 0, napi_id, 0), "unbind at the end");
	pool->bss->paused[0] = 0;
	/* attached again, it has the step again */
	if (!attach())
		return;
	ext->bss->where = BPF_NAPI_SOFTIRQ;
	resumed = ext->bss->resumed;
	ASSERT_TRUE(ping(tx, rx), "ping, attached again");
	ASSERT_GT(ext->bss->resumed, resumed, "resumed, attached again");
}

/*
 * The crossing by itself, on the NAPI of bpf_testmod whose poll finds nothing: schedule it
 * and wait for the poll, a number of times, natively and through the null extension, in
 * softirq and in a thread. NAPI_EXT_ROUNDS makes it a measurement, of which a default kernel
 * is no place: the numbers that count are those of a bench kernel.
 */
struct test_args {
	__u32 arg;
	__u32 pad;
	__u64 ret;
};

static __u64 run_null(struct bpf_program *prog, __u32 arg, int *retval)
{
	struct test_args args = { .arg = arg };
	/* a syscall program's context is written back where it came from */
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), bpf_program__name(prog)))
		return 0;
	if (retval)
		*retval = opts.retval;
	return args.ret;
}

#define MAX_CPUS 64
static int insn_fds[MAX_CPUS], nr_insn_fds;

/* Instructions on every CPU: a thread's poll is not in this task. -1 without a counter. */
static void insns_open(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_HW_INSTRUCTIONS,
	};
	int cpu, nr = libbpf_num_possible_cpus();

	for (cpu = 0; cpu < nr && cpu < MAX_CPUS; cpu++) {
		insn_fds[cpu] = syscall(SYS_perf_event_open, &attr, -1, cpu, -1, 0);
		if (insn_fds[cpu] < 0)
			break;
	}
	nr_insn_fds = cpu;
}

static long long insns_read(void)
{
	long long sum = 0, val;
	int i;

	if (!nr_insn_fds)
		return -1;
	for (i = 0; i < nr_insn_fds; i++)
		if (read(insn_fds[i], &val, sizeof(val)) == sizeof(val))
			sum += val;
	return sum;
}

static void row(struct napi_ext_null *null, const char *what, __u32 rounds)
{
	long long insns;
	__u64 ns;

	/* the first ones find the code and the thread cold */
	run_null(null->progs.test_run, rounds / 10 + 1, NULL);
	insns = insns_read();
	ns = run_null(null->progs.test_run, rounds, NULL);
	insns = insns < 0 ? -1 : insns_read() - insns;
	if (!ASSERT_GT(ns, 0, what))
		return;
	if (insns < 0)
		fprintf(stderr, "napi_ext crossing: %-44s %7.1f ns  (no instruction counter)\n",
			what, (double)ns / rounds);
	else
		fprintf(stderr, "napi_ext crossing: %-44s %7.1f ns %7.1f insns on all CPUs\n",
			what, (double)ns / rounds, (double)insns / rounds);
}

/* @where is where the null extension defers to, or -1 for the one that is the entry alone */
static struct bpf_link *attach_null(struct napi_ext_null **nullp, int ifindex, __u32 flags, int where)
{
	struct napi_ext_null *null = napi_ext_null__open();
	struct bpf_link *l;

	if (!ASSERT_OK_PTR(null, "napi_ext_null__open"))
		return NULL;
	null->struct_ops.napi_null->ifindex = ifindex;
	null->struct_ops.napi_null->flags = flags;
	null->struct_ops.napi_entry->ifindex = ifindex;
	null->struct_ops.napi_entry->flags = flags;
	if (!ASSERT_OK(napi_ext_null__load(null), "napi_ext_null__load")) {
		napi_ext_null__destroy(null);
		return NULL;
	}
	null->bss->where = where;
	l = bpf_map__attach_struct_ops(where < 0 ? null->maps.napi_entry : null->maps.napi_null);
	if (!ASSERT_OK_PTR(l, "attach null")) {
		napi_ext_null__destroy(null);
		return NULL;
	}
	*nullp = null;
	return l;
}

static void test_crossing(void)
{
	__u32 rounds = getenv("NAPI_EXT_ROUNDS") ? atoi(getenv("NAPI_EXT_ROUNDS")) : 20000;
	__u32 thread_rounds = rounds / 10 + 1;
	struct napi_ext_null *drv, *null = NULL;
	struct bpf_link *l;
	int ifindex = 0, id = 0;

	drv = napi_ext_null__open_and_load();
	pool = bpf_napi__open_and_load();
	if (!ASSERT_OK_PTR(drv, "napi_ext_null__open_and_load") ||
	    !ASSERT_OK_PTR(pool, "bpf_napi__open_and_load"))
		goto out;
	run_null(drv->progs.test_dev, 1, &ifindex);
	run_null(drv->progs.test_id, 0, &id);
	if (!ASSERT_GT(ifindex, 0, "ifindex") || !ASSERT_GT(id, 0, "napi id"))
		goto out;
	insns_open();

	row(drv, "native, softirq", rounds);
	l = attach_null(&null, ifindex, BPF_NAPI_OPS_F_INDIRECT, BPF_NAPI_SOFTIRQ);
	if (!l)
		goto out;
	row(drv, "null extension, softirq, indirect calls", rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	l = attach_null(&null, ifindex, 0, BPF_NAPI_SOFTIRQ);
	if (!l)
		goto out;
	row(drv, "null extension, softirq, direct calls", rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	/* the half of it that is the entry: no frame, and the kernel's poll */
	l = attach_null(&null, ifindex, BPF_NAPI_OPS_F_INDIRECT, -1);
	if (!l)
		goto out;
	row(drv, "the entry alone, softirq, indirect call", rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	l = attach_null(&null, ifindex, 0, -1);
	if (!l)
		goto out;
	row(drv, "the entry alone, softirq, direct call", rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);

	SYS(out, "echo 1 > /sys/class/net/napitest0/threaded");
	row(drv, "kernel threaded NAPI", thread_rounds);
	SYS(out, "echo 0 > /sys/class/net/napitest0/threaded");

	pool->bss->napi_id = id;
	if (!ASSERT_OK(run_prog(pool->progs.create_poller, 0, 0, 0), "create_poller") ||
	    !ASSERT_OK(run_prog(pool->progs.bind_napi, 0, id, 0), "bind_napi"))
		goto out;
	row(drv, "thread of the pool, no extension", thread_rounds);
	l = attach_null(&null, ifindex, BPF_NAPI_OPS_F_INDIRECT, BPF_NAPI_THREAD);
	if (!l)
		goto out;
	row(drv, "null extension, thread, indirect calls", thread_rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	/*
	 * The thread's own polls: a poll that uses up its budget has the thread come back
	 * at once, and it enters at again() each time. What one of those costs is the
	 * difference to the thread with no extension, by MORE.
	 */
	run_null(drv->progs.test_ctl, NAPI_TEST_MORE | MORE << 16, NULL);
	row(drv, "thread of the pool, 16 more polls", thread_rounds);
	l = attach_null(&null, ifindex, BPF_NAPI_OPS_F_INDIRECT, BPF_NAPI_THREAD);
	if (!l)
		goto out;
	row(drv, "null extension, thread, 16 more, indirect", thread_rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	l = attach_null(&null, ifindex, 0, BPF_NAPI_THREAD);
	if (!l)
		goto out;
	row(drv, "null extension, thread, 16 more, direct", thread_rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	run_null(drv->progs.test_ctl, NAPI_TEST_MORE, NULL);
	l = attach_null(&null, ifindex, 0, BPF_NAPI_THREAD);
	if (!l)
		goto out;
	row(drv, "null extension, thread, direct calls", thread_rounds);
	/* bound, and softirq: what the entry chooses */
	null->bss->where = BPF_NAPI_SOFTIRQ;
	row(drv, "null extension, softirq, bound to a thread", rounds);
	bpf_link__destroy(l);
	napi_ext_null__destroy(null);
	ASSERT_OK(run_prog(pool->progs.unbind_napi, 0, id, 0), "unbind");
out:
	while (nr_insn_fds)
		close(insn_fds[--nr_insn_fds]);
	if (drv)
		run_null(drv->progs.test_dev, 0, NULL);
	bpf_napi__destroy(pool);
	pool = NULL;
	napi_ext_null__destroy(drv);
}

/*
 * An interrupt of the device while its NAPI is polled is a poll of its own, which the driver's
 * poll schedules where it completes the NAPI: inside the continuation that polls, whose frame
 * is over by then. Every poll of the driver passes the entry, once.
 */
static void missed(struct napi_ext_null *drv, const char *what)
{
	__u64 polls = run_null(drv->progs.test_ctl, NAPI_TEST_POLLS, NULL);
	__u64 entries = ext->bss->entries[BPF_NAPI_SCHEDULE];
	__u64 polled = ext->bss->polled;
	int i, j;

	run_null(drv->progs.test_ctl, NAPI_TEST_MISS, NULL);
	for (i = 1; i <= 20; i++) {
		run_null(drv->progs.test_run, 1, NULL);
		/* the poll that was scheduled, and the one that it found missed */
		for (j = 0; j < 2000; j++) {
			if (run_null(drv->progs.test_ctl, NAPI_TEST_POLLS, NULL) >= polls + 2 * i)
				break;
			usleep(1000);
		}
	}
	run_null(drv->progs.test_ctl, NAPI_TEST_NO_MISS, NULL);
	ASSERT_EQ(run_null(drv->progs.test_ctl, NAPI_TEST_POLLS, NULL), polls + 40, what);
	ASSERT_EQ(ext->bss->entries[BPF_NAPI_SCHEDULE], entries + 40, what);
	ASSERT_EQ(ext->bss->polled, polled + 40, what);
	ASSERT_EQ(ext->bss->resumed, ext->bss->deferred, what);
	ASSERT_EQ(ext->bss->no_frame, 0, what);
}

/*
 * What a device does with its NAPIs while an extension is about. One that it adds has the
 * extension if the device has it, whatever its memory was before: a driver that reopens
 * its channels allocates them anew, and another one keeps them for the next time.
 */
static void test_device(void)
{
	struct napi_ext *other = NULL;
	struct napi_ext_null *drv;
	struct bpf_link *l = NULL;
	int ifindex = 0, id = 0;
	__u64 entries, polls;

	drv = napi_ext_null__open_and_load();
	pool = bpf_napi__open_and_load();
	ext = napi_ext__open();
	if (!ASSERT_OK_PTR(drv, "napi_ext_null__open_and_load") ||
	    !ASSERT_OK_PTR(pool, "bpf_napi__open_and_load") || !ASSERT_OK_PTR(ext, "napi_ext__open"))
		goto out;
	run_null(drv->progs.test_dev, 1, &ifindex);
	run_null(drv->progs.test_id, 0, &id);
	if (!ASSERT_GT(ifindex, 0, "ifindex") || !ASSERT_GT(id, 0, "napi id"))
		goto out;
	ext->struct_ops.napi_ext->ifindex = ifindex;
	if (!ASSERT_OK(napi_ext__load(ext), "napi_ext__load") || !attach())
		goto out;
	ext->bss->mode = MODE_DEFER;
	ext->bss->where = BPF_NAPI_SOFTIRQ;
	missed(drv, "missed, softirq");

	pool->bss->napi_id = id;
	if (!ASSERT_OK(run_prog(pool->progs.create_poller, 0, 0, 0), "create_poller") ||
	    !ASSERT_OK(run_prog(pool->progs.bind_napi, 0, id, 0), "bind_napi"))
		goto out;
	ext->bss->where = BPF_NAPI_THREAD;
	polls = pool->bss->polls[0];
	missed(drv, "missed, thread");
	ASSERT_GE(pool->bss->polls[0], polls + 40, "polls of the thread, missed");
	ASSERT_OK(run_prog(pool->progs.unbind_napi, 0, id, 0), "unbind");
	ext->bss->where = BPF_NAPI_SOFTIRQ;

	/* a new NAPI of the device, in memory that says nothing */
	run_null(drv->progs.test_ctl, NAPI_TEST_DEL, NULL);
	ASSERT_GT((int)run_null(drv->progs.test_ctl, NAPI_TEST_ADD_ZEROED, NULL), 0, "NAPI, anew");
	entries = ext->bss->entries[BPF_NAPI_SCHEDULE];
	ASSERT_GT(run_null(drv->progs.test_run, 10, NULL), 0, "polls, new NAPI");
	ASSERT_EQ(ext->bss->entries[BPF_NAPI_SCHEDULE], entries + 10, "entries, new NAPI");
	ASSERT_EQ(ext->bss->resumed, ext->bss->deferred, "resumed, new NAPI");

	/* one that left the device while the extension was on it, and came back to none */
	run_null(drv->progs.test_ctl, NAPI_TEST_DEL, NULL);
	detach();
	ASSERT_GT((int)run_null(drv->progs.test_ctl, NAPI_TEST_ADD, NULL), 0, "NAPI, as it was");
	/* another device has an extension: this one's NAPI is nothing to it */
	other = napi_ext__open();
	if (!ASSERT_OK_PTR(other, "napi_ext__open, other"))
		goto out;
	other->struct_ops.napi_ext->ifindex = if_nametoindex("lo");
	if (!ASSERT_OK(napi_ext__load(other), "napi_ext__load, other"))
		goto out;
	l = bpf_map__attach_struct_ops(other->maps.napi_ext);
	if (!ASSERT_OK_PTR(l, "attach to another device"))
		goto out;
	polls = run_null(drv->progs.test_ctl, NAPI_TEST_POLLS, NULL);
	ASSERT_GT(run_null(drv->progs.test_run, 10, NULL), 0, "polls, other");
	ASSERT_EQ(run_null(drv->progs.test_ctl, NAPI_TEST_POLLS, NULL), polls + 10, "polled, other");
	ASSERT_EQ(other->bss->entries[BPF_NAPI_SCHEDULE], 0, "entries of the other extension");
	bpf_link__destroy(l);
	l = NULL;

	/* its device has the extension again, and goes with it: the calls were direct */
	if (!attach())
		goto out;
	entries = ext->bss->entries[BPF_NAPI_SCHEDULE];
	ASSERT_GT(run_null(drv->progs.test_run, 10, NULL), 0, "polls, attached again");
	ASSERT_EQ(ext->bss->entries[BPF_NAPI_SCHEDULE], entries + 10, "entries, attached again");
	run_null(drv->progs.test_dev, 0, NULL);
out:
	bpf_link__destroy(l);
	if (ext_link)
		detach();
	if (drv)
		run_null(drv->progs.test_dev, 0, NULL);
	bpf_napi__destroy(pool);
	pool = NULL;
	napi_ext__destroy(other);
	napi_ext__destroy(ext);
	ext = NULL;
	napi_ext_null__destroy(drv);
}

void test_napi_ext(void)
{
	struct nstoken *tok = NULL;
	socklen_t len = sizeof(napi_id);
	int err;

	if (test__start_subtest("refused"))
		test_refused();
	if (test__start_subtest("crossing"))
		test_crossing();
	if (test__start_subtest("device"))
		test_device();
	if (!test__start_subtest("veth"))
		return;

	ext = napi_ext__open();
	pool = bpf_napi__open_and_load();
	if (!ASSERT_OK_PTR(ext, "napi_ext__open") || !ASSERT_OK_PTR(pool, "bpf_napi__open_and_load"))
		goto out;

	SYS(out, "ip netns add " NS_SRC);
	SYS(out, "ip netns add " NS_DST);
	SYS(out, "ip link add veth_src netns " NS_SRC " type veth peer name veth_dst netns " NS_DST);
	SYS(out, "ip -n " NS_SRC " addr add dev veth_src " SRC_IP "/24");
	SYS(out, "ip -n " NS_DST " addr add dev veth_dst " DST_IP "/24");
	SYS(out, "ip -n " NS_SRC " link set dev veth_src up");
	SYS(out, "ip -n " NS_DST " link set dev veth_dst up");
	/* GRO puts veth receive on a NAPI, for frames from a sender without TSO features */
	SYS(out, "ip netns exec " NS_DST " ethtool -K veth_dst gro on");
	SYS(out, "ip netns exec " NS_SRC " ethtool -K veth_src tso off");

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
	if (!ASSERT_TRUE(ping(tx, rx), "ping before"))
		goto out;
	err = getsockopt(rx, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &len);
	if (!ASSERT_OK(err, "SO_INCOMING_NAPI_ID") || !ASSERT_GT(napi_id, 0, "napi_id"))
		goto out;

	/* the extension is attached to the device, in the namespace of this task */
	ext->struct_ops.napi_ext->ifindex = if_nametoindex("veth_dst");
	if (!ASSERT_GT(ext->struct_ops.napi_ext->ifindex, 0, "ifindex") ||
	    !ASSERT_OK(napi_ext__load(ext), "napi_ext__load") || !attach())
		goto out;

	softirq();
	unwound();
	thread();
	taken_back();

	/* and through the pointers of the extension and of the frame, as the calls were first */
	detach();
	napi_ext__destroy(ext);
	ext = napi_ext__open();
	if (!ASSERT_OK_PTR(ext, "napi_ext__open, indirect"))
		goto out;
	ext->struct_ops.napi_ext->ifindex = if_nametoindex("veth_dst");
	ext->struct_ops.napi_ext->flags = BPF_NAPI_OPS_F_INDIRECT;
	if (!ASSERT_OK(napi_ext__load(ext), "napi_ext__load, indirect") || !attach())
		goto out;
	softirq();
	unwound();

	/* the device goes with the extension on it, and a poll of it pending */
	ext->bss->where = BPF_NAPI_SOFTIRQ;
	ASSERT_TRUE(ping(tx, rx), "ping at the end");
	SYS_NOFAIL("ip link del veth_dst");
	usleep(100000);
out:
	if (ext_link)
		detach();
	if (tx >= 0)
		close(tx);
	if (rx >= 0)
		close(rx);
	if (tok)
		close_netns(tok);
	bpf_napi__destroy(pool);
	napi_ext__destroy(ext);
	SYS_NOFAIL("ip netns del " NS_SRC);
	SYS_NOFAIL("ip netns del " NS_DST);
}
