// SPDX-License-Identifier: GPL-2.0
/*
 * An extension on the path of a packet, on the NAPI of bpf_testmod, whose poll receives
 * packets as a driver has them, see progs/rx_ext.c: every packet passes the extension, which
 * offers it to GRO and puts it on the batch, in its entry or in the continuation that the
 * kernel resumes where GRO flushes a packet that it held. What the stack gets is what it gets
 * with no extension, packet by packet and list by list. The kernel goes its own way where a
 * head lends no frame, where code is unwound, and where the extension goes with frames
 * suspended in packets. Extensions that could keep a packet are not loaded.
 */
#include <net/if.h>
#include <test_progs.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "../progs/rx_ext.h"
#include "rx_ext.skel.h"
#include "rx_ext_fail.skel.h"
#include "napi_ext_null.skel.h"

/* Mirrors the @op of bpf_kfunc_napi_test_ctl() in test_kmods/bpf_testmod.c and what it receives */
#define NAPI_TEST_RX 6
enum { RX_UDP, RX_FLOW, RX_FLOWS, RX_PUSH, RX_SMALL, RX_CLONE, RX_FEW };
#define RX(kind, n) (NAPI_TEST_RX | (kind) << 8 | (n) << 16)
#define RX_HALF (1U << 31)

#define POLLS 4

static char log_buf[1 << 20];

/* Load the extension in map @name of progs/rx_ext_fail.c: the verifier says @msg */
static void refused(const char *name, const char *prog_name, const char *msg)
{
	struct rx_ext_fail *skel = rx_ext_fail__open();
	struct bpf_program *prog;
	struct bpf_map *map;

	if (!ASSERT_OK_PTR(skel, "rx_ext_fail__open"))
		return;
	bpf_object__for_each_map(map, skel->obj)
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS)
			bpf_map__set_autocreate(map, !strcmp(bpf_map__name(map), name));
	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, prog_name))
		goto out;
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	if (ASSERT_ERR(rx_ext_fail__load(skel), name) && !strstr(log_buf, msg)) {
		PRINT_FAIL("%s: the log does not say '%s'\n", name, msg);
		fprintf(stderr, "%s\n", log_buf + (strlen(log_buf) > 2000 ? strlen(log_buf) - 2000 : 0));
	}
out:
	rx_ext_fail__destroy(skel);
}

static void test_refused(void)
{
	refused("ext_keeps", "keeps", "Unreleased reference");
	refused("ext_keeps_declined", "keeps_declined", "Unreleased reference");
	refused("ext_batches_taken", "batches_taken", "resource release invalidated this pointer");
	refused("ext_reads_taken", "reads_taken", "invalid mem access 'scalar'");
	refused("ext_cont_keeps", "cont_keeps", "Unreleased reference");
	refused("ext_cont_offers", "cont_offers", "calling kernel function bpf_rx_gro is not allowed");
	refused("ext_too_big", "too_big", "coro_frame of 72 bytes does not fit in its host");
	refused("ext_no_host", "no_host", "which is in none of its slots");
	refused("ext_holds", "holds", "deferred coro_frame holds a reference besides its host");
	refused("ext_cached", "cached", "deferred coro_frame is not in memory of a host");
}

struct test_args {
	__u32 arg;
	__u32 pad;
	__u64 ret;
};

static __u64 run_drv(struct bpf_program *prog, __u32 arg, int *retval)
{
	struct test_args args = { .arg = arg };
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

static struct napi_ext_null *drv;
static struct rx_ext *ext;
static struct bpf_link *ext_link;

static bool attach(void)
{
	ext_link = bpf_map__attach_struct_ops(ext->maps.rx_ext);
	return ASSERT_OK_PTR(ext_link, "attach_struct_ops");
}

static void detach(void)
{
	bpf_link__destroy(ext_link);
	ext_link = NULL;
}

/* @polls polls that receive @n packets of @kind each. Returns the ns that they took. */
static __u64 receive(__u32 kind, __u32 n, __u32 polls)
{
	__u64 ns;

	run_drv(drv->progs.test_ctl, RX(kind, n), NULL);
	ns = run_drv(drv->progs.test_run, polls, NULL);
	run_drv(drv->progs.test_ctl, RX(0, 0), NULL);
	return ns;
}

static void forget(void)
{
	memset(ext->bss->seen, 0, sizeof(ext->bss->seen));
	ext->bss->nr_seen = 0;
	ext->bss->nr_lists = 0;
	ext->bss->arrived = 0;
	ext->bss->taken = 0;
	ext->bss->declined = 0;
	ext->bss->resumed = 0;
	ext->bss->native = 0;
	ext->bss->no_frame = 0;
}

static struct rx_seen kernel_saw[RX_SEEN];
static __u64 kernel_nr, kernel_lists;

/* What the stack gets of these packets with no extension */
static void kernel(__u32 kind, __u32 n)
{
	if (ext_link)
		detach();
	forget();
	receive(kind, n, POLLS);
	kernel_nr = ext->bss->nr_seen;
	kernel_lists = ext->bss->nr_lists;
	memcpy(kernel_saw, ext->bss->seen, sizeof(kernel_saw));
	ASSERT_GT(kernel_nr, 0, "packets, kernel");
	ASSERT_EQ(ext->bss->arrived, 0, "arrived, kernel");
}

/* And with the extension in @mode: the same, packet by packet and list by list */
static bool same(const char *what, int mode, __u32 kind, __u32 n)
{
	__u64 i;

	kernel(kind, n);
	ext->bss->mode = mode;
	if (!attach())
		return false;
	forget();
	receive(kind, n, POLLS);
	ASSERT_EQ(ext->bss->arrived, POLLS * n, what);
	ASSERT_EQ(ext->bss->nr_seen, kernel_nr, what);
	ASSERT_EQ(ext->bss->nr_lists, kernel_lists, what);
	for (i = 0; i < kernel_nr && i < RX_SEEN; i++) {
		if (!memcmp(&ext->bss->seen[i], &kernel_saw[i], sizeof(kernel_saw[i])))
			continue;
		PRINT_FAIL("%s: packet %llu: len %u segs %u size %u hash %x summed %u list %u, the kernel's: len %u segs %u size %u hash %x summed %u list %u\n",
			   what, i, ext->bss->seen[i].len, ext->bss->seen[i].gso_segs,
			   ext->bss->seen[i].gso_size, ext->bss->seen[i].hash,
			   ext->bss->seen[i].ip_summed, ext->bss->seen[i].list,
			   kernel_saw[i].len, kernel_saw[i].gso_segs, kernel_saw[i].gso_size,
			   kernel_saw[i].hash, kernel_saw[i].ip_summed, kernel_saw[i].list);
		return false;
	}
	return true;
}

/* The null path: GRO, and the batch */
static void path(const char *what, __u32 kind, __u32 n, __u64 taken, __u64 resumed)
{
	if (!same(what, MODE_GRO, kind, n))
		return;
	ASSERT_EQ(ext->bss->taken, taken, what);
	ASSERT_EQ(ext->bss->declined, POLLS * n - taken, what);
	ASSERT_EQ(ext->bss->resumed, resumed, what);
	ASSERT_EQ(ext->bss->no_frame, 0, what);
	ASSERT_EQ(ext->bss->frame_off, 0, what);
	/* GRO did something: fewer packets than came, where it held any */
	if (resumed && resumed < taken)
		ASSERT_LT(ext->bss->nr_seen, POLLS * n, what);
}

/* The segments in the packets that the stack got */
static __u64 segments(void)
{
	__u64 i, segs = 0;

	for (i = 0; i < ext->bss->nr_seen && i < RX_SEEN; i++)
		segs += ext->bss->seen[i].gso_segs ?: 1;
	return segs;
}

static bool wait_seen(__u64 want, const char *what)
{
	int i;

	for (i = 0; i < 3000 && ext->bss->nr_seen < want; i++)
		usleep(1000);
	return ASSERT_EQ(ext->bss->nr_seen, want, what);
}

static void test_path(void)
{
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc, .handle = 1, .priority = 1);
	__u64 resumed;
	int ifindex = 0;

	drv = napi_ext_null__open_and_load();
	ext = rx_ext__open();
	if (!ASSERT_OK_PTR(drv, "napi_ext_null__open_and_load") || !ASSERT_OK_PTR(ext, "rx_ext__open"))
		goto out;
	run_drv(drv->progs.test_dev, 1, &ifindex);
	if (!ASSERT_GT(ifindex, 0, "ifindex"))
		goto out;
	ext->struct_ops.rx_ext->ifindex = ifindex;
	ext->struct_ops.rx_null->ifindex = ifindex;
	ext->struct_ops.rx_entry->ifindex = ifindex;
	ext->bss->ifindex = ifindex;
	if (!ASSERT_OK(rx_ext__load(ext), "rx_ext__load"))
		goto out;
	/* the observers: where a list goes up, and what is in it */
	ext->links.list = bpf_program__attach(ext->progs.list);
	if (!ASSERT_OK_PTR(ext->links.list, "attach list"))
		goto out;
	hook.ifindex = ifindex;
	tc.prog_fd = bpf_program__fd(ext->progs.ingress);
	if (!ASSERT_OK(bpf_tc_hook_create(&hook), "tc hook") ||
	    !ASSERT_OK(bpf_tc_attach(&hook, &tc), "tc attach"))
		goto out;
	SYS(out, "ip link set dev napitest0 up");

	/* GRO has no use for a datagram: on to the batch, in the entry */
	path("a datagram", RX_UDP, 1, 0, 0);
	path("datagrams", RX_UDP, 8, 0, 0);
	path("datagrams, more than a batch", RX_UDP, 20, 0, 0);
	/* the first segment of a flow is held and the others are merged into it: one goes on */
	path("a flow", RX_FLOW, 8, POLLS * 8, POLLS);
	/* the last one ends the run: the flush is in the offer of that one */
	path("a flow, pushed", RX_PUSH, 8, POLLS * 8, POLLS);
	/* each held for itself, and flushed where the poll completes */
	path("flows", RX_FLOWS, 16, POLLS * 16, POLLS * 16);
	/* four packets of five segments each: the batch is full by segments, not by packets */
	path("four flows", RX_FEW, 20, POLLS * 20, POLLS * 4);
	/* more than GRO holds: the oldest of a bucket is flushed in the offer of the next */
	path("flows, more than GRO holds", RX_FLOWS, 80, POLLS * 80, POLLS * 80);

	/* a head with no room below the packet, or one that a clone shares, lends no frame */
	if (same("small heads", MODE_GRO, RX_SMALL, 8))
		ASSERT_EQ(ext->bss->no_frame, POLLS * 8, "no frame, small heads");
	if (same("cloned heads", MODE_GRO, RX_CLONE, 8))
		ASSERT_EQ(ext->bss->no_frame, POLLS * 8, "no frame, cloned heads");

	/* the kernel's own path with no frame */
	if (same("native", MODE_NATIVE, RX_FLOW, 8))
		ASSERT_EQ(ext->bss->native, POLLS * 8, "native");
	/* the kernel unwinds a continuation, and an entry with the frame in hand */
	if (same("continuation unwound", MODE_DIVES, RX_FLOWS, 16))
		ASSERT_EQ(ext->bss->resumed, POLLS * 16, "resumed, unwound");
	detach();
	ext->bss->mode = MODE_ENTRY_DIVES;
	if (!attach())
		goto out;
	forget();
	receive(RX_FLOW, 8, POLLS);
	ASSERT_EQ(segments(), POLLS * 8, "segments, entry unwound");
	ASSERT_EQ(ext->bss->taken + ext->bss->declined, 0, "offered, entry unwound");
	ASSERT_GT(ext->bss->frames, 0, "frames of the recursion");

	/* past GRO: every segment goes up by itself */
	detach();
	ext->bss->mode = MODE_PAST_GRO;
	if (!attach())
		goto out;
	forget();
	receive(RX_FLOW, 8, POLLS);
	ASSERT_EQ(ext->bss->nr_seen, POLLS * 8, "packets past GRO");
	ASSERT_EQ(segments(), POLLS * 8, "segments past GRO");
	ext->bss->mode = MODE_GRO;

	/*
	 * The extension goes with frames suspended in packets that GRO holds: the timer of
	 * GRO flushes them, and nothing is resumed.
	 */
	SYS(out, "echo 300000000 > /sys/class/net/napitest0/gro_flush_timeout");
	forget();
	receive(RX_FLOWS, 8, 1);
	ASSERT_EQ(ext->bss->taken, 8, "held for the timer");
	resumed = ext->bss->resumed;
	detach();
	wait_seen(8, "flushed after the detach");
	ASSERT_EQ(ext->bss->resumed, resumed, "resumed after the detach");

	/* nor by the next extension, which holds packets beside them */
	if (!attach())
		goto out;
	forget();
	receive(RX_FLOWS, 8, 1);
	resumed = ext->bss->resumed;
	detach();
	if (!attach())
		goto out;
	run_drv(drv->progs.test_ctl, RX(RX_FLOWS, 8) | RX_HALF, NULL);
	run_drv(drv->progs.test_run, 1, NULL);
	run_drv(drv->progs.test_ctl, RX(0, 0), NULL);
	ASSERT_EQ(ext->bss->taken, 16, "held for the timer, two extensions");
	wait_seen(16, "flushed, two extensions");
	ASSERT_LE(ext->bss->resumed, resumed + 8, "resumed, of the second extension only");
	ASSERT_GT(ext->bss->resumed, resumed, "resumed, of the second extension");
	SYS(out, "echo 0 > /sys/class/net/napitest0/gro_flush_timeout");

	/* the device goes with the extension on it and packets held */
	SYS(out, "echo 300000000 > /sys/class/net/napitest0/gro_flush_timeout");
	receive(RX_FLOWS, 8, 1);
	run_drv(drv->progs.test_dev, 0, NULL);
out:
	if (ext_link)
		detach();
	if (drv)
		run_drv(drv->progs.test_dev, 0, NULL);
	rx_ext__destroy(ext);
	ext = NULL;
	napi_ext_null__destroy(drv);
	drv = NULL;
}

#define MAX_CPUS 64
static int insn_fds[MAX_CPUS], nr_insn_fds;

/* Instructions on every CPU. -1 without a counter. */
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

/* @packets packets of @kind, @n a poll: what one costs, the driver's part and the stack's too */
static void cost(const char *who, const char *what, __u32 kind, __u32 n, __u32 packets)
{
	__u32 polls = packets / n + 1;
	long long insns;
	__u64 ns;

	receive(kind, n, polls / 10 + 1);
	insns = insns_read();
	ns = receive(kind, n, polls);
	insns = insns < 0 ? -1 : insns_read() - insns;
	if (!ASSERT_GT(ns, 0, what))
		return;
	if (insns < 0)
		fprintf(stderr, "rx_ext cost: %-9s %-22s %2u a poll %7.1f ns a packet\n",
			who, what, n, (double)ns / polls / n);
	else
		fprintf(stderr, "rx_ext cost: %-9s %-22s %2u a poll %7.1f ns %7.1f insns a packet\n",
			who, what, n, (double)ns / polls / n, (double)insns / polls / n);
}

/*
 * A packet's way from the driver's hand to where the stack drops it, natively, through the
 * null extension, and through one whose entry leaves every packet to the kernel: a packet
 * that GRO has no use for, one that it holds and flushes, and segments that it merges, at
 * several packets a poll. NAPI_EXT_ROUNDS packets make it a measurement, of which a default
 * kernel is no place: the numbers that count are those of a bench kernel.
 */
static void test_cost(void)
{
	static const struct {
		const char *what;
		__u32 kind, n;
	} rows[] = {
		{ "not held", RX_UDP, 1 }, { "not held", RX_UDP, 8 }, { "not held", RX_UDP, 60 },
		{ "held", RX_FLOWS, 1 }, { "held", RX_FLOWS, 8 }, { "held", RX_FLOWS, 60 },
		{ "one held, others merged", RX_FLOW, 8 }, { "one held, others merged", RX_FLOW, 60 },
	};
	__u32 packets = getenv("NAPI_EXT_ROUNDS") ? atoi(getenv("NAPI_EXT_ROUNDS")) : 2000;
	static const char * const who[] = { "native", "null", "entry" };
	struct bpf_map *maps[3] = {};
	int ifindex = 0, i, w;

	drv = napi_ext_null__open_and_load();
	ext = rx_ext__open();
	if (!ASSERT_OK_PTR(drv, "napi_ext_null__open_and_load") || !ASSERT_OK_PTR(ext, "rx_ext__open"))
		goto out;
	run_drv(drv->progs.test_dev, 1, &ifindex);
	if (!ASSERT_GT(ifindex, 0, "ifindex"))
		goto out;
	ext->struct_ops.rx_ext->ifindex = ifindex;
	ext->struct_ops.rx_null->ifindex = ifindex;
	ext->struct_ops.rx_entry->ifindex = ifindex;
	/* no observer: nothing but the path */
	if (!ASSERT_OK(rx_ext__load(ext), "rx_ext__load"))
		goto out;
	maps[1] = ext->maps.rx_null;
	maps[2] = ext->maps.rx_entry;
	SYS(out, "ip link set dev napitest0 up");
	insns_open();
	for (i = 0; i < ARRAY_SIZE(rows); i++) {
		for (w = 0; w < ARRAY_SIZE(who); w++) {
			if (maps[w]) {
				ext_link = bpf_map__attach_struct_ops(maps[w]);
				if (!ASSERT_OK_PTR(ext_link, who[w]))
					goto out;
			}
			cost(who[w], rows[i].what, rows[i].kind, rows[i].n, packets);
			if (maps[w])
				detach();
		}
	}
out:
	while (nr_insn_fds)
		close(insn_fds[--nr_insn_fds]);
	if (ext_link)
		detach();
	if (drv)
		run_drv(drv->progs.test_dev, 0, NULL);
	rx_ext__destroy(ext);
	ext = NULL;
	napi_ext_null__destroy(drv);
	drv = NULL;
}

void test_rx_ext(void)
{
	if (test__start_subtest("refused"))
		test_refused();
	if (test__start_subtest("path"))
		test_path();
	if (test__start_subtest("cost"))
		test_cost();
}
