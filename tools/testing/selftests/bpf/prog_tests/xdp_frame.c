// SPDX-License-Identifier: GPL-2.0
/*
 * Frames a program keeps. The program under test stamps a scrambled sequence
 * number into each live frame it is run with, takes the frame and files it in
 * an rbtree node keyed by that number; a syscall program then drains the tree,
 * so the test can check that the frames come out sorted, that the payload read
 * back through a dynptr is what was sent, that reads stay within the frame,
 * that the program can write to its frames, and that frames left in the tree
 * are returned by the frame's destructor, also when it runs with IRQs off.
 */
#include <test_progs.h>
#include <network_helpers.h>
#include "xdp_frame.skel.h"
#include "xdp_frame_ext.skel.h"

#define NR_FRAMES	16
#define FRAME_LEN	128
#define REC_DATA	64
#define SEQ_OFF		14
#define MARK_OFF	(REC_DATA - 4)

struct frame_rec {
	__u32 seq;
	__u32 len;
	int read_err;
	int bad_read_err;
	int write_err;
	__u8 data[REC_DATA];
};

static void fill_frame(__u8 *frame, int len)
{
	int i;

	for (i = 0; i < len; i++)
		frame[i] = (i * 7) ^ 0x5a;
	/* A local experimental ethertype: nothing in the stack wants it. */
	frame[12] = 0x88;
	frame[13] = 0xb5;
}

static int steal_frames(struct xdp_frame *skel, __u8 *frame, int nr)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = frame,
		    .data_size_in = FRAME_LEN,
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    .repeat = nr,
		    .batch_size = nr);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_frame_steal), &opts);
	if (!ASSERT_OK(err, "test_run steal"))
		return -1;
	if (!ASSERT_EQ(skel->bss->stolen, nr, "stolen") ||
	    !ASSERT_EQ(skel->bss->steal_failed, 0, "steal_failed"))
		return -1;
	return 0;
}

static int drain_frames(struct xdp_frame *skel, int max)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	skel->bss->drain_max = max;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_frame_drain), &opts);
	if (!ASSERT_OK(err, "test_run drain") || !ASSERT_EQ(opts.retval, 0, "drain retval"))
		return -1;
	return 0;
}

static void check_rec(struct xdp_frame *skel, const __u8 *frame, __u32 idx)
{
	struct frame_rec rec;
	__u32 mark;
	int err;

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.recs), &idx, &rec);
	if (!ASSERT_OK(err, "lookup rec"))
		return;
	/* Drained in order of the stamp, whatever the arrival order was. */
	ASSERT_EQ(rec.seq, idx, "rec seq");
	ASSERT_EQ(rec.len, FRAME_LEN, "rec len");
	ASSERT_EQ(rec.read_err, 0, "read_err");
	ASSERT_EQ(rec.bad_read_err, -E2BIG, "bad_read_err");
	ASSERT_EQ(rec.write_err, 0, "write_err");
	ASSERT_MEMEQ(rec.data, frame, SEQ_OFF, "data before the stamp");
	ASSERT_MEMEQ(rec.data + SEQ_OFF + 4, frame + SEQ_OFF + 4, MARK_OFF - SEQ_OFF - 4,
		     "data after the stamp");
	memcpy(&mark, rec.data + MARK_OFF, sizeof(mark));
	ASSERT_EQ(mark, rec.seq, "mark written through the dynptr");
}

static void test_steal_drain(void)
{
	struct xdp_frame *skel;
	__u8 frame[FRAME_LEN];
	__u32 idx;

	skel = xdp_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_frame__open_and_load"))
		return;
	fill_frame(frame, sizeof(frame));
	if (steal_frames(skel, frame, NR_FRAMES) || drain_frames(skel, 0))
		goto out;
	ASSERT_EQ(skel->bss->drained, NR_FRAMES, "drained");
	ASSERT_EQ(skel->bss->released, NR_FRAMES, "released");
	for (idx = 0; idx < NR_FRAMES; idx++)
		check_rec(skel, frame, idx);
out:
	xdp_frame__destroy(skel);
}

/* Frames still in the tree when the program goes are returned by the destructor. */
static void test_teardown_returns(void)
{
	struct xdp_frame *skel;
	__u8 frame[FRAME_LEN];

	skel = xdp_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_frame__open_and_load"))
		return;
	fill_frame(frame, sizeof(frame));
	if (steal_frames(skel, frame, NR_FRAMES) || drain_frames(skel, NR_FRAMES / 2))
		goto out;
	ASSERT_EQ(skel->bss->drained, NR_FRAMES / 2, "drained");
out:
	xdp_frame__destroy(skel);
}

#define TAINT_WARN_BIT	9	/* 'W' in /proc/sys/kernel/tainted */

static int read_taint(unsigned long *taint)
{
	FILE *f = fopen("/proc/sys/kernel/tainted", "r");
	int n;

	if (!f)
		return -errno;
	n = fscanf(f, "%lu", taint);
	fclose(f);
	return n == 1 ? 0 : -EINVAL;
}

/*
 * A node dropped with IRQs off runs the destructor of its frame there, where
 * the page pool cannot be entered: its ring takes a _bh lock outside softirq.
 * The frame has to wait for a work item instead of warning on the way in.
 */
static void test_drop_irqs_off(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	unsigned long before, after;
	struct xdp_frame *skel;
	__u8 frame[FRAME_LEN];
	int err;

	if (!ASSERT_OK(read_taint(&before), "read taint"))
		return;
	if (before & (1UL << TAINT_WARN_BIT)) {
		printf("%s:SKIP:the kernel has warned before\n", __func__);
		test__skip();
		return;
	}
	skel = xdp_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_frame__open_and_load"))
		return;
	fill_frame(frame, sizeof(frame));
	if (steal_frames(skel, frame, NR_FRAMES))
		goto out;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_frame_drop_irqs_off), &opts);
	if (!ASSERT_OK(err, "test_run drop") || !ASSERT_EQ(opts.retval, 0, "drop retval"))
		goto out;
	ASSERT_EQ(skel->bss->dropped_irqs_off, NR_FRAMES, "dropped_irqs_off");
	if (ASSERT_OK(read_taint(&after), "read taint"))
		ASSERT_FALSE(after & (1UL << TAINT_WARN_BIT), "no warning");
out:
	xdp_frame__destroy(skel);
}

/* Without live frames the buffer is not a driver's; the steal is refused. */
static void test_no_live_frames(void)
{
	__u8 frame[FRAME_LEN], out[FRAME_LEN];
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = frame,
		    .data_size_in = sizeof(frame),
		    .data_out = out,
		    .data_size_out = sizeof(out),
		    .repeat = 1);
	struct xdp_frame *skel;
	int err;

	skel = xdp_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_frame__open_and_load"))
		return;
	fill_frame(frame, sizeof(frame));
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.xdp_frame_steal), &opts);
	ASSERT_OK(err, "test_run steal");
	ASSERT_EQ(opts.retval, XDP_PASS, "retval");
	ASSERT_EQ(skel->bss->stolen, 0, "stolen");
	ASSERT_EQ(skel->bss->steal_failed, 1, "steal_failed");
	xdp_frame__destroy(skel);
}

/*
 * An extension that replaces a global function of an XDP program cannot take
 * the frame: the program it extends keeps its copies of the context.
 */
static void test_steal_from_extension(void)
{
	struct xdp_frame_ext *ext = NULL;
	struct xdp_frame *skel;
	char log[16 * 1024] = {};
	int err;

	skel = xdp_frame__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_frame__open_and_load"))
		return;
	ext = xdp_frame_ext__open();
	if (!ASSERT_OK_PTR(ext, "xdp_frame_ext__open"))
		goto out;
	bpf_program__set_log_buf(ext->progs.steal_in_extension, log, sizeof(log));
	err = bpf_program__set_attach_target(ext->progs.steal_in_extension,
					     bpf_program__fd(skel->progs.xdp_frame_ext_target),
					     "xdp_frame_verdict");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;
	ASSERT_ERR(xdp_frame_ext__load(ext), "xdp_frame_ext__load");
	ASSERT_HAS_SUBSTR(log, "cannot be called from a global function or an extension program",
			  "log");
out:
	xdp_frame_ext__destroy(ext);
	xdp_frame__destroy(skel);
}

void test_xdp_frame(void)
{
	if (test__start_subtest("steal_drain"))
		test_steal_drain();
	if (test__start_subtest("teardown_returns"))
		test_teardown_returns();
	if (test__start_subtest("drop_irqs_off"))
		test_drop_irqs_off();
	if (test__start_subtest("no_live_frames"))
		test_no_live_frames();
	if (test__start_subtest("steal_from_extension"))
		test_steal_from_extension();
}
