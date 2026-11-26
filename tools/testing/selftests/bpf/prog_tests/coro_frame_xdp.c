// SPDX-License-Identifier: GPL-2.0
/*
 * Coroutine frames in the headroom of a packet, see progs/coro_frame_xdp.c: where the frame
 * is, what it leaves of the headroom and what the headroom leaves for it, and that a frame
 * which is parked with its packet gives the packet back however it ends.
 */
#include <test_progs.h>
#include <network_helpers.h>
#include "coro_frame_xdp.skel.h"
#include "coro_frame_xdp_count.skel.h"
#include "../progs/coro_frame_xdp.h"

#define FRAME_LEN	128
/* what the buffer has in front of a frame: struct xdp_frame and the header of the frame */
#define FRAME_OFF	64
#define XDP_HEADROOM	256

static struct coro_frame_xdp_count *count;

static void fill_frame(__u8 *frame, int len)
{
	int i;

	for (i = 0; i < len; i++)
		frame[i] = (i * 7) ^ 0x5a;
	/* A local experimental ethertype: nothing in the stack wants it. */
	frame[12] = 0x88;
	frame[13] = 0xb5;
}

/* One run on a buffer of the test, which no program can keep */
static int run_op(struct coro_frame_xdp *skel, enum coro_frame_xdp_op op, int want)
{
	__u8 frame[FRAME_LEN];
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = frame,
		    .data_size_in = sizeof(frame),
		    .repeat = 1);
	int err;

	fill_frame(frame, sizeof(frame));
	skel->bss->op = op;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.handle), &opts);
	if (!ASSERT_OK(err, "test_run") || !ASSERT_EQ(opts.retval, want, "retval"))
		return -1;
	return 0;
}

/* @nr runs on live frames, which the program can keep, @batch at a time from one pool */
static int run_batches(struct coro_frame_xdp *skel, enum coro_frame_xdp_op op, int nr, int batch)
{
	__u8 frame[FRAME_LEN];
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = frame,
		    .data_size_in = sizeof(frame),
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    .repeat = nr,
		    .batch_size = batch);

	fill_frame(frame, sizeof(frame));
	skel->bss->op = op;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.handle), &opts),
		       "test_run live"))
		return -1;
	return 0;
}

static int run_live(struct coro_frame_xdp *skel, enum coro_frame_xdp_op op, int nr)
{
	return run_batches(skel, op, nr, nr);
}

static bool wait_for(__u64 *counter, __u64 want, const char *what)
{
	int i;

	for (i = 0; i < 2000 && READ_ONCE(*counter) != want; i++)
		usleep(1000);
	return ASSERT_EQ(READ_ONCE(*counter), want, what);
}

static int run_moved(struct coro_frame_xdp *skel, enum coro_frame_xdp_op op, int by0, int by1)
{
	skel->bss->by[0] = by0;
	skel->bss->by[1] = by1;
	skel->bss->moved[0] = 1;
	skel->bss->moved[1] = 1;
	skel->bss->got = 0;
	skel->bss->intact = 0;
	skel->bss->data_off = 0;
	return run_op(skel, op, XDP_PASS);
}

/* The frame is behind the room for struct xdp_frame and its header, and a buffer has one */
static void test_place(void)
{
	struct coro_frame_xdp *skel = coro_frame_xdp__open_and_load();

	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (run_op(skel, OP_PLACE, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->got, 1, "got");
	ASSERT_EQ(skel->bss->got_again, 0, "got_again");
	ASSERT_EQ(skel->bss->data_off, XDP_HEADROOM - FRAME_OFF, "data_off");
	ASSERT_EQ(skel->bss->sum, 3, "sum");
	/* the next packet has its own */
	if (run_op(skel, OP_PLACE, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->got, 2, "got, next");
	/*
	 * and so has each one in a buffer that goes around: a test run has its buffers back
	 * with their contexts as the program left them, once the pages that its pool began
	 * with are used up, and what one lent is not lent still
	 */
	skel->data->verdict = XDP_DROP;
	if (run_batches(skel, OP_PLACE, 512, 8))
		goto out;
	ASSERT_EQ(skel->bss->got, 514, "got, live");
	ASSERT_EQ(skel->bss->got_again, 0, "got_again, live");
	ASSERT_EQ(skel->bss->data_off, XDP_HEADROOM - FRAME_OFF, "data_off, live");
out:
	coro_frame_xdp__destroy(skel);
}

/* Headroom that the program has taken for the packet or its metadata lends no frame */
static void test_taken(void)
{
	struct coro_frame_xdp *skel = coro_frame_xdp__open_and_load();
	int end = FRAME_OFF + FRAME_SIZE;

	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	/* the packet begins four bytes in front of where the frame would end */
	if (run_moved(skel, OP_TAKEN, end - 4 - XDP_HEADROOM, 0))
		goto out;
	ASSERT_EQ(skel->bss->moved[0], 0, "moved, head");
	ASSERT_EQ(skel->bss->got, 0, "got, head");
	/* its metadata does */
	if (run_moved(skel, OP_TAKEN, 0, end - 4 - XDP_HEADROOM))
		goto out;
	ASSERT_EQ(skel->bss->moved[1], 0, "moved, meta");
	ASSERT_EQ(skel->bss->got, 0, "got, meta");
	/* the packet begins where the frame ends */
	if (run_moved(skel, OP_TAKEN, end - XDP_HEADROOM, 0))
		goto out;
	ASSERT_EQ(skel->bss->moved[0], 0, "moved, fits");
	ASSERT_EQ(skel->bss->got, 1, "got, fits");
	ASSERT_EQ(skel->bss->data_off, FRAME_SIZE, "data_off, fits");
	/* and with four bytes of metadata between the two */
	if (run_moved(skel, OP_TAKEN, end + 4 - XDP_HEADROOM, -4))
		goto out;
	ASSERT_EQ(skel->bss->moved[1], 0, "moved, meta fits");
	ASSERT_EQ(skel->bss->got, 1, "got, meta fits");
	ASSERT_EQ(skel->bss->data_off, FRAME_SIZE + 4, "data_off, meta fits");
out:
	coro_frame_xdp__destroy(skel);
}

/* What the frame has is no headroom for the packet, nor for its metadata */
static void test_limits(void)
{
	struct coro_frame_xdp *skel = coro_frame_xdp__open_and_load();
	int end = FRAME_OFF + FRAME_SIZE;

	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	/* without a frame all of it is, down to the room for struct xdp_frame */
	if (run_moved(skel, OP_TAKEN, 40 - XDP_HEADROOM, 0))
		goto out;
	ASSERT_EQ(skel->bss->moved[0], 0, "moved, no frame");
	/* with one, one byte into the frame is refused, and up to the frame is not */
	if (run_moved(skel, OP_LIMIT_HEAD, end - 1 - XDP_HEADROOM, end - XDP_HEADROOM))
		goto out;
	ASSERT_EQ(skel->bss->moved[0], -EINVAL, "moved, into the frame");
	ASSERT_EQ(skel->bss->moved[1], 0, "moved, up to the frame");
	ASSERT_EQ(skel->bss->data_off, FRAME_SIZE, "data_off");
	ASSERT_EQ(skel->bss->intact, 2, "intact");
	if (run_moved(skel, OP_LIMIT_META, end - 4 - XDP_HEADROOM, end - XDP_HEADROOM))
		goto out;
	ASSERT_EQ(skel->bss->moved[0], -EINVAL, "moved, meta into the frame");
	ASSERT_EQ(skel->bss->moved[1], 0, "moved, meta up to the frame");
	ASSERT_EQ(skel->bss->data_off, FRAME_SIZE, "data_off, meta");
	ASSERT_EQ(skel->bss->intact, 2, "intact, meta");
out:
	coro_frame_xdp__destroy(skel);
}

static int run_slot(struct coro_frame_xdp *skel, enum coro_frame_xdp_op op, __u32 slot, int want)
{
	skel->bss->slot = slot;
	return run_op(skel, op, want);
}

/*
 * The last reference of the program with @id is gone. Its release destroys the frames that it
 * left, and only then is its id taken off the list of programs: wait for that.
 */
static bool released(__u32 id)
{
	__u32 next;
	int i;

	for (i = 0; i < 10000; i++) {
		if (bpf_prog_get_next_id(id - 1, &next) || next != id)
			return true;
		usleep(1000);
	}
	return ASSERT_LT(i, 10000, "the program is released");
}

/*
 * A frame that is parked with its packet: the program resumes it or destroys it, the kernel
 * destroys it for the program, and each time the packet goes back to its memory. The frame
 * is FRAME_OFF bytes behind the packet that the program holds.
 */
static void test_park(void)
{
	struct coro_frame_xdp *skel = coro_frame_xdp__open_and_load();
	struct coro_frame_xdp__bss bss = {};
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int bss_fd = -1, zero = 0;
	__u64 back;

	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	back = count->bss->returned;
	/* a buffer of the test is not kept, and its frame not parked */
	if (run_op(skel, OP_PARK, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->steal_failed, 1, "steal_failed");
	ASSERT_EQ(skel->bss->parked, 0, "parked");
	if (run_live(skel, OP_PARK, 5))
		goto out;
	ASSERT_EQ(skel->bss->steal_failed, 1, "steal_failed, live");
	ASSERT_EQ(skel->bss->parked, 5, "parked, live");
	ASSERT_EQ(count->bss->returned, back, "returned, parked");
	if (run_slot(skel, OP_RESUME, 0, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->resumed, 1, "resumed");
	ASSERT_EQ(skel->bss->frame_off, FRAME_OFF, "frame_off");
	ASSERT_EQ(count->bss->returned, back + 1, "returned, resumed");
	if (run_slot(skel, OP_RESUME, 0, XDP_DROP) || run_slot(skel, OP_DESTROY, 1, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->destroyed, 1, "destroyed");
	ASSERT_EQ(count->bss->returned, back + 2, "returned, destroyed");
	if (run_slot(skel, OP_DROP, 2, XDP_PASS))
		goto out;
	wait_for(&skel->bss->destroyed, 2, "destroyed, by the kernel");
	wait_for(&count->bss->returned, back + 3, "returned, dropped");
	/* the other two are in the map when the program goes */
	bss_fd = dup(bpf_map__fd(skel->maps.bss));
	if (!ASSERT_GE(bss_fd, 0, "bss_fd") ||
	    !ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.handle), &info, &len),
		       "get_info"))
		goto out;
	coro_frame_xdp__destroy(skel);
	skel = NULL;
	if (released(info.id) && ASSERT_OK(bpf_map_lookup_elem(bss_fd, &zero, &bss), "bss"))
		ASSERT_EQ(bss.destroyed, 4, "destroyed, with the program");
	wait_for(&count->bss->returned, back + 5, "returned, with the program");
out:
	if (bss_fd >= 0)
		close(bss_fd);
	coro_frame_xdp__destroy(skel);
}

/* The continuation sends the packet as its last act: the frame is gone with it */
static void test_send(void)
{
	struct coro_frame_xdp *skel = coro_frame_xdp__open_and_load();
	__u64 back;

	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	back = count->bss->returned;
	if (run_live(skel, OP_PARK_SENDS, 1) || run_slot(skel, OP_RESUME, 0, XDP_PASS))
		goto out;
	ASSERT_EQ(skel->bss->sent, 1, "sent");
	/* a frame of a test run arrived through no NAPI instance: it goes back to its memory */
	ASSERT_EQ(skel->bss->send_err, -ENODEV, "send_err");
	ASSERT_EQ(count->bss->returned, back + 1, "returned");
out:
	coro_frame_xdp__destroy(skel);
}

/* The kernel unwinds the continuation, or the program: a landing pad gives the packet back */
static void test_unwound(void)
{
	struct coro_frame_xdp *skel = coro_frame_xdp__open_and_load();
	__u64 back, early, frames;

	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	back = count->bss->returned;
	if (run_live(skel, OP_PARK_DIVES, 1) || run_slot(skel, OP_RESUME, 0, XDP_ABORTED))
		goto out;
	frames = skel->bss->frames;
	ASSERT_GT(frames, 0, "frames");
	ASSERT_EQ(skel->bss->resumed, 0, "resumed");
	ASSERT_EQ(count->bss->returned, back + 1, "returned, continuation");
	/* the program is unwound in the run that took the packet, before the driver is done */
	early = count->bss->early;
	if (run_live(skel, OP_DIVE, 1))
		goto out;
	ASSERT_GT(skel->bss->frames, frames, "frames, program");
	ASSERT_EQ(skel->bss->parked, 1, "parked");
	ASSERT_EQ(count->bss->early, early + 1, "given up, program");
	ASSERT_EQ(count->bss->returned, back + 1, "returned, program");
out:
	coro_frame_xdp__destroy(skel);
}

void test_coro_frame_xdp(void)
{
	count = coro_frame_xdp_count__open_and_load();
	if (!ASSERT_OK_PTR(count, "count open_and_load"))
		return;
	if (!ASSERT_OK(coro_frame_xdp_count__attach(count), "count attach"))
		goto out;
	if (test__start_subtest("place"))
		test_place();
	if (test__start_subtest("taken"))
		test_taken();
	if (test__start_subtest("limits"))
		test_limits();
	if (test__start_subtest("park"))
		test_park();
	if (test__start_subtest("send"))
		test_send();
	if (test__start_subtest("unwound"))
		test_unwound();
out:
	coro_frame_xdp_count__destroy(count);
}
