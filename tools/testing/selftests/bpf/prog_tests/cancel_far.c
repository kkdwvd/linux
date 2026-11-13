// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/pkt_cls.h>
#include "cancel_far.skel.h"

/* src_reg of BPF_JMP | BPF_JCOND that only the verifier inserts, see linux/filter.h */
#define BPF_CANCEL_GOTO	2

static char stream[64 * 1024];

/* Run @prog once. Returns what it returned. */
static int run(struct bpf_program *prog)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	/* a raw tracepoint prog takes no packet */
	if (bpf_program__type(prog) == BPF_PROG_TYPE_SCHED_CLS) {
		opts.data_in = data;
		opts.data_size_in = sizeof(data);
		opts.repeat = 1;
	}
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts),
		       bpf_program__name(prog)))
		return -1;
	return opts.retval;
}

/* What @prog wrote to its stderr stream since this was called last */
static const char *read_stream(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	int fd = bpf_program__fd(prog), max = sizeof(stream) - 1, len = 0, n;

	do {
		n = bpf_prog_stream_read(fd, BPF_STREAM_STDERR, stream + len, max - len, &ropts);
		if (n > 0)
			len += n;
	} while (n > 0 && len < max);
	stream[len] = 0;
	return stream;
}

/* "@prog @of", to tell which prog an assertion is about */
static const char *what(struct bpf_program *prog, const char *of)
{
	static char buf[128];

	snprintf(buf, sizeof(buf), "%s %s", bpf_program__name(prog), of);
	return buf;
}

static int records;

static int on_record(void *ctx, void *data, size_t size)
{
	records++;
	return 0;
}

/*
 * A record that was neither submitted nor discarded stops the consumer in front of it for
 * good. The ring buffer of the progs has no such record and none that was submitted: it is
 * empty, and a record that is submitted now gets to the consumer.
 */
static void ringbuf_is_clean(struct cancel_far *skel, struct ring_buffer *rb,
			     struct bpf_program *prog)
{
	records = 0;
	ring_buffer__consume(rb);
	ASSERT_EQ(records, 0, what(prog, "records"));
	ASSERT_EQ(ring__avail_data_size(ring_buffer__ring(rb, 0)), 0, what(prog, "ringbuf"));
	run(skel->progs.ringbuf_submit);
	ring_buffer__consume(rb);
	ASSERT_EQ(records, 1, what(prog, "record"));
}

/*
 * @prog is cancelled at the point that writes @report: a tc prog returns TC_ACT_SHOT where
 * its last insn returns TC_ACT_OK, and a raw tracepoint prog 0 like its last insn. Its pad says
 * so in the stream, nothing ran behind the point, and the record that the frame may have held
 * is discarded.
 */
static void cancelled(struct cancel_far *skel, struct ring_buffer *rb, struct bpf_program *prog,
		      const char *report)
{
	bool tc = bpf_program__type(prog) == BPF_PROG_TYPE_SCHED_CLS;
	const char *out;

	skel->bss->behind = 0;
	ASSERT_EQ(run(prog), tc ? TC_ACT_SHOT : 0, what(prog, "retval"));
	ASSERT_EQ(skel->bss->behind, 0, what(prog, "behind"));
	out = read_stream(prog);
	ASSERT_HAS_SUBSTR(out, report, what(prog, "report"));
	ASSERT_HAS_SUBSTR(out, "ERROR: Program was cancelled", what(prog, "stream"));
	ringbuf_is_clean(skel, rb, prog);
}

/*
 * The insns that the verifier left of @prog: @nr cancel_goto have a pad that is more than @min
 * insns away. Each of them is one insn, with the offset in imm and no jump behind it to get
 * to the pad with, and what it points to begins behind an exit, like every pad.
 */
static void check_insns(struct bpf_program *prog, int min, int nr)
{
	struct bpf_insn *insns;
	__u32 cnt, i, pad;
	int far = 0;

	if (!ASSERT_OK(get_xlated_program(bpf_program__fd(prog), &insns, &cnt),
		       what(prog, "get_xlated_program")))
		return;
	for (i = 0; i < cnt; i++) {
		if (insns[i].code != (BPF_JMP | BPF_JCOND) || insns[i].src_reg != BPF_CANCEL_GOTO)
			continue;
		ASSERT_EQ(insns[i].off, 0, what(prog, "off"));
		if (insns[i].imm <= min)
			continue;
		far++;
		pad = i + 1 + insns[i].imm;
		if (!ASSERT_LT(pad, cnt, what(prog, "pad")))
			break;
		ASSERT_EQ(insns[pad - 1].code, BPF_JMP | BPF_EXIT, what(prog, "in front of the pad"));
		ASSERT_NEQ(insns[i + 1].code, BPF_JMP | BPF_JA, what(prog, "goto"));
	}
	ASSERT_EQ(far, nr, what(prog, "cancel_goto"));
	free(insns);
}

static const char no_room[] = "ERROR: No room in the stack for a call of a recursive function";
static const char arena_fault[] = "ERROR: Arena READ access at unmapped address";

/* The frame holds the record at the one point of @prog that has a pad more than @min insns away */
static void test_point(struct cancel_far *skel, struct ring_buffer *rb, struct bpf_program *prog,
		       const char *report, int min)
{
	cancelled(skel, rb, prog, report);
	check_insns(prog, min, 1);
}

static void test_flag(struct cancel_far *skel, struct ring_buffer *rb, struct bpf_program *prog,
		      int min)
{
	/*
	 * gets_record() returns with a record. The store behind its call sets the flag, and
	 * the pad of the call of dives() finds it set and discards the record.
	 */
	skel->bss->zero = 0;
	skel->bss->dive = 0;
	cancelled(skel, rb, prog, no_room);
	/* gets_record() dives before it has a record: the pad of its call releases nothing */
	skel->bss->dive = 1;
	cancelled(skel, rb, prog, no_room);
	skel->bss->dive = 0;
	/* the path that has 0 in the place of the record: the pad finds the flag clear */
	skel->bss->zero = 1;
	cancelled(skel, rb, prog, no_room);
	skel->bss->zero = 0;
	/* the calls of gets_record() and of dives() */
	check_insns(prog, min, 2);
}

void test_cancel_far(void)
{
	struct ring_buffer *rb = NULL;
	struct cancel_far *skel;

	/* The interpreter runs no pads. */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	/* what the verifier says about the progs. They run below, where their globals are set. */
	RUN_TESTS(cancel_far);

#if !defined(__x86_64__) && !defined(__aarch64__)
	return;
#endif
	skel = cancel_far__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cancel_far__open_and_load"))
		return;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), on_record, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;

	if (test__start_subtest("call")) {
		test_point(skel, rb, skel->progs.call_2k, no_room, 2048);
		test_point(skel, rb, skel->progs.call_33k, no_room, 32767);
	}
	if (test__start_subtest("arena")) {
		test_point(skel, rb, skel->progs.arena_2k, arena_fault, 2048);
		test_point(skel, rb, skel->progs.arena_33k, arena_fault, 32767);
	}
	if (test__start_subtest("private stack"))
		test_point(skel, rb, skel->progs.priv_stack_33k, arena_fault, 32767);
	if (test__start_subtest("flag")) {
		test_flag(skel, rb, skel->progs.flag_2k, 2048);
		test_flag(skel, rb, skel->progs.flag_33k, 32767);
	}
out:
	ring_buffer__free(rb);
	cancel_far__destroy(skel);
}
