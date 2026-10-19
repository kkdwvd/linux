// SPDX-License-Identifier: GPL-2.0
/*
 * Cost of keeping a reference in a unique stack slot for the unwinder: each
 * program acquires a reference, passes a cancellation point holding it and
 * releases it, loaded as is or with BPF_F_TEST_SPILL_REFS. A ringbuf record is
 * acquired by a helper, an allocated object by a kfunc.
 */
#include "bench.h"
#include "bench_bpf_timing.h"
#include "cancel_bench.skel.h"
#include "bpf_util.h"

static struct ctx {
	struct cancel_bench *skel;
	struct bpf_bench_timing timing;
	int prog_fd;
	const char *name;
} ctx;

static void cancel_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumers\n");
		exit(1);
	}
}

static void cancel_run_once(void *unused __always_unused)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	bpf_prog_test_run_opts(ctx.prog_fd, &topts);
}

static void cancel_setup(const char *name, const char *prog_name, bool spill)
{
	struct cancel_bench *skel;
	struct bpf_program *prog;
	int err;

	setup_libbpf();

	skel = cancel_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}
	bpf_object__for_each_program(prog, skel->obj) {
		bpf_program__set_autoload(prog, !strcmp(bpf_program__name(prog), prog_name));
		if (spill)
			bpf_program__set_flags(prog, bpf_program__flags(prog) | BPF_F_TEST_SPILL_REFS);
	}

	err = cancel_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton: %s\n", strerror(-err));
		cancel_bench__destroy(skel);
		exit(1);
	}

	ctx.skel = skel;
	ctx.name = name;
	ctx.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(skel->obj, prog_name));

	BENCH_TIMING_INIT(&ctx.timing, skel, 0);
	bpf_bench_calibrate(&ctx.timing, cancel_run_once, NULL);

	env.duration_sec = 600;
}

static void *cancel_producer(void *input)
{
	while (true)
		cancel_run_once(NULL);

	return NULL;
}

static void cancel_measure(struct bench_res *res)
{
	bpf_bench_timing_measure(&ctx.timing, res);
}

static void cancel_report_final(struct bench_res res[], int res_cnt)
{
	bpf_bench_timing_report(&ctx.timing, ctx.name, NULL);
}

#define CANCEL_BENCH(ident, bench_name, prog, spill)			\
static void cancel_##ident##_setup(void)				\
{									\
	cancel_setup(bench_name, prog, spill);				\
}									\
									\
const struct bench bench_cancel_##ident = {				\
	.name		= bench_name,					\
	.validate	= cancel_validate,				\
	.setup		= cancel_##ident##_setup,			\
	.producer_thread = cancel_producer,				\
	.measure	= cancel_measure,				\
	.report_final	= cancel_report_final,				\
}

CANCEL_BENCH(ringbuf, "cancel-ringbuf", "bench_ringbuf", false);
CANCEL_BENCH(ringbuf_spill, "cancel-ringbuf-spill", "bench_ringbuf", true);
CANCEL_BENCH(obj, "cancel-obj", "bench_obj", false);
CANCEL_BENCH(obj_spill, "cancel-obj-spill", "bench_obj", true);
