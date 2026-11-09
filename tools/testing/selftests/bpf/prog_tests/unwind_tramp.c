// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "unwind_tramp.skel.h"

/* What a cancelled tc program returns: TC_ACT_SHOT. */
#define CANCELLED 2

static char log_buf[16 * 1024];

static int run(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return opts.retval;
}

/*
 * Load the tracer @name alone in a fresh instance of the object, attached to
 * subprog @func of the program @tgt_fd. Returns the instance with the tracer
 * attached; or NULL when @msg says why the load has to fail, after checking
 * that it did so with @msg in its log.
 */
static struct unwind_tramp *trace(int tgt_fd, const char *func, const char *name, const char *msg)
{
	struct bpf_program *prog, *p;
	struct unwind_tramp *skel;
	int err;

	skel = unwind_tramp__open();
	if (!ASSERT_OK_PTR(skel, "open tracer"))
		return NULL;
	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto fail;
	bpf_object__for_each_program(p, skel->obj)
		bpf_program__set_autoload(p, p == prog);
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	err = bpf_program__set_attach_target(prog, tgt_fd, func);
	if (!ASSERT_OK(err, "set_attach_target"))
		goto fail;

	err = unwind_tramp__load(skel);
	if (msg) {
		ASSERT_ERR(err, name);
		ASSERT_HAS_SUBSTR(log_buf, msg, name);
		goto fail;
	}
	if (!ASSERT_OK(err, name) || !ASSERT_OK(unwind_tramp__attach(skel), name))
		goto fail;
	return skel;
fail:
	unwind_tramp__destroy(skel);
	return NULL;
}

/* Run spin_in_subprog with a tracer attached: the cancellation still unwinds the caller. */
static void run_traced(struct unwind_tramp *tgt, struct unwind_tramp *tracer)
{
	if (!tracer)
		return;
	tgt->bss->released_cnt = 0;
	tgt->bss->subprog_returned = 0;
	ASSERT_EQ(run(tgt->progs.spin_in_subprog), CANCELLED, "cancelled with tracer");
	ASSERT_EQ(tgt->bss->released_cnt, 1, "released with tracer");
	ASSERT_EQ(tgt->bss->subprog_returned, 0, "subprog_returned with tracer");
	ASSERT_EQ(tracer->bss->fentry_cnt + tracer->bss->fexit_cnt, 1, "tracer ran");
	unwind_tramp__destroy(tracer);
}

/* Serial: each cancelled run spins for the time slice of a may_goto, 250 ms. */
void serial_test_unwind_tramp(void)
{
	struct unwind_tramp *tgt;
	struct bpf_program *p;
	int spin_fd, throw_fd, err;

	/* The kernel cancels programs on these architectures only. */
#if !defined(__x86_64__) && !defined(__aarch64__)
	test__skip();
	return;
#endif
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}
	tgt = unwind_tramp__open();
	if (!ASSERT_OK_PTR(tgt, "open target"))
		return;
	bpf_object__for_each_program(p, tgt->obj)
		bpf_program__set_autoload(p, p == tgt->progs.release_hook ||
					     p == tgt->progs.spin_in_subprog ||
					     p == tgt->progs.throw_in_subprog);
	err = unwind_tramp__load(tgt);
	if (!ASSERT_OK(err, "load target"))
		goto out;
	if (!ASSERT_OK(unwind_tramp__attach(tgt), "attach release hook"))
		goto out;
	spin_fd = bpf_program__fd(tgt->progs.spin_in_subprog);
	throw_fd = bpf_program__fd(tgt->progs.throw_in_subprog);

	/* The cancellation in the subprog unwinds its caller, which never sees it return. */
	ASSERT_EQ(run(tgt->progs.spin_in_subprog), CANCELLED, "cancelled");
	ASSERT_EQ(tgt->bss->released_cnt, 1, "released");
	ASSERT_EQ(tgt->bss->subprog_returned, 0, "subprog_returned");
	ASSERT_EQ(run(tgt->progs.throw_in_subprog), 0, "thrown");

	/* A trampoline that calls the subprog would stop the unwinder at the subprog. */
	trace(spin_fd, "global_spin", "fexit_spin", "Only fentry can attach to global_spin");
	trace(spin_fd, "global_calls_spin", "fexit_calls_spin",
	      "Only fentry can attach to global_calls_spin");
	trace(throw_fd, "global_throw", "fexit_throw", "Only fentry can attach to global_throw");

	/* Nothing unwinds through these subprogs: a trampoline is in nobody's way. */
	run_traced(tgt, trace(spin_fd, "global_leaf", "fexit_leaf", NULL));
	run_traced(tgt, trace(spin_fd, "global_calls_leaf", "fexit_calls_leaf", NULL));
	/* fentry leaves no frame behind while the subprog runs. */
	run_traced(tgt, trace(spin_fd, "global_spin", "fentry_spin", NULL));
out:
	unwind_tramp__destroy(tgt);
}
