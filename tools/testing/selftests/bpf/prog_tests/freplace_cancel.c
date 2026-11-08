// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/pkt_cls.h>

#include "freplace_cancel.skel.h"
#include "freplace_cancel_tgt.skel.h"

/*
 * Attach @ext to function @name of the target, run the target, and check
 * that the cancelled extension returned the target's cancel value and that
 * the unwinder released what it held.
 */
static void run(struct freplace_cancel *skel, struct bpf_program *ext, int tgt_fd,
		const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct bpf_link *link;

	link = bpf_program__attach_freplace(ext, tgt_fd, name);
	if (!ASSERT_OK_PTR(link, "attach freplace"))
		return;
	skel->bss->acquired = 0;
	skel->bss->released = 0;
	if (ASSERT_OK(bpf_prog_test_run_opts(tgt_fd, &topts), "test_run")) {
		ASSERT_EQ(topts.retval, TC_ACT_SHOT, "the target's cancel value");
		ASSERT_NEQ(skel->bss->acquired, 0, "acquired");
		ASSERT_EQ(skel->bss->released, skel->bss->acquired, "released");
	}
	bpf_link__destroy(link);
}

/*
 * An extension of a cancellable tc program is cancelled: it returns the
 * value of the program it extends, into the program's frame when it replaces
 * a global function of it, and to what ran the program when it replaces the
 * program itself.
 */
void test_freplace_cancel(void)
{
	struct freplace_cancel_tgt *tgt;
	struct freplace_cancel *skel;
	int tgt_fd, err;

	tgt = freplace_cancel_tgt__open_and_load();
	if (!ASSERT_OK_PTR(tgt, "open_and_load target"))
		return;
	tgt_fd = bpf_program__fd(tgt->progs.tc_main);

	skel = freplace_cancel__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto out_tgt;
	err = bpf_program__set_attach_target(skel->progs.ext_glob, tgt_fd, "tc_glob");
	err = err ?: bpf_program__set_attach_target(skel->progs.ext_main, tgt_fd, "tc_main");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;
	if (!ASSERT_OK(freplace_cancel__load(skel), "load"))
		goto out;
	/* The extensions attach one at a time, the release hook for every run. */
	bpf_program__set_autoattach(skel->progs.ext_glob, false);
	bpf_program__set_autoattach(skel->progs.ext_main, false);
	if (!ASSERT_OK(freplace_cancel__attach(skel), "attach hook"))
		goto out;

	if (test__start_subtest("global_func"))
		run(skel, skel->progs.ext_glob, tgt_fd, "tc_glob");
	if (test__start_subtest("main"))
		run(skel, skel->progs.ext_main, tgt_fd, "tc_main");
out:
	freplace_cancel__destroy(skel);
out_tgt:
	freplace_cancel_tgt__destroy(tgt);
}
