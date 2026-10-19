// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "verifier_noreturn_call.skel.h"
#include "noreturn_attach.skel.h"

static char log_buf[16 * 1024];

static int run(int fd)
{
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = sizeof(data),
		.repeat = 1,
	);

	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run");
	return opts.retval;
}

/*
 * The target calls global_throws_13(), which throws 13 on every path, so
 * nothing after the call is verified or JITed: the call is the last insn
 * of the subprog that makes it.
 * msg: why the program cannot be loaded. Otherwise retval is what the
 * target returns with the program attached.
 */
static void attach(int tgt_fd, const char *name, const char *msg, int retval)
{
	struct bpf_link *link = NULL;
	struct noreturn_attach *skel;
	struct bpf_program *prog;
	int err;

	skel = noreturn_attach__open();
	if (!ASSERT_OK_PTR(skel, "noreturn_attach__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		goto out;
	bpf_program__set_autoload(prog, true);
	log_buf[0] = 0;
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	err = bpf_program__set_attach_target(prog, tgt_fd, "global_throws_13");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = noreturn_attach__load(skel);
	if (msg) {
		ASSERT_ERR(err, name);
		ASSERT_HAS_SUBSTR(log_buf, msg, name);
		goto out;
	}
	if (!ASSERT_OK(err, name))
		goto out;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto out;
	ASSERT_EQ(run(tgt_fd), retval, "retval");
	if (prog == skel->progs.fentry_noreturn)
		ASSERT_EQ(skel->bss->fentry_cnt, 1, "fentry_cnt");
out:
	bpf_link__destroy(link);
	noreturn_attach__destroy(skel);
}

void test_noreturn_attach(void)
{
	struct verifier_noreturn_call *tgt;
	struct bpf_program *prog;
	int tgt_fd, err;

	tgt = verifier_noreturn_call__open();
	if (!ASSERT_OK_PTR(tgt, "verifier_noreturn_call__open"))
		return;
	bpf_object__for_each_program(prog, tgt->obj)
		bpf_program__set_autoload(prog, prog == tgt->progs.ends_with_global_throw);
	err = verifier_noreturn_call__load(tgt);
	if (!ASSERT_OK(err, "verifier_noreturn_call__load"))
		goto out;
	tgt_fd = bpf_program__fd(tgt->progs.ends_with_global_throw);
	ASSERT_EQ(run(tgt_fd), 13, "retval");

	attach(tgt_fd, "fentry_noreturn", NULL, 13);
	/* bpf_throw would unwind over the trampoline, which never returns then */
	attach(tgt_fd, "fexit_noreturn", "Only fentry can attach to global_throws_13, which might throw",
	       0);
	/* nothing would run after the call that the extension returns to */
	attach(tgt_fd, "freplace_returns",
	       "Extension cannot replace a function whose callers expect it not to return", 0);
	ASSERT_EQ(run(tgt_fd), 13, "retval");
out:
	verifier_noreturn_call__destroy(tgt);
}
