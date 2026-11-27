// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/resource.h>
#include "unwind_lsm.skel.h"

void test_unwind_lsm(void)
{
	/* errno of setpriority() with no_cb, with_cb, in_cb on the hook */
	static const int err[] = { EPERM, E2BIG, EPERM };
	struct unwind_lsm *skel = unwind_lsm__open_and_load();
	struct bpf_program *prog;
	struct bpf_link *link;
	int i = 0;

	if (!skel && errno == ENOTSUPP)
		return test__skip();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	skel->bss->pid = getpid();
	bpf_object__for_each_program(prog, skel->obj) {
		link = bpf_program__attach(prog);
		ASSERT_EQ(setpriority(PRIO_PROCESS, 0, 1), -1, bpf_program__name(prog));
		ASSERT_EQ(errno, err[i++], bpf_program__name(prog));
		bpf_link__destroy(link);
	}
	unwind_lsm__destroy(skel);
}
