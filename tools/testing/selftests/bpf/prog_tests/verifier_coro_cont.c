// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "verifier_coro_cont.skel.h"

/* The suspend kfunc is bpf_testmod's. */
void test_verifier_coro_cont(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	RUN_TESTS(verifier_coro_cont);
}
