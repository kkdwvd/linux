// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "verifier_coro_frame_kfunc.skel.h"

void test_verifier_coro_frame_kfunc(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	RUN_TESTS(verifier_coro_frame_kfunc);
}
