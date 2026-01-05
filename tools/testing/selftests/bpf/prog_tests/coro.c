// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>

#include "coro_libbpf.skel.h"
#include "coro_libbpf_fail.skel.h"

void test_coro(void)
{
	RUN_TESTS(coro_libbpf);
	RUN_TESTS(coro_libbpf_fail);
}
