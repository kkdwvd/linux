// SPDX-License-Identifier: GPL-2.0
/*
 * A definition of lib1_func() in an object: before libarchive.a, the archive's
 * is not linked for it; after, the two conflict
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int lib1_func(int x)
{
	return x + 1000;
}
