// SPDX-License-Identifier: GPL-2.0
/*
 * The first member of libarchive.a, which archive_lib3.c, after it in the
 * archive, needs
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int lib1_val;

int lib1_func(int x)
{
	lib1_val += x;
	return x + 1;
}
