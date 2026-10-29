// SPDX-License-Identifier: GPL-2.0
/*
 * The last member of libarchive.a, the one archive_main.c needs, which needs
 * archive_lib1.c, before it in the archive
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern int lib1_func(int x);

int lib3_val;

int lib3_func(int x)
{
	lib3_val += x;
	return 2 * lib1_func(x);
}
