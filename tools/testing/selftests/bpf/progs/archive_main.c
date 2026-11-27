// SPDX-License-Identifier: GPL-2.0
/* The program that is linked against libarchive.a, of archive_lib[123].c */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "archive.h"

extern int lib3_func(int x);

SEC("syscall")
int archive_run(struct archive_args *args)
{
	args->out = lib3_func(args->in);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
