// SPDX-License-Identifier: GPL-2.0
/* A weak reference to lib1_func(), which no member of libarchive.a is linked for */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "archive.h"

extern int lib1_func(int x) __weak;

SEC("syscall")
int archive_weak_run(struct archive_args *args)
{
	if (lib1_func)
		args->out = lib1_func(args->in);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
