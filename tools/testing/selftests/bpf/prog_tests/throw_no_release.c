// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "cap_helpers.h"

static int load(__u32 prog_flags)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .prog_flags = prog_flags);
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns,
			     ARRAY_SIZE(insns), &opts);
}

/* [WIP] BPF_F_THROW_NO_RELEASE needs CAP_BPF and CAP_PERFMON */
void test_throw_no_release(void)
{
	__u64 caps = 1ULL << CAP_SYS_ADMIN | 1ULL << CAP_PERFMON;
	__u64 old_caps;
	int fd, err;

	fd = load(BPF_F_THROW_NO_RELEASE);
	if (ASSERT_GE(fd, 0, "flag with CAP_PERFMON"))
		close(fd);

	err = cap_disable_effective(caps, &old_caps);
	if (!ASSERT_OK(err, "drop CAP_SYS_ADMIN and CAP_PERFMON"))
		return;

	fd = load(0);
	if (ASSERT_GE(fd, 0, "no flag without CAP_PERFMON"))
		close(fd);

	fd = load(BPF_F_THROW_NO_RELEASE);
	ASSERT_EQ(fd, -EPERM, "flag without CAP_PERFMON");
	if (fd >= 0)
		close(fd);

	err = cap_enable_effective(old_caps, NULL);
	ASSERT_OK(err, "restore capabilities");
}
