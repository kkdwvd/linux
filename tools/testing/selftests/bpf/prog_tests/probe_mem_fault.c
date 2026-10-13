// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "cap_helpers.h"
#include "network_helpers.h"
#include "unpriv_helpers.h"
#include "probe_mem_fault.skel.h"
#include "probe_mem_fault_unpriv.skel.h"

#if defined(__x86_64__)
#include <asm/vsyscall.h>
#endif

/*
 * Addresses a PROBE_MEM load has to survive. Either the JIT's address check
 * or the fault handler must turn each load into a zero result. The user and
 * guard page addresses are those of x86-64 with four and five paging levels;
 * on other kernels they are merely unmapped.
 */
static const struct {
	const char *name;
	__u64 addr;
} bad_addrs[] = {
	{ "null", 0 },
	{ "low_user", 4096 },
	{ "last_user_page_4l", (1ULL << 47) - 2 * 4096 },
	{ "guard_page_4l", (1ULL << 47) - 4096 },
	{ "last_user_page_5l", (1ULL << 56) - 2 * 4096 },
	{ "guard_page_5l", (1ULL << 56) - 4096 },
	{ "non_canonical", 1ULL << 63 },
#if defined(__x86_64__)
	{ "vsyscall", VSYSCALL_ADDR },
	{ "vsyscall_tail", VSYSCALL_ADDR + 0x800 },
#endif
};

static void trigger(struct probe_mem_fault *skel, int *runs)
{
	skel->bss->val_dw = ~0ULL;
	skel->bss->val_w = ~0U;
	skel->bss->val_b = ~0;
	usleep(1);
	ASSERT_EQ(skel->bss->runs, ++*runs, "runs");
}

static void test_addrs(void)
{
	struct probe_mem_fault *skel;
	int runs = 0, i;

	skel = probe_mem_fault__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->target_pid = getpid();
	if (!ASSERT_OK(probe_mem_fault__attach(skel), "attach"))
		goto out;

	/* A valid kernel address is read for real. */
	skel->bss->use_current_task = true;
	trigger(skel, &runs);
	ASSERT_EQ(skel->bss->val_w, getpid(), "pid");
	ASSERT_NEQ(skel->bss->val_dw, 0, "start_time");
	ASSERT_NEQ(skel->bss->val_b, 0, "comm");

	skel->bss->use_current_task = false;
	for (i = 0; i < ARRAY_SIZE(bad_addrs); i++) {
		if (!test__start_subtest(bad_addrs[i].name))
			continue;
		skel->bss->addr = bad_addrs[i].addr;
		trigger(skel, &runs);
		ASSERT_EQ(skel->bss->val_dw, 0, "start_time");
		ASSERT_EQ(skel->bss->val_w, 0, "pid");
		ASSERT_EQ(skel->bss->val_b, 0, "comm");
	}
out:
	probe_mem_fault__destroy(skel);
}

/*
 * A program loaded without CAP_BPF is not registered in kallsyms, so the
 * fault handler cannot find its exception table entries, but with CAP_PERFMON
 * it still gets PROBE_MEM loads through bpf_skc_to_tcp_sock(). Attach such a
 * socket filter to a TCP connection and let it walk a NULL pointer.
 */
static void test_unpriv(void)
{
	__u64 caps = (1ULL << CAP_SYS_ADMIN) | (1ULL << CAP_BPF), old_caps;
	struct probe_mem_fault_unpriv *skel = NULL;
	int server = -1, client = -1, conn = -1, prog_fd, err;
	char buf = 'x';

	if (get_unpriv_sysctl_disabled()) {
		test__skip();
		return;
	}

	server = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 3000);
	if (!ASSERT_OK_FD(server, "start_server"))
		return;
	client = connect_to_fd(server, 3000);
	if (!ASSERT_OK_FD(client, "connect_to_fd"))
		goto out;
	conn = accept(server, NULL, NULL);
	if (!ASSERT_OK_FD(conn, "accept"))
		goto out;
	if (!ASSERT_OK(settimeo(conn, 3000), "settimeo"))
		goto out;

	err = cap_disable_effective(caps, &old_caps);
	if (!ASSERT_OK(err, "cap_disable_effective"))
		goto out;
	skel = probe_mem_fault_unpriv__open_and_load();
	err = cap_enable_effective(old_caps, NULL);
	ASSERT_OK(err, "cap_enable_effective");
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.probe_mem_fault_unpriv);
	err = setsockopt(conn, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
	if (!ASSERT_OK(err, "SO_ATTACH_BPF"))
		goto out;

	ASSERT_EQ(write(client, &buf, 1), 1, "write");
	ASSERT_EQ(read(conn, &buf, 1), 1, "read");
	ASSERT_GE(skel->bss->runs, 1, "runs");
	ASSERT_EQ(skel->bss->ulp_name, 0, "ulp_name");
out:
	probe_mem_fault_unpriv__destroy(skel);
	if (conn >= 0)
		close(conn);
	if (client >= 0)
		close(client);
	close(server);
}

void test_probe_mem_fault(void)
{
	test_addrs();
	if (test__start_subtest("unpriv"))
		test_unpriv();
}
