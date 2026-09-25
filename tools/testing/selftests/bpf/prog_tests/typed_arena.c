// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/user.h>
#ifndef PAGE_SIZE /* on some archs it comes in sys/user.h */
#include <unistd.h>
#define PAGE_SIZE getpagesize()
#endif

#include "typed_arena.skel.h"

/* The map's memory usage as the "memlock:" line of its fdinfo. */
static long map_memlock(int map_fd)
{
	char path[64], line[128];
	long memlock = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", map_fd);
	f = fopen(path, "r");
	if (!ASSERT_OK_PTR(f, "open_fdinfo"))
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "memlock:\t%ld", &memlock) == 1)
			break;
	}
	fclose(f);
	ASSERT_NEQ(memlock, -1, "parse_memlock");
	return memlock;
}

static int run_ret(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

	if (!ASSERT_OK(err, name))
		return -1;
	return opts.retval;
}

static int run(struct bpf_program *prog, const char *name)
{
	int ret = run_ret(prog, name);

	if (!ASSERT_OK(ret, name))
		return -1;
	return 0;
}

/* Poll the module object's reference count until a deferred release has run. */
static long wait_ref_cnt(struct typed_arena *skel, long want)
{
	int i;

	for (i = 0; i < 500; i++) {
		if (run(skel->progs.read_ref_cnt, "read_ref_cnt"))
			return -1;
		if (skel->bss->ref_cnt == want)
			break;
		usleep(10000);
	}
	return skel->bss->ref_cnt;
}

/* Poll a fixed allocation until the release of the page it names has run. */
static int wait_alloc_at_handle(struct typed_arena *skel)
{
	int i, ret = -1;

	for (i = 0; i < 500; i++) {
		ret = run_ret(skel->progs.alloc_at_handle, "alloc_at_handle");
		if (ret <= 0)
			break;
		usleep(10000);
	}
	return ret;
}

/* Objects persist across invocations, and pages come and go around them. */
static void test_pages(void)
{
	struct typed_arena *skel;
	long ps = PAGE_SIZE, base, base_cnt;
	__u32 handle;
	int fd;

	skel = typed_arena__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_load"))
		return;
	fd = bpf_map__fd(skel->maps.arena);

	/* Registration at load accounts the page tables and the scratch page. */
	base = map_memlock(fd);
	ASSERT_GE(base, ps, "registered");
	if (run(skel->progs.read_ref_cnt, "base_ref_cnt"))
		goto out;
	base_cnt = skel->bss->ref_cnt;

	if (run(skel->progs.alloc, "alloc"))
		goto out;
	handle = skel->bss->handle;
	ASSERT_EQ(map_memlock(fd), base + ps, "after_alloc");

	skel->bss->value = 42;
	if (run(skel->progs.write_value, "write_value"))
		goto out;
	skel->bss->value = 0;
	if (run(skel->progs.read_value, "read_value"))
		goto out;
	ASSERT_EQ(skel->bss->value, 42, "persisted");

	/* The page is taken until released. */
	ASSERT_EQ(run_ret(skel->progs.alloc_at_handle, "alloc_at_handle"), 1, "taken");

	if (run(skel->progs.stash_ref, "stash_ref"))
		goto out;
	ASSERT_EQ(wait_ref_cnt(skel, base_cnt + 1), base_cnt + 1, "ref_stashed");

	/* Release drops the reference after the grace period and returns the memory. */
	if (run(skel->progs.free_page, "free_page"))
		goto out;
	ASSERT_EQ(wait_ref_cnt(skel, base_cnt), base_cnt, "ref_dropped");
	ASSERT_EQ(map_memlock(fd), base, "after_free");

	/* The same page can be claimed again, and comes back zeroed. */
	if (run(skel->progs.alloc_at_handle, "realloc"))
		goto out;
	ASSERT_EQ(skel->bss->handle, handle, "same_handle");
	if (run(skel->progs.read_value, "read_fresh"))
		goto out;
	ASSERT_EQ(skel->bss->value, 0, "fresh");
	if (run(skel->progs.free_page, "free_again"))
		goto out;

	/*
	 * A handle nobody allocated reads as the dummy object, which takes the
	 * page away from the allocator until it is released in turn.
	 */
	skel->bss->handle = 7 * ps;
	skel->bss->value = 1;
	if (run(skel->progs.read_value, "read_unallocated"))
		goto out;
	ASSERT_EQ(skel->bss->value, 0, "dummy");
	ASSERT_EQ(run_ret(skel->progs.alloc_at_handle, "alloc_scratch_page"), 1, "scratch_taken");
	if (run(skel->progs.free_page, "free_scratch_page"))
		goto out;
	ASSERT_EQ(wait_alloc_at_handle(skel), 0, "scratch_released");
	ASSERT_EQ(skel->bss->handle, 7 * ps, "scratch_page_reused");
out:
	typed_arena__destroy(skel);
}

/*
 * A typed arena belongs to the program BTF that registered it. Two loads of
 * the same object sharing one arena map carry two BTF objects, so their
 * handles name objects in two typed arenas.
 */
static void test_identity(void)
{
	struct typed_arena *skel1, *skel2 = NULL;

	skel1 = typed_arena__open_and_load();
	if (!ASSERT_OK_PTR(skel1, "open_load1"))
		return;
	skel2 = typed_arena__open();
	if (!ASSERT_OK_PTR(skel2, "open2"))
		goto out;
	if (!ASSERT_OK(bpf_map__reuse_fd(skel2->maps.arena, bpf_map__fd(skel1->maps.arena)),
		       "reuse_fd"))
		goto out;
	if (!ASSERT_OK(typed_arena__load(skel2), "load2"))
		goto out;

	if (run(skel1->progs.alloc, "alloc1"))
		goto out;
	skel1->bss->value = 7;
	if (run(skel1->progs.write_value, "write1"))
		goto out;
	skel2->bss->handle = skel1->bss->handle;
	if (run(skel2->progs.read_value, "read2"))
		goto out;
	ASSERT_EQ(skel2->bss->value, 0, "distinct_typed_arena");
	if (run(skel1->progs.read_value, "read1"))
		goto out;
	ASSERT_EQ(skel1->bss->value, 7, "own_typed_arena");
out:
	typed_arena__destroy(skel2);
	typed_arena__destroy(skel1);
}

void test_typed_arena(void)
{
	if (test__start_subtest("pages"))
		test_pages();
	if (test__start_subtest("identity"))
		test_identity();
}
