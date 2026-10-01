// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "bpf_ma_ttrace.skel.h"

#define NR_ELEMS 4096

/*
 * Fill the map and delete all elements in chunks with a pause in between, so
 * that the first chunk starts a GP and the others are freed while it's in
 * flight. They should be freed without further alloc or free from this map.
 * Wait for the GP flags to clear in bpf_mem_cache of every cpu and check that
 * all lists are empty.
 */
static void check_map(struct bpf_ma_ttrace *skel, struct bpf_map *map,
		      struct bpf_program *prog, int chunk)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int fd = bpf_map__fd(map);
	__u32 cnt = NR_ELEMS;
	long *vals = NULL;
	int *keys = NULL;
	int i, err;

	keys = calloc(NR_ELEMS, sizeof(*keys));
	vals = calloc(NR_ELEMS, sizeof(*vals));
	if (!ASSERT_OK_PTR(keys, "keys") || !ASSERT_OK_PTR(vals, "vals"))
		goto out;
	for (i = 0; i < NR_ELEMS; i++)
		keys[i] = i;

	err = bpf_map_update_batch(fd, keys, vals, &cnt, NULL);
	if (!ASSERT_OK(err, "update_batch") || !ASSERT_EQ(cnt, NR_ELEMS, "update_cnt"))
		goto out;
	for (i = 0; i < NR_ELEMS; i += chunk) {
		cnt = chunk;
		err = bpf_map_delete_batch(fd, keys + i, &cnt, NULL);
		if (!ASSERT_OK(err, "delete_batch") || !ASSERT_EQ(cnt, chunk, "delete_cnt"))
			goto out;
		if (i + chunk < NR_ELEMS)
			usleep(20000);
	}

	/*
	 * Wait for all __free_by_rcu() and __free_rcu() callbacks to finish.
	 * Without the fixes the lists stay non-empty after the flags clear.
	 */
	for (i = 0; i < 300; i++) {
		err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
		if (!ASSERT_OK(err, "test_run") || !ASSERT_OK(opts.retval, "retval"))
			goto out;
		if (!skel->bss->rcu_in_progress && !skel->bss->in_progress &&
		    !skel->bss->not_sent && !skel->bss->not_freed)
			break;
		usleep(100000);
	}
	ASSERT_EQ(skel->bss->nr_caches, skel->bss->nr_cpus, "nr_caches");
	ASSERT_EQ(skel->bss->rcu_in_progress, 0, "rcu_in_progress");
	ASSERT_EQ(skel->bss->in_progress, 0, "in_progress");
	ASSERT_EQ(skel->bss->not_sent, 0, "not_sent");
	ASSERT_EQ(skel->bss->not_freed, 0, "not_freed");
out:
	free(keys);
	free(vals);
}

void test_bpf_ma_ttrace(void)
{
	struct bpf_ma_ttrace *skel;
	int nr_cpus;

	skel = bpf_ma_ttrace__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_cpus, 0, "nr_cpus"))
		goto out;
	skel->bss->nr_cpus = nr_cpus;

	/*
	 * The first free_bulk() starts RCU tasks trace GP, the rest of the
	 * elements are freed while it's in flight.
	 */
	if (test__start_subtest("ttrace"))
		check_map(skel, skel->maps.htab, skel->progs.check_ttrace, NR_ELEMS);
	/*
	 * The first chunk starts RCU GP in check_free_by_rcu(), the rest of
	 * the elements are freed by unit_free_rcu() while it's in flight.
	 */
	if (test__start_subtest("rcu"))
		check_map(skel, skel->maps.rhtab, skel->progs.check_rcu, 512);
out:
	bpf_ma_ttrace__destroy(skel);
}
