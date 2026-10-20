// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include <linux/if_ether.h>

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

/* The progs are under #ifdef __BPF_FEATURE_UNWIND */
static bool llvm_lowers_unwinding(const char *file)
{
	struct btf *btf = btf__parse(file, NULL);
	bool ret;

	ret = btf && btf__find_by_name_kind(btf, "loop_catches", BTF_KIND_FUNC) > 0;
	btf__free(btf);
	return ret;
}

/* The prog gets @n as the length of the data behind an Ethernet header */
static void run(struct bpf_object *obj, const char *name, int n, int retval, int dtors)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	struct bpf_map *map = bpf_object__find_map_by_name(obj, ".data.dtors");
	char data[256] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = ETH_HLEN + n,
		.repeat = 1,
	);
	int key = 0, val = 0;

	if (!ASSERT_OK_PTR(prog, name) || !ASSERT_OK_PTR(map, "dtors"))
		return;
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run");
	ASSERT_EQ(opts.retval, retval, "retval");
	ASSERT_OK(bpf_map__lookup_elem(map, &key, sizeof(key), &val, sizeof(val), 0), "lookup");
	ASSERT_EQ(val, dtors, "dtors");
}

void test_unwind_cxx_cb(void)
{
	const char *file = "./unwind_cxx_cb.bpf.o";
	struct bpf_object *obj;
	int err;

	if (access(file, R_OK)) {
		printf("%s:SKIP:gcc doesn't build %s\n", __func__, file);
		test__skip();
		return;
	}
	if (!llvm_lowers_unwinding(file)) {
		printf("%s:SKIP:llvm doesn't lower unwinding\n", __func__);
		test__skip();
		return;
	}
	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	err = bpf_object__load(obj);
	if (err == -ENOTSUPP) {
		printf("%s:SKIP:JIT does not support unwinding\n", __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "load"))
		goto out;

	/*
	 * The callback runs n times, throws on its third run, and its guard's
	 * destructor runs each time. The pad returns 40 plus the runs when it was
	 * given the exception that was thrown, 99 otherwise; the loop that ends
	 * first returns its runs.
	 */
	run(obj, "loop_catches", 2, 2, 11);
	run(obj, "loop_catches", 50, 43, 111);
	run(obj, "loop_helper_catches", 2, 2, 11);
	run(obj, "loop_helper_catches", 50, 43, 111);
	run(obj, "loop_lambda_catches", 2, 2, 0);
	run(obj, "loop_lambda_catches", 50, 43, 0);
	/* The array has 4 elements, and the callback throws on the key n */
	run(obj, "for_each_catches", 1, 42, 0);
	run(obj, "for_each_catches", 50, 4, 0);
out:
	bpf_object__close(obj);
}
