// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "../sdt.h"

static void test_headers(const char *file)
{
	const char * const names[] = { "cpp_helpers", "cpp_tracing", "cpp_endian", "cpp_core" };
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	struct bpf_map *bss;
	char packet[64] = {};
	int key = 0, result, value = 42, err, i;
	LIBBPF_OPTS(bpf_test_run_opts, run,
		.data_in = packet,
		.data_size_in = sizeof(packet),
		.repeat = 1,
	);
	LIBBPF_OPTS(bpf_usdt_opts, usdt, .usdt_cookie = 123);

	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		prog = bpf_object__find_program_by_name(obj, names[i]);
		if (!ASSERT_OK_PTR(prog, names[i]))
			goto out;
		err = bpf_prog_test_run_opts(bpf_program__fd(prog), &run);
		if (!ASSERT_OK(err, names[i]))
			goto out;
		ASSERT_EQ(run.retval, i == 0 ? 16 : 0, names[i]);
	}

	prog = bpf_object__find_program_by_name(obj, "cpp_usdt");
	if (!ASSERT_OK_PTR(prog, "usdt_prog"))
		goto out;
	link = bpf_program__attach_usdt(prog, 0, "/proc/self/exe", "bpf_headers", "args", &usdt);
	if (!ASSERT_OK_PTR(link, "attach_usdt"))
		goto out;
	STAP_PROBE2(bpf_headers, args, -7, &value);
	bss = bpf_object__find_map_by_name(obj, ".bss");
	if (!ASSERT_OK_PTR(bss, "bss"))
		goto out;
	if (ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(bss), &key, &result), "read_usdt_result"))
		ASSERT_EQ(result, 1, "usdt_result");
out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
}

void test_bpf_headers(void)
{
#ifdef BPF_HEADERS_CXX
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const char *cpp_file = "test_bpf_headers_bpfel.bpf.o";
#else
	const char *cpp_file = "test_bpf_headers_bpfeb.bpf.o";
#endif
#endif

	if (test__start_subtest("C"))
		test_headers("test_bpf_headers.bpf.o");
	if (test__start_subtest("C++")) {
#ifdef BPF_HEADERS_CXX
		test_headers(cpp_file);
#else
		test__skip();
#endif
	}
}
