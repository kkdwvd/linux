// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>

/* counter<int>::count, counter<long>::count, and static tag_d */
#define COUNT_INT "_ZN7counterIiE5countE"
#define COUNT_LONG "_ZN7counterIlE5countE"
#define TAG_D "_ZL5tag_d"

/* The progs are C++, which gcc doesn't build, and use BTF of inline variables */
static bool skip(const char *file, const char *inline_var)
{
	struct btf *btf;
	bool ret;

	if (access(file, R_OK)) {
		printf("comdat_cxx:SKIP:gcc doesn't build %s\n", file);
		test__skip();
		return true;
	}
	btf = btf__parse(file, NULL);
	ret = !btf || btf__find_by_name_kind(btf, inline_var, BTF_KIND_VAR) < 0;
	btf__free(btf);
	if (ret) {
		printf("comdat_cxx:SKIP:llvm doesn't describe inline variables in BTF\n");
		test__skip();
	}
	return ret;
}

/*
 * .bss, .data and .rodata hold the data of COMDAT groups that the compiler
 * names, .data.tags that of those with that name. No group has a map of its
 * own.
 */
static void check_maps(struct bpf_object *obj)
{
	struct bpf_map *map;
	int cnt = 0;

	bpf_object__for_each_map(map, obj)
		cnt += bpf_map__is_internal(map);
	ASSERT_EQ(cnt, 4, "internal_maps");
	ASSERT_OK_PTR(bpf_object__find_map_by_name(obj, ".bss"), ".bss");
	ASSERT_OK_PTR(bpf_object__find_map_by_name(obj, ".data"), ".data");
	ASSERT_OK_PTR(bpf_object__find_map_by_name(obj, ".rodata"), ".rodata");
	ASSERT_OK_PTR(bpf_object__find_map_by_name(obj, ".data.tags"), ".data.tags");
	ASSERT_NULL(bpf_object__find_map_by_name(obj, ".data.same"), ".data.same");
}

/* The value of the variable var in the map of section sec, as BTF describes it */
static long var_value(struct bpf_object *obj, const char *sec, const char *var)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, sec);
	struct btf *btf = bpf_object__btf(obj);
	const struct btf_var_secinfo *vsi;
	const struct btf_type *t, *v;
	char val[256] = {};
	int i, key = 0;

	if (!ASSERT_OK_PTR(map, sec) ||
	    !ASSERT_LE(bpf_map__value_size(map), sizeof(val), "value_size") ||
	    !ASSERT_OK(bpf_map__lookup_elem(map, &key, sizeof(key), val,
					    bpf_map__value_size(map), 0), "lookup"))
		return -1;

	t = btf__type_by_id(btf, bpf_map__btf_value_type_id(map));
	if (!ASSERT_TRUE(t && btf_is_datasec(t), "datasec"))
		return -1;
	vsi = btf_var_secinfos(t);
	for (i = 0; i < btf_vlen(t); i++, vsi++) {
		v = btf__type_by_id(btf, vsi->type);
		if (strcmp(btf__name_by_offset(btf, v->name_off), var))
			continue;
		if (vsi->size == sizeof(long))
			return *(long *)(val + vsi->offset);
		return *(int *)(val + vsi->offset);
	}
	PRINT_FAIL("no variable %s in %s\n", var, sec);
	return -1;
}

/* prime_sum(len) is primes[len % 8] + 100, the base */
static int run(struct bpf_object *obj, const char *name, unsigned int len)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	char data[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = len,
		.repeat = 1,
	);

	if (!ASSERT_OK_PTR(prog, name) ||
	    !ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), name))
		return -1;
	return opts.retval;
}

/* An object that is loaded as it is has one copy of each group */
static void test_object(void)
{
	const char *file = "./comdat_cxx.bpf.o";
	struct bpf_object *obj;

	if (skip(file, "calls"))
		return;
	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	check_maps(obj);
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;

	ASSERT_EQ(run(obj, "comdat_a", 16), 102 + 1, "comdat_a");
	ASSERT_EQ(run(obj, "comdat_b", 17), 103 + 2 + 1, "comdat_b");
	ASSERT_EQ(run(obj, "comdat_a", 23), 119 + 2, "comdat_a");
	/* tag_a + tag_b + tag_c + tag_d + same, tag_d once incremented */
	ASSERT_EQ(run(obj, "comdat_tags", 16), 1 + 2 + 3 + 5 + 6, "comdat_tags");
	/* shape::area(16) + twice::area(16) */
	ASSERT_EQ(run(obj, "comdat_virtual", 16), 256 + 512, "comdat_virtual");

	ASSERT_EQ(var_value(obj, ".bss", "calls"), 3, "calls");
	ASSERT_EQ(var_value(obj, ".bss", COUNT_INT), 2, "count_int");
	ASSERT_EQ(var_value(obj, ".bss", COUNT_LONG), 2, "count_long");
	ASSERT_EQ(var_value(obj, ".data", "base"), 100, "base");
	ASSERT_EQ(var_value(obj, ".data", "plain"), 1, "plain");
	ASSERT_EQ(var_value(obj, ".data", "same"), 6, "same");
	ASSERT_EQ(var_value(obj, ".rodata", "primes"), 2, "primes");
	ASSERT_EQ(var_value(obj, ".data.tags", "tag_b"), 2, "tag_b");
	ASSERT_EQ(var_value(obj, ".data.tags", "tag_c"), 3, "tag_c");
	ASSERT_EQ(var_value(obj, ".data.tags", TAG_D), 5, "tag_d");
out:
	bpf_object__close(obj);
}

static int link_objs(const char *out, const char *file1, const char *file2)
{
	struct bpf_linker *linker;
	int err;

	linker = bpf_linker__new(out, NULL);
	if (!linker)
		return -errno;
	err = bpf_linker__add_file(linker, file1, NULL);
	if (!err && file2)
		err = bpf_linker__add_file(linker, file2, NULL);
	err = err ?: bpf_linker__finalize(linker);
	bpf_linker__free(linker);
	return err;
}

/* The linker keeps the first copy of each group, which both objects then use */
static void test_linked(void)
{
	const char *file1 = "./comdat_cxx.bpf.o", *file2 = "./comdat_cxx2.bpf.o";
	char out[] = "/tmp/comdat_cxx.XXXXXX";
	struct bpf_object *obj = NULL;
	int fd;

	if (skip(file1, "calls") || skip(file2, "calls"))
		return;
	fd = mkstemp(out);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return;
	close(fd);

	if (!ASSERT_OK(link_objs(out, file1, file2), "link"))
		goto out;

	obj = bpf_object__open_file(out, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		goto out;
	check_maps(obj);
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;

	ASSERT_EQ(run(obj, "comdat_a", 16), 102 + 1, "comdat_a");
	ASSERT_EQ(run(obj, "comdat_c", 18), 105 + 4, "comdat_c");
	ASSERT_EQ(run(obj, "comdat_tags", 16), 1 + 2 + 3 + 5 + 6, "comdat_tags");
	ASSERT_EQ(run(obj, "comdat_virtual", 16), 256 + 512, "comdat_virtual");
	/* twice::area(16) + tag_a + same */
	ASSERT_EQ(run(obj, "comdat_virtual2", 16), 512 + 1 + 6, "comdat_virtual2");

	ASSERT_EQ(var_value(obj, ".bss", "calls"), 2, "calls");
	ASSERT_EQ(var_value(obj, ".bss", COUNT_INT), 4, "count_int");
	ASSERT_EQ(var_value(obj, ".data", "same"), 6, "same");
	ASSERT_EQ(var_value(obj, ".data.tags", "tag_a"), 1, "tag_a");
	ASSERT_EQ(var_value(obj, ".data.tags", "tag_b"), 2, "tag_b");
	ASSERT_EQ(var_value(obj, ".data.tags", TAG_D), 5, "tag_d");
out:
	bpf_object__close(obj);
	unlink(out);
}

/* The initial value of the __arena variable var, as BTF describes it */
static long arena_value(struct bpf_object *obj, const char *var)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "arena");
	struct btf *btf = bpf_object__btf(obj);
	const struct btf_var_secinfo *vsi;
	const struct btf_type *t, *v;
	const char *data;
	size_t sz;
	int i, id;

	data = map ? bpf_map__initial_value(map, &sz) : NULL;
	id = btf__find_by_name_kind(btf, ".addr_space.1", BTF_KIND_DATASEC);
	if (!ASSERT_OK_PTR(data, "arena_data") || !ASSERT_GT(id, 0, "arena_datasec"))
		return -1;
	t = btf__type_by_id(btf, id);
	if (!ASSERT_EQ(t->size, sz, "arena_size"))
		return -1;
	vsi = btf_var_secinfos(t);
	for (i = 0; i < btf_vlen(t); i++, vsi++) {
		v = btf__type_by_id(btf, vsi->type);
		if (strcmp(btf__name_by_offset(btf, v->name_off), var))
			continue;
		if (vsi->size == sizeof(long))
			return *(long *)(data + vsi->offset);
		return *(int *)(data + vsi->offset);
	}
	PRINT_FAIL("no variable %s in the arena\n", var);
	return -1;
}

static void run_arena(const char *file)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	prog = bpf_object__find_program_by_name(obj, "comdat_arena");
	if (!prog) {
		printf("comdat_cxx:SKIP:llvm doesn't do addr_space_cast\n");
		test__skip();
		goto out;
	}

	ASSERT_EQ(arena_value(obj, "plain_ar"), 5, "plain_ar");
	ASSERT_EQ(arena_value(obj, "_ZL9static_ar"), 7, "static_ar");
	ASSERT_EQ(arena_value(obj, "hits"), 0, "hits");
	ASSERT_EQ(arena_value(obj, "total"), 10, "total");
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;

	/* hits * 1000 + total, which grows by plain_ar + static_ar */
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run");
	ASSERT_EQ(opts.retval, 1000 + 10 + 5 + 7, "first");
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run");
	ASSERT_EQ(opts.retval, 2000 + 22 + 5 + 8, "second");
out:
	bpf_object__close(obj);
}

/* The arena sections of the groups and the other one are one, linked or not */
static void test_arena(void)
{
	const char *file = "./comdat_cxx_arena.bpf.o";
	char out[] = "/tmp/comdat_cxx_arena.XXXXXX";
	int fd;

	if (skip(file, "hits"))
		return;
	run_arena(file);

	fd = mkstemp(out);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return;
	close(fd);
	if (ASSERT_OK(link_objs(out, file, NULL), "link"))
		run_arena(out);
	unlink(out);
}

void test_comdat_cxx(void)
{
	if (test__start_subtest("object"))
		test_object();
	if (test__start_subtest("linked"))
		test_linked();
	if (test__start_subtest("arena"))
		test_arena();
}
