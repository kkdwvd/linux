// SPDX-License-Identifier: GPL-2.0
/*
 * Linking against archives: the linker takes the members that the inputs
 * before the archive need, as ld does. libarchive.a has archive_lib1.bpf.o,
 * archive_lib2.bpf.o and archive_lib3.bpf.o, in that order; archive_main.bpf.o
 * needs lib3_func() of the last, which needs lib1_func() of the first, and
 * nothing needs the second.
 */
#include <test_progs.h>
#include <bpf/btf.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "archive.skel.h"
#include "progs/archive.h"

#define MAIN "./archive_main.bpf.o"
#define LIB "./libarchive.a"
#define LIB3 "./archive_lib3.bpf.o"
#define DUP "./archive_dup.bpf.o"
#define WEAK "./archive_weak.bpf.o"
#define TMP "/tmp/archive.XXXXXX"

static char link_log[4096];

static int log_link(enum libbpf_print_level level, const char *fmt, va_list args)
{
	size_t len = strlen(link_log);

	if (level == LIBBPF_WARN)
		vsnprintf(link_log + len, sizeof(link_log) - len, fmt, args);
	return 0;
}

/* Link files, in their order, into out, keeping the warnings in link_log */
static int link_files(const char *out, const char **files)
{
	libbpf_print_fn_t old_print;
	struct bpf_linker *linker;
	int err = 0;

	link_log[0] = 0;
	old_print = libbpf_set_print(log_link);
	linker = bpf_linker__new(out, NULL);
	if (!ASSERT_OK_PTR(linker, "linker_new")) {
		err = -errno;
		goto out;
	}
	for (; !err && *files; files++)
		err = bpf_linker__add_file(linker, *files, NULL);
	err = err ?: bpf_linker__finalize(linker);
	bpf_linker__free(linker);
out:
	libbpf_set_print(old_print);
	return err;
}

/* Link files into a temporary file, named in out, which the caller unlinks */
static int link_tmp(char *out, const char **files)
{
	int fd;

	fd = mkstemp(out);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return -1;
	close(fd);
	if (ASSERT_OK(link_files(out, files), "link"))
		return 0;
	unlink(out);
	return -1;
}

/* The BTF of the link of files, which libbpf doesn't open when an extern is left */
static struct btf *link_btf(const char **files)
{
	char out[] = TMP;
	struct btf *btf;

	if (link_tmp(out, files))
		return NULL;
	btf = btf__parse(out, NULL);
	ASSERT_OK_PTR(btf, "btf");
	unlink(out);
	return btf;
}

/* The link of files, loaded */
static struct bpf_object *link_load(const char **files)
{
	char out[] = TMP;
	struct bpf_object *obj;

	if (link_tmp(out, files))
		return NULL;
	obj = bpf_object__open_file(out, NULL);
	if (ASSERT_OK_PTR(obj, "open") && !ASSERT_OK(bpf_object__load(obj), "load")) {
		bpf_object__close(obj);
		obj = NULL;
	}
	unlink(out);
	return obj;
}

/* The link of files fails, saying what */
static void link_fails(const char **files, const char *what)
{
	char out[] = TMP;
	int fd;

	fd = mkstemp(out);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return;
	close(fd);
	ASSERT_ERR(link_files(out, files), "link");
	ASSERT_HAS_SUBSTR(link_log, what, "link log");
	unlink(out);
}

/* The linkage of the FUNC name, or -1 if there is none */
static int func_linkage(struct btf *btf, const char *name)
{
	int id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

	return id > 0 ? (int)btf_vlen(btf__type_by_id(btf, id)) : -1;
}

static bool has_var(struct btf *btf, const char *name)
{
	return btf__find_by_name_kind(btf, name, BTF_KIND_VAR) > 0;
}

/* Which members of libarchive.a the link has: the first, the last, and never the second */
static void check_members(struct btf *btf, bool lib1, bool lib3)
{
	ASSERT_EQ(has_var(btf, "lib1_val"), lib1, "lib1_val");
	ASSERT_EQ(has_var(btf, "lib3_val"), lib3, "lib3_val");
	ASSERT_EQ(func_linkage(btf, "lib3_func") == BTF_FUNC_GLOBAL, lib3, "lib3_func");
	ASSERT_FALSE(has_var(btf, "lib2_val"), "lib2_val");
	ASSERT_FALSE(has_var(btf, "lib2_map"), "lib2_map");
	ASSERT_EQ(func_linkage(btf, "lib2_func"), -1, "lib2_func");
	ASSERT_EQ(func_linkage(btf, "lib2_prog"), -1, "lib2_prog");
}

/* archive_run(in) is lib3_func(in), 2 * lib1_func(in) */
static int run(struct bpf_object *obj, int in)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "archive_run");
	struct archive_args args = { .in = in };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);

	if (!ASSERT_OK_PTR(prog, "archive_run") ||
	    !ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run"))
		return -1;
	return args.out;
}

/* The skeleton, which the Makefile linked against the archive, loads and runs */
static void test_skel(void)
{
	struct archive *skel;

	skel = archive__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	check_members(bpf_object__btf(skel->obj), true, true);
	ASSERT_NULL(bpf_object__find_map_by_name(skel->obj, "lib2_map"), "lib2_map");
	ASSERT_NULL(bpf_object__find_program_by_name(skel->obj, "lib2_prog"), "lib2_prog");
	ASSERT_EQ(run(skel->obj, 5), 2 * (5 + 1), "run");
	ASSERT_EQ(skel->bss->lib1_val, 5, "lib1_val");
	ASSERT_EQ(skel->bss->lib3_val, 5, "lib3_val");
	archive__destroy(skel);
}

/* The archive without its index, or in the BSD format, links the same */
static void test_format(const char *lib)
{
	const char *files[] = { MAIN, lib, NULL };
	struct bpf_object *obj;

	obj = link_load(files);
	if (!obj)
		return;
	check_members(bpf_object__btf(obj), true, true);
	ASSERT_EQ(run(obj, 7), 2 * (7 + 1), "run");
	bpf_object__close(obj);
}

/* An archive before the object that needs it satisfies nothing */
static void test_order(void)
{
	const char *files[] = { LIB, MAIN, NULL };
	struct btf *btf;

	btf = link_btf(files);
	if (!btf)
		return;
	check_members(btf, false, false);
	btf__free(btf);
}

/* A weak reference links no member; a strong one after it does */
static void test_weak(void)
{
	const char *weak[] = { WEAK, LIB, NULL };
	const char *strong[] = { WEAK, LIB3, LIB, NULL };
	struct btf *btf;

	btf = link_btf(weak);
	if (!btf)
		return;
	check_members(btf, false, false);
	ASSERT_EQ(func_linkage(btf, "lib1_func"), BTF_FUNC_EXTERN, "lib1_func");
	btf__free(btf);

	btf = link_btf(strong);
	if (!btf)
		return;
	check_members(btf, true, true);
	ASSERT_EQ(func_linkage(btf, "lib1_func"), BTF_FUNC_GLOBAL, "lib1_func");
	btf__free(btf);
}

/*
 * A member is not linked for a symbol that an earlier input defines, and
 * the definition of a later input conflicts with a linked one
 */
static void test_defined(void)
{
	const char *before[] = { DUP, MAIN, LIB, NULL };
	const char *after[] = { MAIN, LIB, DUP, NULL };
	struct bpf_object *obj;

	obj = link_load(before);
	if (!obj)
		return;
	check_members(bpf_object__btf(obj), false, true);
	ASSERT_EQ(func_linkage(bpf_object__btf(obj), "lib1_func"), BTF_FUNC_GLOBAL, "lib1_func");
	ASSERT_EQ(run(obj, 5), 2 * (5 + 1000), "run");
	bpf_object__close(obj);

	link_fails(after, "conflicting non-weak symbol");
}

/* A member of a hand-made archive, see write_archive() */
struct member {
	const char *name;
	const void *data;
	size_t size;
	/* the symbol the index lists it for, if any */
	const char *sym;
};

/* The header of a member, with the size of its data */
static void write_ar_hdr(FILE *f, const char *name, size_t size)
{
	fprintf(f, "%-16s%-12d%-6d%-6d%-8o%-10zu`\n", name, 0, 0, 0, 0644, size);
}

static void write_ar_data(FILE *f, const void *data, size_t size)
{
	fwrite(data, 1, size, f);
	/* members start at even offsets */
	if (size & 1)
		fputc('\n', f);
}

/*
 * Write an archive of members to path, in the GNU format, with an index of
 * the members that have a symbol if indexed, and with the magic of a thin
 * archive if thin
 */
static int write_archive(const char *path, const struct member *members, int n, bool indexed,
			 bool thin)
{
	size_t index_sz = 0, off;
	FILE *f;
	int i, j;

	f = fopen(path, "w");
	if (!ASSERT_OK_PTR(f, "fopen"))
		return -errno;
	fputs(thin ? "!<thin>\n" : "!<arch>\n", f);

	if (indexed) {
		__u32 be, syms = 0;

		for (i = 0; i < n; i++)
			if (members[i].sym) {
				syms++;
				index_sz += strlen(members[i].sym) + 1;
			}
		index_sz += sizeof(be) * (syms + 1);
		write_ar_hdr(f, "/", index_sz);
		be = htobe32(syms);
		fwrite(&be, 1, sizeof(be), f);
		/* the offset of each member's header: after the magic and the index */
		off = 8 + 60 + ((index_sz + 1) & ~1UL);
		for (i = 0; i < n; i++) {
			if (members[i].sym) {
				be = htobe32(off);
				fwrite(&be, 1, sizeof(be), f);
			}
			off += 60 + ((members[i].size + 1) & ~1UL);
		}
		for (i = 0; i < n; i++)
			if (members[i].sym)
				fwrite(members[i].sym, 1, strlen(members[i].sym) + 1, f);
		if (index_sz & 1)
			fputc('\n', f);
	}

	for (i = 0; i < n; i++) {
		char name[17];

		j = snprintf(name, sizeof(name), "%s/", members[i].name);
		if (!ASSERT_LT(j, sizeof(name), "member name"))
			break;
		write_ar_hdr(f, name, members[i].size);
		write_ar_data(f, members[i].data, members[i].size);
	}
	return fclose(f) ? -errno : 0;
}

/*
 * A member that is not a BPF object is an error when it is linked, or when
 * the members are scanned for want of an index. Thin archives are refused.
 */
static void test_bad_members(void)
{
	/* a relocatable x86-64 object with no sections */
	Elf64_Ehdr ehdr = {
		.e_ident = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB,
			     EV_CURRENT },
		.e_type = ET_REL,
		.e_machine = EM_X86_64,
		.e_version = EV_CURRENT,
		.e_ehsize = sizeof(ehdr),
	};
	const char junk[] = "not an object\n";
	/* both listed for what archive_main.bpf.o needs */
	struct member members[] = {
		{ .name = "lib3.o", .data = &ehdr, .size = sizeof(ehdr), .sym = "lib3_func" },
		{ .name = "junk", .data = junk, .size = sizeof(junk) - 1, .sym = "lib3_func" },
	};
	const char *files[] = { MAIN, NULL, NULL };
	char path[] = "/tmp/libarchive.XXXXXX";
	int fd;

	fd = mkstemp(path);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return;
	close(fd);
	files[1] = path;

	if (ASSERT_OK(write_archive(path, members, 2, true, false), "write indexed"))
		link_fails(files, "(lib3.o)' is not a relocatable 64-bit BPF ELF object");
	if (ASSERT_OK(write_archive(path, members + 1, 1, true, false), "write indexed junk"))
		link_fails(files, "member 'junk' of archive");
	if (ASSERT_OK(write_archive(path, members, 2, false, false), "write unindexed"))
		link_fails(files, "member 'junk' of archive");
	if (ASSERT_OK(write_archive(path, members, 2, true, true), "write thin"))
		link_fails(files, "thin archive");
	unlink(path);
}

/* The programs in C++ are only built by clang */
static bool skip_cxx(const char *file)
{
	if (access(file, R_OK)) {
		printf("archive:SKIP:gcc doesn't build %s\n", file);
		test__skip();
		return true;
	}
	return false;
}

/*
 * The COMDAT groups of a linked member are those of the object, where the
 * two have them, and the member's otherwise; a member whose groups the object
 * has is not linked for them.
 */
static void test_comdat(void)
{
	const char *files[] = { "./comdat_cxx_use.bpf.o", "./libcomdat_cxx.a", NULL };
	struct bpf_program *prog;
	struct bpf_object *obj;
	char data[64] = {};
	struct btf *btf;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = 16,
		.repeat = 1,
	);

	if (skip_cxx(files[0]) || skip_cxx(files[1]))
		return;
	obj = link_load(files);
	if (!obj)
		return;
	btf = bpf_object__btf(obj);
	ASSERT_EQ(func_linkage(btf, "comdat_lib"), BTF_FUNC_GLOBAL, "comdat_lib");
	/* counter<long>::count, of the member only */
	ASSERT_TRUE(has_var(btf, "_ZN7counterIlE5countE"), "count_long");
	/* the programs of comdat_cxx2.bpf.o, whose groups the object has */
	ASSERT_NULL(bpf_object__find_program_by_name(obj, "comdat_c"), "comdat_c");
	ASSERT_NULL(bpf_object__find_program_by_name(obj, "comdat_virtual2"), "comdat_virtual2");

	prog = bpf_object__find_program_by_name(obj, "comdat_use");
	if (!ASSERT_OK_PTR(prog, "comdat_use"))
		goto out;
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run");
	/* 2 * prime_sum(16), counter<long>::bump(100) and counter<int>::bump(10) then (1) */
	ASSERT_EQ(opts.retval, 2 * (2 + 100) + 100 + 10 + 11, "retval");
out:
	bpf_object__close(obj);
}

void test_archive(void)
{
	if (test__start_subtest("skel"))
		test_skel();
	if (test__start_subtest("noindex"))
		test_format("./libarchive_noindex.a");
	if (test__start_subtest("bsd"))
		test_format("./libarchive_bsd.a");
	if (test__start_subtest("order"))
		test_order();
	if (test__start_subtest("weak"))
		test_weak();
	if (test__start_subtest("defined"))
		test_defined();
	if (test__start_subtest("bad_members"))
		test_bad_members();
	if (test__start_subtest("comdat"))
		test_comdat();
}
