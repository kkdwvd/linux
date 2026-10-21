// SPDX-License-Identifier: GPL-2.0
/*
 * A function that only data refers to. libbpf appends the functions whose
 * addresses are in arena data to the program and stores their JITed addresses
 * there. The program loads the address from arena and calls it with callx of
 * a number. Here user space stores the address by hand.
 */
#include <test_progs.h>
#include <linux/filter.h>
#include <bpf/btf.h>
#include <sys/mman.h>

/* JITs that take BPF_F_ARENA_SCALAR */
#if defined(__x86_64__) || defined(__aarch64__)

#define ARENA_PAGES	1

/*
 * main:   r1 = address of arena; r2 = *(u64 *)(r1 + 0); r1 = 10; callx r2; exit
 * add7:   r0 = r1; r0 += 7; exit
 */
#define CALLX_CALLEE_INSN	6
static const struct bpf_insn callx_insns[] = {
	BPF_LD_IMM64_RAW(BPF_REG_1, BPF_PSEUDO_MAP_VALUE, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_1, 10),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL | BPF_X, BPF_REG_2, 0, 0, 0),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 7),
	BPF_EXIT_INSN(),
};

/* main doesn't call anything, add7 is JITed all the same */
#define NO_CALLX_CALLEE_INSN	4
static const struct bpf_insn no_callx_insns[] = {
	BPF_LD_IMM64_RAW(BPF_REG_1, BPF_PSEUDO_MAP_VALUE, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 7),
	BPF_EXIT_INSN(),
};

/* the callee reads r6, which it doesn't have, and it's verified */
#define BAD_CALLEE_INSN	4
static const struct bpf_insn bad_callee_insns[] = {
	BPF_LD_IMM64_RAW(BPF_REG_1, BPF_PSEUDO_MAP_VALUE, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_6),
	BPF_EXIT_INSN(),
};

static char log_buf[16 * 1024];
static int main_id, callee_id, btf_fd;

static int load(const struct bpf_insn *prog_insns, int cnt, int callee_insn, int arena_fd,
		__u32 flags)
{
	struct bpf_func_info func_info[2] = {
		{ .insn_off = 0, .type_id = main_id },
		{ .insn_off = callee_insn, .type_id = callee_id },
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.prog_flags = BPF_F_SLEEPABLE | flags,
		.prog_btf_fd = btf_fd,
		.func_info = func_info,
		.func_info_cnt = 2,
		.func_info_rec_size = sizeof(func_info[0]),
		.log_buf = log_buf,
		.log_size = sizeof(log_buf),
		.log_level = 1,
	);
	struct bpf_insn insns[16];

	memcpy(insns, prog_insns, cnt * sizeof(insns[0]));
	insns[0].imm = arena_fd;
	log_buf[0] = 0;
	return bpf_prog_load(BPF_PROG_TYPE_SYSCALL, "callx_data", "GPL", insns, cnt, &opts);
}

#define LOAD(insns, callee_insn, arena_fd, flags) \
	load(insns, ARRAY_SIZE(insns), callee_insn, arena_fd, flags)

/* JITed addresses of main and of the callee */
static int jited_funcs(int prog_fd, __u64 *ksyms)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	info.nr_jited_ksyms = 2;
	info.jited_ksyms = ptr_to_u64(ksyms);
	if (!ASSERT_OK(bpf_prog_get_info_by_fd(prog_fd, &info, &len), "prog_info"))
		return -1;
	if (!ASSERT_EQ(info.nr_jited_ksyms, 2, "nr_jited_ksyms"))
		return -1;
	return 0;
}

static void __test_callx_scalar_arena_data(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts, .map_flags = BPF_F_MMAPABLE);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int int_id, proto_id, arena_fd, prog_fd = -1, fd;
	size_t arena_sz = ARENA_PAGES * getpagesize();
	void *arena = MAP_FAILED;
	struct btf *btf;
	__u64 ksyms[2];

	/* there is no support for callx in the interpreter */
	if (!is_jit_enabled()) {
		test__skip();
		return;
	}

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf_new"))
		return;
	int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	proto_id = btf__add_func_proto(btf, int_id);
	main_id = btf__add_func(btf, "main_prog", BTF_FUNC_GLOBAL, proto_id);
	callee_id = btf__add_func(btf, "callee", BTF_FUNC_STATIC, proto_id);
	if (!ASSERT_GT(main_id, 0, "btf_add_main") ||
	    !ASSERT_GT(callee_id, 0, "btf_add_callee") ||
	    !ASSERT_OK(btf__load_into_kernel(btf), "btf_load"))
		goto out_btf;
	btf_fd = btf__fd(btf);

	arena_fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "callx_data", 0, 0, ARENA_PAGES, &map_opts);
	if (!ASSERT_OK_FD(arena_fd, "arena_create"))
		goto out_btf;
	/* the program takes the address of arena, that is where it's mapped */
	arena = mmap(NULL, arena_sz, PROT_READ | PROT_WRITE, MAP_SHARED, arena_fd, 0);
	if (!ASSERT_NEQ(arena, MAP_FAILED, "arena_mmap"))
		goto out;

	/* nothing refers to the callee, and it's unreachable without the flag */
	fd = LOAD(callx_insns, CALLX_CALLEE_INSN, arena_fd, 0);
	if (!ASSERT_LT(fd, 0, "load_no_flag"))
		close(fd);
	ASSERT_HAS_SUBSTR(log_buf, "unreachable insn 6", "log_no_flag");

	/* with the flag it's verified even if the program doesn't call it */
	fd = LOAD(bad_callee_insns, BAD_CALLEE_INSN, arena_fd, BPF_F_ARENA_SCALAR);
	if (!ASSERT_LT(fd, 0, "load_bad_callee"))
		close(fd);
	ASSERT_HAS_SUBSTR(log_buf, "R6 !read_ok", "log_bad_callee");

	/* and it's JITed */
	fd = LOAD(no_callx_insns, NO_CALLX_CALLEE_INSN, arena_fd, BPF_F_ARENA_SCALAR);
	if (ASSERT_OK_FD(fd, "load_no_callx")) {
		jited_funcs(fd, ksyms);
		close(fd);
	} else {
		printf("%s\n", log_buf);
	}

	prog_fd = LOAD(callx_insns, CALLX_CALLEE_INSN, arena_fd, BPF_F_ARENA_SCALAR);
	if (!ASSERT_OK_FD(prog_fd, "load_callx")) {
		printf("%s\n", log_buf);
		goto out;
	}
	if (jited_funcs(prog_fd, ksyms))
		goto out;
	if (!ksyms[1]) {
		/* addresses are hidden */
		test__skip();
		goto out;
	}

	/* what libbpf does for a pointer to a function in arena data */
	*(__u64 *)arena = ksyms[1];
	if (ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &topts), "run"))
		ASSERT_EQ(topts.retval, 17, "retval");
out:
	if (prog_fd >= 0)
		close(prog_fd);
	if (arena != MAP_FAILED)
		munmap(arena, arena_sz);
	close(arena_fd);
out_btf:
	btf__free(btf);
}

#else

static void __test_callx_scalar_arena_data(void)
{
	test__skip();
}

#endif

void test_callx_scalar_arena_data(void)
{
	__test_callx_scalar_arena_data();
}
