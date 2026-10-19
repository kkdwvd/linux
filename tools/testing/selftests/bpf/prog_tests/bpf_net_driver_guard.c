// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "bpf_net_driver_guard.skel.h"
#include "bpf_net_driver_guard_attach.skel.h"
#include "bpf_net_mlx5.skel.h"
#include "bpf_net_mlx5_run.skel.h"

static void test_guard(const char *prog_name)
{
	struct bpf_net_driver_guard_attach *attach = NULL;
	struct bpf_net_driver_guard *target;
	struct bpf_program *prog, *pos;
	char log_buf[64 * 1024];
	int err;

	target = bpf_net_driver_guard__open_and_load();
	if (!ASSERT_OK_PTR(target, "target_open_and_load"))
		return;

	attach = bpf_net_driver_guard_attach__open();
	if (!ASSERT_OK_PTR(attach, "attach_open"))
		goto out;

	prog = bpf_object__find_program_by_name(attach->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "find_program"))
		goto out;

	bpf_object__for_each_program(pos, attach->obj)
		bpf_program__set_autoload(pos, pos == prog);

	err = bpf_program__set_attach_target(prog, bpf_program__fd(target->progs.guard_open),
					     "guard_open");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	log_buf[0] = '\0';
	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	err = bpf_net_driver_guard_attach__load(attach);
	ASSERT_EQ(err, -EACCES, "load_rejected");
	ASSERT_HAS_SUBSTR(log_buf, "Cannot attach to bpf_net_driver_ops struct_ops programs",
			  "verifier_log");
out:
	bpf_net_driver_guard_attach__destroy(attach);
	bpf_net_driver_guard__destroy(target);
}

static void test_admission(const struct bpf_insn *insns, size_t count, int expected_error)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	char log_buf[16 * 1024] = {};
	const struct btf_member *member;
	const struct btf_type *type;
	struct btf *btf;
	int type_id, fd, i;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "vmlinux_btf"))
		return;
	type_id = btf__find_by_name_kind(btf, "bpf_net_driver_ops", BTF_KIND_STRUCT);
	if (!ASSERT_GT(type_id, 0, "ops_type"))
		goto out;
	type = btf__type_by_id(btf, type_id);
	member = btf_members(type);
	for (i = 0; i < btf_vlen(type); i++)
		if (!strcmp(btf__name_by_offset(btf, member[i].name_off), "open"))
			break;
	if (!ASSERT_LT(i, btf_vlen(type), "open_member"))
		goto out;
	opts.attach_btf_id = type_id;
	opts.expected_attach_type = i;
	opts.log_buf = log_buf;
	opts.log_size = sizeof(log_buf);
	fd = bpf_prog_load(BPF_PROG_TYPE_STRUCT_OPS, "netdrv_guard", "GPL", insns, count, &opts);
	if (expected_error) {
		ASSERT_EQ(fd, expected_error, "load_rejected");
		ASSERT_HAS_SUBSTR(log_buf,
				  "attach to unsupported member open of struct bpf_net_driver_ops",
				  "admission_log");
	} else {
		ASSERT_GE(fd, 0, "load_accepted");
	}
	if (fd >= 0)
		close(fd);
out:
	btf__free(btf);
}

static void test_admission_edges(void)
{
	const struct bpf_insn forward_jmp32[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		BPF_JMP32_A(1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn backward_jmp32[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 2, 1),
		BPF_JMP32_A(-3),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn backward_layout[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP32_A(2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP32_A(-4),
	};
	const struct bpf_insn imm64[] = {
		BPF_LD_IMM64(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn callx[] = {
		BPF_MOV64_IMM(BPF_REG_2, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL | BPF_X, BPF_REG_2, 0, 0, 0),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn subprog_call[] = {
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn pseudo_func[] = {
		BPF_LD_IMM64_RAW(BPF_REG_2, BPF_PSEUDO_FUNC, 3),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	const struct bpf_insn atomic[] = {
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_ATOMIC_OP(BPF_DW, BPF_ADD, BPF_REG_10, BPF_REG_0, -8),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	if (test__start_subtest("forward_jmp32"))
		test_admission(forward_jmp32, ARRAY_SIZE(forward_jmp32), 0);
	if (test__start_subtest("backward_jmp32"))
		test_admission(backward_jmp32, ARRAY_SIZE(backward_jmp32), -EACCES);
	if (test__start_subtest("backward_layout"))
		test_admission(backward_layout, ARRAY_SIZE(backward_layout), 0);
	if (test__start_subtest("imm64"))
		test_admission(imm64, ARRAY_SIZE(imm64), 0);
	if (test__start_subtest("callx"))
		test_admission(callx, ARRAY_SIZE(callx), -EACCES);
	if (test__start_subtest("subprog_call"))
		test_admission(subprog_call, ARRAY_SIZE(subprog_call), -EACCES);
	if (test__start_subtest("pseudo_func"))
		test_admission(pseudo_func, ARRAY_SIZE(pseudo_func), -EACCES);
	if (test__start_subtest("atomic"))
		test_admission(atomic, ARRAY_SIZE(atomic), -EACCES);
}

static void test_insn_limit(size_t count, int expected_error)
{
	struct bpf_insn *insns;
	size_t i;

	insns = calloc(count, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "insns_alloc"))
		return;
	for (i = 0; i < count - 1; i++)
		insns[i] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[count - 1] = BPF_EXIT_INSN();
	test_admission(insns, count, expected_error);
	free(insns);
}

static void test_mlx5_load(bool production)
{
	struct bpf_net_mlx5 *instrumented = NULL;
	struct bpf_net_mlx5_run *run = NULL;
	struct bpf_object *object;
	struct bpf_program *prog;

	if (production) {
		run = bpf_net_mlx5_run__open();
		if (!ASSERT_OK_PTR(run, "mlx5_run_open"))
			goto out;
		run->struct_ops.bvnet->ifindex = 1;
		object = run->obj;
	} else {
		instrumented = bpf_net_mlx5__open();
		if (!ASSERT_OK_PTR(instrumented, "mlx5_open"))
			goto out;
		instrumented->struct_ops.bvnet->ifindex = 1;
		object = instrumented->obj;
	}
	bpf_object__for_each_program(prog, object)
		bpf_program__set_flags(prog, BPF_F_ARENA_SCALAR);
	if (production)
		ASSERT_OK(bpf_net_mlx5_run__load(run), "mlx5_run_load");
	else
		ASSERT_OK(bpf_net_mlx5__load(instrumented), "mlx5_load");
out:
	bpf_net_mlx5_run__destroy(run);
	bpf_net_mlx5__destroy(instrumented);
}

void test_bpf_net_driver_guard(void)
{
	const char * const prog_names[] = {
		"guard_fentry",
		"guard_fexit",
		"guard_fmod_ret",
		"guard_freplace",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(prog_names); i++) {
		if (test__start_subtest(prog_names[i]))
			test_guard(prog_names[i]);
	}
	test_admission_edges();
	if (test__start_subtest("insn_limit"))
		test_insn_limit(32768, 0);
	if (test__start_subtest("insn_limit_exceeded"))
		test_insn_limit(32769, -E2BIG);
	if (test__start_subtest("mlx5_policy_load"))
		test_mlx5_load(false);
	if (test__start_subtest("mlx5_production_policy_load"))
		test_mlx5_load(true);
}
