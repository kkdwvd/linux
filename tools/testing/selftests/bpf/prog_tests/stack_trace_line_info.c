// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include <network_helpers.h>
#include "stack_trace_line_info.skel.h"

static int prepare_load(struct bpf_program *prog, struct bpf_prog_load_opts *opts, long cookie)
{
	if (cookie) {
		opts->line_info = NULL;
		opts->line_info_cnt = 0;
		opts->line_info_rec_size = 0;
	}
	return 0;
}

static bool run_prog(struct bpf_program *prog)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	return ASSERT_OK(err, "test_run") && ASSERT_EQ(opts.retval, 0, "retval");
}

/* The kernel unwinder has to walk JIT frames; verified on x86-64 and arm64. */
static bool unwinds_jit_frames(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	return true;
#else
	return false;
#endif
}

static void check_frame(const char *trace, const char *name, int line, bool no_linfo)
{
	char expected[64], frame[1024];
	const char *start, *end;

	start = strstr(trace, name);
	if (!ASSERT_OK_PTR(start, name))
		return;
	end = strchr(start, '\n');
	if (!ASSERT_OK_PTR(end, "frame_end") ||
	    !ASSERT_LT(end - start, sizeof(frame), "frame_length"))
		return;
	memcpy(frame, start, end - start);
	frame[end - start] = '\0';
	ASSERT_HAS_SUBSTR(frame, "+0x", "symbol_offset");
	if (no_linfo) {
		ASSERT_NULL(strchr(frame, '('), "no_line_info");
	} else {
		snprintf(expected, sizeof(expected), "(stack_trace_line_info.c:%d:", line);
		ASSERT_HAS_SUBSTR(frame, expected, "source_location");
	}
}

/*
 * Check the source location that %pS or %pB appends for @addr against
 * @linfo. Returns true when the kernel truncated the basename.
 */
static bool check_symbol(struct stack_trace_line_info *skel, __u64 addr,
			 const struct bpf_line_info *linfo, bool backtrace)
{
	int len, file_len, suffix_len;
	const char *file, *base, *loc;
	char suffix[32];

	file = btf__name_by_offset(bpf_object__btf(skel->obj), linfo->file_name_off);
	base = strrchr(file, '/');
	if (base)
		file = base + 1;
	if (!strcmp(file, "stack trace).c"))
		file = "stack\\x20trace\\x29.c";
	file_len = strlen(file);
	suffix_len = snprintf(suffix, sizeof(suffix), ":%u:%u)",
			      BPF_LINE_INFO_LINE_NUM(linfo->line_col),
			      BPF_LINE_INFO_LINE_COL(linfo->line_col));

	skel->bss->symbol_addr = addr;
	skel->bss->backtrace = backtrace;
	skel->bss->symbol_size = sizeof(skel->bss->symbol) - 2;
	memset(skel->bss->symbol, 0xa5, sizeof(skel->bss->symbol));
	if (!run_prog(skel->progs.stack_trace_symbol))
		return false;
	ASSERT_EQ((unsigned char)skel->bss->symbol[0], 0xa5, "leading_canary");
	ASSERT_EQ((unsigned char)skel->bss->symbol[sizeof(skel->bss->symbol) - 1], 0xa5,
		  "trailing_canary");

	loc = strstr(skel->bss->symbol + 1, " (");
	if (!ASSERT_OK_PTR(loc, "source_location"))
		return false;
	loc += 2;
	len = strlen(loc);
	if (!ASSERT_GT(len, suffix_len, "location_length") ||
	    !ASSERT_STREQ(loc + len - suffix_len, suffix, "line_and_column"))
		return false;
	len -= suffix_len;
	if (len >= file_len) {
		ASSERT_EQ(len, file_len, "basename_length");
		ASSERT_STRNEQ(loc, file, file_len, "basename");
		return false;
	}
	/* A long basename is cut short with "..." while the location is kept. */
	if (!ASSERT_GE(len, 3, "truncation_marker_length") ||
	    !ASSERT_STRNEQ(loc + len - 3, "...", 3, "truncation_marker"))
		return false;
	ASSERT_STRNEQ(loc, file, len - 3, "truncated_basename");
	return true;
}

static void check_boundaries(struct stack_trace_line_info *skel)
{
	struct bpf_line_info linfo[64];
	struct bpf_func_info finfo[8];
	__u64 jited_linfo[64];
	struct bpf_prog_info info = {
		.line_info = ptr_to_u64(linfo),
		.nr_line_info = ARRAY_SIZE(linfo),
		.line_info_rec_size = sizeof(linfo[0]),
		.jited_line_info = ptr_to_u64(jited_linfo),
		.nr_jited_line_info = ARRAY_SIZE(jited_linfo),
		.jited_line_info_rec_size = sizeof(jited_linfo[0]),
		.func_info = ptr_to_u64(finfo),
		.nr_func_info = ARRAY_SIZE(finfo),
		.func_info_rec_size = sizeof(finfo[0]),
	};
	__u32 info_len = sizeof(info);
	bool truncated = false;
	int err, i;

	err = bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.stack_trace_main), &info, &info_len);
	if (!ASSERT_OK(err, "prog_info") ||
	    !ASSERT_LE(info.nr_line_info, ARRAY_SIZE(linfo), "nr_line_info") ||
	    !ASSERT_EQ(info.nr_jited_line_info, info.nr_line_info, "nr_jited_line_info") ||
	    !ASSERT_GE(info.nr_func_info, 2, "nr_func_info"))
		return;

	/*
	 * JIT line addresses identify the start of a source line. At that exact
	 * address %pS must select the new line, while %pB selects the preceding
	 * instruction's line.
	 */
	for (i = 0; i < info.nr_line_info && linfo[i].insn_off < finfo[1].insn_off; i++) {
		if (i + 1 < info.nr_line_info && jited_linfo[i] == jited_linfo[i + 1])
			continue;
		truncated |= check_symbol(skel, jited_linfo[i], &linfo[i], false);
		if (i && jited_linfo[i] > jited_linfo[i - 1])
			truncated |= check_symbol(skel, jited_linfo[i], &linfo[i - 1], true);
	}
	ASSERT_TRUE(truncated, "truncation_exercised");

	/* snprintf() must respect the caller's buffer even with source info. */
	skel->bss->symbol_size = 8;
	memset(skel->bss->symbol, 0xa5, sizeof(skel->bss->symbol));
	if (!run_prog(skel->progs.stack_trace_symbol))
		return;
	ASSERT_EQ((unsigned char)skel->bss->symbol[0], 0xa5, "short_leading_canary");
	ASSERT_EQ(skel->bss->symbol[8], '\0', "short_termination");
	ASSERT_EQ((unsigned char)skel->bss->symbol[9], 0xa5, "short_trailing_canary");
	ASSERT_GT(skel->bss->symbol_len, 8, "untruncated_length");
}

static void test_line_info(bool no_linfo)
{
	LIBBPF_OPTS(libbpf_prog_handler_opts, opts,
		.cookie = no_linfo,
		.prog_prepare_load_fn = prepare_load,
	);
	struct stack_trace_line_info *skel;
	int handler;

	handler = libbpf_register_prog_handler("tc", BPF_PROG_TYPE_SCHED_CLS, 0, &opts);
	if (!ASSERT_GE(handler, 0, "register_handler"))
		return;
	skel = stack_trace_line_info__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;
	skel->bss->print_stack = !no_linfo;
	if (!run_prog(skel->progs.stack_trace_main))
		goto out;
	if (skel->bss->trace_len == -EOPNOTSUPP) {
		test__skip();
		goto out;
	}
	ASSERT_GT(skel->bss->trace_len, 2, "trace_length");
	printf("%s", skel->bss->trace);
	if (unwinds_jit_frames()) {
		check_frame(skel->bss->trace, "_stack_trace_leaf+", 100, no_linfo);
		check_frame(skel->bss->trace, "_stack_trace_middle+", 200, no_linfo);
		check_frame(skel->bss->trace, "_stack_trace_main+", 300, no_linfo);
	}
	if (!no_linfo)
		check_boundaries(skel);
out:
	stack_trace_line_info__destroy(skel);
	ASSERT_OK(libbpf_unregister_prog_handler(handler), "unregister_handler");
}

void test_stack_trace_line_info(void)
{
	if (!env.jit_enabled) {
		test__skip();
		return;
	}
	if (test__start_subtest("line_info"))
		test_line_info(false);
	if (test__start_subtest("no_line_info"))
		test_line_info(true);
}
