// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/mman.h>

#include "stream.skel.h"
#include "stream_fail.skel.h"

void test_stream_failure(void)
{
	RUN_TESTS(stream_fail);
}

void test_stream_success(void)
{
	RUN_TESTS(stream);
	return;
}

void test_stream_output(void)
{
	return;
}

struct {
	int prog_off;
	const char *errstr;
} stream_error_arr[] = {
	{
		offsetof(struct stream, progs.stream_cond_break),
		"ERROR: Timeout detected for may_goto instruction",
	},
	{
		offsetof(struct stream, progs.stream_deadlock),
		"ERROR: AA or ABBA deadlock detected",
	},
	{
		offsetof(struct stream, progs.stream_arena_read),
		"ERROR: Arena READ access at unmapped address 0xdeadbeef",
	},
	{
		offsetof(struct stream, progs.stream_arena_write),
		"ERROR: Arena WRITE access at unmapped address 0xdeadbeef",
	},
};

void test_stream_errors(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct stream *skel;
	int ret, prog_fd;
	char buf[64];

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	for (int i = 0; i < ARRAY_SIZE(stream_error_arr); i++) {
		prog_fd = bpf_program__fd(((struct bpf_program **)&skel->progs)[i]);
		ret = bpf_prog_test_run_opts(prog_fd, &opts);
		ASSERT_OK(ret, "ret");
		ASSERT_OK(opts.retval, "retval");

		ret = bpf_prog_stream_read(prog_fd, 2, buf, sizeof(buf));
		ASSERT_EQ(ret, sizeof(buf), "stream read");
		ASSERT_STRNEQ(stream_error_arr[i].errstr, buf, strlen(stream_error_arr[i].errstr),
			      "compare error msg");
	}

	stream__destroy(skel);
}

void test_stream_syscall(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct stream *skel;
	int ret, prog_fd;
	char buf[64];

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.stream_syscall);
	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");

	bpf_prog_stream_read(0, 1, buf, sizeof(buf));
	ret = -errno;
	ASSERT_EQ(ret, -EINVAL, "bad prog_fd");

	bpf_prog_stream_read(prog_fd, 0, buf, sizeof(buf));
	ret = -errno;
	ASSERT_EQ(ret, -ENOENT, "bad stream id");

	bpf_prog_stream_read(prog_fd, 1, NULL, sizeof(buf));
	ret = -errno;
	ASSERT_EQ(ret, -EFAULT, "bad stream buf");

	ret = bpf_prog_stream_read(prog_fd, 1, buf, 2);
	ASSERT_EQ(ret, 2, "bytes");
	ret = bpf_prog_stream_read(prog_fd, 1, buf, 2);
	ASSERT_EQ(ret, 2, "bytes");
	ret = bpf_prog_stream_read(prog_fd, 1, buf, 1);
	ASSERT_EQ(ret, 0, "no bytes stdout");
	ret = bpf_prog_stream_read(prog_fd, 2, buf, 1);
	ASSERT_EQ(ret, 0, "no bytes stderr");

	stream__destroy(skel);
}

/*
typedef int (*sample_cb_t)(void *, void *, size_t);

static void stream_ringbuf_output(int prog_id, sample_cb_t sample_cb)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct ring_buffer *ringbuf;
	struct stream_bpftool *skel;
	int fd, ret;

	skel = stream_bpftool__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream_bpftool_open_and_load"))
		return;

	fd = bpf_map__fd(skel->maps.ringbuf);

	ringbuf = ring_buffer__new(fd, sample_cb, NULL, NULL);
	if (!ASSERT_OK_PTR(ringbuf, "ringbuf_new"))
		goto end;

	skel->bss->prog_id = prog_id;
	skel->bss->stream_id = 1;
	do {
		skel->bss->written_count = skel->bss->written_size = 0;
		ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.bpftool_dump_prog_stream), &opts);
		if (ret)
			break;
		ret = ring_buffer__consume_n(ringbuf, skel->bss->written_count);
		if (!ASSERT_EQ(ret, skel->bss->written_count, "consume"))
			break;
		ret = 0;
	} while (opts.retval == EAGAIN);

	ASSERT_OK(ret, "ret");
	ASSERT_EQ(opts.retval, 0, "retval");

end:
	stream_bpftool__destroy(skel);
}

int cnt = 0;

static int process_sample(void *ctx, void *data, size_t len)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "num=%d\n", cnt++);
	ASSERT_TRUE(strcmp(buf, (char *)data) == 0, "sample strcmp");
	return 0;
}

void test_stream_output(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct stream *skel;
	int ret;

	skel = stream__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stream__open_and_load"))
		return;

	ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.stream_test_output), &info, &info_len), "get info");
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.stream_test_output), &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");
	stream_ringbuf_output(info.id, process_sample);

	ASSERT_EQ(cnt, 1000, "cnt");

	stream__destroy(skel);
	return;
}
*/
