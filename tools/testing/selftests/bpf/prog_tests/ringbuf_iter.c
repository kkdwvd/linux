// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <time.h>
#include "test_ringbuf_iter.skel.h"

/* Mirrors the context of the producer programs. */
struct produce_args {
	__u64 seq;
	__u32 count;
	__u32 size;
	__u32 discard_mod;
	__u32 flags;
	__u32 produced;
	__u32 failed;
};

static int page_size;

static int produce(int prog_fd, struct produce_args *args)
{
	/* Syscall programs copy the context back into ctx_in. */
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = args,
		.ctx_size_in = sizeof(*args),
	);
	int err;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "produce_run") || !ASSERT_OK(opts.retval, "produce_retval"))
		return -1;
	return 0;
}

/* Produce `count` records of `size` bytes starting at `seq`, all of which must fit. */
static int produce_n(int prog_fd, __u64 seq, __u32 count, __u32 size)
{
	struct produce_args args = { .seq = seq, .count = count, .size = size };

	if (produce(prog_fd, &args))
		return -1;
	if (!ASSERT_EQ(args.produced, count, "produced") || !ASSERT_EQ(args.failed, 0, "failed"))
		return -1;
	return 0;
}

/* Every 8-byte word of a record holds its sequence number. */
static bool record_ok(const void *data, __u32 len, __u64 seq)
{
	const __u64 *w = data;
	__u32 i;

	if (len % 8)
		return false;
	for (i = 0; i < len / 8; i++) {
		if (w[i] != seq)
			return false;
	}
	return true;
}

static int noop_cb(void *ctx, void *data, size_t len)
{
	return 0;
}

static struct test_ringbuf_iter *open_load(size_t normal_sz, size_t overwrite_sz)
{
	struct test_ringbuf_iter *skel;
	int err;

	skel = test_ringbuf_iter__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return NULL;
	bpf_map__set_max_entries(skel->maps.ringbuf, normal_sz);
	bpf_map__set_max_entries(skel->maps.ringbuf_ow, overwrite_sz);
	err = test_ringbuf_iter__load(skel);
	if (!ASSERT_OK(err, "skel_load")) {
		test_ringbuf_iter__destroy(skel);
		return NULL;
	}
	return skel;
}

static void subtest_basic(void)
{
	LIBBPF_OPTS(ring_record, rec);
	struct test_ringbuf_iter *skel;
	struct ring_buffer *rb, *rb_cb;
	struct ring *r, *r_cb, *r2;
	int prog_fd, err, i;
	unsigned long cons;

	skel = open_load(4 * page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), NULL, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	r = ring_buffer__ring(rb, 0);
	if (!ASSERT_OK_PTR(r, "ring_buffer__ring"))
		goto out_rb;

	/* Empty ring: nothing to fetch, nothing pending after a release. */
	ASSERT_EQ(ring__next(r, &rec), 0, "next_empty");
	ASSERT_EQ(ring__release(r), 0, "release_empty");

	/* A bogus record descriptor is rejected. */
	rec.sz = 0;
	ASSERT_EQ(ring__next(r, &rec), -EINVAL, "next_bad_sz");
	rec.sz = sizeof(rec);
	ASSERT_EQ(ring__next(r, NULL), -EINVAL, "next_null_rec");

	/* A ring set up with a callback is not for the record API, and vice versa. */
	rb_cb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), noop_cb, NULL, NULL);
	if (!ASSERT_OK_PTR(rb_cb, "ring_buffer__new_cb"))
		goto out_rb;
	r_cb = ring_buffer__ring(rb_cb, 0);
	ASSERT_EQ(ring__next(r_cb, &rec), -EINVAL, "next_cb_ring");
	ASSERT_EQ(ring__release(r_cb), -EINVAL, "release_cb_ring");
	ASSERT_EQ(ring__check_record(r_cb, &rec), -EINVAL, "verify_cb_ring");
	ring_buffer__free(rb_cb);

	/* Records of different sizes, including empty ones. */
	if (produce_n(prog_fd, 0, 10, 8) || produce_n(prog_fd, 10, 10, 0) ||
	    produce_n(prog_fd, 20, 10, 120) || produce_n(prog_fd, 30, 10, 256))
		goto out_rb;

	cons = ring__consumer_pos(r);
	for (i = 0; i < 40; i++) {
		err = ring__next(r, &rec);
		if (!ASSERT_EQ(err, 1, "next"))
			goto out_rb;
		ASSERT_EQ(rec.len, i < 10 ? 8 : i < 20 ? 0 : i < 30 ? 120 : 256, "rec_len");
		ASSERT_EQ(rec.lost_bytes, 0, "rec_lost");
		ASSERT_TRUE(record_ok(rec.data, rec.len, i), "rec_data");
		ASSERT_EQ(rec.pos & 7, 0, "rec_pos_aligned");
		if (i)
			ASSERT_GT(rec.pos, cons, "rec_pos_after_cons");
		/* Fetched records are not consumed until released. */
		ASSERT_EQ(ring__consumer_pos(r), cons, "cons_unchanged");
	}
	ASSERT_EQ(ring__next(r, &rec), 0, "next_drained");
	/* The data pointers of the whole batch are still valid here. */
	ASSERT_TRUE(record_ok(rec.data, rec.len, 39), "last_rec_still_valid");
	/* Verification is a no-op on a regular ring, but still wants a position. */
	ASSERT_EQ(ring__check_record(r, &rec), 0, "verify_plain");
	ASSERT_EQ(ring__check_record(r, &(struct ring_record){ .sz = sizeof(size_t) }), -EINVAL,
		  "verify_short_rec");

	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");
	ASSERT_EQ(ring__avail_data_size(r), 0, "avail_zero");
	ASSERT_EQ(ring__next(r, &rec), 0, "next_after_release");

	/* Records produced after a fetch loop are reported by the release. */
	if (produce_n(prog_fd, 40, 3, 16))
		goto out_rb;
	ASSERT_EQ(ring__next(r, &rec), 1, "next_more");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_more2");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_more3");
	ASSERT_EQ(ring__next(r, &rec), 0, "next_more_end");
	/* A new consumer starts at the published position, not at our cursor. */
	r2 = ring__new(bpf_map__fd(skel->maps.ringbuf), NULL);
	if (!ASSERT_OK_PTR(r2, "ring__new_second"))
		goto out_rb;
	ASSERT_EQ(ring__next(r2, &rec), 1, "second_consumer_next");
	ASSERT_TRUE(record_ok(rec.data, rec.len, 40), "second_consumer_data");
	ring__free(r2);
	if (produce_n(prog_fd, 43, 1, 16))
		goto out_rb;
	ASSERT_EQ(ring__release(r), 1, "release_pending");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_pending");
	ASSERT_TRUE(record_ok(rec.data, rec.len, 43), "pending_data");
	ASSERT_EQ(ring__release(r), 0, "release_done");

	/* The callback API refuses a ring without a callback, the record API does not care. */
	ASSERT_EQ(ring__consume(r), -EINVAL, "consume_no_cb");
	ASSERT_EQ(ring_buffer__poll(rb, 0), -EINVAL, "poll_no_cb");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_rewind_discard(void)
{
	LIBBPF_OPTS(ring_record, rec);
	struct produce_args args = { .seq = 0, .count = 20, .size = 32, .discard_mod = 4 };
	struct test_ringbuf_iter *skel;
	struct ring_buffer *rb;
	struct ring *r;
	bool rewound = false;
	int prog_fd, i;
	__u64 seq;

	skel = open_load(4 * page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), NULL, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	r = ring_buffer__ring(rb, 0);

	/* Every 4th record is discarded: seq 0, 4, 8, 12, 16 never show up. */
	if (produce(prog_fd, &args) || !ASSERT_EQ(args.produced, 20, "produced"))
		goto out_rb;

	for (i = 0, seq = 1; i < 15; i++, seq++) {
		if (seq % 4 == 0)
			seq++;
		if (!ASSERT_EQ(ring__next(r, &rec), 1, "next"))
			goto out_rb;
		ASSERT_TRUE(record_ok(rec.data, rec.len, seq), "rec_data");
		if (i == 2 && !rewound) {
			/* Peek: rewind and get the same three records again. */
			rewound = true;
			ring__rewind(r);
			ASSERT_EQ(ring__consumer_pos(r), 0, "cons_after_rewind");
			i = -1;
			seq = 0;
		}
	}
	ASSERT_EQ(ring__next(r, &rec), 0, "next_end");
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");

	/* Discarded records at the end are skipped even when nothing follows. */
	args.seq = 20;
	args.count = 1;
	args.discard_mod = 1;
	if (produce(prog_fd, &args))
		goto out_rb;
	ASSERT_EQ(ring__next(r, &rec), 0, "next_only_discarded");
	ASSERT_EQ(ring__release(r), 0, "release_discarded");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_past_discarded");

	/* Partial release: only what was fetched is consumed, the rest is fetched again. */
	if (produce_n(prog_fd, 21, 4, 16))
		goto out_rb;
	ASSERT_EQ(ring__next(r, &rec), 1, "next_partial1");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_partial2");
	ASSERT_EQ(ring__release(r), 1, "release_partial");
	ASSERT_EQ(ring__consumer_pos(r), rec.pos + 8 + 16, "cons_partial");
	ring__rewind(r);
	ASSERT_EQ(ring__next(r, &rec), 1, "next_rest1");
	ASSERT_TRUE(record_ok(rec.data, rec.len, 23), "rest1_data");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_rest2");
	ASSERT_TRUE(record_ok(rec.data, rec.len, 24), "rest2_data");
	ASSERT_EQ(ring__next(r, &rec), 0, "next_rest_end");
	ASSERT_EQ(ring__release(r), 0, "release_rest");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_manager(void)
{
	LIBBPF_OPTS(ring_record, rec);
	struct test_ringbuf_iter *skel;
	struct epoll_event evs[2];
	struct ring_buffer *rb;
	struct ring *r;
	int prog_fd, ow_fd, epfd;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);
	ow_fd = bpf_program__fd(skel->progs.produce_overwrite);

	/* A callback-less manager with two rings: the second one is overwritable. */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), NULL, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	if (!ASSERT_OK(ring_buffer__add(rb, bpf_map__fd(skel->maps.ringbuf_ow), NULL, NULL),
		       "ring_buffer__add"))
		goto out_rb;

	/* The manager's epoll descriptor reports the readable rings. */
	epfd = ring_buffer__epoll_fd(rb);
	ASSERT_EQ(epoll_wait(epfd, evs, 2, 0), 0, "epoll_empty");
	if (produce_n(ow_fd, 100, 2, 16))
		goto out_rb;
	ASSERT_EQ(epoll_wait(epfd, evs, 2, 1000), 1, "epoll_one");
	if (produce_n(prog_fd, 0, 2, 16))
		goto out_rb;
	ASSERT_EQ(epoll_wait(epfd, evs, 2, 1000), 2, "epoll_both");

	/* Drain both with the record API, then nothing is readable anymore. */
	r = ring_buffer__ring(rb, 0);
	ASSERT_EQ(ring__next(r, &rec), 1, "drain0_1");
	ASSERT_EQ(ring__next(r, &rec), 1, "drain0_2");
	ASSERT_EQ(ring__next(r, &rec), 0, "drain0_end");
	ASSERT_EQ(ring__release(r), 0, "drain0_release");
	r = ring_buffer__ring(rb, 1);
	ASSERT_EQ(ring__next(r, &rec), 1, "drain1_1");
	ASSERT_TRUE(record_ok(rec.data, rec.len, 100), "drain1_1_data");
	ASSERT_EQ(ring__check_record(r, &rec), 0, "drain1_1_verify");
	ASSERT_EQ(ring__next(r, &rec), 1, "drain1_2");
	ASSERT_EQ(ring__next(r, &rec), 0, "drain1_end");
	ASSERT_EQ(ring__release(r), 0, "drain1_release");
	ASSERT_EQ(epoll_wait(epfd, evs, 2, 0), 0, "epoll_drained");

	/* The callback API refuses both the missing callback and the overwritable ring. */
	ASSERT_EQ(ring_buffer__consume(rb), -EINVAL, "consume_no_cb");
	ASSERT_EQ(ring__consume(ring_buffer__ring(rb, 1)), -EOPNOTSUPP, "consume_overwrite");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_standalone(void)
{
	LIBBPF_OPTS(ring_record, rec);
	struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
	struct test_ringbuf_iter *skel;
	struct ring *r, *bad;
	int prog_fd, epfd, arr_fd;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	/* Only ring buffer maps are accepted. */
	arr_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(arr_fd, "array_create"))
		goto out;
	bad = ring__new(arr_fd, NULL);
	ASSERT_ERR_PTR(bad, "ring__new_array");
	ASSERT_EQ(errno, EINVAL, "ring__new_array_errno");
	close(arr_fd);
	bad = ring__new(-1, NULL);
	ASSERT_ERR_PTR(bad, "ring__new_badfd");

	r = ring__new(bpf_map__fd(skel->maps.ringbuf), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;
	ASSERT_EQ(ring__size(r), page_size, "ring__size");
	ASSERT_EQ(ring__map_fd(r), bpf_map__fd(skel->maps.ringbuf), "ring__map_fd");

	/* Edge-triggered epoll on the map fd, driven by the application. */
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (!ASSERT_OK_FD(epfd, "epoll_create1"))
		goto out_ring;
	if (!ASSERT_OK(epoll_ctl(epfd, EPOLL_CTL_ADD, ring__map_fd(r), &ev), "epoll_ctl"))
		goto out_epoll;

	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 0), 0, "epoll_empty");
	if (produce_n(prog_fd, 0, 5, 16))
		goto out_epoll;
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 1000), 1, "epoll_ready");

	do {
		while (ring__next(r, &rec) > 0)
			ASSERT_TRUE(record_ok(rec.data, rec.len, rec.pos / 24), "rec_data");
	} while (ring__release(r) > 0);
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 0), 0, "epoll_drained");

	/* The consumer position was published, so the next record wakes us up. */
	if (produce_n(prog_fd, 5, 1, 16))
		goto out_epoll;
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 1000), 1, "epoll_ready_again");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_again");
	ASSERT_TRUE(record_ok(rec.data, rec.len, 5), "rec_data_again");
	ASSERT_EQ(ring__release(r), 0, "release_again");

out_epoll:
	close(epfd);
out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

/* Records of `size` bytes occupy size + 8 bytes of ring space. */
static void subtest_overwrite_basic(void)
{
	LIBBPF_OPTS(ring_record, rec);
	struct test_ringbuf_iter *skel;
	struct ring *r;
	int prog_fd, n = 0;
	__u64 seq, first;
	__u32 size = 120, rec_sz = size + 8, per_ring = page_size / rec_sz;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	/* Fill the ring 3 times over; the producer never fails. */
	if (produce_n(prog_fd, 0, 3 * per_ring, size))
		goto out_ring;
	ASSERT_LE(ring__avail_data_size(r), page_size, "avail_bounded");
	ASSERT_GT(ring__avail_data_size(r), 0, "avail_nonzero");

	/* The first record reports the gap, the rest is contiguous and intact. */
	if (!ASSERT_EQ(ring__next(r, &rec), 1, "next_first"))
		goto out_ring;
	first = ((__u64 *)rec.data)[0];
	ASSERT_GT(first, 2 * per_ring - 1, "first_seq_recent");
	ASSERT_EQ(rec.lost_bytes, first * rec_sz, "first_lost_bytes");
	ASSERT_EQ(rec.pos, first * rec_sz, "first_pos");
	ASSERT_TRUE(record_ok(rec.data, rec.len, first), "first_data");
	ASSERT_EQ(ring__check_record(r, &rec), 0, "first_verify");
	seq = first + 1;
	n = 1;
	while (ring__next(r, &rec) > 0) {
		ASSERT_EQ(rec.lost_bytes, 0, "lost_bytes");
		ASSERT_TRUE(record_ok(rec.data, rec.len, seq), "data");
		ASSERT_EQ(ring__check_record(r, &rec), 0, "verify");
		seq++;
		n++;
	}
	ASSERT_EQ(seq, 3 * per_ring, "all_recent_records_seen");
	ASSERT_LE(n, per_ring, "no_more_than_a_ring");
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");
	ASSERT_EQ(ring__avail_data_size(r), 0, "avail_zero");

	/* Streaming on: no gap when the consumer keeps up. */
	if (produce_n(prog_fd, seq, 2, size))
		goto out_ring;
	ASSERT_EQ(ring__next(r, &rec), 1, "next_streaming");
	ASSERT_EQ(rec.lost_bytes, 0, "no_lost_streaming");
	ASSERT_TRUE(record_ok(rec.data, rec.len, seq), "data_streaming");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_streaming2");
	ASSERT_EQ(ring__next(r, &rec), 0, "next_streaming_end");
	ASSERT_EQ(ring__check_record(r, &rec), 0, "verify_streaming");
	ASSERT_EQ(ring__release(r), 0, "release_streaming");
	seq += 2;

	/* Lapped while holding fetched records: release still reports data. */
	if (produce_n(prog_fd, seq, 1, size))
		goto out_ring;
	ASSERT_EQ(ring__next(r, &rec), 1, "next_before_lap");
	if (produce_n(prog_fd, seq + 1, 2 * per_ring, size))
		goto out_ring;
	ASSERT_EQ(ring__check_record(r, &rec), -EOVERFLOW, "verify_lapped");
	ASSERT_EQ(ring__release(r), 1, "release_lapped");
	ASSERT_EQ(ring__next(r, &rec), 1, "next_after_lap");
	ASSERT_GT(rec.lost_bytes, 0, "lost_after_lap");
	ASSERT_GT(((__u64 *)rec.data)[0], seq, "seq_after_lap");
	ASSERT_EQ(ring__check_record(r, &rec), 0, "verify_after_lap");
	ring__rewind(r);

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

/* Flight recorder: dump the ring on demand without consuming it. */
static void subtest_overwrite_dump(void)
{
	LIBBPF_OPTS(ring_record, rec);
	LIBBPF_OPTS(ring_record, first);
	struct test_ringbuf_iter *skel;
	struct ring *r;
	__u64 first_dump[64], second_dump[64], seq = 0;
	int prog_fd, n1 = 0, n2 = 0, i;
	/* Whatever the page size, the ring holds fewer than 64 of these records. */
	__u32 size = page_size / 64 - 8, per_ring = page_size / (size + 8);
	char *copy;

	copy = calloc(64, size);
	if (!ASSERT_OK_PTR(copy, "calloc"))
		return;
	skel = open_load(page_size, page_size);
	if (!skel)
		goto out_copy;
	prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	if (produce_n(prog_fd, seq, 5 * per_ring, size))
		goto out_ring;
	seq += 5 * per_ring;

	/* Copy everything out, then verify the batch through its first record. */
	while (n1 < 64 && ring__next(r, &rec) > 0) {
		if (n1 == 0)
			first = rec;
		memcpy(copy + n1 * size, rec.data, rec.len);
		first_dump[n1++] = rec.pos;
	}
	ASSERT_GT(n1, 0, "dump1_records");
	ASSERT_LE(n1, per_ring, "dump1_bounded");
	ASSERT_EQ(ring__check_record(r, &first), 0, "dump1_verify");
	for (i = 0; i < n1; i++)
		ASSERT_TRUE(record_ok(copy + i * size, size, seq - n1 + i), "dump1_data");
	/* Keep the data in the ring: rewind instead of releasing. */
	ring__rewind(r);
	ASSERT_EQ(ring__consumer_pos(r), 0, "cons_untouched");

	/* The second dump sees the same records again, gap included. */
	while (n2 < 64 && ring__next(r, &rec) > 0) {
		if (n2 == 0) {
			ASSERT_EQ(rec.lost_bytes, first.lost_bytes, "dump2_lost");
			first = rec;
		}
		second_dump[n2++] = rec.pos;
	}
	ASSERT_EQ(n2, n1, "dump2_same_count");
	for (i = 0; i < n1 && i < n2; i++)
		ASSERT_EQ(second_dump[i], first_dump[i], "dump2_same_pos");
	ASSERT_EQ(ring__check_record(r, &first), 0, "dump2_verify");

	/* Dump and clear: this time release, which empties the ring for the consumer. */
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__next(r, &rec), 0, "next_after_clear");
	ASSERT_EQ(ring__avail_data_size(r), 0, "avail_after_clear");
	/*
	 * Not covered here: a gap found while the oldest record is still busy,
	 * then released and rewound, which needs a reservation held across
	 * program invocations that a syscall program cannot provide.
	 */

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
out_copy:
	free(copy);
}

struct race_ctx {
	int prog_fd;
	volatile bool stop;
	__u64 runs;
};

static void *race_producer(void *arg)
{
	static const __u32 sizes[] = { 8, 24, 64, 120, 256, 16 };
	struct race_ctx *ctx = arg;
	struct produce_args args = { .seq = 0, .count = 16, .flags = BPF_RB_NO_WAKEUP };
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);
	int i = 0;

	while (!ctx->stop) {
		args.size = sizes[i++ % ARRAY_SIZE(sizes)];
		if (bpf_prog_test_run_opts(ctx->prog_fd, &opts))
			break;
		ctx->runs++;
	}
	return NULL;
}

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * A producer laps the consumer continuously while the consumer reads with each
 * of the three consumption styles. Every record that passes verification must
 * be intact, sequence numbers must only go up, and gaps must be reported.
 */
static void subtest_overwrite_race(void)
{
	LIBBPF_OPTS(ring_record, rec);
	LIBBPF_OPTS(ring_record, first);
	struct test_ringbuf_iter *skel;
	struct race_ctx ctx = {};
	struct ring *r;
	pthread_t thread;
	__u64 end, prev_seq = 0, seq, verified = 0, overwritten = 0, lost = 0;
	int err, style, i, n;
	char copy[8][256];
	__u64 losts[8];
	__u32 lens[8];

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	ctx.prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	if (!ASSERT_OK(pthread_create(&thread, NULL, race_producer, &ctx), "pthread_create"))
		goto out_ring;

	end = now_ns() + 1500000000ULL;
	for (style = 0; now_ns() < end; style = (style + 1) % 2) {
		switch (style) {
		case 0:
			/* Zero-copy reader: copy, verify, then trust the copy. */
			err = ring__next(r, &rec);
			if (!ASSERT_GE(err, 0, "next"))
				goto out_thread;
			if (!err)
				continue;
			/* The length is not trusted before the record is verified. */
			memcpy(copy[0], rec.data,
			       rec.len < sizeof(copy[0]) ? rec.len : sizeof(copy[0]));
			err = ring__check_record(r, &rec);
			if (err == -EOVERFLOW) {
				overwritten++;
				continue;
			}
			if (!ASSERT_OK(err, "verify"))
				goto out_thread;
			seq = ((__u64 *)copy[0])[0];
			if (!ASSERT_TRUE(record_ok(copy[0], rec.len, seq), "next_intact"))
				goto out_thread;
			if (!ASSERT_TRUE(!verified || seq > prev_seq, "next_seq_increasing"))
				goto out_thread;
			if (verified && seq != prev_seq + 1)
				ASSERT_GT(rec.lost_bytes, 0, "next_gap_reported");
			lost += rec.lost_bytes;
			prev_seq = seq;
			verified++;
			break;
		case 1:
			/* Batch reader: copy up to 8 records, verify the first one. */
			for (n = 0; n < 8; n++) {
				err = ring__next(r, &rec);
				if (err <= 0)
					break;
				memcpy(copy[n], rec.data,
				       rec.len < sizeof(copy[n]) ? rec.len : sizeof(copy[n]));
				lens[n] = rec.len;
				losts[n] = rec.lost_bytes;
				lost += rec.lost_bytes;
				if (n == 0)
					first = rec;
			}
			if (!ASSERT_GE(err, 0, "batch_next"))
				goto out_thread;
			if (!n)
				continue;
			err = ring__check_record(r, &first);
			if (err == -EOVERFLOW) {
				overwritten += n;
				continue;
			}
			if (!ASSERT_OK(err, "batch_verify"))
				goto out_thread;
			for (i = 0; i < n; i++) {
				seq = ((__u64 *)copy[i])[0];
				if (!ASSERT_TRUE(record_ok(copy[i], lens[i], seq), "batch_intact"))
					goto out_thread;
				if (!ASSERT_TRUE(!verified || seq > prev_seq,
						 "batch_seq_increasing"))
					goto out_thread;
				if (verified && seq != prev_seq + 1)
					ASSERT_GT(losts[i], 0, "batch_gap_reported");
				prev_seq = seq;
				verified++;
			}
			break;
		}
		/* Release now and then, like a real consumer would. */
		if (verified % 64 == 0)
			ring__release(r);
	}

out_thread:
	ctx.stop = true;
	pthread_join(thread, NULL);

	/* The producer is quiet: drain the rest, nothing can fail verification now. */
	while ((err = ring__next(r, &rec)) == 1) {
		memcpy(copy[0], rec.data, rec.len < sizeof(copy[0]) ? rec.len : sizeof(copy[0]));
		ASSERT_OK(ring__check_record(r, &rec), "drain_verify");
		seq = ((__u64 *)copy[0])[0];
		ASSERT_TRUE(record_ok(copy[0], rec.len, seq), "drain_intact");
		verified++;
	}
	ASSERT_EQ(err, 0, "drain_end");
	ASSERT_EQ(ring__release(r), 0, "drain_release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "drain_caught_up");

	ASSERT_GT(ctx.runs, 0, "producer_ran");
	ASSERT_GT(verified, 0, "verified_records");
	if (env.verbosity > VERBOSE_NONE)
		printf("producer runs %llu, verified %llu, overwritten %llu, lost bytes %llu\n",
		       ctx.runs, verified, overwritten, lost);

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

void test_ringbuf_iter(void)
{
	page_size = getpagesize();

	if (test__start_subtest("basic"))
		subtest_basic();
	if (test__start_subtest("rewind_discard"))
		subtest_rewind_discard();
	if (test__start_subtest("manager"))
		subtest_manager();
	if (test__start_subtest("standalone"))
		subtest_standalone();
	if (test__start_subtest("overwrite_basic"))
		subtest_overwrite_basic();
	if (test__start_subtest("overwrite_dump"))
		subtest_overwrite_dump();
	if (test__start_subtest("overwrite_race"))
		subtest_overwrite_race();
}
