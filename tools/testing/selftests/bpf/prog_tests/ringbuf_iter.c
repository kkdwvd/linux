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
	__u64 fill;
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

/*
 * Produce `count` records of `size` bytes starting at `seq`. Every 8-byte word
 * of a record holds `fill`, or the sequence number if `fill` is 0.
 */
static int produce_fill(int prog_fd, __u64 seq, __u32 count, __u32 size, __u64 fill)
{
	struct produce_args args = { .seq = seq, .count = count, .size = size, .fill = fill };

	if (produce(prog_fd, &args))
		return -1;
	if (!ASSERT_EQ(args.produced, count, "produced") || !ASSERT_EQ(args.failed, 0, "failed"))
		return -1;
	return 0;
}

static int produce_n(int prog_fd, __u64 seq, __u32 count, __u32 size)
{
	return produce_fill(prog_fd, seq, count, size, 0);
}

/* Check that every 8-byte word of a record holds `word`. */
static bool record_ok(const void *data, __u32 len, __u64 word)
{
	const __u64 *w = data;
	__u32 i;

	if (len % 8)
		return false;
	for (i = 0; i < len / 8; i++) {
		if (w[i] != word)
			return false;
	}
	return true;
}

/* ASSERT_OK_PTR() passes for NULL when errno is 0, which is what an empty ring gives */
static const struct ring_rec *next_rec(struct ring *r, const char *name)
{
	const struct ring_rec *rec = ring__next(r);

	ASSERT_TRUE(rec != NULL, name);
	return rec;
}

/*
 * Count the bytes that were overwritten or discarded before a record: it is
 * the distance between its position and the end of the previous record.
 */
struct lost_tracker {
	unsigned long next_pos;
	__u64 lost_bytes;
};

static unsigned long track_lost(struct lost_tracker *t, const struct ring_rec *rec)
{
	unsigned long gap = rec->pos - t->next_pos;

	t->lost_bytes += gap;
	t->next_pos = rec->pos + (BPF_RINGBUF_HDR_SZ + rec->len + 7) / 8 * 8;
	return gap;
}

static int noop_cb(void *ctx, void *data, size_t len)
{
	return 0;
}

static int count_cb(void *ctx, void *data, size_t len)
{
	(*(int *)ctx)++;
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
	struct test_ringbuf_iter *skel;
	struct ring_buffer *rb, *rb_cb;
	const struct ring_rec *rec;
	struct ring *r, *r_cb, *r2;
	struct ring_rec first = {};
	unsigned long cons;
	int prog_fd, i;

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

	/* Nothing to consume in an empty ring, and that is not an error. */
	errno = 0;
	ASSERT_NULL(ring__next(r), "next_empty");
	ASSERT_EQ(errno, 0, "next_empty_errno");
	ASSERT_EQ(ring__release(r), 0, "release_empty");

	/* A ring with a callback can't be used with ring__next(). */
	rb_cb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), noop_cb, NULL, NULL);
	if (!ASSERT_OK_PTR(rb_cb, "ring_buffer__new_cb"))
		goto out_rb;
	r_cb = ring_buffer__ring(rb_cb, 0);
	errno = 0;
	ASSERT_NULL(ring__next(r_cb), "next_cb_ring");
	ASSERT_EQ(errno, EINVAL, "next_cb_ring_errno");
	ASSERT_EQ(ring__release(r_cb), -EINVAL, "release_cb_ring");
	ASSERT_FALSE(ring__invalidated(r_cb), "invalidated_cb_ring");
	ring_buffer__free(rb_cb);

	/* Records of different sizes, including empty ones. */
	if (produce_n(prog_fd, 0, 10, 8) || produce_n(prog_fd, 10, 10, 0) ||
	    produce_n(prog_fd, 20, 10, 120) || produce_n(prog_fd, 30, 10, 256))
		goto out_rb;

	cons = ring__consumer_pos(r);
	for (i = 0; i < 40; i++) {
		rec = next_rec(r, "next");
		if (!rec)
			goto out_rb;
		ASSERT_EQ(rec->len, i < 10 ? 8 : i < 20 ? 0 : i < 30 ? 120 : 256, "rec_len");
		ASSERT_TRUE(record_ok(rec->data, rec->len, i), "rec_data");
		ASSERT_EQ(rec->pos & 7, 0, "rec_pos_aligned");
		if (i)
			ASSERT_GT(rec->pos, cons, "rec_pos_after_cons");
		else
			first = *rec;
		/* Records are not consumed until they are released. */
		ASSERT_EQ(ring__consumer_pos(r), cons, "cons_unchanged");
	}
	ASSERT_NULL(ring__next(r), "next_drained");
	/* The copy of the first struct ring_rec still points to valid data. */
	ASSERT_EQ(first.pos, cons, "first_rec_pos");
	ASSERT_TRUE(record_ok(first.data, first.len, 0), "first_rec_still_valid");
	/* Records of a regular ring are never overwritten. */
	ASSERT_FALSE(ring__invalidated(r), "invalidated_plain");

	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");
	ASSERT_EQ(ring__avail_data_size(r), 0, "avail_zero");
	ASSERT_NULL(ring__next(r), "next_after_release");

	/* ring__release() returns 1 for records produced after the last ring__next(). */
	if (produce_n(prog_fd, 40, 3, 16))
		goto out_rb;
	ASSERT_TRUE(ring__next(r) != NULL, "next_more");
	ASSERT_TRUE(ring__next(r) != NULL, "next_more2");
	ASSERT_TRUE(ring__next(r) != NULL, "next_more3");
	ASSERT_NULL(ring__next(r), "next_more_end");
	/* A new ring starts at the consumer position, not where r is. */
	r2 = ring__new(bpf_map__fd(skel->maps.ringbuf), NULL);
	if (!ASSERT_OK_PTR(r2, "ring__new_second"))
		goto out_rb;
	rec = next_rec(r2, "second_consumer_next");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 40), "second_consumer_data");
	ring__free(r2);
	if (produce_n(prog_fd, 43, 1, 16))
		goto out_rb;
	ASSERT_EQ(ring__release(r), 1, "release_pending");
	rec = next_rec(r, "next_pending");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 43), "pending_data");
	ASSERT_EQ(ring__release(r), 0, "release_done");

	/* A ring without a callback can't be consumed through callbacks. */
	ASSERT_EQ(ring__consume(r), -EINVAL, "consume_no_cb");
	ASSERT_EQ(ring_buffer__consume(rb), -EINVAL, "manager_consume_no_cb");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_rewind_discard(void)
{
	struct produce_args args = { .seq = 0, .count = 20, .size = 32, .discard_mod = 4 };
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
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
		rec = next_rec(r, "next");
		if (!rec)
			goto out_rb;
		ASSERT_TRUE(record_ok(rec->data, rec->len, seq), "rec_data");
		if (i == 2 && !rewound) {
			/* Rewind and get the same three records again. */
			rewound = true;
			ring__rewind(r);
			ASSERT_EQ(ring__consumer_pos(r), 0, "cons_after_rewind");
			i = -1;
			seq = 0;
		}
	}
	ASSERT_NULL(ring__next(r), "next_end");
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");

	/* Discarded records at the end are skipped as well. */
	args.seq = 20;
	args.count = 1;
	args.discard_mod = 1;
	if (produce(prog_fd, &args))
		goto out_rb;
	ASSERT_NULL(ring__next(r), "next_only_discarded");
	ASSERT_EQ(ring__release(r), 0, "release_discarded");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_past_discarded");

	/* Release consumes only what ring__next() returned so far. */
	if (produce_n(prog_fd, 21, 4, 16))
		goto out_rb;
	ASSERT_TRUE(ring__next(r) != NULL, "next_partial1");
	rec = next_rec(r, "next_partial2");
	if (!rec)
		goto out_rb;
	ASSERT_EQ(ring__release(r), 1, "release_partial");
	ASSERT_EQ(ring__consumer_pos(r), rec->pos + 8 + 16, "cons_partial");
	ring__rewind(r);
	rec = next_rec(r, "next_rest1");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 23), "rest1_data");
	rec = next_rec(r, "next_rest2");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 24), "rest2_data");
	ASSERT_NULL(ring__next(r), "next_rest_end");
	ASSERT_EQ(ring__release(r), 0, "release_rest");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

/* Wait with ring_buffer__wait() and consume with ring__next(). */
static void subtest_manager(void)
{
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring_buffer *rb;
	struct ring *r, *r_ow;
	int prog_fd, ow_fd, cb_cnt = 0;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);
	ow_fd = bpf_program__fd(skel->progs.produce_overwrite);

	/* Two rings without callbacks, the second one is overwritable. */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), NULL, NULL, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;
	if (!ASSERT_OK(ring_buffer__add(rb, bpf_map__fd(skel->maps.ringbuf_ow), NULL, NULL),
		       "ring_buffer__add"))
		goto out_rb;
	r = ring_buffer__ring(rb, 0);
	r_ow = ring_buffer__ring(rb, 1);

	/* ring__free() doesn't free rings that are owned by a ring_buffer. */
	ring__free(r);
	ring__free(r_ow);

	/* ring_buffer__wait() returns the number of rings with data and consumes nothing. */
	ASSERT_EQ(ring_buffer__wait(rb, 0), 0, "wait_empty");
	if (produce_n(ow_fd, 100, 2, 16))
		goto out_rb;
	ASSERT_EQ(ring_buffer__wait(rb, 1000), 1, "wait_one");
	if (produce_n(prog_fd, 0, 2, 16))
		goto out_rb;
	ASSERT_EQ(ring_buffer__wait(rb, 1000), 2, "wait_both");
	ASSERT_EQ(ring__consumer_pos(r), 0, "wait_consumed_nothing");
	ASSERT_EQ(ring__consumer_pos(r_ow), 0, "wait_consumed_nothing_ow");

	/* A ring has data until its records are released. */
	ASSERT_TRUE(ring__next(r) != NULL, "drain0_1");
	ASSERT_TRUE(ring__next(r) != NULL, "drain0_2");
	ASSERT_NULL(ring__next(r), "drain0_end");
	ASSERT_EQ(ring_buffer__wait(rb, 0), 2, "wait_unreleased");
	ASSERT_EQ(ring__release(r), 0, "drain0_release");
	ASSERT_EQ(ring_buffer__wait(rb, 0), 1, "wait_released");

	rec = next_rec(r_ow, "drain1_1");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 100), "drain1_1_data");
	ASSERT_FALSE(ring__invalidated(r_ow), "drain1_1_invalidated");
	ASSERT_TRUE(ring__next(r_ow) != NULL, "drain1_2");
	ASSERT_NULL(ring__next(r_ow), "drain1_end");
	ASSERT_EQ(ring__release(r_ow), 0, "drain1_release");
	ASSERT_EQ(ring_buffer__wait(rb, 0), 0, "wait_drained");

	/* Callbacks don't work without a callback or on an overwritable ring. */
	ASSERT_EQ(ring_buffer__poll(rb, 0), -EINVAL, "poll_no_cb");
	ASSERT_EQ(ring_buffer__consume(rb), -EINVAL, "consume_no_cb");
	ASSERT_EQ(ring__consume(r_ow), -EOPNOTSUPP, "consume_overwrite");
	ring_buffer__free(rb);

	/* ring_buffer__wait() doesn't call the callback of a ring that has one. */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), count_cb, &cb_cnt, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new_mixed"))
		goto out;
	if (!ASSERT_OK(ring_buffer__add(rb, bpf_map__fd(skel->maps.ringbuf_ow), NULL, NULL),
		       "ring_buffer__add_mixed"))
		goto out_rb;
	r = ring_buffer__ring(rb, 0);
	r_ow = ring_buffer__ring(rb, 1);
	if (produce_n(prog_fd, 2, 3, 16) || produce_n(ow_fd, 102, 2, 16))
		goto out_rb;
	ASSERT_EQ(ring_buffer__wait(rb, 1000), 2, "wait_mixed");
	ASSERT_EQ(cb_cnt, 0, "wait_mixed_no_cb");
	ASSERT_EQ(ring__consume(r), 3, "mixed_consume");
	ASSERT_EQ(cb_cnt, 3, "mixed_consume_cb");
	ASSERT_TRUE(ring__next(r_ow) != NULL, "mixed_next1");
	ASSERT_TRUE(ring__next(r_ow) != NULL, "mixed_next2");
	ASSERT_NULL(ring__next(r_ow), "mixed_next_end");
	ASSERT_EQ(ring__release(r_ow), 0, "mixed_release");
	ASSERT_EQ(ring_buffer__wait(rb, 0), 0, "wait_mixed_drained");

out_rb:
	ring_buffer__free(rb);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_standalone(void)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring *r, *bad;
	int prog_fd, epfd, arr_fd;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_normal);

	/* ring__new() only takes ring buffer maps. */
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

	/* Wait with edge-triggered epoll on the map fd. */
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
		while ((rec = ring__next(r)))
			ASSERT_TRUE(record_ok(rec->data, rec->len, rec->pos / 24), "rec_data");
	} while (ring__release(r) > 0);
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 0), 0, "epoll_drained");

	/* The consumer position was updated, so the next record wakes us up. */
	if (produce_n(prog_fd, 5, 1, 16))
		goto out_epoll;
	ASSERT_EQ(epoll_wait(epfd, &ev, 1, 1000), 1, "epoll_ready_again");
	rec = next_rec(r, "next_again");
	if (rec)
		ASSERT_TRUE(record_ok(rec->data, rec->len, 5), "rec_data_again");
	ASSERT_EQ(ring__release(r), 0, "release_again");

out_epoll:
	close(epfd);
out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

static void subtest_overwrite_basic(void)
{
	struct test_ringbuf_iter *skel;
	struct lost_tracker lost = {};
	const struct ring_rec *rec;
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
	lost.next_pos = ring__consumer_pos(r);

	/* Fill the ring 3 times over, a record takes size + 8 bytes. */
	if (produce_n(prog_fd, 0, 3 * per_ring, size))
		goto out_ring;
	ASSERT_LE(ring__avail_data_size(r), page_size, "avail_bounded");
	ASSERT_GT(ring__avail_data_size(r), 0, "avail_nonzero");

	/* Only the most recent records are left, and they come without gaps. */
	rec = next_rec(r, "next_first");
	if (!rec)
		goto out_ring;
	first = ((__u64 *)rec->data)[0];
	ASSERT_GT(first, 2 * per_ring - 1, "first_seq_recent");
	ASSERT_EQ(rec->pos, first * rec_sz, "first_pos");
	ASSERT_EQ(track_lost(&lost, rec), first * rec_sz, "first_lost_bytes");
	ASSERT_TRUE(record_ok(rec->data, rec->len, first), "first_data");
	ASSERT_FALSE(ring__invalidated(r), "first_invalidated");
	seq = first + 1;
	n = 1;
	while ((rec = ring__next(r))) {
		ASSERT_EQ(track_lost(&lost, rec), 0, "lost_bytes");
		ASSERT_TRUE(record_ok(rec->data, rec->len, seq), "data");
		ASSERT_FALSE(ring__invalidated(r), "invalidated");
		seq++;
		n++;
	}
	ASSERT_EQ(seq, 3 * per_ring, "all_recent_records_seen");
	ASSERT_LE(n, per_ring, "no_more_than_a_ring");
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "cons_caught_up");
	ASSERT_EQ(ring__avail_data_size(r), 0, "avail_zero");

	/* Nothing is lost when the consumer keeps up. */
	if (produce_n(prog_fd, seq, 2, size))
		goto out_ring;
	rec = next_rec(r, "next_streaming");
	if (!rec)
		goto out_ring;
	ASSERT_EQ(track_lost(&lost, rec), 0, "no_lost_streaming");
	ASSERT_TRUE(record_ok(rec->data, rec->len, seq), "data_streaming");
	rec = next_rec(r, "next_streaming2");
	if (!rec)
		goto out_ring;
	ASSERT_EQ(track_lost(&lost, rec), 0, "no_lost_streaming2");
	ASSERT_NULL(ring__next(r), "next_streaming_end");
	ASSERT_FALSE(ring__invalidated(r), "invalidated_streaming");
	ASSERT_EQ(ring__release(r), 0, "release_streaming");
	seq += 2;

	/* The producer overwrites a record that was returned and not released. */
	if (produce_n(prog_fd, seq, 1, size))
		goto out_ring;
	ASSERT_TRUE(ring__next(r) != NULL, "next_before_lap");
	if (produce_n(prog_fd, seq + 1, 2 * per_ring, size))
		goto out_ring;
	ASSERT_TRUE(ring__invalidated(r), "invalidated_lapped");
	ASSERT_EQ(ring__release(r), 1, "release_lapped");
	rec = next_rec(r, "next_after_lap");
	if (!rec)
		goto out_ring;
	ASSERT_GT(track_lost(&lost, rec), 0, "lost_after_lap");
	ASSERT_GT(((__u64 *)rec->data)[0], seq, "seq_after_lap");
	ASSERT_FALSE(ring__invalidated(r), "invalidated_after_lap");
	ring__rewind(r);

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

/* Dump the ring without consuming it. */
static void subtest_overwrite_dump(void)
{
	unsigned long first_dump[64], second_dump[64];
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring *r;
	int prog_fd, n1 = 0, n2 = 0, i;
	/* The ring holds fewer than 64 of these records, whatever the page size. */
	__u32 size = page_size / 64 - 8, per_ring = page_size / (size + 8);
	__u64 seq = 0;
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

	/* Copy all records, then check once that none of them was overwritten. */
	while (n1 < 64 && (rec = ring__next(r))) {
		memcpy(copy + n1 * size, rec->data, rec->len);
		first_dump[n1++] = rec->pos;
	}
	ASSERT_GT(n1, 0, "dump1_records");
	ASSERT_LE(n1, per_ring, "dump1_bounded");
	ASSERT_FALSE(ring__invalidated(r), "dump1_invalidated");
	for (i = 0; i < n1; i++)
		ASSERT_TRUE(record_ok(copy + i * size, size, seq - n1 + i), "dump1_data");
	/* Rewind instead of releasing to keep the records in the ring. */
	ring__rewind(r);
	ASSERT_EQ(ring__consumer_pos(r), 0, "cons_untouched");

	/* The second dump gets the same records. */
	while (n2 < 64 && (rec = ring__next(r)))
		second_dump[n2++] = rec->pos;
	ASSERT_EQ(n2, n1, "dump2_same_count");
	for (i = 0; i < n1 && i < n2; i++)
		ASSERT_EQ(second_dump[i], first_dump[i], "dump2_same_pos");
	ASSERT_FALSE(ring__invalidated(r), "dump2_invalidated");

	/* Release this time, which consumes the records. */
	ASSERT_EQ(ring__release(r), 0, "release");
	ASSERT_NULL(ring__next(r), "next_after_clear");
	ASSERT_EQ(ring__avail_data_size(r), 0, "avail_after_clear");

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
out_copy:
	free(copy);
}

/*
 * ring__invalidated() covers all records returned since the last release or
 * rewind. Records take 64 bytes and the ring is full from the start, so every
 * new record overwrites the oldest one.
 */
static void subtest_overwrite_batch(void)
{
	__u32 size = 56, rec_sz = size + 8, per_ring = page_size / rec_sz - 1;
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring *r;
	__u64 seq, next_seq;
	int prog_fd, i;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	if (produce_n(prog_fd, 0, per_ring, size))
		goto out_ring;
	seq = per_ring;

	/* No records were returned yet. */
	ASSERT_FALSE(ring__invalidated(r), "invalidated_nothing");

	for (i = 0; i < 4; i++) {
		rec = next_rec(r, "batch1_next");
		if (!rec)
			goto out_ring;
		ASSERT_EQ(rec->pos, i * rec_sz, "batch1_pos");
	}
	ASSERT_FALSE(ring__invalidated(r), "batch1_invalidated");

	/* Records 0 and 1 get overwritten. Getting more records doesn't change the result. */
	if (produce_n(prog_fd, seq, 2, size))
		goto out_ring;
	seq += 2;
	ASSERT_TRUE(ring__invalidated(r), "batch1_overwritten");
	for (i = 4; i < 8; i++) {
		rec = next_rec(r, "batch1_more_next");
		if (!rec)
			goto out_ring;
		ASSERT_EQ(rec->pos, i * rec_sz, "batch1_more_pos");
		ASSERT_TRUE(record_ok(rec->data, rec->len, i), "batch1_more_data");
	}
	ASSERT_TRUE(ring__invalidated(r), "batch1_still_overwritten");

	/* Only records returned after a release count. */
	ASSERT_EQ(ring__release(r), 1, "release");
	ASSERT_FALSE(ring__invalidated(r), "invalidated_after_release");
	for (i = 8; i < 10; i++) {
		rec = next_rec(r, "batch2_next");
		if (!rec)
			goto out_ring;
		ASSERT_EQ(rec->pos, i * rec_sz, "batch2_pos");
	}
	ASSERT_FALSE(ring__invalidated(r), "batch2_invalidated");

	/* Records 2 to 10 get overwritten, which includes the two returned last. */
	if (produce_n(prog_fd, seq, 9, size))
		goto out_ring;
	seq += 9;
	ASSERT_TRUE(ring__invalidated(r), "batch2_overwritten");

	/* After a rewind ring__next() continues from the oldest record that is left. */
	ring__rewind(r);
	ASSERT_FALSE(ring__invalidated(r), "invalidated_after_rewind");
	next_seq = 11;
	while ((rec = ring__next(r))) {
		ASSERT_EQ(rec->pos, next_seq * rec_sz, "batch3_pos");
		ASSERT_TRUE(record_ok(rec->data, rec->len, next_seq), "batch3_data");
		next_seq++;
	}
	ASSERT_EQ(next_seq, seq, "batch3_all_records_seen");
	ASSERT_FALSE(ring__invalidated(r), "batch3_invalidated");
	ASSERT_EQ(ring__release(r), 0, "release_end");

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
}

/*
 * After the producer lapped the consumer, ring__next() must not take record
 * data for a record header. Here that would lead it to a bogus record that is
 * recent enough to pass ring__invalidated().
 */
static void subtest_overwrite_forged(void)
{
	__u32 size = 56, rec_sz = size + 8, per_ring = page_size / rec_sz - 1;
	/* A discarded record of 16 bytes: 24 bytes to skip with its header. */
	struct { __u32 len; __u32 pg_off; } hdr = { .len = BPF_RINGBUF_DISCARD_BIT | 16 };
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct ring *r;
	__u64 forged, seq;
	int prog_fd;

	memcpy(&forged, &hdr, sizeof(forged));

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;

	/* Fill the ring with 64-byte records and consume the first one. */
	if (produce_n(prog_fd, 0, per_ring, size))
		goto out_ring;
	rec = next_rec(r, "next_first");
	if (!rec)
		goto out_ring;
	ASSERT_EQ(rec->pos, 0, "first_pos");
	ASSERT_FALSE(ring__invalidated(r), "first_invalidated");
	ASSERT_EQ(ring__release(r), 1, "first_release");

	/*
	 * Overwrite the first two records. The first new record takes 96 bytes,
	 * so the second one starts at offset 32 in the ring and its data is now
	 * at offset 64, where ring__next() will look for a header. That data
	 * reads as headers of discarded records, and following them ends at
	 * 112, in the rest of the old second record. A record at 112 would be
	 * less than a ring size behind the producer.
	 */
	if (produce_fill(prog_fd, per_ring, 1, 88, forged) ||
	    produce_fill(prog_fd, per_ring + 1, 1, size, forged))
		goto out_ring;

	/* The third record is the oldest one left, ring__next() continues from it. */
	for (seq = 2; seq < per_ring; seq++) {
		rec = next_rec(r, "next_lapped");
		if (!rec)
			goto out_ring;
		ASSERT_EQ(rec->pos, seq * rec_sz, "lapped_pos");
		ASSERT_EQ(rec->len, size, "lapped_len");
		ASSERT_TRUE(record_ok(rec->data, rec->len, seq), "lapped_data");
		ASSERT_FALSE(ring__invalidated(r), "lapped_invalidated");
	}
	/* The two new records come last. */
	rec = next_rec(r, "next_forged1");
	if (!rec)
		goto out_ring;
	ASSERT_EQ(rec->len, 88, "forged1_len");
	ASSERT_TRUE(record_ok(rec->data, rec->len, forged), "forged1_data");
	rec = next_rec(r, "next_forged2");
	if (!rec)
		goto out_ring;
	ASSERT_EQ(rec->len, size, "forged2_len");
	ASSERT_TRUE(record_ok(rec->data, rec->len, forged), "forged2_data");
	ASSERT_FALSE(ring__invalidated(r), "forged_invalidated");
	ASSERT_NULL(ring__next(r), "next_end");
	ASSERT_EQ(ring__release(r), 0, "release");

out_ring:
	ring__free(r);
out:
	test_ringbuf_iter__destroy(skel);
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

#define RACE_BATCH	8
#define RACE_MAX_LEN	256

struct race_state {
	struct lost_tracker lost;
	__u64 prev_seq;
	__u64 valid;
	__u64 overwritten;
	__u64 gaps;
};

/* These run for every record, so they don't use ASSERT_*(), which logs every pass. */
static bool race_len_ok(const struct ring_rec *rec)
{
	if (rec->len >= 8 && rec->len <= RACE_MAX_LEN && rec->len % 8 == 0)
		return true;
	PRINT_FAIL("record at %lu has length %u\n", rec->pos, rec->len);
	return false;
}

/* A record that was not overwritten: its data is valid and it comes after the previous one. */
static bool race_accept(struct race_state *s, const struct ring_rec *rec, const void *copy)
{
	__u64 seq = ((const __u64 *)copy)[0];
	unsigned long gap;

	if (!record_ok(copy, rec->len, seq)) {
		PRINT_FAIL("record at %lu is torn\n", rec->pos);
		return false;
	}
	if (s->valid && seq <= s->prev_seq) {
		PRINT_FAIL("sequence number %llu follows %llu\n", seq, s->prev_seq);
		return false;
	}
	/* Records are missing in between exactly when there is a gap between positions. */
	gap = track_lost(&s->lost, rec);
	if (s->valid && (gap != 0) != (seq != s->prev_seq + 1)) {
		PRINT_FAIL("%lu bytes lost between sequence numbers %llu and %llu\n",
			   gap, s->prev_seq, seq);
		return false;
	}
	s->gaps += gap != 0;
	s->prev_seq = seq;
	s->valid++;
	return true;
}

/*
 * Consume an overwritable ring while a thread keeps producing into it. The
 * consumer alternates between checking each record and checking a batch of
 * records at once, and sometimes waits before the check so that the producer
 * laps it. Records that pass the check must have valid data and increasing
 * sequence numbers, and the length of a record must be valid even before the
 * check.
 */
static void subtest_overwrite_race(void)
{
	char copy[RACE_BATCH][RACE_MAX_LEN];
	struct ring_rec recs[RACE_BATCH];
	struct test_ringbuf_iter *skel;
	const struct ring_rec *rec;
	struct race_state s = {};
	struct race_ctx ctx = {};
	struct ring *r;
	pthread_t thread;
	__u64 end, pause, iter;
	bool invalidated;
	int i, n;

	skel = open_load(page_size, page_size);
	if (!skel)
		return;
	ctx.prog_fd = bpf_program__fd(skel->progs.produce_overwrite);
	r = ring__new(bpf_map__fd(skel->maps.ringbuf_ow), NULL);
	if (!ASSERT_OK_PTR(r, "ring__new"))
		goto out;
	s.lost.next_pos = ring__consumer_pos(r);

	if (!ASSERT_OK(pthread_create(&thread, NULL, race_producer, &ctx), "pthread_create"))
		goto out_ring;

	end = now_ns() + 1500000000ULL;
	for (iter = 0; now_ns() < end; iter++) {
		if (iter % 2) {
			/* Copy a batch of records and check once. */
			for (n = 0; n < RACE_BATCH && (rec = ring__next(r)); n++) {
				if (!race_len_ok(rec))
					goto out_thread;
				memcpy(copy[n], rec->data, rec->len);
				recs[n] = *rec;
			}
			if (iter % 64 == 63) {
				pause = now_ns() + 50000;
				while (now_ns() < pause)
					;
			}
			invalidated = ring__invalidated(r);
			for (i = 0; i < n && !invalidated; i++) {
				if (!race_accept(&s, &recs[i], copy[i]))
					goto out_thread;
			}
			if (invalidated)
				s.overwritten += n;
		} else {
			/* Check every record, until one fails. */
			for (n = 0; n < 64 && (rec = ring__next(r)); n++) {
				if (!race_len_ok(rec))
					goto out_thread;
				memcpy(copy[0], rec->data, rec->len);
				if (iter % 64 == 62 && n == 0) {
					pause = now_ns() + 50000;
					while (now_ns() < pause)
						;
				}
				if (ring__invalidated(r)) {
					s.overwritten++;
					break;
				}
				if (!race_accept(&s, rec, copy[0]))
					goto out_thread;
			}
		}
		ring__release(r);
	}

out_thread:
	ctx.stop = true;
	pthread_join(thread, NULL);

	/* The producer is done, so nothing can be overwritten anymore. */
	ring__release(r);
	while ((rec = ring__next(r))) {
		if (!race_len_ok(rec))
			break;
		memcpy(copy[0], rec->data, rec->len);
		if (ring__invalidated(r)) {
			PRINT_FAIL("record at %lu overwritten without a producer\n", rec->pos);
			break;
		}
		if (!race_accept(&s, rec, copy[0]))
			break;
	}
	ASSERT_EQ(ring__release(r), 0, "drain_release");
	ASSERT_EQ(ring__consumer_pos(r), ring__producer_pos(r), "drain_caught_up");

	ASSERT_GT(ctx.runs, 0, "producer_ran");
	ASSERT_GT(s.valid, 0, "valid_records");
	if (env.verbosity > VERBOSE_NONE)
		printf("producer runs %llu, valid %llu, overwritten %llu, gaps %llu, lost bytes %llu\n",
		       ctx.runs, s.valid, s.overwritten, s.gaps, s.lost.lost_bytes);

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
	if (test__start_subtest("overwrite_batch"))
		subtest_overwrite_batch();
	if (test__start_subtest("overwrite_forged"))
		subtest_overwrite_forged();
	if (test__start_subtest("overwrite_race"))
		subtest_overwrite_race();
}
