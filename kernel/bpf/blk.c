// SPDX-License-Identifier: GPL-2.0
/*
 * Block device reads from BPF that complete into a coroutine.
 *
 * bpf_blk_open() opens a block device by major and minor number and keeps
 * it in a table keyed by the device number; bpf_blk_read_coro() submits a
 * read of whole sectors from such a device into arena memory and consumes
 * the coroutine frame it is given. When the read completes, the status is
 * written to the request in the arena and the frame is resumed from BH
 * context on the completing CPU, so a program can express a chain of
 * dependent reads, as XRP's resubmission does, as a coroutine suspending
 * at each read. bpf_blk_close() closes the device again.
 */
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bpf.h>
#include <linux/bpf_coro.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/xarray.h>

struct bpf_blk_dev {
	struct file *file;
	struct block_device *bdev;
	struct rcu_head rcu;
};

static DEFINE_XARRAY(bpf_blk_devs);
static DEFINE_MUTEX(bpf_blk_mutex);
/* Reads submitted and completed, and frames resumed, for bpf_blk_close(). */
static atomic64_t bpf_blk_submitted, bpf_blk_completed, bpf_blk_resumed;

struct bpf_blk_req {
	struct bpf_coro_cont cont;
	struct bpf_blk_io *io;		/* in the arena */
	u32 nr_pages;
	struct page *pages[];
};

static void bpf_blk_fini(struct bpf_coro_cont *cont)
{
	atomic64_inc(&bpf_blk_resumed);
	kfree(container_of(cont, struct bpf_blk_req, cont));
}

static void bpf_blk_end_io(struct bio *bio)
{
	struct bpf_blk_req *req = bio->bi_private;
	u32 i;

	WRITE_ONCE(req->io->status, blk_status_to_errno(bio->bi_status));
	pr_debug("bpf_blk: end_io status %d hardirq %d cpu %d frame %px\n",
			    blk_status_to_errno(bio->bi_status), !!in_hardirq(), smp_processor_id(),
			    req->cont.frame);
	for (i = 0; i < req->nr_pages; i++)
		put_page(req->pages[i]);
	bio_put(bio);
	atomic64_inc(&bpf_blk_completed);
	bpf_coro_cont_resume(&req->cont);
}

/* The arena's kernel mapping: pointers the JIT rebased live in here. */
static bool bpf_arena_range_ok(struct bpf_prog_aux *aux, const void *p, u32 len)
{
	u64 start = bpf_arena_get_kern_vm_start(aux->arena), addr = (u64)(long)p;

	return aux->arena && addr >= start && addr + len > addr && addr + len <= start + SZ_4G;
}

__bpf_kfunc_start_defs();

/**
 * bpf_blk_open - open a block device for bpf_blk_read_coro()
 * @major: device major number
 * @minor: device minor number
 *
 * Opens the device read-only and keeps it until bpf_blk_close(). Returns 0,
 * -EEXIST when it is already open, or the error of opening it.
 */
__bpf_kfunc int bpf_blk_open(u32 major, u32 minor)
{
	struct bpf_blk_dev *d;
	struct file *file;
	int err;

	d = kzalloc_obj(*d, GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	file = bdev_file_open_by_dev(MKDEV(major, minor), BLK_OPEN_READ, d, NULL);
	if (IS_ERR(file)) {
		kfree(d);
		return PTR_ERR(file);
	}
	d->file = file;
	d->bdev = file_bdev(file);
	mutex_lock(&bpf_blk_mutex);
	err = xa_insert(&bpf_blk_devs, MKDEV(major, minor), d, GFP_KERNEL);
	mutex_unlock(&bpf_blk_mutex);
	if (err) {
		fput(file);
		kfree(d);
		return err == -EBUSY ? -EEXIST : err;
	}
	return 0;
}

static void bpf_blk_dev_free(struct rcu_head *rcu)
{
	struct bpf_blk_dev *d = container_of(rcu, struct bpf_blk_dev, rcu);

	fput(d->file);
	kfree(d);
}

/**
 * bpf_blk_close - close a device opened with bpf_blk_open()
 * @major: device major number
 * @minor: device minor number
 *
 * Reads in flight complete; reads submitted after this fail with -ENODEV.
 */
__bpf_kfunc int bpf_blk_close(u32 major, u32 minor)
{
	struct bpf_blk_dev *d;

	mutex_lock(&bpf_blk_mutex);
	d = xa_erase(&bpf_blk_devs, MKDEV(major, minor));
	mutex_unlock(&bpf_blk_mutex);
	if (!d)
		return -ENODEV;
	call_rcu(&d->rcu, bpf_blk_dev_free);
	pr_info("bpf_blk: close %u:%u: %lld reads submitted, %lld completed, %lld frames resumed\n",
		major, minor, (long long)atomic64_read(&bpf_blk_submitted),
		(long long)atomic64_read(&bpf_blk_completed),
		(long long)atomic64_read(&bpf_blk_resumed));
	return 0;
}

/**
 * bpf_blk_read_coro - read sectors into the arena and resume a coroutine
 * @io__arena: the request: device, sector and length in, status out
 * @buf__arena: destination, @io->len bytes of mapped arena memory
 * @frame__coro_suspend: the coroutine frame to resume when the read is done
 * @aux: the calling program (implicit)
 *
 * Consumes the frame. The read completes into @io->status (0 or -errno) and
 * then the frame's resume function runs from BH context. Returns 0 when the
 * read was submitted; on an error the frame is resumed at once with the
 * error in @io->status, so the coroutine always continues.
 */
__bpf_kfunc int bpf_blk_read_coro(struct bpf_blk_io *io__arena, void *buf__arena,
				  void *frame__coro_suspend, struct bpf_prog_aux *aux)
{
	struct bpf_blk_io *io = io__arena;
	void *buf = buf__arena, *p;
	struct bpf_blk_req *req = NULL;
	struct bpf_blk_dev *d;
	struct bio *bio = NULL;
	struct bpf_coro_cont fallback;
	u32 len, nr_pages, i = 0;
	u64 sector;
	int err;

	if (!bpf_arena_range_ok(aux, io, sizeof(*io)) || !vmalloc_to_page(io)) {
		/* No place to report the status to; the frame is still ours. */
		bpf_coro_cont_init(&fallback, frame__coro_suspend, aux, NULL);
		bpf_coro_cont_resume_now(&fallback);
		return -EFAULT;
	}
	sector = READ_ONCE(io->sector);
	len = READ_ONCE(io->len);
	if (!len || len > BPF_BLK_IO_MAX || len % SECTOR_SIZE || (u64)(long)buf % SECTOR_SIZE ||
	    !bpf_arena_range_ok(aux, buf, len)) {
		err = -EINVAL;
		goto fail;
	}
	nr_pages = DIV_ROUND_UP(offset_in_page(buf) + len, PAGE_SIZE);

	d = xa_load(&bpf_blk_devs, READ_ONCE(io->dev));
	if (!d) {
		err = -ENODEV;
		goto fail;
	}
	if (sector + len / SECTOR_SIZE > bdev_nr_sectors(d->bdev)) {
		err = -ERANGE;
		goto fail;
	}
	req = kmalloc(struct_size(req, pages, nr_pages), GFP_ATOMIC);
	if (!req) {
		err = -ENOMEM;
		goto fail;
	}
	req->io = io;
	req->nr_pages = 0;
	bio = bio_alloc(d->bdev, nr_pages, REQ_OP_READ, GFP_ATOMIC);
	if (!bio) {
		err = -ENOMEM;
		goto fail;
	}
	bio->bi_iter.bi_sector = sector;
	for (p = buf; p < buf + len; p += PAGE_SIZE - offset_in_page(p), i++) {
		u32 chunk = min_t(u32, PAGE_SIZE - offset_in_page(p), buf + len - p);
		struct page *page = vmalloc_to_page(p);

		if (!page) {
			err = -EFAULT;
			goto fail;
		}
		get_page(page);
		req->pages[req->nr_pages++] = page;
		if (bio_add_page(bio, page, chunk, offset_in_page(p)) != chunk) {
			err = -EIO;
			goto fail;
		}
	}
	bio->bi_private = req;
	bio->bi_end_io = bpf_blk_end_io;
	/* Never wait for a tag: this runs in BH context. */
	bio->bi_opf |= REQ_NOWAIT;
	bpf_coro_cont_init(&req->cont, frame__coro_suspend, aux, bpf_blk_fini);
	atomic64_inc(&bpf_blk_submitted);
	submit_bio(bio);
	return 0;

fail:
	WRITE_ONCE(io->status, err);
	if (bio)
		bio_put(bio);
	if (req) {
		for (i = 0; i < req->nr_pages; i++)
			put_page(req->pages[i]);
		kfree(req);
	}
	bpf_coro_cont_init(&fallback, frame__coro_suspend, aux, NULL);
	bpf_coro_cont_resume_now(&fallback);
	return err;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_blk_kfunc_ids)
BTF_ID_FLAGS(func, bpf_blk_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_blk_close, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_blk_read_coro, KF_IMPLICIT_ARGS)
BTF_KFUNCS_END(bpf_blk_kfunc_ids)

static const struct btf_kfunc_id_set bpf_blk_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_blk_kfunc_ids,
};

static int __init bpf_blk_kfunc_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_blk_kfunc_set);
	err = err ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_blk_kfunc_set);
	return err;
}
late_initcall(bpf_blk_kfunc_init);
