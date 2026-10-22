/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Read-only dynptr operations in BPF, without a kfunc call.
 *
 * A dynptr lives in stack slots a privileged program may load, as a struct
 * bpf_dynptr_kern: the data pointer, the size word, which carries the type
 * and the read-only bit above the 24-bit size, and the offset of the view
 * into the data. The type cast instruction then turns the data pointer into
 * one the program reads through probe loads, at any offset for a void pointer
 * or along the members of a kernel struct. That is all a read-only operation
 * needs: the operations below follow the kfuncs and helpers they are named
 * after, for every dynptr type, and the code they compile to holds no call.
 * Operations that write, to the data or to the dynptr itself, remain kfunc and
 * helper calls.
 */
#ifndef __BPF_DYNPTR_H__
#define __BPF_DYNPTR_H__

#include "bpf_experimental.h"
#include "bpf_kfuncs.h"
#include "errno.h"

/* The layout of the size word of struct bpf_dynptr_kern */
#define BPF_DYNPTR_SIZE_MASK	0xffffffU
#define BPF_DYNPTR_TYPE_SHIFT	28
#define BPF_DYNPTR_RDONLY_BIT	(1U << 31)

static __always_inline struct bpf_dynptr_kern *__bpf_dynptr_kern(const struct bpf_dynptr *p)
{
	return (struct bpf_dynptr_kern *)p;
}

static __always_inline enum bpf_dynptr_type bpf_dynptr_type_inline(const struct bpf_dynptr *p)
{
	return (__bpf_dynptr_kern(p)->size & ~BPF_DYNPTR_RDONLY_BIT) >> BPF_DYNPTR_TYPE_SHIFT;
}

static __always_inline bool bpf_dynptr_is_null_inline(const struct bpf_dynptr *p)
{
	return !__bpf_dynptr_kern(p)->data;
}

static __always_inline bool bpf_dynptr_is_rdonly_inline(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *k = __bpf_dynptr_kern(p);

	return k->data && (k->size & BPF_DYNPTR_RDONLY_BIT);
}

static __always_inline __u64 bpf_dynptr_size_inline(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *k = __bpf_dynptr_kern(p);

	if (!k->data)
		return -EINVAL;
	if (bpf_dynptr_type_inline(p) == BPF_DYNPTR_TYPE_FILE) {
		/* A file dynptr keeps a 64-bit size behind its data pointer */
		struct bpf_dynptr_file_impl *df;

		df = bpf_type_cast(k->data, struct bpf_dynptr_file_impl);
		return df->size;
	}
	return k->size & BPF_DYNPTR_SIZE_MASK;
}

/*
 * bpf_dynptr_slice(p, offset, NULL, len): a pointer to the len bytes of the
 * dynptr at offset, or NULL when the range is outside the dynptr or the bytes
 * are not in the linear part of a packet. The pointer is read through probe
 * loads.
 */
static __always_inline const void *bpf_dynptr_slice_inline(const struct bpf_dynptr *p,
							   __u64 offset, __u64 len)
{
	struct bpf_dynptr_kern *k = __bpf_dynptr_kern(p);
	__u32 size = k->size & BPF_DYNPTR_SIZE_MASK;
	void *data = k->data;
	__u64 total;

	if (!data || len > size || offset > size - len)
		return NULL;
	total = k->offset + offset;

	switch (bpf_dynptr_type_inline(p)) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		return bpf_void_cast(data) + total;
	case BPF_DYNPTR_TYPE_SKB: {
		/* skb_pointer_if_linear() */
		struct sk_buff *skb = bpf_type_cast(data, struct sk_buff);

		if (total + len > skb->len - skb->data_len)
			return NULL;
		return bpf_void_cast(skb->data) + total;
	}
	case BPF_DYNPTR_TYPE_XDP: {
		/*
		 * bpf_xdp_pointer() in the linear area. The kfunc also returns
		 * a slice within one fragment, whose page the kernel can
		 * address and the program cannot, so that is NULL here.
		 */
		struct xdp_buff *xdp = bpf_type_cast(data, struct xdp_buff);

		if (total > 0xffff || len > 0xffff || total + len > xdp->data_end - xdp->data)
			return NULL;
		return bpf_void_cast(xdp->data) + total;
	}
	case BPF_DYNPTR_TYPE_SKB_META: {
		/* bpf_skb_meta_pointer(): the metadata ends at the mac header */
		struct sk_buff *skb = bpf_type_cast(data, struct sk_buff);
		struct skb_shared_info *shinfo = bpf_type_cast(skb->head + skb->end,
							       struct skb_shared_info);

		return bpf_void_cast(skb->head) + skb->mac_header - shinfo->meta_len + total;
	}
	default:
		/* a file dynptr can only be read into a buffer */
		return NULL;
	}
}

/*
 * bpf_dynptr_slice_inline() for a dynptr the verifier knows is over an skb:
 * its data pointer is a trusted sk_buff pointer, so the skb is read through
 * plain loads and only the packet bytes through probe loads.
 */
static __always_inline const void *bpf_dynptr_skb_slice_inline(const struct bpf_dynptr *p,
							       __u64 offset, __u64 len)
{
	struct bpf_dynptr_kern *k = __bpf_dynptr_kern(p);
	__u32 size = k->size & BPF_DYNPTR_SIZE_MASK;
	struct sk_buff *skb = k->data;
	__u64 total;

	if (!skb || len > size || offset > size - len)
		return NULL;
	total = k->offset + offset;
	if (total + len > skb->len - skb->data_len)
		return NULL;
	return bpf_void_cast(skb->data) + total;
}

/*
 * bpf_dynptr_read(dst, len, p, offset, 0), copying through probe loads when
 * the bytes are contiguous and through the helper otherwise. len must be a
 * constant small enough for the compiler to open-code the copy.
 */
static __always_inline int bpf_dynptr_read_inline(void *dst, __u32 len, const struct bpf_dynptr *p,
						  __u64 offset)
{
	const void *src = bpf_dynptr_slice_inline(p, offset, len);

	if (!src)
		return bpf_dynptr_read(dst, len, p, offset, 0);
	__builtin_memcpy(dst, src, len);
	return 0;
}

#endif
