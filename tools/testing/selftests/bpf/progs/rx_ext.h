/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RX_EXT_H
#define __RX_EXT_H

/* What the extension of progs/rx_ext.c does with a packet, see prog_tests/rx_ext.c */
enum rx_ext_mode {
	MODE_GRO,	/* offers it to GRO, and puts it on the batch: the kernel's path */
	MODE_NATIVE,	/* leaves it to the kernel */
	MODE_PAST_GRO,	/* puts it on the batch at once */
	MODE_DIVES,	/* as MODE_GRO, and the kernel unwinds the continuation of a held one */
	MODE_ENTRY_DIVES, /* the kernel unwinds the entry with the frame in hand */
};

/* A packet as the stack got it */
struct rx_seen {
	__u32 len;
	__u32 data_len;
	__u32 hash;
	__u32 gso_type;
	__u16 gso_size;
	__u16 gso_segs;
	__u8 l4_hash;
	__u8 ip_summed;
	__u8 csum_level;
	__u8 nr_frags;
	__u8 frag_list;
	__u8 pad[3];
	__u32 list;	/* the lists that went up before the one that it is in */
};

#define RX_SEEN 4096

#endif
