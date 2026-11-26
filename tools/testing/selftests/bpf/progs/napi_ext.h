/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NAPI_EXT_H
#define __NAPI_EXT_H

/* What the extension of progs/napi_ext.c does with a poll, see prog_tests/napi_ext.c */
enum napi_ext_mode {
	MODE_DEFER,	/* defers it to 'where', and its continuation polls */
	MODE_NATIVE,	/* leaves it to the kernel */
	MODE_DIVES,	/* defers it, and the kernel unwinds the continuation before the poll */
	MODE_ENTRY_DIVES, /* the kernel unwinds the entry with the frame in hand */
};

#endif
