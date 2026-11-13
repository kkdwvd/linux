// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(map_flags, BPF_F_RB_OVERWRITE);
} ringbuf SEC(".maps");

/* Half of the ring buffer or more, so that each record overwrites the previous one. */
const volatile unsigned long rec_size;

long reserve_failed;

SEC("syscall")
int produce(void *ctx)
{
	void *rec;
	int i;

	bpf_for(i, 0, 64) {
		rec = bpf_ringbuf_reserve(&ringbuf, rec_size, 0);
		if (!rec) {
			reserve_failed++;
			continue;
		}
		bpf_ringbuf_submit(rec, BPF_RB_NO_WAKEUP);
	}
	return 0;
}
