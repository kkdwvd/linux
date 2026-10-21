// SPDX-License-Identifier: GPL-2.0
/*
 * __arena variables of COMDAT groups. Each group has an .addr_space.1 of its
 * own, which with that of the other __arena variables is the arena data.
 */
#define SEC(name) __attribute__((section(name), used))
#define __arena __attribute__((address_space(1)))
#define __uint(name, val) int (*name)[val]

struct arena_map {
	__uint(type, 33);		/* BPF_MAP_TYPE_ARENA */
	__uint(map_flags, 1024);	/* BPF_F_MMAPABLE */
	__uint(max_entries, 1);
} arena SEC(".maps");

int __arena plain_ar = 5;
static int __arena static_ar = 7;
inline int __arena hits;
inline long __arena total = 10;

/* Dereferencing __arena variables needs addr_space_cast */
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
extern "C" SEC("syscall") int comdat_arena(void *ctx)
{
	hits++;
	total += plain_ar + static_ar;
	static_ar++;
	return hits * 1000 + total;
}
#endif

char _license[] SEC("license") = "GPL";
