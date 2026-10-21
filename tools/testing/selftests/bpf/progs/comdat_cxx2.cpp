// SPDX-License-Identifier: GPL-2.0
/* The same COMDAT groups as comdat_cxx.cpp, which the linker keeps one of */
#include "comdat_cxx.h"

extern "C" SEC("tc") int comdat_c(struct __sk_buff *skb)
{
	return prime_sum(skb->len) + counter<int>::bump(3);
}

static __noinline int area_of2(const shape *s, int x)
{
	return s->area(x);
}

extern "C" SEC("tc") int comdat_virtual2(struct __sk_buff *skb)
{
	twice t;

	return area_of2(&t, skb->len) + tag_a + same;
}

char LICENSE[] SEC("license") = "GPL";
