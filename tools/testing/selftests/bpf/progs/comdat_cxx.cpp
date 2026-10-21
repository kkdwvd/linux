// SPDX-License-Identifier: GPL-2.0
/* COMDAT groups in an object that is loaded as it is, and linked with comdat_cxx2.cpp */
#include "comdat_cxx.h"

/* .data, which base joins */
int plain = 1;

/* .data.tags with the inline variables of that name */
int tag_c SEC(".data.tags") = 3;
static int tag_d SEC(".data.tags") = 4;

extern "C" SEC("tc") int comdat_a(struct __sk_buff *skb)
{
	return prime_sum(skb->len) + counter<int>::bump(1);
}

extern "C" SEC("tc") int comdat_b(struct __sk_buff *skb)
{
	return prime_sum(skb->len) + counter<long>::bump(2) + plain;
}

extern "C" SEC("tc") int comdat_tags(struct __sk_buff *skb)
{
	tag_d++;
	return tag_a + tag_b + tag_c + tag_d + same;
}

/* callx through the vtable of an object on the stack */
static __noinline int area_of(const shape *s, int x)
{
	return s->area(x);
}

extern "C" SEC("tc") int comdat_virtual(struct __sk_buff *skb)
{
	shape s;
	twice t;

	return area_of(&s, skb->len) + area_of(&t, skb->len);
}

char _license[] SEC("license") = "GPL";
