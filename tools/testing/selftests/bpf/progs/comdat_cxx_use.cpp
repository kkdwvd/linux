// SPDX-License-Identifier: GPL-2.0
/* The program that is linked against libcomdat_cxx.a, for comdat_lib() */
#include "comdat_cxx.h"

extern "C" int comdat_lib(unsigned int i);

extern "C" SEC("tc") int comdat_use(struct __sk_buff *skb)
{
	int r = comdat_lib(skb->len);

	r += prime_sum(skb->len);
	r += counter<int>::bump(1);
	return r;
}

char LICENSE[] SEC("license") = "GPL";
