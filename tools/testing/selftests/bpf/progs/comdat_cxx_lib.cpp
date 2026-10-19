// SPDX-License-Identifier: GPL-2.0
/*
 * A member of libcomdat_cxx.a with the COMDAT groups of comdat_cxx.h, those
 * of prime_sum() and counter<int> shared with comdat_cxx_use.cpp, and that of
 * counter<long> its own
 */
#include "comdat_cxx.h"

extern "C" int comdat_lib(unsigned int i)
{
	int r = prime_sum(i);

	r += counter<int>::bump(10);
	r += counter<long>::bump(100);
	return r;
}
