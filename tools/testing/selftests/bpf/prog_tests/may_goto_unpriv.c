// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "cap_helpers.h"
#include "unpriv_helpers.h"

#include "may_goto_unpriv.skel.h"

#define ADMIN_CAPS ((1ULL << CAP_SYS_ADMIN) | (1ULL << CAP_NET_ADMIN) | \
		    (1ULL << CAP_PERFMON) | (1ULL << CAP_BPF))

static char log[64 * 1024];

/*
 * Load the program, without the administrative capabilities when @unpriv,
 * and return the number of sites the frame descriptor statistics of the
 * verifier log report, -1 when the load or the statistics are missing.
 */
static int load_and_count_sites(bool unpriv)
{
	struct may_goto_unpriv *skel;
	__u64 caps = 0;
	int err, sites = -1;
	char *stats;

	skel = may_goto_unpriv__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return -1;
	log[0] = '\0';
	bpf_program__set_log_buf(skel->progs.may_goto_once, log, sizeof(log));
	bpf_program__set_log_level(skel->progs.may_goto_once, 4 /* BPF_LOG_STATS */);

	if (unpriv && !ASSERT_OK(cap_disable_effective(ADMIN_CAPS, &caps), "drop caps"))
		goto out;
	err = may_goto_unpriv__load(skel);
	if (unpriv)
		cap_enable_effective(caps, NULL);
	if (!ASSERT_OK(err, "load")) {
		fprintf(stderr, "verifier log:\n%s", log);
		goto out;
	}

	stats = strstr(log, "frame descriptors: sites ");
	if (ASSERT_OK_PTR(stats, "frame descriptor statistics"))
		sites = atoi(stats + strlen("frame descriptors: sites "));
out:
	may_goto_unpriv__destroy(skel);
	return sites;
}

/*
 * A program loaded without CAP_BPF is not in the kernel's symbol table, so
 * the slow path of its timed may_goto cannot find it to cancel it: the
 * verifier describes no frames for it, while it does with the capability.
 */
void test_may_goto_unpriv(void)
{
	if (get_unpriv_sysctl_disabled()) {
		test__skip();
		return;
	}
	ASSERT_GT(load_and_count_sites(false), 0, "sites with CAP_BPF");
	ASSERT_EQ(load_and_count_sites(true), 0, "sites without CAP_BPF");
}
