// SPDX-License-Identifier: GPL-2.0
/*
 * ops.init() of the scheduler is unwound and returns 0. The scheduler was told
 * and exits with an error, and none of its operators is called on the way.
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "init_unwound.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct init_unwound *skel;

	skel = init_unwound__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(init_unwound__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct init_unwound *skel = ctx;
	struct bpf_link *link;

	link = bpf_map__attach_struct_ops(skel->maps.init_unwound_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/* the exit is reported before the attach returns */
	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));
	SCX_EQ(skel->bss->nr_ops_after_init, 0);

	bpf_link__destroy(link);

	SCX_EQ(skel->bss->nr_ops_after_init, 0);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct init_unwound *skel = ctx;

	init_unwound__destroy(skel);
}

struct scx_test init_unwound = {
	.name = "init_unwound",
	.description = "Verify that a scheduler whose ops.init() is unwound calls no operator",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&init_unwound)
