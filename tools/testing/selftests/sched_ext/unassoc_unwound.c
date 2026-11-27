// SPDX-License-Identifier: GPL-2.0
/*
 * An operator of a root scheduler with ops.sub_attach() is a program of two
 * struct_ops maps, and is unwound. sched_ext cannot tell which scheduler the
 * program belongs to, and the root scheduler exits with an error.
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sched.h>
#include <unistd.h>
#include "unassoc_unwound.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct unassoc_unwound *skel;

	skel = unassoc_unwound__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(unassoc_unwound__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct unassoc_unwound *skel = ctx;
	struct bpf_link *link, *link2;
	int i;

	link = bpf_map__attach_struct_ops(skel->maps.unassoc_unwound_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/* fails, a scheduler is enabled: but the map has taken ops.running() by then */
	link2 = bpf_map__attach_struct_ops(skel->maps.unassoc_unwound_ops2);
	SCX_FAIL_IF(link2, "Attached a second scheduler");

	/* the next task that starts to run unwinds the operator: 5 s is far more than it takes */
	skel->bss->fail_now = true;
	for (i = 0; i < 5000 && !skel->data->uei.kind; i++) {
		sched_yield();
		usleep(1000);
	}

	bpf_link__destroy(link);

	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct unassoc_unwound *skel = ctx;

	unassoc_unwound__destroy(skel);
}

struct scx_test unassoc_unwound = {
	.name = "unassoc_unwound",
	.description = "Verify that an unwound program of two struct_ops maps fails the root scheduler",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&unassoc_unwound)
