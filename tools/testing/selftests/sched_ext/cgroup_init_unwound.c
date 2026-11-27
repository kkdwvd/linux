// SPDX-License-Identifier: GPL-2.0
/*
 * ops.cgroup_init() of the scheduler is unwound for the first cgroup and
 * returns 0. The scheduler was told and has failed: the operator is not called
 * for the cgroups that follow.
 */
#include <bpf/bpf.h>
#include <linux/limits.h>
#include <scx/common.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "cgroup_init_unwound.bpf.skel.h"
#include "cgroup_util.h"
#include "scx_test.h"

#define NR_CGROUPS 2

struct cgroup_init_unwound_ctx {
	struct cgroup_init_unwound *skel;
	char cgroup[NR_CGROUPS][PATH_MAX];
	int nr_created;
};

static struct cgroup_init_unwound_ctx test_ctx;

/* The cpu controller gives a cgroup a task group, which ops.cgroup_init() is called for */
static enum scx_test_status setup_cgroups(struct cgroup_init_unwound_ctx *ctx)
{
	char root[PATH_MAX], buf[4096];
	int i;

	if (cg_find_unified_root(root, sizeof(root), NULL))
		return SCX_TEST_SKIP;
	if (cg_read(root, "cgroup.subtree_control", buf, sizeof(buf)))
		return SCX_TEST_SKIP;
	if (!strstr(buf, "cpu") && cg_write(root, "cgroup.subtree_control", "+cpu"))
		return SCX_TEST_SKIP;

	for (i = 0; i < NR_CGROUPS; i++) {
		snprintf(ctx->cgroup[i], sizeof(ctx->cgroup[i]), "%s/scx_cgroup_init_unwound_%d_%d",
			 root, getpid(), i);
		SCX_FAIL_IF(cg_create(ctx->cgroup[i]), "Failed to create cgroup %s",
			    ctx->cgroup[i]);
		ctx->nr_created++;
	}
	return SCX_TEST_PASS;
}

static enum scx_test_status setup(void **ctx)
{
	struct cgroup_init_unwound *skel;

	skel = cgroup_init_unwound__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(cgroup_init_unwound__load(skel), "Failed to load skel");

	test_ctx.skel = skel;
	*ctx = &test_ctx;

	return setup_cgroups(&test_ctx);
}

static enum scx_test_status run(void *arg)
{
	struct cgroup_init_unwound_ctx *ctx = arg;
	struct bpf_link *link;

	link = bpf_map__attach_struct_ops(ctx->skel->maps.cgroup_init_unwound_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/*
	 * The enable path takes the unwound operator for one that failed, and
	 * waits for the scheduler to be disabled: the exit is reported before the
	 * attach returns.
	 */
	SCX_EQ(ctx->skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));
	/* the root cgroup and the ones made here: only the first one was told */
	SCX_EQ(ctx->skel->bss->nr_cgroup_init, 1);

	bpf_link__destroy(link);

	SCX_EQ(ctx->skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));
	SCX_EQ(ctx->skel->bss->nr_cgroup_init, 1);
	/* no cgroup is given back to a scheduler that failed */
	SCX_EQ(ctx->skel->bss->nr_cgroup_exit, 0);

	return SCX_TEST_PASS;
}

static void cleanup(void *arg)
{
	struct cgroup_init_unwound_ctx *ctx = arg;

	while (ctx->nr_created)
		cg_destroy(ctx->cgroup[--ctx->nr_created]);
	cgroup_init_unwound__destroy(ctx->skel);
}

struct scx_test cgroup_init_unwound = {
	.name = "cgroup_init_unwound",
	.description = "Verify that an unwound ops.cgroup_init() is not called for the cgroups that follow",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&cgroup_init_unwound)
