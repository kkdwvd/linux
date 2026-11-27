// SPDX-License-Identifier: GPL-2.0
/*
 * A timer callback of a scheduler that is gone, with its struct_ops map, is
 * unwound while another scheduler is the root. The root has nothing to do with
 * the program and goes on, whether or not it takes sub-schedulers.
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <unistd.h>
#include "stale_unwound.bpf.skel.h"
#include "unassoc_unwound.bpf.skel.h"
#include "maximal.bpf.skel.h"
#include "scx_test.h"

/* @subs: the new root has ops.sub_attach() */
static enum scx_test_status run_one(bool subs)
{
	struct unassoc_unwound *root = NULL;
	struct bpf_prog_info info = {};
	struct maximal *plain = NULL;
	__u32 len = sizeof(info), key;
	struct user_exit_info *uei;
	struct stale_unwound *old;
	int timers_fd, state_fd, fd, i;
	struct bpf_link *link;
	__u64 val = 1;

	old = stale_unwound__open();
	SCX_FAIL_IF(!old, "Failed to open the old scheduler");
	SCX_ENUM_INIT(old);
	SCX_FAIL_IF(stale_unwound__load(old), "Failed to load the old scheduler");
	link = bpf_map__attach_struct_ops(old->maps.stale_unwound_ops);
	SCX_FAIL_IF(!link, "Failed to attach the old scheduler");

	/* user space keeps the map of the timer, so the timer stays armed, and holds ops.init() */
	timers_fd = dup(bpf_map__fd(old->maps.timers));
	state_fd = dup(bpf_map__fd(old->maps.state));
	SCX_FAIL_IF(timers_fd < 0 || state_fd < 0, "Failed to keep the maps");
	SCX_FAIL_IF(bpf_prog_get_info_by_fd(bpf_program__fd(old->progs.stale_unwound_exit),
					    &info, &len), "Failed to get the id of ops.exit()");

	/* the old scheduler goes: its struct_ops map is freed when ops.exit() is gone */
	bpf_link__destroy(link);
	stale_unwound__destroy(old);
	for (i = 0; i < 5000; i++) {
		fd = bpf_prog_get_fd_by_id(info.id);
		if (fd < 0)
			break;
		close(fd);
		usleep(1000);
	}
	SCX_FAIL_IF(fd >= 0, "The struct_ops map of the old scheduler was not freed");

	if (subs) {
		root = unassoc_unwound__open();
		SCX_FAIL_IF(!root, "Failed to open the new root");
		SCX_ENUM_INIT(root);
		SCX_FAIL_IF(unassoc_unwound__load(root), "Failed to load the new root");
		link = bpf_map__attach_struct_ops(root->maps.unassoc_unwound_ops);
		uei = &root->data->uei;
	} else {
		plain = maximal__open();
		SCX_FAIL_IF(!plain, "Failed to open the new root");
		SCX_ENUM_INIT(plain);
		SCX_FAIL_IF(maximal__load(plain), "Failed to load the new root");
		link = bpf_map__attach_struct_ops(plain->maps.maximal_ops);
		uei = &plain->data->uei;
	}
	SCX_FAIL_IF(!link, "Failed to attach the new root");

	/* the old callback throws from now on. After the second time the first one is through. */
	key = 0;
	SCX_FAIL_IF(bpf_map_update_elem(state_fd, &key, &val, 0), "Failed to update the state");
	key = 1;
	for (i = 0; i < 5000; i++) {
		SCX_FAIL_IF(bpf_map_lookup_elem(state_fd, &key, &val), "Failed to read the state");
		if (val >= 2)
			break;
		usleep(1000);
	}

	bpf_link__destroy(link);
	close(timers_fd);
	close(state_fd);

	SCX_GE(val, 2);
	if (uei->kind != EXIT_KIND(SCX_EXIT_UNREG))
		SCX_FAIL("The new root (%s ops.sub_attach()) exited with kind %llu: %s",
			 subs ? "with" : "without", (unsigned long long)uei->kind, uei->msg);

	if (root)
		unassoc_unwound__destroy(root);
	if (plain)
		maximal__destroy(plain);

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	enum scx_test_status subs = run_one(true), plain = run_one(false);

	return subs != SCX_TEST_PASS ? subs : plain;
}

struct scx_test stale_unwound = {
	.name = "stale_unwound",
	.description = "Verify that an unwound program of a scheduler that is gone leaves the next root alone",
	.run = run,
};
REGISTER_SCX_TEST(&stale_unwound)
