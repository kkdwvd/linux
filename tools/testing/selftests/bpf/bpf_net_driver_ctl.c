// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "bpf_net_mlx5_run.skel.h"
#include "bpf_net_virtio_run.skel.h"

static volatile sig_atomic_t child_pid;
static volatile sig_atomic_t interrupted;

static void forward_signal(int signal)
{
	interrupted = signal;
	if (child_pid > 0)
		kill(-child_pid, signal);
}

static int interface_up(const char *name, bool *up, bool write)
{
	struct ifreq request = {};
	int fd, err;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	strncpy(request.ifr_name, name, IFNAMSIZ - 1);
	err = ioctl(fd, SIOCGIFFLAGS, &request);
	if (!err && write) {
		if (*up)
			request.ifr_flags |= IFF_UP;
		else
			request.ifr_flags &= ~IFF_UP;
		err = ioctl(fd, SIOCSIFFLAGS, &request);
	} else if (!err) {
		*up = !!(request.ifr_flags & IFF_UP);
	}
	err = err ? -errno : 0;
	close(fd);
	return err;
}

static bool driver_state(const char *name, const char *expected)
{
	char path[256], state[32];
	FILE *file;
	bool match = false;

	snprintf(path, sizeof(path), "/sys/class/net/%s/bpf_driver/state", name);
	file = fopen(path, "r");
	if (!file)
		return false;
	if (fscanf(file, "%31s", state) == 1)
		match = !strcmp(state, expected);
	fclose(file);
	return match;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s --ifindex N --transport virtio|mlx5 --mode native|bpf -- COMMAND [ARG...]\n",
		name);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "ifindex", required_argument, NULL, 'i' },
		{ "transport", required_argument, NULL, 't' },
		{ "mode", required_argument, NULL, 'm' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	struct sigaction action = { .sa_handler = forward_signal };
	struct bpf_net_virtio_run *virtio = NULL;
	struct bpf_net_mlx5_run *mlx5 = NULL;
	struct bpf_link *link = NULL;
	struct bpf_object *object = NULL;
	struct bpf_map *ops = NULL;
	struct bpf_program *program;
	struct timespec start, end;
	const char *transport = NULL, *mode = NULL;
	bool initial_up = false, changed = false, up;
	unsigned long index = 0;
	char name[IFNAMSIZ], *tail;
	int opt, err, status = 0, result = 1;
	pid_t pid, waited;
	double elapsed;

	while ((opt = getopt_long(argc, argv, "+i:t:m:h", options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			errno = 0;
			index = strtoul(optarg, &tail, 10);
			if (errno || !*optarg || *tail || !index || index > UINT_MAX)
				goto bad_usage;
			break;
		case 't':
			transport = optarg;
			break;
		case 'm':
			mode = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			goto bad_usage;
		}
	}
	if (!index || !transport || (strcmp(transport, "virtio") && strcmp(transport, "mlx5")) ||
	    !mode || (strcmp(mode, "native") && strcmp(mode, "bpf")) || optind == argc)
		goto bad_usage;
	if (!if_indextoname(index, name)) {
		perror("if_indextoname");
		return 1;
	}
	if (!driver_state(name, "native")) {
		fprintf(stderr, "%s must use an unattached BPF transport in native state\n", name);
		return 1;
	}
	err = interface_up(name, &initial_up, false);
	if (err)
		goto interface_error;
	sigemptyset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
	up = false;
	err = interface_up(name, &up, true);
	if (err)
		goto interface_error;
	changed = true;
	if (!strcmp(mode, "bpf")) {
		if (!strcmp(transport, "mlx5")) {
			mlx5 = bpf_net_mlx5_run__open();
			if (!mlx5)
				goto out;
			mlx5->struct_ops.bvnet->ifindex = index;
			object = mlx5->obj;
			ops = mlx5->maps.bvnet;
		} else {
			virtio = bpf_net_virtio_run__open();
			if (!virtio)
				goto out;
			virtio->struct_ops.bvnet->ifindex = index;
			object = virtio->obj;
			ops = virtio->maps.bvnet;
		}
		bpf_object__for_each_program(program, object)
			bpf_program__set_flags(program, BPF_F_ARENA_SCALAR);
		err = mlx5 ? bpf_net_mlx5_run__load(mlx5) : bpf_net_virtio_run__load(virtio);
		if (err)
			goto out;
		link = bpf_map__attach_struct_ops(ops);
		err = libbpf_get_error(link);
		if (err) {
			link = NULL;
			goto out;
		}
	}
	up = true;
	err = interface_up(name, &up, true);
	if (err)
		goto interface_error;
	if (interrupted)
		goto out;
	clock_gettime(CLOCK_MONOTONIC, &start);
	pid = fork();
	if (pid < 0) {
		perror("fork");
		goto out;
	}
	if (!pid) {
		setpgid(0, 0);
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		execvp(argv[optind], &argv[optind]);
		perror(argv[optind]);
		_exit(127);
	}
	setpgid(pid, pid);
	child_pid = pid;
	if (interrupted)
		kill(-pid, interrupted);
	do {
		waited = waitpid(pid, &status, 0);
	} while (waited < 0 && errno == EINTR);
	child_pid = 0;
	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
	if (waited < 0) {
		perror("waitpid");
		goto out;
	}
	result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	fprintf(stderr, "bpf-net-driver: mode=%s transport=%s ifindex=%lu elapsed_seconds=%.9f status=%d\n",
		mode, transport, index, elapsed, result);
	if (!driver_state(name, mode)) {
		fprintf(stderr, "Driver changed state during workload; reject this measurement\n");
		result = 1;
	}
	goto out;
interface_error:
	fprintf(stderr, "Interface %s: %s\n", name, strerror(-err));
out:
	if (changed && if_nametoindex(name) == index) {
		up = false;
		err = interface_up(name, &up, true);
		if (err) {
			fprintf(stderr, "Failed to stop %s: %s\n", name, strerror(-err));
			result = 1;
		}
	}
	bpf_link__destroy(link);
	bpf_net_mlx5_run__destroy(mlx5);
	bpf_net_virtio_run__destroy(virtio);
	if (changed && if_nametoindex(name) == index) {
		err = interface_up(name, &initial_up, true);
		if (err) {
			fprintf(stderr, "Failed to restore %s: %s\n", name, strerror(-err));
			result = 1;
		}
	}
	return interrupted ? 128 + interrupted : result;
bad_usage:
	usage(argv[0]);
	return 2;
}
