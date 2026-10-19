// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <limits.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include "bpf_net_mlx5.skel.h"
#include "bpf_net_mlx5_run.skel.h"
#include "bpf_net_virtio.skel.h"
#include "bpf_net_virtio_bad.skel.h"
#include "bpf_net_virtio_run.skel.h"

#define PEER_ADDR "192.0.2.2"

static const char *test_ifname;
static const char *peer_netns;
static bool mlx5_transport;

struct driver_program {
	struct bpf_net_virtio *virtio;
	struct bpf_net_mlx5 *mlx5;
	struct bpf_net_virtio_run *virtio_run;
	struct bpf_net_mlx5_run *mlx5_run;
	struct bpf_object *obj;
	struct bpf_map *ops;
	typeof(((struct bpf_net_virtio *)0)->arena->received) *received;
	typeof(((struct bpf_net_virtio *)0)->arena->transmitted) *transmitted;
	typeof(((struct bpf_net_virtio *)0)->arena->completed) *completed;
	volatile __u32 *fault_mode;
};

struct live_traffic {
	pthread_t thread;
	int client;
	int server;
	bool stop;
	unsigned int sent;
};

static int set_up(bool up)
{
	struct ifreq ifr = {};
	int fd, err;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	strncpy(ifr.ifr_name, test_ifname, IFNAMSIZ - 1);
	err = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (!err) {
		if (up)
			ifr.ifr_flags |= IFF_UP;
		else
			ifr.ifr_flags &= ~IFF_UP;
		err = ioctl(fd, SIOCSIFFLAGS, &ifr);
	}
	close(fd);
	return err;
}

static int interface_mtu(int *mtu, bool write)
{
	struct ifreq ifr = {};
	int fd, err;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	strncpy(ifr.ifr_name, test_ifname, IFNAMSIZ - 1);
	ifr.ifr_mtu = *mtu;
	err = ioctl(fd, write ? SIOCSIFMTU : SIOCGIFMTU, &ifr);
	if (!err && !write)
		*mtu = ifr.ifr_mtu;
	close(fd);
	return err;
}

static bool driver_state(const char *expected)
{
	char path[256], state[32];
	FILE *file;
	bool match = false;

	snprintf(path, sizeof(path), "/sys/class/net/%s/bpf_driver/state", test_ifname);
	file = fopen(path, "r");
	if (!file)
		return false;
	if (fscanf(file, "%31s", state) == 1)
		match = !strcmp(state, expected);
	fclose(file);
	return match;
}

static bool wait_state(const char *expected)
{
	for (int i = 0; i < 100; i++) {
		if (driver_state(expected))
			return true;
		usleep(100000);
	}
	return false;
}

static long long driver_stat(const char *name)
{
	char path[256];
	long long value = LLONG_MIN;
	FILE *file;

	snprintf(path, sizeof(path), "/sys/class/net/%s/bpf_driver/%s", test_ifname, name);
	file = fopen(path, "r");
	if (!file)
		return value;
	if (fscanf(file, "%lld", &value) != 1)
		value = LLONG_MIN;
	fclose(file);
	return value;
}

static bool wait_recovered(long long before)
{
	for (int i = 0; i < 100; i++) {
		if (driver_state("revoked") && driver_stat("recoveries") > before)
			return true;
		usleep(100000);
	}
	return false;
}

static bool exchange(int type)
{
	char sent[1024], got[sizeof(sent)];
	struct sockaddr_storage addr;
	struct nstoken *ns;
	socklen_t addrlen;
	int server = -1, client = -1, accepted = -1;
	bool ok = false;
	ssize_t n;

	ns = open_netns(peer_netns);
	if (!ASSERT_OK_PTR(ns, "peer_netns"))
		return false;
	server = start_server(AF_INET, type, PEER_ADDR, 0, 3000);
	close_netns(ns);
	if (!ASSERT_GE(server, 0, "server_socket"))
		goto out;
	client = connect_to_fd(server, 3000);
	if (!ASSERT_GE(client, 0, "client_socket"))
		goto out;
	if (type == SOCK_STREAM) {
		accepted = accept(server, NULL, NULL);
		if (!ASSERT_GE(accepted, 0, "accept"))
			goto out;
		settimeo(accepted, 3000);
	}
	for (int i = 0; i < 64; i++) {
		memset(sent, i, sizeof(sent));
		if (!ASSERT_EQ(send(client, sent, sizeof(sent), MSG_NOSIGNAL), sizeof(sent), "send"))
			goto out;
		if (type == SOCK_STREAM) {
			n = recv(accepted, got, sizeof(got), MSG_WAITALL);
		} else {
			addrlen = sizeof(addr);
			n = recvfrom(server, got, sizeof(got), 0, (void *)&addr, &addrlen);
		}
		if (!ASSERT_EQ(n, sizeof(got), "receive_at_peer") ||
		    !ASSERT_MEMEQ(got, sent, sizeof(sent), "payload_at_peer"))
			goto out;
		if (type == SOCK_STREAM)
			n = send(accepted, got, sizeof(got), MSG_NOSIGNAL);
		else
			n = sendto(server, got, sizeof(got), 0, (void *)&addr, addrlen);
		if (!ASSERT_EQ(n, sizeof(got), "reply"))
			goto out;
		n = recv(client, got, sizeof(got), type == SOCK_STREAM ? MSG_WAITALL : 0);
		if (!ASSERT_EQ(n, sizeof(got), "receive_reply") ||
		    !ASSERT_MEMEQ(got, sent, sizeof(sent), "reply_payload"))
			goto out;
	}
	ok = true;
out:
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	return ok;
}

static void destroy_driver(struct driver_program *driver)
{
	if (!driver)
		return;
	bpf_net_virtio__destroy(driver->virtio);
	bpf_net_mlx5__destroy(driver->mlx5);
	bpf_net_virtio_run__destroy(driver->virtio_run);
	bpf_net_mlx5_run__destroy(driver->mlx5_run);
	free(driver);
}

static struct driver_program *load_driver(unsigned int ifindex, bool production)
{
	struct driver_program *driver;
	struct bpf_program *prog;
	int err;

	driver = calloc(1, sizeof(*driver));
	if (!ASSERT_OK_PTR(driver, "driver_alloc"))
		return NULL;
	if (production && mlx5_transport) {
		driver->mlx5_run = bpf_net_mlx5_run__open();
		if (!ASSERT_OK_PTR(driver->mlx5_run, "mlx5_run_open"))
			goto fail;
		driver->mlx5_run->struct_ops.bvnet->ifindex = ifindex;
		driver->obj = driver->mlx5_run->obj;
		driver->ops = driver->mlx5_run->maps.bvnet;
	} else if (production) {
		driver->virtio_run = bpf_net_virtio_run__open();
		if (!ASSERT_OK_PTR(driver->virtio_run, "virtio_run_open"))
			goto fail;
		driver->virtio_run->struct_ops.bvnet->ifindex = ifindex;
		driver->obj = driver->virtio_run->obj;
		driver->ops = driver->virtio_run->maps.bvnet;
	} else if (mlx5_transport) {
		driver->mlx5 = bpf_net_mlx5__open();
		if (!ASSERT_OK_PTR(driver->mlx5, "mlx5_open"))
			goto fail;
		driver->mlx5->struct_ops.bvnet->ifindex = ifindex;
		driver->obj = driver->mlx5->obj;
		driver->ops = driver->mlx5->maps.bvnet;
	} else {
		driver->virtio = bpf_net_virtio__open();
		if (!ASSERT_OK_PTR(driver->virtio, "virtio_open"))
			goto fail;
		driver->virtio->struct_ops.bvnet->ifindex = ifindex;
		driver->obj = driver->virtio->obj;
		driver->ops = driver->virtio->maps.bvnet;
	}
	bpf_object__for_each_program(prog, driver->obj)
		bpf_program__set_flags(prog, BPF_F_ARENA_SCALAR);
	if (production)
		err = mlx5_transport ? bpf_net_mlx5_run__load(driver->mlx5_run) :
			bpf_net_virtio_run__load(driver->virtio_run);
	else
		err = mlx5_transport ? bpf_net_mlx5__load(driver->mlx5) :
			bpf_net_virtio__load(driver->virtio);
	if (!ASSERT_OK(err, "load"))
		goto fail;
	if (production)
		return driver;
	if (mlx5_transport) {
		driver->received = &driver->mlx5->arena->received;
		driver->transmitted = &driver->mlx5->arena->transmitted;
		driver->completed = &driver->mlx5->arena->completed;
		driver->fault_mode = &driver->mlx5->arena->fault_mode;
	} else {
		driver->received = &driver->virtio->arena->received;
		driver->transmitted = &driver->virtio->arena->transmitted;
		driver->completed = &driver->virtio->arena->completed;
		driver->fault_mode = &driver->virtio->arena->fault_mode;
	}
	return driver;
fail:
	destroy_driver(driver);
	return NULL;
}

static void native_traffic(void)
{
	if (!ASSERT_OK(set_up(true), "native_up"))
		return;
	if (ASSERT_TRUE(driver_state("native"), "native_state")) {
		exchange(SOCK_DGRAM);
		exchange(SOCK_STREAM);
	}
	ASSERT_OK(set_up(false), "native_down");
}

static void bpf_traffic(unsigned int ifindex, bool production)
{
	struct driver_program *driver = load_driver(ifindex, production);
	struct bpf_link *link = NULL;
	__u64 received;

	if (!driver)
		return;
	link = bpf_map__attach_struct_ops(driver->ops);
	if (!ASSERT_OK_PTR(link, "attach")) {
		link = NULL;
		goto out;
	}
	if (!ASSERT_OK(set_up(true), "bpf_up"))
		goto out;
	if (!ASSERT_TRUE(driver_state("bpf"), "bpf_state"))
		goto out;
	exchange(SOCK_DGRAM);
	exchange(SOCK_STREAM);
	ASSERT_TRUE(driver_state("bpf"), "bpf_state_after_traffic");
	if (!production) {
		ASSERT_GT(*driver->received, 64, "bpf_rx_refills");
		ASSERT_GT(*driver->transmitted, 64, "bpf_tx_packets");
		ASSERT_GT(*driver->completed, 0, "bpf_tx_completions");
	}
	bpf_link__destroy(link);
	link = NULL;
	if (ASSERT_TRUE(wait_state("native"), "detach_native")) {
		received = production ? 0 : *driver->received;
		exchange(SOCK_DGRAM);
		exchange(SOCK_STREAM);
		if (!production)
			ASSERT_EQ(*driver->received, received, "detached_program_stopped");
	}
out:
	ASSERT_OK(set_up(false), "down");
	bpf_link__destroy(link);
	destroy_driver(driver);
}

static void small_mtu(unsigned int ifindex, bool bpf)
{
	struct driver_program *driver = NULL;
	struct bpf_link *link = NULL;
	struct sockaddr_storage addr;
	struct nstoken *ns;
	socklen_t addrlen = sizeof(addr);
	char payload[768] = {}, got[sizeof(payload)];
	int original_mtu = 0, mtu = 512;
	int server = -1, client = -1, err;
	ssize_t n;

	if (!ASSERT_OK(interface_mtu(&original_mtu, false), "get_mtu"))
		return;
	if (!ASSERT_OK(interface_mtu(&mtu, true), "set_small_mtu"))
		goto out;
	if (bpf) {
		driver = load_driver(ifindex, false);
		if (!driver)
			goto out;
		link = bpf_map__attach_struct_ops(driver->ops);
		if (!ASSERT_OK_PTR(link, "small_mtu_attach")) {
			link = NULL;
			goto out;
		}
	}
	if (!ASSERT_OK(set_up(true), "small_mtu_up"))
		goto out;
	ns = open_netns(peer_netns);
	if (!ASSERT_OK_PTR(ns, "small_mtu_peer"))
		goto out;
	server = start_server(AF_INET, SOCK_DGRAM, PEER_ADDR, 0, 3000);
	close_netns(ns);
	if (!ASSERT_GE(server, 0, "small_mtu_server"))
		goto out;
	client = connect_to_fd(server, 3000);
	if (!ASSERT_GE(client, 0, "small_mtu_client"))
		goto out;
	if (!ASSERT_EQ(send(client, payload, 1, 0), 1, "small_mtu_send"))
		goto out;
	n = recvfrom(server, got, sizeof(got), 0, (void *)&addr, &addrlen);
	if (!ASSERT_EQ(n, 1, "small_mtu_peer_receive"))
		goto out;
	settimeo(client, 200);
	n = sendto(server, payload, sizeof(payload), 0, (void *)&addr, addrlen);
	if (!ASSERT_EQ(n, sizeof(payload), "peer_sends_above_mtu"))
		goto out;
	n = recv(client, got, sizeof(got), 0);
	err = errno;
	ASSERT_EQ(n, -1, "above_mtu_not_delivered");
	ASSERT_EQ(err, EAGAIN, "above_mtu_timeout");
	ASSERT_TRUE(driver_state(bpf ? "bpf" : "native"), "above_mtu_does_not_revoke");
	settimeo(client, 3000);
	n = sendto(server, payload, 64, 0, (void *)&addr, addrlen);
	if (ASSERT_EQ(n, 64, "peer_sends_below_mtu"))
		ASSERT_EQ(recv(client, got, sizeof(got), 0), 64, "below_mtu_still_delivered");
out:
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	ASSERT_OK(set_up(false), "small_mtu_down");
	bpf_link__destroy(link);
	destroy_driver(driver);
	ASSERT_OK(interface_mtu(&original_mtu, true), "restore_mtu");
}

static void trigger_tx(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9321),
	};
	int fd;

	inet_pton(AF_INET, PEER_ADDR, &addr.sin_addr);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return;
	sendto(fd, "trigger", 7, 0, (void *)&addr, sizeof(addr));
	close(fd);
}

static void fault_recovery(unsigned int ifindex, unsigned int mode)
{
	static const int errors[] = {
		-ESTALE, -ERANGE, -ESTALE, -EPROTO, -EPROTO, -ETIMEDOUT, -ETIMEDOUT,
	};
	struct driver_program *driver = load_driver(ifindex, false);
	struct bpf_link *link = NULL;
	long long recoveries, calls;
	__u64 transmitted;

	if (!driver)
		return;
	recoveries = driver_stat("recoveries");
	if (!ASSERT_GE(recoveries, 0, "recoveries_before_fault"))
		goto out;
	*driver->fault_mode = mode;
	link = bpf_map__attach_struct_ops(driver->ops);
	if (!ASSERT_OK_PTR(link, "fault_attach")) {
		link = NULL;
		goto out;
	}
	if (!ASSERT_OK(set_up(true), "fault_up"))
		goto out;
	trigger_tx();
	if (!ASSERT_TRUE(wait_recovered(recoveries), "fault_revoked_and_recovered"))
		goto out;
	ASSERT_EQ(driver_stat("fault"), errors[mode - 1], "recorded_fault");
	transmitted = *driver->transmitted;
	calls = driver_stat("calls");
	exchange(SOCK_DGRAM);
	exchange(SOCK_STREAM);
	ASSERT_EQ(*driver->transmitted, transmitted, "revoked_program_stopped");
	ASSERT_EQ(driver_stat("calls"), calls, "revoked_callbacks_stopped");
out:
	ASSERT_OK(set_up(false), "fault_down");
	bpf_link__destroy(link);
	destroy_driver(driver);
}

static void *traffic_worker(void *arg)
{
	struct live_traffic *traffic = arg;
	struct sockaddr_storage addr;
	char payload[512] = {};
	socklen_t len;
	ssize_t n;

	while (!__atomic_load_n(&traffic->stop, __ATOMIC_RELAXED)) {
		if (send(traffic->client, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL) > 0)
			traffic->sent++;
		len = sizeof(addr);
		n = recvfrom(traffic->server, payload, sizeof(payload), MSG_DONTWAIT,
			     (void *)&addr, &len);
		if (n > 0)
			sendto(traffic->server, payload, n, MSG_DONTWAIT | MSG_NOSIGNAL,
			       (void *)&addr, len);
		recv(traffic->client, payload, sizeof(payload), MSG_DONTWAIT);
		usleep(1000);
	}
	return NULL;
}

static bool start_traffic(struct live_traffic *traffic)
{
	struct nstoken *ns;
	int err;

	memset(traffic, 0, sizeof(*traffic));
	traffic->server = -1;
	traffic->client = -1;
	ns = open_netns(peer_netns);
	if (!ASSERT_OK_PTR(ns, "traffic_netns"))
		return false;
	traffic->server = start_server(AF_INET, SOCK_DGRAM, PEER_ADDR, 0, 3000);
	close_netns(ns);
	if (!ASSERT_GE(traffic->server, 0, "traffic_server"))
		return false;
	traffic->client = connect_to_fd(traffic->server, 3000);
	if (!ASSERT_GE(traffic->client, 0, "traffic_client"))
		goto close_server;
	err = pthread_create(&traffic->thread, NULL, traffic_worker, traffic);
	if (!ASSERT_OK(err, "traffic_thread"))
		goto close_client;
	usleep(50000);
	return true;
close_client:
	close(traffic->client);
close_server:
	close(traffic->server);
	return false;
}

static void stop_traffic(struct live_traffic *traffic)
{
	__atomic_store_n(&traffic->stop, true, __ATOMIC_RELAXED);
	pthread_join(traffic->thread, NULL);
	ASSERT_GT(traffic->sent, 0, "traffic_while_teardown");
	close(traffic->client);
	close(traffic->server);
}

static void detach_stress(unsigned int ifindex)
{
	struct driver_program *driver;
	struct live_traffic traffic;
	struct bpf_link *link;
	bool running;

	for (int i = 0; i < 4; i++) {
		running = false;
		link = NULL;
		driver = load_driver(ifindex, false);
		if (!driver)
			return;
		link = bpf_map__attach_struct_ops(driver->ops);
		if (!ASSERT_OK_PTR(link, "stress_attach")) {
			link = NULL;
			goto out;
		}
		if (!ASSERT_OK(set_up(true), "stress_up"))
			goto out;
		running = start_traffic(&traffic);
		if (!running)
			goto out;
		bpf_link__destroy(link);
		link = NULL;
		ASSERT_TRUE(wait_state("native"), "stress_detach_native");
		stop_traffic(&traffic);
		running = false;
		exchange(SOCK_DGRAM);
out:
		if (running)
			stop_traffic(&traffic);
		ASSERT_OK(set_up(false), "stress_down");
		bpf_link__destroy(link);
		destroy_driver(driver);
	}
}

static bool removal_allowed(const char *device)
{
	char path[256], resolved[PATH_MAX], cmdline[4096];
	const char *allow = getenv("BPF_NET_DRIVER_ALLOW_REMOVE");
	FILE *file;
	bool guest;

	if (mlx5_transport || !allow || strcmp(allow, "1") || !device)
		return false;
	file = fopen("/proc/cmdline", "r");
	if (!file)
		return false;
	guest = fgets(cmdline, sizeof(cmdline), file) && strstr(cmdline, "virtme");
	fclose(file);
	if (!guest)
		return false;
	snprintf(path, sizeof(path), "/sys/class/net/%s/device", test_ifname);
	if (!realpath(path, resolved) || strcmp(strrchr(resolved, '/') + 1, device))
		return false;
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", test_ifname);
	return realpath(path, resolved) &&
		!strcmp(strrchr(resolved, '/') + 1, "bpf_virtio_net");
}

static void remove_with_retained_link(unsigned int ifindex)
{
	const char *device = getenv("BPF_NET_DRIVER_VIRTIO_DEVICE");
	struct driver_program *driver;
	struct live_traffic traffic;
	struct bpf_link *link = NULL;
	bool running = false, removed = false;
	__u64 received;
	FILE *file;
	int err;

	if (!removal_allowed(device)) {
		test__skip();
		return;
	}
	driver = load_driver(ifindex, false);
	if (!driver)
		return;
	link = bpf_map__attach_struct_ops(driver->ops);
	if (!ASSERT_OK_PTR(link, "remove_attach")) {
		link = NULL;
		goto out;
	}
	if (!ASSERT_OK(set_up(true), "remove_up"))
		goto out;
	running = start_traffic(&traffic);
	if (!running)
		goto out;
	file = fopen("/sys/bus/virtio/drivers/bpf_virtio_net/unbind", "w");
	if (!ASSERT_OK_PTR(file, "unbind_open"))
		goto out;
	err = fprintf(file, "%s", device);
	if (!ASSERT_GT(err, 0, "unbind_write")) {
		fclose(file);
		goto out;
	}
	err = fclose(file);
	if (!ASSERT_OK(err, "unbind_close"))
		goto out;
	removed = true;
	ASSERT_EQ(if_nametoindex(test_ifname), 0, "device_removed_link_retained");
	received = *driver->received;
	bpf_link__destroy(link);
	link = NULL;
	stop_traffic(&traffic);
	running = false;
	ASSERT_EQ(*driver->received, received, "removed_program_stopped");
out:
	if (running)
		stop_traffic(&traffic);
	if (!removed)
		ASSERT_OK(set_up(false), "remove_down");
	bpf_link__destroy(link);
	destroy_driver(driver);
}

static void verifier_reject(bool helper)
{
	struct bpf_net_virtio_bad *skel;
	struct bpf_program *prog;

	skel = bpf_net_virtio_bad__open();
	if (!ASSERT_OK_PTR(skel, "bad_open"))
		return;
	if (helper) {
		bpf_program__set_autoload(skel->progs.backward_branch, false);
		bpf_map__set_autocreate(skel->maps.backward, false);
	} else {
		bpf_program__set_autoload(skel->progs.forbidden_helper, false);
		bpf_map__set_autocreate(skel->maps.forbidden, false);
	}
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_flags(prog, BPF_F_ARENA_SCALAR);
	ASSERT_ERR(bpf_net_virtio_bad__load(skel), "driver_policy_reject");
	bpf_net_virtio_bad__destroy(skel);
}

void serial_test_bpf_net_driver(void)
{
	static const char * const faults[] = {
		"stale_capability", "prefix_bounds", "double_submit",
		"unconsumed_tx", "invalid_poll_return", "no_progress", "watchdog",
	};
	unsigned int ifindex;
	const char *transport = getenv("BPF_NET_DRIVER_TRANSPORT");

	test_ifname = getenv("BPF_NET_DRIVER_IFACE");
	peer_netns = getenv("BPF_NET_DRIVER_PEER_NS");
	if (transport && strcmp(transport, "virtio") && strcmp(transport, "mlx5")) {
		ASSERT_FAIL("BPF_NET_DRIVER_TRANSPORT must be virtio or mlx5");
		return;
	}
	mlx5_transport = transport && !strcmp(transport, "mlx5");
	if (!test_ifname || !peer_netns) {
		test__skip();
		return;
	}
	ifindex = if_nametoindex(test_ifname);
	if (!ASSERT_NEQ(ifindex, 0, "test_device"))
		return;
	if (!ASSERT_OK(set_up(false), "initial_down"))
		return;
	if (test__start_subtest("native_tcp_udp"))
		native_traffic();
	if (test__start_subtest("bpf_tcp_udp_detach"))
		bpf_traffic(ifindex, false);
	if (test__start_subtest("bpf_production_tcp_udp_detach"))
		bpf_traffic(ifindex, true);
	if (test__start_subtest("native_small_mtu"))
		small_mtu(ifindex, false);
	if (test__start_subtest("bpf_small_mtu"))
		small_mtu(ifindex, true);
	if (test__start_subtest("detach_under_traffic"))
		detach_stress(ifindex);
	for (unsigned int i = 0; i < ARRAY_SIZE(faults); i++)
		if (test__start_subtest(faults[i]))
			fault_recovery(ifindex, i + 1);
	if (test__start_subtest("forbidden_helper"))
		verifier_reject(true);
	if (test__start_subtest("backward_branch"))
		verifier_reject(false);
	/* Removal is last: the guest runner restores the native device binding. */
	if (test__start_subtest("remove_with_retained_link"))
		remove_with_retained_link(ifindex);
}
