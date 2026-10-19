#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Run inside: kdev vm cmd --no-debug --verbose --disable-microvm \
#              --network loop --no-dhcp -- ./run_bpf_net_driver.sh
set -euo pipefail

case "$(</proc/cmdline)" in
*virtme*) ;;
*) echo "This runner changes guest NIC bindings; run it in a virtme guest." >&2; exit 1 ;;
esac
if [[ $EUID != 0 ]]; then
	echo "Run this guest-only test as root." >&2
	exit 1
fi
if [[ ! -d /sys/bus/virtio/drivers/bpf_virtio_net ]]; then
	modprobe bpf_virtio_net
fi

interfaces=()
for path in /sys/class/net/*; do
	[[ -L $path/device/driver ]] || continue
	[[ $(basename "$(readlink -f "$path/device/driver")") == virtio_net ]] || continue
	interfaces+=("${path##*/}")
done
if (( ${#interfaces[@]} != 2 )); then
	echo "Expected exactly two native virtio NICs from --network loop." >&2
	exit 1
fi

original=${interfaces[0]}
peer=${interfaces[1]}
virtio=$(basename "$(readlink -f "/sys/class/net/$original/device")")
namespace="bpf-net-peer-$$"
experimental=""
rebound=0
peer_moved=0
peer_address_added=0
namespace_created=0

cleanup()
{
	set +e
	if [[ -n $experimental && -e /sys/class/net/$experimental ]]; then
		ip link set "$experimental" down
	fi
	if (( peer_moved )); then
		ip -n "$namespace" link set "$peer" down
		if (( peer_address_added )); then
			ip -n "$namespace" addr del 192.0.2.2/24 dev "$peer"
		fi
		ip -n "$namespace" link set "$peer" netns 1
	fi
	if (( namespace_created )); then
		ip netns del "$namespace"
	fi
	if (( rebound )); then
		if [[ -L /sys/bus/virtio/devices/$virtio/driver ]]; then
			printf '%s' "$virtio" > /sys/bus/virtio/drivers/bpf_virtio_net/unbind
		fi
		printf '%s' "$virtio" > /sys/bus/virtio/drivers/virtio_net/bind
	fi
}
trap cleanup EXIT

ip link set "$original" down
ip link set "$peer" down
printf '%s' "$virtio" > /sys/bus/virtio/drivers/virtio_net/unbind
if ! printf '%s' "$virtio" > /sys/bus/virtio/drivers/bpf_virtio_net/bind; then
	printf '%s' "$virtio" > /sys/bus/virtio/drivers/virtio_net/bind
	exit 1
fi
rebound=1
for path in "/sys/bus/virtio/devices/$virtio/net/"*; do
	[[ -e $path ]] || continue
	experimental=${path##*/}
done
[[ -n $experimental ]]

ip netns add "$namespace"
namespace_created=1
ip link set "$peer" netns "$namespace"
peer_moved=1
ip -n "$namespace" link set lo up
ip -n "$namespace" addr add 192.0.2.2/24 dev "$peer"
peer_address_added=1
ip -n "$namespace" link set "$peer" up
ip addr add 192.0.2.1/24 dev "$experimental"

ifindex=$(<"/sys/class/net/$experimental/ifindex")
./bpf_net_driver_ctl --ifindex "$ifindex" --transport virtio --mode native -- true
./bpf_net_driver_ctl --ifindex "$ifindex" --transport virtio --mode bpf -- true

export BPF_NET_DRIVER_IFACE="$experimental"
export BPF_NET_DRIVER_PEER_NS="$namespace"
export BPF_NET_DRIVER_TRANSPORT=virtio
export BPF_NET_DRIVER_VIRTIO_DEVICE="$virtio"
export BPF_NET_DRIVER_ALLOW_REMOVE=1
./test_progs -t bpf_net_driver "$@"
