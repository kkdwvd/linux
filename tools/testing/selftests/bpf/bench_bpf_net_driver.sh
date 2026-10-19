#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Compare the native reference and BPF policies of an existing BPF transport.
# Configure the device, peer, routes, IRQ placement and workload beforehand.
# This does not bind hardware or compare against stock virtio_net/mlx5e.
set -euo pipefail

usage()
{
	echo "Usage: $0 --interface NAME --transport virtio|mlx5 [--config FILE] [--runs N] [--output DIR] -- COMMAND [ARG...]" >&2
}

interface=""
transport=""
config=""
runs=3
output=""
while (( $# )); do
	case "$1" in
	--interface|--transport|--config|--runs|--output)
		(( $# >= 2 )) || { usage; exit 2; }
		case "$1" in
		--interface) interface=$2 ;;
		--transport) transport=$2 ;;
		--config) config=$2 ;;
		--runs) runs=$2 ;;
		--output) output=$2 ;;
		esac
		shift 2
		;;
	--) shift; break ;;
	--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done
if [[ -z $interface || ! $transport =~ ^(virtio|mlx5)$ || ! $runs =~ ^[1-9][0-9]*$ ]] ||
   (( $# == 0 )); then
	usage
	exit 2
fi
if [[ $EUID != 0 ]]; then
	echo "Run as root; the loader changes the selected interface's UP state." >&2
	exit 1
fi
for tool in ip ethtool taskset sha256sum; do
	command -v "$tool" >/dev/null
done
command -v "$1" >/dev/null
script_dir=$(dirname "$(readlink -f "$0")")
loader="$script_dir/bpf_net_driver_ctl"
[[ -x $loader ]]
[[ -r /sys/class/net/$interface/ifindex ]]
ifindex=$(<"/sys/class/net/$interface/ifindex")
[[ $(<"/sys/class/net/$interface/bpf_driver/state") == native ]]

if [[ -z $config ]]; then
	for path in /proc/config.gz "/boot/config-$(uname -r)" "/lib/modules/$(uname -r)/build/.config"; do
		if [[ -r $path ]]; then
			config=$path
			break
		fi
	done
fi
if [[ -z $config || ! -r $config ]]; then
	echo "Supply --config for the running kernel; benchmark configuration must be recorded." >&2
	exit 1
fi
if [[ -n $output ]]; then
	mkdir -- "$output"
else
	output=$(mktemp -d /tmp/bpf-net-bench.XXXXXX)
fi
output=$(readlink -f "$output")
if [[ $config == *.gz ]]; then
	gzip -cd -- "$config" > "$output/kernel.config"
else
	cp -- "$config" "$output/kernel.config"
fi
debug_options='LOCKDEP|PROVE_LOCKING|PROVE_RCU|DEBUG_PREEMPT|DEBUG_SPINLOCK'
debug_options+='|DEBUG_MUTEXES|DEBUG_RT_MUTEXES|DEBUG_LOCK_ALLOC|CPU_MITIGATIONS'
if grep -Eq "^CONFIG_($debug_options)=y$" "$output/kernel.config"; then
	echo "Use a benchmark kernel with lock/preemption debugging and CPU mitigations compiled out." >&2
	exit 1
fi

{
	uname -a
	printf 'config_source=%q\ninterface=%q\ntransport=%q\n' "$config" "$interface" "$transport"
	printf 'workload_argv='
	printf '%q ' "$@"
	printf '\n'
	printf 'kernel_cmdline='
	cat /proc/cmdline
	taskset -pc "$$"
	sha256sum "$output/kernel.config" "$loader"
} > "$output/environment.txt"
cat /proc/cpuinfo > "$output/cpuinfo.txt"
cat /proc/interrupts > "$output/interrupts.before.txt"
for path in /proc/irq/[0-9]*/smp_affinity_list; do
	printf '%s ' "$path"
	cat "$path"
done > "$output/irq-affinity.txt"
for path in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
	[[ -r $path ]] || continue
	printf '%s ' "$path"
	cat "$path"
done > "$output/cpu-governors.txt"

snapshot()
{
	local prefix=$1

	ip -details -json link show dev "$interface" > "$prefix.link.json"
	ip -statistics -json link show dev "$interface" > "$prefix.statistics.json"
	cat "/sys/class/net/$interface/mtu" > "$prefix.mtu"
	(ethtool -i "$interface" || true) > "$prefix.driver" 2>&1
	(ethtool -k "$interface" || true) > "$prefix.features" 2>&1
	(ethtool -l "$interface" || true) > "$prefix.queues" 2>&1
	(ethtool -g "$interface" || true) > "$prefix.rings" 2>&1
	for path in "/sys/class/net/$interface/bpf_driver/"*; do
		printf '%s=' "${path##*/}"
		cat "$path"
	done > "$prefix.bpf-driver"
}

snapshot "$output/baseline"
for (( pair = 1; pair <= runs; pair++ )); do
	# Alternate order to make every pair contain one run of each policy.
	if (( pair % 2 )); then
		modes=(native bpf)
	else
		modes=(bpf native)
	fi
	for mode in "${modes[@]}"; do
		prefix="$output/pair-$pair-$mode"
		snapshot "$prefix.before"
		printf 'pair=%d mode=%s\n' "$pair" "$mode" | tee -a "$output/order.txt"
		if ! "$loader" --ifindex "$ifindex" --transport "$transport" --mode "$mode" \
			-- "$@" > "$prefix.stdout" 2> "$prefix.stderr"; then
			cat "$prefix.stderr" >&2
			echo "Workload or driver failed; reject this comparison. Artifacts: $output" >&2
			exit 1
		fi
		snapshot "$prefix.after"
		for property in mtu features queues rings driver; do
			if ! cmp -s "$output/baseline.$property" "$prefix.after.$property"; then
				echo "Interface $property changed; reject this comparison. Artifacts: $output" >&2
				exit 1
			fi
		done
	done
done
cat /proc/interrupts > "$output/interrupts.after.txt"
echo "Paired native/BPF reference-policy artifacts: $output"
