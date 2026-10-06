#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# The evaluation's experiment groups, each a list of run.py invocations
# meant for one guest boot. Runs inside the guest as root:
#
#   bench/experiments.sh <group> [out-dir]
#
# Groups:
#   kfunc      bytes per call and CPU per byte of bpf_proactive_reclaim() by
#              memory type, and per-worker throughput against workers on one
#              memcg and across memcgs
#   scale      N applications ramping their aggregate rate, anon and file,
#              under the kernel alone, the userspace loop and pool sizes
#   tick       tick length against lead window during a burst
#   placement  shared pool against per-child workers
#   senpai     steady-state trimming: Senpai's loop against the probe
#   mixed      the realistic mix with a late burst, all modes, with and
#              without the throttle
#
# Sized for a guest of 64 vCPUs and 256 GB with 192 GB of zram: sets of
# tens of gigabytes, allocators at gigabytes a second, 32 applications. MEM
# scales every size and rate in proportion to a different guest's gigabytes
# (MEM=32 for a 32 GB guest). Results land under the out-dir, one directory
# per run.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/.." && pwd)
BIN=${BIN:-$TOP/build/bin}
GROUP=${1:?group}
OUT=${2:-$TOP/build/results/$GROUP}
MEM=${MEM:-256}
SWAP_MB=$(python3 -c "print(int(196608 * $MEM / 256))")
DATA=${DATA:-$TOP/build/results/data-sparse.bin}

mb() { python3 -c "print(int($1 * $MEM / 256))"; }

run() {
	local name=$1; shift
	local dir=$OUT/$name
	rm -rf "$dir"; mkdir -p "$dir"
	echo "=== $name: $*"
	python3 "$HERE/run.py" --bin "$BIN" --out "$dir" --swap-mb "$SWAP_MB" --data "$DATA" \
		--data-mb 400000 "$@" > "$dir/run.log" 2>&1 ||
		{ echo "$name: failed"; tail -5 "$dir/run.log"; }
	grep -E '^(free memory|cpu:|kernel reclaim|reclaimer:)' "$dir/summary.txt" 2>/dev/null | sed 's/^/    /'
}

mkdir -p "$OUT"
echo "group=$GROUP mem=$MEM cpus=$(nproc) memtotal=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)M out=$OUT"

case $GROUP in
kfunc)
	# One cold child of one memory type, a deficit larger than it, one worker.
	one=(--scenario overcommit --grow-after -1 --hot-mb 0 --cache-mb 0 --buffer-mb "$(mb 300000)"
		--settle 60 --seconds 90 --mode bpf)
	for fill in 0 50 100; do
		run anon-fill$fill "${one[@]}" --cold-mb "$(mb 32768)" --fill "$fill" \
			--policy-args "--pool 1 --lead-ms 0"
	done
	run file-clean --scenario overcommit --grow-after -1 --hot-mb 0 --cold-mb 0 \
		--cache-mb "$(mb 32768)" --cache-pass-ms 1000000000 --buffer-mb "$(mb 300000)" \
		--settle 60 --seconds 90 --mode bpf --policy-args "--pool 1 --lead-ms 0"
	# Workers on one memcg, then the same workers across four and sixteen.
	for pool in 2 4 8 16; do
		run one-memcg-pool$pool "${one[@]}" --cold-mb "$(mb 32768)" --fill 50 \
			--policy-args "--pool $pool --lead-ms 0"
	done
	many=(--scenario scale-anon --app-rate 8000 --app-rate-max 8000 --ramp 1 --grow-after 0
		--hot-mb 0 --cache-mb 0 --cold-mb 0 --fill 50 --buffer-mb "$(mb 300000)" --settle 60
		--seconds 90 --mode bpf)
	for pool in 4 8 16; do
		run four-memcgs-pool$pool "${many[@]}" --apps 4 --app-mb "$(mb 8192)" \
			--policy-args "--pool $pool --lead-ms 0"
	done
	for pool in 16 32; do
		run sixteen-memcgs-pool$pool "${many[@]}" --apps 16 --app-mb "$(mb 2048)" \
			--policy-args "--pool $pool --lead-ms 0"
	done
	;;
scale)
	common=(--apps 32 --app-rate 20 --app-rate-max 150 --ramp 40 --app-mb "$(mb 6144)"
		--grow-after 5 --hot-mb "$(mb 16384)" --hot-threads 8 --cache-mb "$(mb 16384)"
		--cache-threads 8 --cold-mb "$(mb 32768)" --cold-threads 8 --buffer-mb "$(mb 32768)"
		--settle 50 --seconds 80)
	for sc in scale-anon scale-file; do
		run $sc-none --scenario $sc "${common[@]}" --mode none
		run $sc-userspace --scenario $sc "${common[@]}" --mode userspace
		for pool in 4 8 16 32; do
			run $sc-bpf-pool$pool --scenario $sc "${common[@]}" --mode bpf \
				--policy-args "--pool $pool"
		done
	done
	;;
tick)
	# Residents of 160 GB leave about 90 GB free; the allocator then asks for
	# 128 GB at 2 GB/s, so the pool must move about 70 GB of cold memory out.
	common=(--scenario overcommit --hot-mb "$(mb 32768)" --hot-threads 8 --cache-mb "$(mb 32768)"
		--cold-mb "$(mb 98304)" --cold-threads 8 --cache-threads 8 --grow-mb "$(mb 131072)"
		--grow-rate 2000 --grow-threads 8 --grow-after 5 --buffer-mb "$(mb 32768)" --settle 60
		--seconds 90 --mode bpf)
	for interval in 25 100 400; do
		for lead in 0 1000; do
			run tick${interval}-lead$lead "${common[@]}" \
				--policy-args "--pool 8 --interval-ms $interval --lead-ms $lead"
		done
	done
	;;
placement)
	common=(--scenario overcommit --hot-mb "$(mb 32768)" --hot-threads 8 --cache-mb "$(mb 32768)"
		--cold-mb "$(mb 98304)" --cold-threads 8 --cache-threads 8 --grow-mb "$(mb 131072)"
		--grow-rate 2000 --grow-threads 8 --grow-after 5 --buffer-mb "$(mb 32768)" --settle 60
		--seconds 90 --mode bpf)
	run shared-pool8 "${common[@]}" --policy-args "--pool 8"
	run per-child2 "${common[@]}" --policy-args "--pool 0 --per-child 2"
	run per-child4 "${common[@]}" --policy-args "--pool 0 --per-child 4"
	run shared-pool8-cpus "${common[@]}" --policy-args "--pool 8 --cpus 56,57,58,59,60,61,62,63"
	;;
senpai)
	common=(--scenario overcommit --grow-after -1 --hot-mb "$(mb 16384)" --hot-threads 8
		--cache-mb "$(mb 16384)" --cache-threads 8 --cache-pass-ms 5000 --cold-mb "$(mb 49152)"
		--cold-threads 8 --buffer-mb "$(mb 4096)" --settle 50 --seconds 300)
	run senpai-6s "${common[@]}" --mode senpai --senpai-interval 6 --senpai-probe 1
	run bpf-probe0.17 "${common[@]}" --mode bpf --policy-args "--pool 4 --probe 0.17"
	run bpf-probe1 "${common[@]}" --mode bpf --policy-args "--pool 4 --probe 1"
	;;
mixed)
	common=(--scenario overcommit --hot-mb "$(mb 32768)" --hot-threads 8 --cache-mb "$(mb 32768)"
		--cache-threads 8 --cache-pass-ms 5000 --cold-mb "$(mb 98304)" --cold-threads 8
		--grow-mb "$(mb 131072)" --grow-rate 2000 --grow-threads 8 --grow-after 30
		--buffer-mb "$(mb 32768)" --settle 60 --seconds 150)
	run mixed-none "${common[@]}" --mode none
	run mixed-userspace "${common[@]}" --mode userspace
	run mixed-bpf-pool8 "${common[@]}" --mode bpf --policy-args "--pool 8"
	run mixed-bpf-pool8-throttle "${common[@]}" --mode bpf --policy-args "--pool 8 --throttle"
	;;
*)
	echo "unknown group $GROUP" >&2
	exit 2
	;;
esac
echo "group=$GROUP done"
