#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# How long a write to memory.reclaim takes on a hot set, against the cost
# of one bpf_proactive_reclaim() call on the same set. Runs inside the
# guest as root:
#
#   bench/reclaim_latency.sh [out-dir]
#
# For each hot set size, a workload walks the set continuously; then each
# amount is written to its memory.reclaim under a timeout, and the wall
# time, the usage change and the stall are recorded. Then bpf_reclaim runs
# over it alone with a probe for ten seconds, and its calls and busy time
# give the cost of one call. Prints key=value lines and a table.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/.." && pwd)
BIN=${BIN:-$TOP/build/bin}
OUT=${1:-$TOP/build/results/reclaim-latency}
SIZES=${SIZES:-1024 4096}
AMOUNTS=${AMOUNTS:-4 64 256}
TIMEOUT=${TIMEOUT:-60}
CG=/sys/fs/cgroup/bpf-reclaim-latency
SWAP_MB=${SWAP_MB:-8192}

mkdir -p "$OUT"
grep -q ' cgroup2 ' /proc/mounts || mount -t cgroup2 none /sys/fs/cgroup
echo never > /sys/kernel/mm/transparent_hugepage/enabled
if ! grep -q zram0 /proc/swaps && [ -e /sys/block/zram0 ]; then
	echo $((SWAP_MB << 20)) > /sys/block/zram0/disksize && mkswap /dev/zram0 > /dev/null && swapon /dev/zram0
fi
echo +memory > /sys/fs/cgroup/cgroup.subtree_control
mkdir -p $CG && echo +memory > $CG/cgroup.subtree_control

printf '%-6s %-8s %-10s %-10s %-10s %-10s\n' size amount seconds freed_mb refaults note | tee "$OUT/table.txt"
for size in $SIZES; do
	mkdir -p $CG/hot
	( echo $BASHPID > $CG/hot/cgroup.procs; exec "$BIN/workload" anon --size "$size" --threads 8 --fill 50 ) > "$OUT/hot-$size.log" 2>&1 &
	wl=$!
	sleep $((5 + size / 1024))
	for amount in $AMOUNTS; do
		before=$(cat $CG/hot/memory.current)
		rf0=$(awk '/workingset_refault_(anon|file)/{s+=$2} END{print s}' $CG/hot/memory.stat)
		t0=$(date +%s.%N)
		timeout -s INT "$TIMEOUT" bash -c "echo $((amount << 20)) > $CG/hot/memory.reclaim" 2>/dev/null
		rc=$?
		t1=$(date +%s.%N)
		after=$(cat $CG/hot/memory.current)
		rf1=$(awk '/workingset_refault_(anon|file)/{s+=$2} END{print s}' $CG/hot/memory.stat)
		note=ok; [ $rc -eq 124 ] && note=timeout; [ $rc -ne 0 ] && [ $rc -ne 124 ] && note=err$rc
		printf '%-6s %-8s %-10.2f %-10d %-10d %-10s\n' "$size" "${amount}M" "$(echo "$t1 - $t0" | bc)" \
			"$(( (before - after) >> 20 ))" "$((rf1 - rf0))" "$note" | tee -a "$OUT/table.txt"
		echo "memory_reclaim size_mb=$size amount_mb=$amount seconds=$(echo "$t1 - $t0" | bc) freed_mb=$(( (before - after) >> 20 )) refaults=$((rf1 - rf0)) rc=$rc" >> "$OUT/results.txt"
		sleep 3
	done
	# The kfunc, one call at a time, through the pool's probe for ten seconds.
	timeout -s INT 12 "$BIN/bpf_reclaim" --buffer 1 --pool 1 --probe 100 --cpu-budget 100 \
		--min-efficiency 0 --lead-ms 0 $CG > "$OUT/bpf-$size.log" 2>&1
	calls=$(grep '^cgroup=hot' "$OUT/bpf-$size.log" | grep -o ' calls=[0-9]*' | cut -d= -f2)
	busy=$(grep '^cgroup=hot' "$OUT/bpf-$size.log" | grep -o 'busy_ms=[0-9]*' | cut -d= -f2)
	got=$(grep '^cgroup=hot' "$OUT/bpf-$size.log" | grep -o 'reclaimed=[0-9]*' | head -1 | cut -d= -f2)
	rf=$(grep '^cgroup=hot' "$OUT/bpf-$size.log" | grep -o 'refaults=[0-9]*' | cut -d= -f2)
	if [ -n "$calls" ] && [ "$calls" -gt 0 ]; then
		printf '%-6s %-8s %-10.3f %-10d %-10d %-10s\n' "$size" kfunc "$(echo "$busy / 1000 / $calls" | bc -l)" \
			"$((got >> 20))" "$rf" "per-call,${calls}calls" | tee -a "$OUT/table.txt"
		echo "kfunc size_mb=$size calls=$calls busy_ms=$busy reclaimed=$got refaults=$rf" >> "$OUT/results.txt"
	else
		echo "kfunc size_mb=$size: no calls (see bpf-$size.log)" | tee -a "$OUT/table.txt"
	fi
	kill -INT $wl 2>/dev/null; wait $wl 2>/dev/null
	sleep 2
	rmdir $CG/hot 2>/dev/null
done
