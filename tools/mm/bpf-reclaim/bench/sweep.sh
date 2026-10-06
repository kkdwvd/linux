#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Run a matrix of modes and pool sizes over a scenario and print the
# summaries. Each cell is one run.py invocation; set VM_CMD to a command
# prefix that boots a guest and runs its arguments there, for example
#   VM_CMD="kdev vm cmd --no-debug --disable-microvm --skip-modules --cpus 8 --memory 8G --"
# or a virtme-ng equivalent; without it the cells run on this host.
#
#   MODES="none userspace senpai bpf" POOLS="1 2 4" SCENARIOS="overcommit" bench/sweep.sh [run.py args]
#
# Results land under build/results/<scenario>-<mode>[-pool<N>]/.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/.." && pwd)
BIN=${BIN:-$TOP/build/bin}
OUT=${OUT:-$TOP/build/results}
VM_CMD=${VM_CMD:-}
MODES=${MODES:-none userspace bpf}
POOLS=${POOLS:-2}
SCENARIOS=${SCENARIOS:-overcommit}

for sc in $SCENARIOS; do
	for mode in $MODES; do
		pools="-"
		[[ $mode == bpf ]] && pools=$POOLS
		for pool in $pools; do
			name=$sc-$mode
			extra=()
			if [[ $pool != - ]]; then
				name=$name-pool$pool
				extra=(--policy-args "--pool $pool")
			fi
			dir=$OUT/$name
			rm -rf "$dir"
			mkdir -p "$dir"
			echo "=== $name ==="
			$VM_CMD python3 "$HERE/run.py" --bin "$BIN" --out "$dir" --scenario "$sc" \
				--mode "$mode" "${extra[@]}" "$@" > "$dir/run.log" 2>&1 ||
				echo "$name: run failed, see $dir/run.log"
			cat "$dir/summary.txt" 2>/dev/null
			echo
		done
	done
done
