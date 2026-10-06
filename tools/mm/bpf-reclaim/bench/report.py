#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Tabulate the summary.json files under a results directory.

  bench/report.py DIR...            one row per run: the buffer, the kernel's
                                    reclaim, the reclaimer's cost, the hot
                                    set's and the allocators' latency
  bench/report.py --cost DIR...     one row per run and cgroup: bytes per
                                    call and megabytes per CPU-second of
                                    the reclaim done there
"""

import argparse
import glob
import json
import os
import sys

MB = 1 << 20


def load(dirs):
    runs = []
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, '**', 'summary.json'), recursive=True)):
            with open(path) as f:
                j = json.load(f)
            j['name'] = os.path.basename(os.path.dirname(path))
            runs.append(j)
    return runs


def reclaimer_cpu(j):
    return j['pool_cpu_s'] if j['pool_cpu_s'] > 0.05 else j['controller_cpu_s']


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dirs', nargs='+')
    ap.add_argument('--cost', action='store_true')
    args = ap.parse_args()
    runs = load(args.dirs)
    if not runs:
        sys.exit('no summary.json found')

    if args.cost:
        print(f'{"run":28} {"cgroup":8} {"MB":>7} {"calls":>7} {"KB/call":>8} {"ms/call":>8} '
              f'{"MB/cpu-s":>9} {"MB/s":>7} {"refaults":>8}')
        for j in runs:
            secs = j['args']['seconds']
            for name, kv in sorted(j.get('reclaimer', {}).get('cgroups', {}).items()):
                got = int(kv.get('reclaimed', 0))
                calls = int(kv.get('calls', kv.get('writes', 0)) or 0)
                busy = int(kv.get('busy_ms', 0))
                print(f'{j["name"]:28} {name:8} {got / MB:>7.0f} {calls:>7} '
                      f'{got / 1024 / calls if calls else 0:>8.0f} '
                      f'{busy / calls if calls else 0:>8.2f} '
                      f'{got / MB / (busy / 1000) if busy else 0:>9.0f} {got / MB / secs:>7.0f} '
                      f'{kv.get("refaults", "-"):>8}')
        return

    print(f'{"run":28} {"mode":9} {"free min":>8} {"below%":>6} {"direct":>7} {"kswapd":>7} '
          f'{"reclaimed":>9} {"cpu s":>6} {"hot rf":>7} {"hot p99":>8} {"app p99":>8} {"awake":>14}')
    for j in runs:
        a = j['args']
        d = j['vmstat_delta']
        cg_b, cg_a = j['cgroups_before'], j['cgroups_after']
        free = j['free_series_mb']
        below = 100 * sum(1 for f in free if f < a['buffer_mb']) // max(len(free), 1)
        hot_rf = cg_a.get('hot', {}).get('refaults', 0) - cg_b.get('hot', {}).get('refaults', 0)
        hot = j['workloads'].get('hot') or {}
        apps = [v for k, v in j['workloads'].items() if (k.startswith('app') or k == 'grow') and v]
        app_p99 = max((v['p99_us_max'] for v in apps), default=0)
        c = j.get('reclaimer', {}).get('control', {})
        if 'reclaimed' in c:
            reclaimed = int(c['reclaimed']) // MB
        else:
            reclaimed = d['pgsteal_proactive'] * 4096 // MB
        awake = ''
        if 'awake_ticks' in c:
            ticks = max(int(c.get('ticks', 1)), 1)
            hist = [int(x) for x in c['awake_ticks'].split(',')]
            awake = ' '.join(f'{i}:{100 * n // ticks}' for i, n in enumerate(hist) if n)
        print(f'{j["name"]:28} {a["mode"]:9} {min(free) if free else 0:>7}M {below:>6} '
              f'{d["pgsteal_direct"]:>7} {d["pgsteal_kswapd"]:>7} {reclaimed:>8}M '
              f'{reclaimer_cpu(j):>6.1f} {hot_rf:>7} {hot.get("p99_us_max", 0):>8} {app_p99:>8} '
              f'{awake:>14}')


if __name__ == '__main__':
    main()
