#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run one proactive reclaim scenario and summarise it.

Runs as root on a host or in a guest with cgroup v2. Sets up zram swap and
one cgroup per workload under a parent, starts the workloads, lets them
settle, runs a reclaimer over the parent for --seconds, then stops
everything and writes a summary: whether the free-memory buffer held, what
the kernel's own reclaim had to do, what each cgroup looks like and what
reclaim cost it in CPU, and how each workload fared in throughput and chunk
latency. Everything the run produced lands in --out.

Modes, all over the same workloads:

  none       no reclaimer; the kernel's kswapd and direct reclaim alone
  bpf        bpf_reclaim, the BPF pool, with --policy-args passed through;
             its threads are placed in a cgroup of their own so that their
             CPU is reported
  userspace  userspace_reclaim.py --law buffer: the pool's objective from
             userspace through memory.reclaim at --userspace-interval
  senpai     userspace_reclaim.py --law senpai: pressure-targeted trimming
             with no buffer objective, Senpai's law and interval

Scenarios:

  overcommit a hot anonymous working set, a page cache working set, a cold
             anonymous set, and after --grow-after seconds an allocator
             growing at --grow-rate MB/s to --grow-mb
  scale-anon the three residents plus --apps allocators in cgroups of
             their own, each ramping from --app-rate to --app-rate-max MB/s
             over --ramp seconds, so that the pool must reclaim at the
             aggregate rate in parallel across cgroups
  scale-file the same with streaming readers of a file instead

The VM that runs this is not its business; see the README for examples.
"""

import argparse
import json
import os
import resource
import signal
import subprocess
import sys
import time

CGROUP_ROOT = '/sys/fs/cgroup'
PARENT = 'bpf-reclaim-bench'
POOL = 'bpf-reclaim-pool'
MB = 1 << 20

VMSTAT_KEYS = ['pgsteal_kswapd', 'pgsteal_direct', 'pgsteal_proactive', 'pgscan_kswapd',
               'pgscan_direct', 'pgscan_proactive', 'allocstall_normal', 'allocstall_movable',
               'pswpout', 'pswpin', 'workingset_refault_anon', 'workingset_refault_file',
               'oom_kill']


def log(msg):
    print(f'bench: {msg}', flush=True)


def write(path, value):
    with open(path, 'w') as f:
        f.write(str(value))


def read(path):
    with open(path) as f:
        return f.read()


def read_kv(path):
    out = {}
    try:
        for line in read(path).splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    out[parts[0].rstrip(':')] = int(parts[1])
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def meminfo():
    return {k: v * 1024 for k, v in read_kv('/proc/meminfo').items()}


def cpu_times():
    """user nice system idle iowait irq softirq steal of all CPUs, in ticks."""
    with open('/proc/stat') as f:
        return [int(x) for x in f.readline().split()[1:9]]


def cpu_split(after, before):
    d = [a - b for a, b in zip(after, before)]
    total = sum(d) or 1
    return {'user': 100 * (d[0] + d[1]) / total, 'system': 100 * d[2] / total,
            'idle': 100 * (d[3] + d[4]) / total, 'irq': 100 * (d[5] + d[6]) / total}


def setup_swap(swap_mb):
    if not swap_mb:
        return 'none'
    if not os.path.exists('/sys/block/zram0'):
        log('no zram device: the kernel lacks CONFIG_ZRAM, anon reclaim will find nothing')
        return 'none'
    swapon = read('/proc/swaps')
    if '/dev/zram0' in swapon:
        return 'zram (already on)'
    write('/sys/block/zram0/disksize', swap_mb * MB)
    subprocess.run(['mkswap', '/dev/zram0'], check=True, capture_output=True)
    subprocess.run(['swapon', '/dev/zram0'], check=True, capture_output=True)
    return f'zram {swap_mb}M'


def setup_cgroups(names, want_cpu):
    if not os.path.exists(os.path.join(CGROUP_ROOT, 'cgroup.controllers')):
        subprocess.run(['mount', '-t', 'cgroup2', 'none', CGROUP_ROOT], check=True)
    controllers = read(os.path.join(CGROUP_ROOT, 'cgroup.controllers')).split()
    if 'memory' not in controllers:
        raise SystemExit('bench: no memory controller')
    enable = '+memory' + (' +cpu' if want_cpu and 'cpu' in controllers else '')
    write(os.path.join(CGROUP_ROOT, 'cgroup.subtree_control'), enable)
    parent = os.path.join(CGROUP_ROOT, PARENT)
    os.makedirs(parent, exist_ok=True)
    write(os.path.join(parent, 'cgroup.subtree_control'), enable)
    pool = os.path.join(CGROUP_ROOT, POOL)
    os.makedirs(pool, exist_ok=True)
    paths = {}
    for name in names:
        path = os.path.join(parent, name)
        os.makedirs(path, exist_ok=True)
        paths[name] = path
    return parent, pool, paths


def pressure(path):
    """some and full total stall time of memory.pressure, in seconds."""
    out = {}
    try:
        for line in read(os.path.join(path, 'memory.pressure')).splitlines():
            parts = line.split()
            out[parts[0]] = int(parts[-1].split('=')[1]) / 1e6
    except OSError:
        pass
    return out


def cgroup_view(path):
    st = read_kv(os.path.join(path, 'memory.stat'))
    ev = read_kv(os.path.join(path, 'memory.events'))
    cpu = read_kv(os.path.join(path, 'cpu.stat'))
    swap_path = os.path.join(path, 'memory.swap.current')
    return {
        'current_mb': int(read(os.path.join(path, 'memory.current'))) // MB,
        'anon_mb': st.get('anon', 0) // MB,
        'file_mb': st.get('file', 0) // MB,
        'swap_mb': int(read(swap_path)) // MB if os.path.exists(swap_path) else 0,
        'refaults': st.get('workingset_refault_anon', 0) + st.get('workingset_refault_file', 0),
        'pgscan_proactive': st.get('pgscan_proactive', 0),
        'pgsteal_proactive': st.get('pgsteal_proactive', 0),
        'pgsteal_direct': st.get('pgsteal_direct', 0),
        'high_events': ev.get('high', 0),
        'max_events': ev.get('max', 0),
        'oom_events': ev.get('oom', 0),
        'pressure': pressure(path),
        'cpu_usage_s': cpu.get('usage_usec', 0) / 1e6,
        'cpu_system_s': cpu.get('system_usec', 0) / 1e6,
    }


class Workload:
    def __init__(self, name, argv, cgroup, out, start_after=0):
        self.name = name
        self.argv = argv
        self.cgroup = cgroup
        self.logpath = os.path.join(out, f'{name}.log')
        self.start_after = start_after
        self.proc = None
        self.logf = None

    def start(self):
        cgroup = self.cgroup

        def enter():
            write(os.path.join(cgroup, 'cgroup.procs'), os.getpid())

        self.logf = open(self.logpath, 'w')
        self.proc = subprocess.Popen(self.argv, stdout=self.logf, stderr=subprocess.STDOUT,
                                     preexec_fn=enter)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.logf:
            self.logf.close()

    def summary(self):
        secs = []
        try:
            for line in open(self.logpath):
                if not line.startswith('t='):
                    continue
                kv = dict(p.split('=') for p in line.split())
                secs.append((float(kv['mb']), int(kv['p99_us']), int(kv['max_us'])))
        except (OSError, KeyError, ValueError):
            pass
        if not secs:
            return None
        mbs = [s[0] for s in secs]
        p99 = sorted(s[1] for s in secs)
        return {
            'seconds': len(secs),
            'mb_s': sum(mbs) / len(mbs),
            'mb_s_min': min(mbs),
            'p99_us_median': p99[len(p99) // 2],
            'p99_us_max': p99[-1],
            'max_us': max(s[2] for s in secs),
        }


def scenario_names(args):
    # The residents with a size, then the scenario's own workloads.
    names = [n for n, mb in (('hot', args.hot_mb), ('cache', args.cache_mb),
                             ('cold', args.cold_mb)) if mb]
    if args.scenario == 'overcommit':
        return names + (['grow'] if args.grow_after >= 0 else [])
    return names + [f'app{i}' for i in range(args.apps)]


def scenario(args, paths, out):
    workload = os.path.join(args.bin, 'workload')
    fill = ['--fill', str(args.fill)]
    wls = []
    if args.hot_mb:
        wls.append(Workload('hot', [workload, 'anon', '--size', str(args.hot_mb), '--threads',
                                    str(args.hot_threads)] + fill, paths['hot'], out))
    if args.cache_mb:
        wls.append(Workload('cache', [workload, 'file', '--path', args.data, '--size',
                                      str(args.cache_mb), '--pass-ms', str(args.cache_pass_ms)],
                            paths['cache'], out))
    if args.cold_mb:
        wls.append(Workload('cold', [workload, 'anon', '--size', str(args.cold_mb), '--once'] + fill,
                            paths['cold'], out))
    if args.scenario == 'overcommit':
        if args.grow_after >= 0:
            wls.append(Workload('grow', [workload, 'grow', '--rate', str(args.grow_rate),
                                         '--limit', str(args.grow_mb)] + fill,
                                paths['grow'], out, start_after=args.grow_after))
        return wls
    ramp = ['--rate', str(args.app_rate), '--rate-max', str(args.app_rate_max),
            '--ramp', str(args.ramp)]
    for i in range(args.apps):
        name = f'app{i}'
        if args.scenario == 'scale-anon':
            argv = [workload, 'grow', '--limit', str(args.app_mb)] + ramp + fill
        else:
            argv = [workload, 'file', '--path', args.data, '--stream', '--size', str(args.app_mb),
                    '--offset', str((i + 1) * args.app_mb)] + ramp
        wls.append(Workload(name, argv, paths[name], out, start_after=max(args.grow_after, 0)))
    return wls


def reclaimer_argv(args, parent, pool):
    if args.mode == 'none':
        return None
    if args.mode == 'bpf':
        argv = [os.path.join(args.bin, 'bpf_reclaim'), '--buffer', str(args.buffer_mb),
                '--pool-cgroup', pool]
        if args.policy_args:
            argv += args.policy_args.split()
        return argv + [parent]
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'userspace_reclaim.py')
    argv = [sys.executable, script, parent]
    if args.mode == 'userspace':
        argv += ['--law', 'buffer', '--buffer', str(args.buffer_mb),
                 '--interval', str(args.userspace_interval), '--probe', str(args.userspace_probe)]
    else:
        argv += ['--law', 'senpai', '--interval', str(args.senpai_interval),
                 '--probe', str(args.senpai_probe)]
    if args.userspace_args:
        argv += args.userspace_args.split()
    return argv


def wait_ready(proc, logpath, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        if 'ready' in read(logpath):
            return True
        time.sleep(0.2)
    return False


def parse_totals(logpath):
    totals = {'control': {}, 'cgroups': {}, 'threads': []}
    try:
        for line in open(logpath):
            if line.startswith('control '):
                totals['control'] = dict(p.split('=', 1) for p in line.split()[1:])
            elif line.startswith('cgroup='):
                kv = dict(p.split('=', 1) for p in line.split())
                totals['cgroups'][kv['cgroup']] = kv
            elif line.startswith('thread='):
                totals['threads'].append(dict(p.split('=', 1) for p in line.split()))
    except OSError:
        pass
    return totals


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bin', required=True, help='directory with bpf_reclaim and workload')
    ap.add_argument('--out', required=True, help='directory for logs and the summary')
    ap.add_argument('--data', help='file for the page cache workloads; created sparse if missing')
    ap.add_argument('--data-mb', type=int, default=65536, help='size of that file when created')
    ap.add_argument('--scenario', choices=['overcommit', 'scale-anon', 'scale-file'],
                    default='overcommit')
    ap.add_argument('--mode', choices=['none', 'bpf', 'userspace', 'senpai'], default='bpf')
    ap.add_argument('--seconds', type=int, default=60)
    ap.add_argument('--settle', type=int, default=5,
                    help='seconds the resident workloads get before the reclaimer starts')
    ap.add_argument('--swap-mb', type=int, default=4096, help='zram swap size, 0 for none')
    ap.add_argument('--buffer-mb', type=int, default=0,
                    help='free memory to keep; default an eighth of RAM')
    ap.add_argument('--policy-args', default='', help='extra bpf_reclaim arguments')
    ap.add_argument('--userspace-args', default='', help='extra userspace_reclaim.py arguments')
    ap.add_argument('--userspace-interval', type=float, default=0.1)
    ap.add_argument('--userspace-probe', type=float, default=0)
    ap.add_argument('--senpai-interval', type=float, default=6)
    ap.add_argument('--senpai-probe', type=float, default=1)
    # The scenario.
    ap.add_argument('--hot-mb', type=int, default=600, help='0 leaves a resident out')
    ap.add_argument('--hot-threads', type=int, default=2)
    ap.add_argument('--cache-mb', type=int, default=400)
    ap.add_argument('--cache-pass-ms', type=int, default=2000)
    ap.add_argument('--cold-mb', type=int, default=700)
    ap.add_argument('--grow-mb', type=int, default=1200)
    ap.add_argument('--grow-rate', type=int, default=100, help='MB/s')
    ap.add_argument('--grow-after', type=int, default=20,
                    help='seconds before the allocators start; -1 never starts them')
    ap.add_argument('--fill', type=int, default=50, help='percent of each anon page random')
    ap.add_argument('--apps', type=int, default=4)
    ap.add_argument('--app-rate', type=int, default=20)
    ap.add_argument('--app-rate-max', type=int, default=100)
    ap.add_argument('--ramp', type=int, default=40)
    ap.add_argument('--app-mb', type=int, default=8192)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    if not args.data:
        args.data = os.path.join(args.bin, 'data.bin')
    if not os.path.exists(args.data):
        with open(args.data, 'wb') as f:
            f.truncate(args.data_mb * MB)
    thp = '/sys/kernel/mm/transparent_hugepage/enabled'
    if os.path.exists(thp):
        write(thp, 'never')
    mem = meminfo()
    if not args.buffer_mb:
        args.buffer_mb = mem['MemTotal'] // MB // 8
    swap = setup_swap(args.swap_mb)
    names = scenario_names(args)
    parent, pool, paths = setup_cgroups(names, True)
    wls = scenario(args, paths, args.out)
    log(f'MemTotal={mem["MemTotal"] // MB}M MemFree={mem["MemFree"] // MB}M swap={swap} '
        f'buffer={args.buffer_mb}M mode={args.mode} scenario={args.scenario}')

    for w in wls:
        if not w.start_after:
            w.start()
    log(f'workloads started, settling for {args.settle}s')
    time.sleep(args.settle)

    vm_before = read_kv('/proc/vmstat')
    cpu_before = cpu_times()
    cg_before = {n: cgroup_view(paths[n]) for n in names if os.path.exists(paths[n])}
    pool_before = cgroup_view(pool)
    with open(os.path.join(args.out, 'vmstat.before'), 'w') as f:
        f.write(read('/proc/vmstat'))

    reclaimer = None
    reclaimer_log = None
    argv = reclaimer_argv(args, parent, pool)
    if argv:
        reclaimer_log = open(os.path.join(args.out, 'reclaimer.log'), 'w')
        log('starting the reclaimer: ' + ' '.join(argv))
        reclaimer = subprocess.Popen(argv, stdout=reclaimer_log, stderr=subprocess.STDOUT)
        if not wait_ready(reclaimer, os.path.join(args.out, 'reclaimer.log')):
            reclaimer_log.close()
            print(read(os.path.join(args.out, 'reclaimer.log')))
            for w in wls:
                w.stop()
            raise SystemExit('bench: the reclaimer did not become ready')

    free_series = []
    t0 = time.monotonic()
    with open(os.path.join(args.out, 'meminfo.csv'), 'w') as mf:
        mf.write('t,free_mb,available_mb,swap_used_mb\n')
        while time.monotonic() - t0 < args.seconds:
            time.sleep(1)
            t = time.monotonic() - t0
            for w in wls:
                if w.start_after and not w.proc and t >= w.start_after:
                    w.start()
                    log(f'{w.name} started at {t:.0f}s')
            m = meminfo()
            free_series.append(m['MemFree'])
            mf.write(f'{t:.0f},{m["MemFree"] // MB},{m["MemAvailable"] // MB},'
                     f'{(m["SwapTotal"] - m["SwapFree"]) // MB}\n')

    cpu_after = cpu_times()
    cg_after = {n: cgroup_view(paths[n]) for n in names if os.path.exists(paths[n])}
    pool_after = cgroup_view(pool)
    controller_cpu = 0.0
    if reclaimer:
        reclaimer.send_signal(signal.SIGINT)
        try:
            _, status, ru = os.wait4(reclaimer.pid, 0)
            controller_cpu = ru.ru_utime + ru.ru_stime
        except ChildProcessError:
            pass
        reclaimer_log.close()
    for w in wls:
        w.stop()
    vm_after = read_kv('/proc/vmstat')
    with open(os.path.join(args.out, 'vmstat.after'), 'w') as f:
        f.write(read('/proc/vmstat'))

    cpu = cpu_split(cpu_after, cpu_before)
    delta = {k: vm_after.get(k, 0) - vm_before.get(k, 0) for k in VMSTAT_KEYS}
    totals = parse_totals(os.path.join(args.out, 'reclaimer.log')) if reclaimer else {}
    pool_cpu = pool_after['cpu_usage_s'] - pool_before['cpu_usage_s']

    lines = []
    lines.append(f'scenario: {args.scenario} {args.seconds}s mode={args.mode} '
                 f'buffer={args.buffer_mb}M swap={swap} fill={args.fill}%'
                 + (f' policy="{args.policy_args}"' if args.policy_args else ''))
    if args.scenario != 'overcommit':
        lines.append(f'applications: {args.apps} x {args.app_rate}->{args.app_rate_max} MB/s over '
                     f'{args.ramp}s from t={max(args.grow_after, 0)}s (aggregate '
                     f'{args.apps * args.app_rate}->{args.apps * args.app_rate_max} MB/s)')
    if free_series:
        below = sum(1 for f in free_series if f < args.buffer_mb * MB)
        lines.append(f'free memory: min {min(free_series) // MB}M, mean '
                     f'{sum(free_series) // len(free_series) // MB}M, last {free_series[-1] // MB}M'
                     f'; below the buffer {100 * below // len(free_series)}% of the time')
    lines.append(f'cpu: user {cpu["user"]:.0f}% system {cpu["system"]:.0f}% irq {cpu["irq"]:.0f}% '
                 f'idle {cpu["idle"]:.0f}% of {os.cpu_count()} CPUs; reclaimer: pool cgroup '
                 f'{pool_cpu:.1f}s, process {controller_cpu:.1f}s')
    lines.append(f'kernel reclaim: allocstall={delta["allocstall_normal"] + delta["allocstall_movable"]}'
                 f' pgsteal_direct={delta["pgsteal_direct"]} pgsteal_kswapd={delta["pgsteal_kswapd"]}'
                 f' pgsteal_proactive={delta["pgsteal_proactive"]} pages; swap out={delta["pswpout"]}'
                 f' in={delta["pswpin"]}; refaults anon={delta["workingset_refault_anon"]}'
                 f' file={delta["workingset_refault_file"]}; oom_kill={delta["oom_kill"]}')
    lines.append('')
    lines.append(f'{"cgroup":8} {"current":>8} {"anon":>6} {"file":>6} {"swapped":>8} '
                 f'{"refaults":>9} {"direct":>8} {"high":>6} {"some%":>7} {"full%":>7} '
                 f'{"cpu s":>7} {"sys s":>7}')
    for name in names:
        a, b = cg_after.get(name), cg_before.get(name)
        if not a:
            continue
        some = (a['pressure'].get('some', 0) - (b or a)['pressure'].get('some', 0)) / args.seconds * 100
        full = (a['pressure'].get('full', 0) - (b or a)['pressure'].get('full', 0)) / args.seconds * 100
        lines.append(f'{name:8} {a["current_mb"]:>7}M {a["anon_mb"]:>5}M {a["file_mb"]:>5}M '
                     f'{a["swap_mb"]:>7}M {a["refaults"] - (b or a)["refaults"]:>9} '
                     f'{a["pgsteal_direct"] - (b or a)["pgsteal_direct"]:>8} '
                     f'{a["high_events"] - (b or a)["high_events"]:>6} {some:>6.2f}% {full:>6.2f}% '
                     f'{a["cpu_usage_s"] - (b or a)["cpu_usage_s"]:>7.1f} '
                     f'{a["cpu_system_s"] - (b or a)["cpu_system_s"]:>7.1f}')
    lines.append('')
    lines.append(f'{"workload":8} {"secs":>5} {"MB/s":>9} {"min MB/s":>9} {"p99 med us":>11} '
                 f'{"p99 max us":>11} {"max us":>9}')
    summaries = {}
    for w in wls:
        s = w.summary()
        summaries[w.name] = s
        if not s:
            lines.append(f'{w.name:8} (no output)')
            continue
        lines.append(f'{w.name:8} {s["seconds"]:>5} {s["mb_s"]:>9.1f} {s["mb_s_min"]:>9.1f} '
                     f'{s["p99_us_median"]:>11} {s["p99_us_max"]:>11} {s["max_us"]:>9}')
    if totals.get('control'):
        c = totals['control']
        lines.append('')
        if 'ticks' in c:
            ticks = max(int(c['ticks']), 1)
            hist = [int(x) for x in c.get('awake_ticks', '0').split(',')]
            lines.append(f'reclaimer: {int(c["reclaimed"]) // MB}M reclaimed, buffer breached '
                         f'{100 * int(c["deficit_ticks"]) // ticks}% of ticks, free min '
                         f'{int(c["free_min"]) // MB}M, led {c.get("lead_ticks", 0)} ticks, '
                         f'behind {c.get("behind_ticks", 0)} ticks; workers awake per tick: '
                         + ' '.join(f'{i}{"+" if i == len(hist) - 1 else ""}:{100 * n // ticks}%'
                                    for i, n in enumerate(hist) if n))
        else:
            lines.append(f'reclaimer: {int(c.get("reclaimed", 0)) // MB}M reclaimed over '
                         f'{c.get("passes", "?")} passes, free min '
                         f'{int(c.get("free_min", 0)) // MB}M')
        for name, kv in totals['cgroups'].items():
            cost = int(kv.get('busy_ms', 0))
            got = int(kv.get('reclaimed', 0))
            eff = f'{got / MB / (cost / 1000):.0f}M/s' if cost else '-'
            lines.append(f'  {name}: reclaimed {got // MB}M in {cost}ms ({eff}), '
                         + ', '.join(f'{k}={kv[k]}' for k in ('calls', 'refaults', 'gated_ticks',
                                                              'expensive_ticks', 'throttles',
                                                              'writes', 'gated') if k in kv))
    summary = '\n'.join(lines)
    with open(os.path.join(args.out, 'summary.txt'), 'w') as f:
        f.write(summary + '\n')
    with open(os.path.join(args.out, 'summary.json'), 'w') as f:
        json.dump({'args': vars(args), 'free_series_mb': [x // MB for x in free_series],
                   'vmstat_delta': delta, 'cpu': cpu, 'pool_cpu_s': pool_cpu,
                   'controller_cpu_s': controller_cpu, 'cgroups_before': cg_before,
                   'cgroups_after': cg_after, 'workloads': summaries, 'reclaimer': totals},
                  f, indent=1, default=str)
    print(summary, flush=True)
    log(f'results in {args.out}')


if __name__ == '__main__':
    main()
