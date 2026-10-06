#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""A userspace reclaimer over memory.reclaim, the baseline the BPF pool is
compared against.

Two laws, one loop. Every --interval seconds it reads each child of the
root cgroup and writes an amount to its memory.reclaim.

  senpai   Senpai's probe: a child whose memory pressure, the PSI "some"
           stall accumulated over the interval, is under --target is asked
           for --probe percent of its usage, scaled down as pressure
           approaches the target; a child over the target is left alone
           for a doubling number of intervals. Nothing is reclaimed for
           any other reason. This trims idle memory and finds working sets.

  buffer   The pool's objective from userspace: the gap between MemFree
           and --buffer MB is split among the children in proportion to
           their usage above --floor MB, with the same probe law on top
           when --probe is given, and the same pressure gate. This is what
           a tuned userspace controller does with the same signals, read
           through cgroupfs at the same tick, and it pays the user/kernel
           round trips the pool does not.

Prints a status line per interval and totals on SIGTERM or SIGINT, as
key=value lines, so the harness can read both the same way.
"""

import argparse
import os
import signal
import sys
import time

MB = 1 << 20
stop = False


def on_signal(signum, frame):
    global stop
    stop = True


def read(path):
    with open(path) as f:
        return f.read()


def read_int(path):
    try:
        return int(read(path).strip())
    except (OSError, ValueError):
        return 0


def pressure_some_us(path):
    """The total= of the some line of memory.pressure, in microseconds."""
    try:
        for line in read(os.path.join(path, 'memory.pressure')).splitlines():
            if line.startswith('some'):
                return int(line.split('total=')[1])
    except (OSError, IndexError, ValueError):
        pass
    return 0


def meminfo_free():
    for line in read('/proc/meminfo').splitlines():
        if line.startswith('MemFree:'):
            return int(line.split()[1]) * 1024
    return 0


class Child:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.last_stall = pressure_some_us(path)
        self.rest = 0
        self.backoff = 1
        self.asked = 0
        self.reclaimed = 0
        self.writes = 0
        self.failed = 0
        self.gated = 0
        self.busy = 0.0

    def reclaim(self, amount):
        """Ask the kernel for amount bytes; returns what usage dropped by."""
        before = read_int(os.path.join(self.path, 'memory.current'))
        t0 = time.monotonic()
        try:
            with open(os.path.join(self.path, 'memory.reclaim'), 'w') as f:
                f.write(str(amount))
        except OSError:
            self.failed += 1
        self.busy += time.monotonic() - t0
        after = read_int(os.path.join(self.path, 'memory.current'))
        self.writes += 1
        self.asked += amount
        got = max(before - after, 0)
        self.reclaimed += got
        return got


def children_of(root):
    out = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if os.path.isdir(path) and os.path.exists(os.path.join(path, 'memory.current')):
            out.append(path)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root')
    ap.add_argument('--law', choices=['senpai', 'buffer'], default='senpai')
    ap.add_argument('--interval', type=float, default=6.0, help='seconds between passes')
    ap.add_argument('--target', type=float, default=1.0, help='PSI some target, percent of time')
    ap.add_argument('--probe', type=float, default=1.0,
                    help='percent of usage asked per pass under target; senpai default 1')
    ap.add_argument('--max-rest', type=int, default=16, help='longest rest after a gate, in passes')
    ap.add_argument('--buffer', type=int, default=0, help='MB of free memory to keep (buffer law)')
    ap.add_argument('--floor', type=int, default=0, help='MB never reclaimed below')
    ap.add_argument('--status', action='store_true', default=True)
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    kids = {}
    passes = 0
    deficit_passes = 0
    free_min = None
    print(f'ready law={args.law} interval={args.interval}s target={args.target}% '
          f'probe={args.probe}%/pass buffer={args.buffer}M', flush=True)
    t0 = time.monotonic()
    next_pass = t0 + args.interval
    while not stop:
        now = time.monotonic()
        if now < next_pass:
            time.sleep(min(0.05, next_pass - now))
            continue
        dt = now - (next_pass - args.interval)
        next_pass += args.interval
        passes += 1

        paths = children_of(args.root)
        for path in paths:
            if path not in kids:
                kids[path] = Child(path)
        for path in list(kids):
            if path not in paths:
                del kids[path]

        free = meminfo_free()
        free_min = free if free_min is None else min(free_min, free)
        deficit = max(args.buffer * MB - free, 0) if args.law == 'buffer' else 0
        if deficit:
            deficit_passes += 1

        # Sample: pressure over the pass, usage above the floor.
        offers = {}
        total = 0
        for kid in kids.values():
            stall = pressure_some_us(kid.path)
            kid.pressure = (stall - kid.last_stall) / (dt * 1e6) * 100 if dt > 0 else 0
            kid.last_stall = stall
            usage = read_int(os.path.join(kid.path, 'memory.current'))
            kid.usage = usage
            headroom = max(usage - args.floor * MB, 0)
            if kid.pressure >= args.target:
                kid.gated += 1
                kid.rest = kid.backoff
                kid.backoff = min(kid.backoff * 2, args.max_rest)
                headroom = 0
            elif kid.rest:
                kid.rest -= 1
                headroom = 0
            else:
                kid.backoff = max(kid.backoff // 2, 1)
            offers[kid] = headroom
            total += headroom

        # Act: the deficit by share of headroom, the probe by pressure room.
        reclaimed = 0
        for kid, headroom in offers.items():
            if not headroom:
                continue
            amount = 0
            if deficit and total:
                amount += deficit * headroom // total
            if args.probe:
                room = max(args.target - kid.pressure, 0) / args.target if args.target else 1
                amount += int(headroom * args.probe / 100 * room)
            amount &= ~4095
            if amount:
                reclaimed += kid.reclaim(amount)

        if args.status:
            print(f't={now - t0:.1f} free={free / MB:.0f}M deficit={deficit / MB:.0f}M '
                  f'reclaimed={reclaimed / MB:.1f}M cgroups={len(kids)}', flush=True)
            for kid in kids.values():
                print(f'  cg={kid.name} usage={kid.usage / MB:.0f}M pressure={kid.pressure:.2f}% '
                      f'rest={kid.rest} reclaimed={kid.reclaimed / MB:.0f}M', flush=True)

    print(f'control passes={passes} deficit_passes={deficit_passes} '
          f'free_min={free_min or 0} reclaimed={sum(k.reclaimed for k in kids.values())}')
    for kid in kids.values():
        print(f'cgroup={kid.name} reclaimed={kid.reclaimed} asked={kid.asked} writes={kid.writes} '
              f'failed={kid.failed} busy_ms={int(kid.busy * 1000)} gated={kid.gated} '
              f'usage={kid.usage}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
