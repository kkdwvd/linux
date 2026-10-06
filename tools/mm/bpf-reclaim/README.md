bpf_reclaim: proactive memory reclaim in BPF
============================================

A pool of BPF kernel threads that keeps a buffer of free memory on an
overcommitted host by reclaiming cold memory from the children of a cgroup
ahead of demand, without eating any child's working set, and a benchmark
that measures it against the kernel alone and against userspace reclaimers
over `memory.reclaim`.

The policy is one program, `reclaim.bpf.c`, built up in the commits that add
it, each of which explains the piece it adds and what it measured. This file
is the operator's view: what it needs, how to build and run it, what the
knobs mean, and what the benchmark does.

Requirements
------------

A kernel from this tree with:

- `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_MEMCG`, cgroup v2;
- the BPF wait queue and kthread kfuncs and the memory cgroup kfuncs
  (`bpf_proactive_reclaim()`, `bpf_psi_total()`,
  `bpf_global_zone_page_state()`, `bpf_mem_cgroup_set_high()`), which the
  commits before this directory add;
- `CONFIG_PSI`, for the pressure signal (without it the gate runs on
  refaults alone);
- swap, for anonymous memory to be reclaimable at all; the benchmark uses
  `CONFIG_ZRAM` with the LZO backend.

On the build host: clang, and the tree's libbpf and bpftool, which the
Makefile builds.

Building
--------

    make -C tools/mm/bpf-reclaim

builds `build/bin/bpf_reclaim` and `build/bin/workload`. The BPF program is
compiled against `vmlinux.h` generated from the tree's `vmlinux`; point
`VMLINUX_BTF=` at it when it is not in the tree root, or `VMLINUX_H=` at an
existing header. `O=` relocates `build/`.

Running
-------

    bpf_reclaim [options] ROOT_CGROUP

manages the children of `ROOT_CGROUP`: the cgroups directly under it, found
again every tick, so children may come and go. It prints a status block
every second and totals as `key=value` lines on `SIGINT` or `SIGTERM`.

The buffer and its loop:

- `--buffer MB` free memory to keep; default an eighth of RAM.
- `--interval-ms N` the controller's tick; default 100.
- `--lead-ms N` how far ahead a drain of free memory is met: once the drain
  would reach the buffer within this window, a tick's worth of it is added
  to the demand before the buffer is breached; default 1000.
- `--max-rate MB/s` a cap on the pool's reclaim; default none.
- `--chunk MB` what a worker claims from a child at a time; default 2.

What a child is protected by:

- `--floor MB` usage never reclaimed below, for every child. A child's own
  `memory.low` and `memory.min` count as a floor too: the kernel ignores a
  cgroup's protection when that cgroup is itself the root of a reclaim, as
  it is for every call here, so the policy honours them itself.
- `--target PCT` the PSI memory "some" stall fraction a child may show,
  in percent of wall time; default 1.
- `--cpu-budget PCT` the CPU a child may cost per tick, in percent of one
  CPU; default the whole pool.
- `--min-efficiency MB/s` bytes per CPU-second below which reclaiming a
  child counts as expensive; default 16.
- `--child NAME:key=value,...` overrides for one child, relative to the
  root: `floor=MB`, `weight=N` (importance in the split, 1 to 10000),
  `target=PCT`, `budget=PCT`, `efficiency=MB/s`, `swappiness=N|anon`,
  `exclude`.

The probe and the backstop:

- `--probe PCT/s` asks every child under its pressure target for that
  fraction of its headroom per second, shrinking to zero at the target,
  with or without a deficit. This is Senpai's trimming; off by default.
- `--throttle` and `--throttle-ticks N`: once free memory has been below
  the buffer for N consecutive ticks (default 5), set `memory.high` of the
  child growing fastest for its weight to its usage, so that its own tasks
  reclaim and are delayed on their way back to user space; lifted when the
  buffer is back.

Placement:

- `--pool N` shared worker threads; default 2.
- `--pool-cgroup PATH` the cgroup the controller and the shared workers
  live in; `cpu.max` and `cpu.weight` there bound the pool, `cpu.stat`
  there shows what it cost.
- `--cpus LIST` CPUs the shared workers are bound to, round robin.
- `--per-child N` workers created inside each child the first time it is
  given quota, serving only that child; their CPU is charged to the child
  by membership. `--pool 0` leaves only those. A child that cannot hold
  tasks gets its workers in the pool's cgroup instead; a worker leaves a
  child whose processes have all exited, so the child can be removed.

How the policy decides
----------------------

Each tick the controller reads the free page count and, per child, usage,
the PSI stall total, the refault counters, and the kernel's count of what
proactive reclaim scanned and freed there. The demand is the gap below the
buffer plus the forecast drain. It is split among the children in
proportion to weight times coldness times headroom, capped per child at a
slice of its headroom that grows with its coldness.

Coldness is each child's learned estimate of how much of what it holds can
be taken without coming back. It halves, and the child sits out, when
refaults take back half of what was reclaimed from it, when its pressure is
over target with refaults behind it, or when reclaiming it yields less than
the efficiency floor per CPU-second. It grows by an eighth when the child
serves what it was asked without those. A gated child rests for a number of
ticks that doubles with every consecutive gate and halves with every good
tick, so a child that keeps proving hot is probed ever more rarely.

Workers sleep on a wait queue and are woken in the number the quota needs
at the measured per-worker throughput. A worker claims a chunk of a
child's quota with a compare-and-swap and calls `bpf_proactive_reclaim()`,
which frees at most 64 pages per call, until the chunk is done, the child
has nothing left, the child's CPU budget for the tick is spent, or a call
yielded too little for its time.

Two signals are measured and reported but not acted on: "undone" reclaim,
memory the pool took that was back by the next tick whether as a refault
or a fresh allocation, which matters because refault counting undercounts
once a child is squeezed small; and growth, new allocation net of reclaim
and refaults, which names the runaway.

The benchmark
-------------

`bench/run.py` runs one scenario under one reclaimer and writes a summary;
it needs root and cgroup v2, and nothing else. `bench/workload` generates
the workloads: a hot or cold anonymous set, a page cache set, a streaming
reader, an allocator growing at a rate. `bench/userspace_reclaim.py` is the
userspace baseline over `memory.reclaim`, with Senpai's law or the pool's
buffer objective. `bench/sweep.sh` runs a matrix of modes and pool sizes.

    bench/run.py --bin build/bin --out /tmp/r --mode bpf --scenario overcommit \
        --buffer-mb 1024 --grow-mb 1800 --grow-rate 150 --seconds 60

The modes are `none` (kernel only), `userspace` (the buffer objective from
userspace at a 100 ms tick), `senpai` (pressure-targeted trimming every six
seconds) and `bpf`. The scenarios are `overcommit` (a hot set, a page cache
set, a cold set, and an allocator starting later), `scale-anon` and
`scale-file` (the three residents plus N applications ramping their
allocation or streaming rate, so the pool must reclaim in parallel across
cgroups). The summary reports free memory against the buffer, the kernel's
own reclaim counters, each cgroup's state, pressure and CPU time, each
workload's throughput and chunk latency, and the reclaimer's totals.

The runs here used a kdev guest; a virtme-ng guest works the same way:

    vng --cpus 8 --memory 16G --rw -- \
        python3 tools/mm/bpf-reclaim/bench/run.py --bin tools/mm/bpf-reclaim/build/bin \
            --out /tmp/r --mode bpf

    VM_CMD="vng --cpus 8 --memory 16G --rw --" MODES="none userspace bpf" POOLS="1 2 4" \
        tools/mm/bpf-reclaim/bench/sweep.sh --scenario scale-anon --apps 4

Known limits
------------

- The shared pool's CPU is bounded and accounted by its cgroup, not charged
  to the children it reclaims for. Per-child workers are charged by
  membership at the cost of a thread per child. Charging a shared pool is
  the subject of the remote charging RFC referenced below.
- Reclaiming anonymous memory into zram or zswap frees the difference
  between the raw and the compressed size, not the raw size; the loop
  self-corrects since it watches free memory, but reclaimed bytes and freed
  bytes diverge.
- A probe into a hot child costs one reclaim call per episode, on the order
  of a hundred milliseconds of CPU for a few hundred megabytes of hot
  memory, because the kernel scans the LRU at rising priority before giving
  up; the budget and the rest bound how often, not how much a single call
  costs.
- Protection is taken from a child's configured `memory.low` and
  `memory.min`, which are at least the effective values the kernel would
  compute from the hierarchy.

References
----------

- Shakeel Butt, memcg_ext: memcg policy through cgroup-attached struct_ops,
  https://lore.kernel.org/bpf/20260921192559.2619635-1-shakeel.butt@linux.dev/
- Shakeel Butt, cgroup: charge kernel work to the cgroup it is done for,
  https://lore.kernel.org/bpf/20260924184714.912181-1-shakeel.butt@linux.dev/
- Johannes Weiner, mm: memcontrol: asynchronous reclaim for memory.high,
  https://lore.kernel.org/linux-mm/20200219181219.54356-1-hannes@cmpxchg.org/
- Senpai, https://github.com/facebookincubator/senpai; Weiner et al., TMO:
  Transparent Memory Offloading in Datacenters, ASPLOS 2022.
