.. SPDX-License-Identifier: GPL-2.0

=============================
BPF network driver experiment
=============================

``CONFIG_BPF_NET_DRIVER`` provides an experimental ``struct_ops`` interface for
running network driver policy in BPF. The program decides when to refill RX,
drain completions, submit TX, and deliver received packets. Its software state
can reside in a BPF arena. A native core owns the netdevice, NAPI instance,
packet allocations, and recovery. A native transport owns hardware resources
and translates checked buffer submissions into device descriptors.

This is an intermediate boundary for exploring a larger C driver port. It does
not put the existing mlx5 driver, firmware command engine, or physical rings in
BPF. The interface is experimental and has no stable ABI. Build results, VM
tests, physical NIC tests, and performance measurements are separate evidence;
the presence of a backend or a test does not establish hardware validation.

Ownership boundary
==================

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Owner
     - State and responsibilities
   * - BPF program
     - Refill and batching decisions, packet-format checks, submission policy,
       software queue accounting, buffer IDs, and statistics. Ordinary data
       structures may live in the arena.
   * - Native core
     - Kernel callback objects, device lifetime, serialization, the buffer
       ownership ledger, skb metadata, NAPI/GRO handoff, attachment revocation,
       watchdogs, and recovery work.
   * - Native transport
     - PCI or auxiliary-device integration, firmware objects, DMA mappings,
       physical descriptor rings, completion validation, interrupt control,
       MMIO ordering, and proof of DMA quiescence during teardown.

The API uses ``struct bpf_net_driver *`` as the current invocation's device
handle. Every driver kfunc compares this argument with the active callback
device before dereferencing it. A number saved in an arena does not authorize
access to another device or to arbitrary kernel memory. Normal read-only BTF
access to kernel objects is not disabled; this interface does not provide a
confidentiality boundary around all driver state.

Callbacks and attachment
========================

The interface in ``include/linux/bpf_net_driver.h`` has four callbacks::

    struct bpf_net_driver_ops {
        int  (*open)(struct bpf_net_driver *drv);
        int  (*poll)(struct bpf_net_driver *drv, int budget);
        int  (*xmit)(struct bpf_net_driver *drv, u64 buffer);
        void (*close)(struct bpf_net_driver *drv);
        u32 ifindex;
        struct bpf_net_driver *priv;
    };

All four callbacks are required. The loader sets a nonzero ``ifindex`` and
leaves ``priv`` zero; the core initializes ``priv`` after attachment. Attach a
``.struct_ops.link`` map with ``bpf_map__attach_struct_ops()``. The target must be
a device registered by a compatible transport, in the initial network
namespace, down, and without an existing attachment. Loading the programs and
map alone does not attach them to a device.

Callbacks are non-sleepable and run under one spinlock per device with bottom
halves disabled. This serializes open, poll, xmit, and close even if different
CPUs invoke them. It deliberately excludes a multi-queue concurrency experiment.
The lock does not serialize userspace writes into a shared arena or callbacks
of a different device using the same arena.

``CONFIG_PREEMPT_RT`` is excluded. The per-CPU invocation identity used by the
kfuncs requires callbacks not to interleave on one CPU. RT spinlocks and
bottom-half disabling do not provide that guarantee; RT support needs task-local
invocation state.

Netpoll and netconsole are disabled for these netdevices. They can invoke
transmit from a hard IRQ interrupting a callback that already holds the device
lock, and the present callback model does not support that reentry.

``open`` runs after native hardware startup and initializes the BPF policy,
including RX refill. ``xmit`` receives one CPU-owned TX buffer and must submit
or release it before returning. Returning with that buffer still CPU-owned is
a fault. ``poll`` returns a value in ``[0, budget]`` and may deliver RX packets
only within that invocation. The current core does not invoke it for a zero
NAPI budget. ``close`` can clear software state, but native teardown must work
without it: the core skips the callback after a fault.

Packet buffers and kfuncs
=========================

The core has 256 buffer records, split equally between RX and TX. A nonzero
``u64`` ID combines a slot index with a generation. Allocation or TX entry gives
the policy CPU ownership. A successful submission transfers ownership to the
device. A checked completion transfers it back. Release or RX delivery
invalidates the ID. Copying an ID does not create another ownership reference;
stale IDs and operations in the wrong state fault the attachment.

The current kfunc allowlist is:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Operation
     - Effect
   * - ``bpf_net_buffer_alloc(drv)``
     - Allocate an RX skb with 2048 bytes of capacity; return its ID, or zero
       when allocation or the RX slot pool is exhausted.
   * - ``bpf_net_buffer_length(drv, id)``
     - Read the current packet length of a CPU-owned buffer.
   * - ``bpf_net_buffer_load(drv, id, off, size)``
     - Read 1 through 8 packet bytes within the current length, packed with
       the first byte in the least significant bits of the result.
   * - ``bpf_net_buffer_store(drv, id, off, size, value)``
     - Write 1 through 8 bytes in the same byte order. RX writes address the
       RX allocation; TX writes address a separate 16-byte transport prefix.
   * - ``bpf_net_queue_submit(drv, id, queue, off, len)``
     - Submit one CPU-owned buffer to RX queue 0 or TX queue 1. RX offset must
       be zero and length must fit the allocation. For TX, offset is a transport
       prefix parameter bounded by 16, and packet length must equal the skb
       length. The transport applies its own prefix and format checks.
   * - ``bpf_net_queue_complete(drv, queue)``
     - Consume one completion and return the CPU-owned buffer ID, or zero
       when empty. Native code validates the cookie, ownership, and RX length.
   * - ``bpf_net_queue_kick(drv, queue)``
     - Notify the hardware after submissions using native ordering rules.
   * - ``bpf_net_buffer_release(drv, id)``
     - Drop or reclaim one CPU-owned packet allocation and invalidate its ID.
   * - ``bpf_net_receive(drv, id, off, len)``
     - Transfer a completed RX buffer to the networking stack during poll.
       The core checks packet bounds and Ethernet length, initializes skb
       metadata, and invalidates the ID.

Submission failure, such as a full hardware queue, leaves CPU ownership with
the caller. Invalid handles, bounds, queue selections, completion records, and
callback results revoke the BPF attachment. After a fault, later kfunc calls in
that invocation stop performing device operations.

RX DMA lands in native-owned skb backing. Delivery passes that same allocation
to GRO after releasing the callback lock. TX DMA uses the original linear skb
backing, with a separate native transport prefix if required. There is no
payload copy through the arena, and no arena mapping of an allocation already
owned by the networking stack. The core may linearize a nonlinear TX skb, and
the DMA implementation can impose its own copying requirements. Transport
headers may also be copied into native descriptors, including mlx5's inline
Ethernet header. The experiment does not promise that every networking path is
copy-free.

Execution and recovery
======================

The driver admission check examines callback bytecode before control-flow
optimization and JIT rewriting. It permits at most 32768 instruction slots and
requires an acyclic control-flow graph. Backward branches caused by compiler
block layout are allowed if they do not create a cycle. Calls may target only
the driver kfunc allowlist. BPF subprogram calls, helpers, tail calls, indirect
calls and jumps, function addresses, and atomic memory operations are rejected.
Atomics are excluded because a JIT may implement them with retry loops. C helper
functions must inline, and repeated work must expand within the instruction
limit. The examples spell out fixed repetitions because compiler-directed unrolling of
loops containing several kfunc calls is not reliable.

Admission builds a graph containing every decoded instruction, including code
outside the entry's reachable paths. It checks both successors of conditional
branches, the sole successor of an unconditional branch, and fallthrough for
ordinary instructions and allowed calls. Exits have no successor. Two-slot
immediates form one node, and no edge may enter their second slot. A topological
traversal must remove every node; this rejects cycles regardless of branch
direction or code layout.

These restrictions bound the number of original BPF instruction slots and
native driver calls executed by an invocation. They do not establish a fixed
wall-clock deadline: native allocation, memory accesses, interrupt activity,
and JIT expansion still affect elapsed time. Each allowed native operation
must itself do bounded work. A faulty native transport, firmware interaction,
or reset implementation is outside the verified BPF execution guarantee.

The struct_ops type opts into ``no_prog_composition``. Tracing and extension
attachments, including fentry, fexit, fmod_ret, and freplace, cannot add code to
these programs or their subprograms after admission. Other struct_ops types
retain their existing attachment behavior.

The watchdog detects outstanding TX buffers older than five seconds, including
completed buffers retained by BPF. Polling also detects repeated full-budget
returns without completion progress and short returns that leave completions
pending when notifications are rearmed. An empty queue does not count as a
failure, so an otherwise idle device can still be busy-polled. These
are recovery triggers, not a way to interrupt a running callback. A watchdog
cannot safely unwind arbitrary BPF or native execution while it owns the
device lock. The acyclic admission rule is therefore part of the recovery
design, rather than an optional performance restriction.

These triggers detect ownership violations and particular TX or completion
stalls. They cannot distinguish an intentional packet drop from a broken
policy. For example, a policy can drain RX buffers without replenishing them
and leave no outstanding completion or TX buffer. Administrative link teardown
still drains and revokes that policy, then attempts to restore native service;
automatic recovery is not a general packet-delivery guarantee.

On a fault, the core revokes further BPF dispatch and schedules recovery work.
Under RTNL, recovery stops TX, masks notifications, disables NAPI, and asks the
native transport to stop DMA. Buffers can be reclaimed only after successful
quiescence. Recovery from a BPF fault may then reopen the interface using the
transport's native reference policy. A failed stop quarantines the resources
and prevents reopening; retaining DMA backing is safer than freeing memory the
device may still access.

Destroying a live struct_ops link drains callbacks, clears the attachment, and
attempts to reopen with the native policy. Device removal also drains native
interrupt callbacks and pending work before releasing resources. Neither path
relies on a cooperative BPF close callback. The native transport is responsible
for retaining its own rings and mappings when quiescence cannot be proved.

Packet delivery and NAPI completion run outside the device lock because GRO
can reenter transmit. Stop waits for the entire poll invocation, including
work after NAPI completion, before destroying transport or netdevice state.

``/sys/class/net/<ifname>/bpf_driver/`` exposes ``state``, ``fault``, ``calls``,
and ``recoveries``. State is one of ``native``, ``bpf``, ``recovering``,
``revoked``, or ``quarantined``. A revoked attachment can remain linked while
native recovery handles traffic. Destroy the old link before installing a new
program.

Arena state and the separate kptr experiment
============================================

The BPF policy examples put counters and refill state in a
``BPF_MAP_TYPE_ARENA`` map with ``BPF_F_MMAPABLE | BPF_F_NO_USER_CONV``. The latter
avoids converting arena pointer representations into userspace pointers. The
loader sets ``BPF_F_ARENA_SCALAR`` on programs that need scalar arena accesses:
a load or store through a scalar uses its low 32 bits as an offset within the
program's arena. This is not permission to dereference an arbitrary kernel
address.

Initialize arena state before callbacks begin. The driver allowlist does not
include arena allocation, freeing, or general BPF helpers. Userspace can map
the arena to read counters or change experiment controls. Values loaded from
mutable arena memory must be treated as untrusted by native operations; the
buffer ledger, descriptor checks, and resource ownership remain native.

The separate ``[WIP]`` arena ``bpf_kptr_xchg()`` change is not a typed-arena
safety implementation. Its ``bpf_arena_kptr:TYPE`` program declaration tag picks
one vmlinux pointee type for verifier bookkeeping. The exchange checks the
destination's bounds, alignment, and backing, and an invalid destination returns
the incoming reference unchanged. It does not establish the stored value's
type, exclusive ownership, or lifetime. Raw writes, userspace aliases, and
freeing arena pages can corrupt pointers or lose references. There are no
automatic slot destructors.

That bypass is independently unsafe for untrusted programs. Driver callbacks
cannot call it, and this driver's safety argument does not depend on it.
Generation-tagged scalar buffer IDs are sufficient for the present experiment.
Future typed arenas may retain properly owned kernel-object pointers, but must
also enforce their lifetime and aliasing rules. Such support alone does not
make DMA addresses or mutable hardware descriptors safe to expose.

Transports and comparisons
==========================

``CONFIG_BPF_VIRTIO_NET`` supplies a virtio 1.0 transport in
``drivers/net/bpf_virtio_net.c``. It supports one RX/TX queue pair, linear
Ethernet packets with MTU at most 1500, and no offloads. Virtqueue code owns DMA
descriptors and mapping. The BPF policy writes and validates the transport
header, drains completions, refills RX, and chooses notification points.

``CONFIG_MLX5_BPF_NET`` builds
``drivers/net/ethernet/mellanox/mlx5/core/bpf_net.c`` into mlx5_core. The normal
Ethernet driver remains the default. Selecting the experiment requires
rebinding the Ethernet auxiliary device from ``mlx5_core.eth`` to
``mlx5_core.bpf_net``; the PCI device remains bound to mlx5_core. This retains
the core's firmware command, event, and resource-management services.

The mlx5 native backend creates dedicated SQ/RQ/CQ objects, a protection domain,
transport domain, memory key, UAR, TIS, direct TIR, and an Ethernet steering
rule. It owns DMA mapping and hardware completion decoding. The BPF side
prepares a checked 16-byte SEND control template; native code supplies the DMA
segment, queue number, descriptor size, and WQE index. RX has no virtio header.
The initial backend supports one queue pair and MTU at most 1500 on an Ethernet
PF without active SR-IOV, switchdev, or LAG, and with an inline-header
requirement no greater than L2. It has no offloads. This exercises mlx5 queue
transport without delegating raw device-memory authority. Physical NIC
validation is required before drawing correctness or performance conclusions.

The transport saves the port/vport MTU and promiscuous-mode settings it changes
and restores them during successful teardown. Native CQ errors can notify the
core independently of BPF polling. A core reload destroys the auxiliary device;
the old BPF attachment does not survive it, and the stock Ethernet driver is
again the default after recreation.

Two comparisons answer different questions:

* The native reference policy uses the same transport and checked buffer APIs
  as BPF. Match refill depth, polling limits, batching, and packet processing
  one for one. This comparison isolates the cost of BPF dispatch, compilation,
  arena state, and any extra instrumentation while holding the transport fixed.
* The stock driver comparison uses ``virtio_net`` or ``mlx5e`` with matched
  MTU, queue count, offloads, coalescing, workload, and CPU placement. This
  measures the whole experimental path against the existing implementation.
  It includes costs and missing optimizations in the new native transport and
  checked APIs, so it cannot attribute every difference to BPF execution.

The native recovery policy is the first baseline. It is not a replacement for
the stock-driver baseline. Measure throughput, packet rate, latency, CPU cost,
and refill/completion behavior only after validating packet integrity,
attach/detach, failure recovery, and teardown. Record hardware, firmware,
compiler, kernel configuration, instrumentation, and negotiated features with
the results.

The controller uses the ``bpf_net_virtio_run`` and ``bpf_net_mlx5_run`` policies.
These compile out fault-injection branches and test-only counters, retaining
only the refill state in the arena. The correctness fixtures use instrumented
variants of the same source to inject faults and check callback activity.
Both production and instrumented policies have TCP/UDP traffic tests. Core
ownership checks and attachment diagnostics remain enabled in both modes.

``bpf_net_driver_guard`` tests admission and composition without a NIC.
``bpf_net_driver`` and ``run_bpf_net_driver.sh`` exercise virtio TCP/UDP traffic,
detach, and injected policy faults. The runner changes guest NIC bindings and
uses two connected virtio devices. These fixtures do not test physical mlx5
DMA, firmware error paths, or hardware reset behavior.

Running an experiment
=====================

Build the kernel with ``CONFIG_BPF_NET_DRIVER`` and the chosen transport, then
build the BPF selftests against that kernel's BTF. Use a correctness kernel for
the targeted tests before switching to a benchmark configuration. The load-only
admission and composition tests need no attached NIC::

    ./test_progs -t bpf_net_driver_guard,dummy_st_ops

The virtio traffic runner expects a virtme guest with two connected virtio NICs.
It rebinds one NIC to ``bpf_virtio_net``, configures the peer in a network
namespace, and restores bindings on exit::

    ./run_bpf_net_driver.sh

For physical mlx5, use a dedicated test PF and identify its Ethernet auxiliary
device in ``/sys/bus/auxiliary/devices/``. Set ``STOCK_IF`` to its current
netdevice and ``MLX5_AUX`` to its ``mlx5_core.eth.N`` auxiliary-device name.
Verify that the netdevice's device and the auxiliary device belong to the same
PCI function. Record addresses, routes, and device settings before rebinding;
the new netdevice does not preserve that configuration. These commands keep
the PCI function attached to mlx5_core::

    set -eu
    : "${STOCK_IF:?set the dedicated test netdevice}"
    : "${MLX5_AUX:?set the matching mlx5_core.eth.N auxiliary device}"
    readlink -f "/sys/class/net/$STOCK_IF/device"
    readlink -f "/sys/bus/auxiliary/devices/$MLX5_AUX"
    ip link set dev "$STOCK_IF" down
    printf '%s\n' "$MLX5_AUX" > /sys/bus/auxiliary/drivers/mlx5_core.eth/unbind
    if ! printf '%s\n' "$MLX5_AUX" > /sys/bus/auxiliary/drivers/mlx5_core.bpf_net/bind; then
        printf '%s\n' "$MLX5_AUX" > /sys/bus/auxiliary/drivers/mlx5_core.eth/bind
        exit 1
    fi
    ls "/sys/bus/auxiliary/devices/$MLX5_AUX/net/"

Set ``BPF_IF`` to the resulting ``bpfmN`` interface, configure its peer,
addresses, routes, MTU, and CPU/IRQ placement, and validate the native reference
path. The controller holds a BPF attachment while running a command, then
destroys the link and restores the initial UP state. It requires the interface
to start in ``native`` state. For example, with ``PEER`` set to the peer address::

    ./bpf_net_driver_ctl --ifindex "$(cat /sys/class/net/$BPF_IF/ifindex)" \
        --transport mlx5 --mode bpf -- ping -c 10 "$PEER"

Use ``--transport virtio`` for a ``bpfvN`` interface and ``--mode native`` for
the matched native policy. The controller's elapsed time includes the command
execution; use a workload that reports the packet-rate, throughput, CPU, or
latency metric being compared, with appropriate warmup.

The comparison wrapper alternates native/BPF order across pairs and captures
the command's output, interface state, configuration, counters, and CPU/IRQ
information. It rejects a failed workload or unexpected driver state, and
checks that recorded MTU, features, queue, ring, and driver settings stay
unchanged. ``--output`` must name a new directory. Replace the example workload
with the measurement command and provide the configuration of the running
kernel::

    ./bench_bpf_net_driver.sh --interface "$BPF_IF" --transport mlx5 \
        --config /path/to/running-kernel.config --runs 5 --output results-new \
        -- ./packet-workload "$PEER"

The wrapper requires lock/preemption debugging and CPU mitigations to be
compiled out in the supplied benchmark configuration. It does not attest that
an arbitrary supplied config matches the running kernel. Keep the kernel build
identity and configuration together. It does not change bindings or automate
the stock-driver comparison, and the commands above are a procedure, not a
record of measurements.

After destroying attachments and stopping the experimental interface, restore
the mlx5 Ethernet auxiliary driver and reapply the saved network configuration::

    ip link set dev "$BPF_IF" down
    printf '%s\n' "$MLX5_AUX" > /sys/bus/auxiliary/drivers/mlx5_core.bpf_net/unbind
    printf '%s\n' "$MLX5_AUX" > /sys/bus/auxiliary/drivers/mlx5_core.eth/bind

Moving more of mlx5 into BPF
============================

The current submission API hides descriptor construction and CQ decoding behind
native calls. It is adequate for a first end-to-end policy experiment, but it
does not yet test whether most existing mlx5 C can execute as BPF. In particular,
retaining command transport, firmware-object creation, steering, and all
SQ/RQ/CQ machinery in mlx5_core leaves substantial driver logic native.

A further split should expose more computation while preserving checked commit
points. BPF could own WQE formatting, CQE parsing, software producer/consumer
indices, command packing, object dependency graphs, steering construction, and
error-state policy in arena data. Native code would still validate every
operation that authorizes DMA, names a kernel-owned resource, changes a mapping,
or publishes work to hardware. Arbitrary firmware commands and raw WQE addresses
cannot be treated as safe merely because their bytes came from verified BPF.

A bounded staged-descriptor interface is one possible next step. BPF writes a
template in ordinary arena memory and supplies buffer IDs. A native commit
operation snapshots and validates a fixed-size template, resolves current
device-owned buffers, checks lengths, opcodes, queue capacity, and resource
ownership, and publishes a protected descriptor with the required DMA/MMIO
ordering. Hardware must not consume a user-writable template after validation;
otherwise an arena alias can change it before DMA begins. Completion handling
needs a corresponding snapshot and ownership transition.

Moving the command engine and firmware object graph requires additional native
services: checked command publication, bounded completion delivery, resource
references that survive asynchronous work, and cancellation/reset coordination.
Long startup sequences and firmware waits cannot run inside the present
non-sleepable, acyclic callbacks. They need staged continuations or a
separate process-context interface with an explicit progress and cancellation
contract. This is an interface extension, not a mechanical conversion of
``wait_for_completion()`` into a kfunc.

Packet DMA backing also needs a distinct lifetime from software arena state.
An arena DMA lease would have to pin mappings, prevent free or replacement
while hardware owns them, and exclude kernel-pointer slots and skb metadata
from writable DMA memory. Handing RX memory to the networking stack must revoke
all writable BPF and userspace aliases until the stack releases it. A typed
pointer stored in an arena solves none of those mapping and ownership changes
by itself.

The full port therefore needs two explicit choices. Either keep descriptor and
command authority behind native validation and migrate their ordinary C
construction/state machines into BPF, or grant a trusted driver raw device
authority under a separate isolation model. An IOMMU can restrict DMA mappings;
it does not verify firmware semantics, object lifetimes, or packet ownership.
The current experiment takes the checked-operation approach and leaves that
larger trusted-driver mode unimplemented.
