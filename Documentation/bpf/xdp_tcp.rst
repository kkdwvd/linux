.. SPDX-License-Identifier: GPL-2.0

====================
TCP sockets from XDP
====================

An XDP program can serve established TCP connections. The kfuncs in
``net/ipv4/tcp_xdp.c`` let it read a connection's incoming data in the
driver's receive buffer, before any skb exists, and answer through the
connection, either with data copied from arena memory or with a reply
written into the request's own buffer. The kernel's TCP stack keeps the
connection: the handshake, acknowledgements, congestion control,
retransmission and the window are its. The application that owns the socket
is not woken for data the program takes, and cannot read it. A program that
would rather hand the bytes to a process redirects them into an AF_XDP
socket's ring. Think of it as XDP's data path with the kernel's TCP.

Two interfaces exist. The kfuncs themselves are as stable as any kfunc, see
Documentation/bpf/kfuncs.rst. ``tools/testing/selftests/bpf/bpf_xdp_tcp.h``
is a header of inline wrappers over them, ``bpf_xdp_tcp_sock_*()``, used by
the selftests and meant to be copied into a program together with
``bpf_experimental.h`` and ``bpf_kfuncs.h``, which it includes; the kfunc
prototypes come from ``vmlinux.h``, so include it after that. The rest of
this document uses the wrappers and names the kfunc behind one where it
matters. The `Reference`_ at the end maps the two.

There is no per-socket opt-in. The kfuncs act on any established TCP socket
of the receiving device's network namespace that they do not refuse, see
`Sockets and segments left to the stack`_. The program chooses its
connections before it takes anything: by checking the destination port, or
by looking the connection up without taking it and checking the socket
cookie against a map the application filled with ``getsockopt(SO_COOKIE)``.
Choose before calling ``recv()``: it takes in-order data, acknowledges
duplicates, and serves the connection, see `Terms`_, whenever it does
either. ``lookup()`` does none of that, but it reports only segments it
would take, so a program that chooses by cookie cannot hold frames.
Attaching an XDP program needs ``CAP_NET_ADMIN``, which can already drop or
rewrite the same traffic; what is new is that a program can acknowledge
data on the host's behalf.

When to use it
==============

.. list-table::
   :header-rows: 1

   * - Use it when
     - Do not use it when
   * - Requests fit one segment and replies are short, or fit the request's
       buffer
     - The connection carries bulk data in: there is no GRO, and every
       segment costs a lock section and a software checksum
   * - The MTU keeps a segment in one receive buffer, about 3.5 KiB with
       4 KiB buffers
     - Jumbo frames on a driver that gives XDP one page per buffer: those
       segments go to the stack, and each stops the kernel from taking more
       until the application reads
   * - No ECN marking in the path
     - ECN or DCTCP under congestion: segments carrying ECE or CWR go to the
       stack, with the same effect
   * - The application can read, and serve, what arrives through the socket
       while the program cannot take it
     - Nothing reads the socket: the connection stalls the first time a
       segment is passed to the stack
   * - The host's netfilter, conntrack and TC policy may ignore the
       connection, in both directions
     - A stateful firewall or a TC policer has to see the flow, or conntrack
       is in use and the port is not exempted with ``notrack``
   * - No XFRM policy applies, in either direction, in the namespace
     - Any IPsec policy in the namespace: the kfuncs refuse every socket
   * - Plain TCP sockets, IPv4 or IPv6; with ``CONFIG_IPV6=m``, IPv4
       sockets only
     - kTLS or another ULP, sockmap, MPTCP, MD5 or AO, AccECN, IP options
       or extension headers, VRF: refused

Terms
=====

segment
  The TCP unit: one data segment, or a FIN.
packet
  The XDP context the program was called with. It lives until the program
  returns or steals it.
frame
  A receive buffer the program owns, taken out of XDP with
  ``bpf_xdp_frame_steal()`` or by a wrapper that calls it. ``XDP_CONSUME``
  is the return value that tells the driver the program took the buffer.
take
  What the kernel does to a segment it receives on the program's behalf:
  the connection's receive cursor and read cursor move past the data, an
  acknowledgement is scheduled, and the bytes are the program's.
receive cursor, read cursor
  ``rcv_nxt``, the next byte the connection expects, and ``copied_seq``, the
  next byte the application would read. A taken segment moves both.
hold, admit
  To keep a frame that arrived out of order, or while the socket was busy,
  in the program's own state. Admitting it processes its ACK and SACKs its
  data without moving the cursor; delivering it, later, is a take.
handle
  A ``struct bpf_xdp_tcp_sock`` on the program's stack, with a reference to
  the connection. Always zero it before use, since the wrappers read its
  fields; release it on every path with ``bpf_xdp_tcp_sock_release()``.
arena send, frame reply
  The two ways to answer: a copy from arena memory into the write queue,
  and a segment built around the request's own buffer. See `Sending`_.
busy
  The ``BPF_XDP_TCP_BUSY`` status: a process holds the socket lock, or the
  stack holds data the application has not read, in its receive queue or
  its out-of-order queue.
served connection
  A connection whose socket the kfuncs have moved to their own send path,
  see `The send path`_. That happens the first time ``recv()`` or
  ``consume()`` takes a segment of it or acknowledges a duplicate, ``hold()``
  admits a frame of it, or a send kfunc sends on it; ``lookup()`` changes
  nothing, nor does a receive that reports the segment out of order, busy or
  the stack's. A socket the kfuncs refuse is never served.

Quick start
===========

An in-order echo on port 7777. It gives up on a reply the socket cannot
take, which loses that request; `Sending`_ shows how to keep the reply and
retry.

.. code-block:: c

    #include <vmlinux.h>
    #include <bpf/bpf_helpers.h>
    #include "bpf_arena_common.h"           /* __arena_global, from the selftests */
    #include "bpf_xdp_tcp.h"

    struct {
            __uint(type, BPF_MAP_TYPE_ARENA);
            __uint(map_flags, BPF_F_MMAPABLE);
            __uint(max_entries, 16);
            __ulong(map_extra, 0x1ull << 44);
    } arena SEC(".maps");

    char __arena_global reply[4096];
    __u64 lost;

    SEC("xdp")
    int serve(struct xdp_md *ctx)
    {
            struct bpf_xdp_tcp_sock sock = {};
            struct bpf_dynptr payload;
            int action = XDP_PASS;
            __u32 len, i;

            if (!to_port(ctx, 7777))            /* the program's own header parse */
                    return XDP_PASS;
            if (!bpf_xdp_tcp_sock_recv(ctx, &sock, &payload))
                    return XDP_PASS;            /* not a data segment of an established socket */
            switch (bpf_xdp_tcp_sock_status(&sock)) {
            case BPF_XDP_TCP_RECEIVED:          /* taken: the bytes are ours, answer them */
                    len = bpf_xdp_tcp_sock_len(&sock);
                    if (len > sizeof(reply))
                            len = sizeof(reply);
                    bpf_for(i, 0, len) {
                            char c, *p = bpf_dynptr_slice(&payload, i, &c, 1);

                            if (!p)
                                    break;
                            reply[i] = *p;
                    }
                    if (len && bpf_xdp_tcp_sock_send(&sock, reply, len) < 0)
                            lost++;             /* -EAGAIN: keep it and retry, see Sending */
                    action = XDP_DROP;
                    break;
            case BPF_XDP_TCP_DUPLICATE:         /* acknowledged for us: nothing to do */
                    action = XDP_DROP;
                    break;
            default:                            /* out of order, busy or the stack's */
                    break;
            }
            bpf_xdp_tcp_sock_release(&sock);
            return action;
    }

    char _license[] SEC("license") = "GPL";

``to_port()`` stands for the program's own check of the Ethernet, IPv4 or
IPv6, and TCP headers for the destination port; ``progs/xdp_tcp.c`` has one.
It comes before ``recv()``, which takes in-order data of whatever connection
it finds. Every path releases the handle. ``XDP_DROP`` after a take drops the
buffer, not the data: the kernel has acknowledged it and the program has it.
``xdp_tcp_echo()`` in ``tools/testing/selftests/bpf/progs/xdp_tcp.c`` adds
the out-of-order, frame-reply and AF_XDP variants.

The application and the socket
==============================

The program and the application share one byte stream, and each byte goes
to exactly one of them. The program gets the bytes the kernel takes; the
application reads, with ``recv()``, only the bytes the program passed to the
stack. The program is never given bytes ahead of data the application has
not read yet: while the stack's receive queue or its out-of-order queue
holds anything, every segment of the connection is reported busy, and the
kernel takes segments again only once the application has drained the
socket. A service therefore needs a reader on the socket, and a protocol
that lets some requests arrive there, for example after a loss the program
does not handle itself.

Busy also means a process holds the socket lock, inside ``recvmsg()``,
``sendmsg()`` or ``setsockopt()`` on it. A process blocked in ``recv()``
waiting for data does not hold the lock and does not make the socket busy.

The application is woken for a FIN the program takes: its ``recv()`` returns
0 then, as the stream has ended, although it saw none of the data. The
application may also write to the socket while the program serves it; its
writes and the program's replies interleave as whole calls, except that a
``sendmsg()`` that waits for send memory releases the lock while it waits,
and a reply can then land inside it. Do not mix the two on one connection
unless the protocol allows it.

What runs and what is skipped
=============================

The tables read in the order a packet travels. A cell says ``runs``,
``skipped``, ``not updated``, or ``refused``, the last meaning that a socket
with that property is not served at all. Numbers refer to the notes below
each table.

.. list-table:: Receive, for a segment the program takes
   :header-rows: 1

   * - Layer, wire to socket
     - Taken segment
     - Note
   * - Packet taps (``tcpdump``), TC ingress and ``tcx``, the netfilter
       ingress hook
     - skipped
     - 1
   * - Hardware GRO, GRO
     - skipped
     - 2
   * - netfilter PREROUTING and INPUT, conntrack
     - skipped
     - 3
   * - XFRM input policy, on the socket or in the namespace
     - refused
     -
   * - IP input, IP MIBs
     - skipped
     -
   * - Socket filter, cgroup ingress program, ``socket_sock_rcv_skb`` LSM hook
     - skipped
     -
   * - MD5 and AO signature checks
     - refused
     -
   * - RFS flow hash, NAPI id and incoming CPU of the socket
     - not updated
     - 4
   * - TCP: ACK processing and the sender's state machine, congestion
       control callbacks, RTT, timestamps and PAWS, the window, SACK and
       D-SACK generation, the delayed-ACK decision, FIN, receive-buffer
       autotuning
     - runs
     -
   * - sockops header-option parsing callbacks
     - skipped
     -
   * - Receive queue, wakeup, copy to user space
     - skipped
     - 5
   * - ``TcpInSegs``, ``TCPHPHits``, the socket's ``segs_in``,
       ``data_segs_in`` and ``bytes_received``
     - runs
     -

1. Nothing sees the segment before the program.
2. A NIC's hardware GRO is off for the whole device while an XDP program is
   attached, for every flow; see `Performance characteristics`_.
3. Conntrack sees the handshake and whatever the program passes to the
   stack, and nothing else; see `Consequences for host policy`_.
4. aRFS steering and busy polling do not learn from taken segments.
5. The application cannot read a taken segment; see `The application and
   the socket`_.

.. list-table:: Send, for every segment of a served connection
   :header-rows: 1

   * - Layer, socket to wire
     - Arena send
     - Frame reply
     - Every other segment of the socket: the application's writes, ACKs,
       retransmissions, FIN
   * - ``sendmsg()``, ``socket_sendmsg`` LSM hook, ``SO_TIMESTAMPING``,
       Nagle, ``TCP_CORK``, autocorking
     - skipped
     - skipped
     - not involved
   * - Copy from user space
     - replaced by a copy from the arena
     - skipped
     - not involved
   * - Write queue, congestion control, pacing, TCP small queues,
       retransmission
     - runs
     - runs
     - runs
   * - ``tcp_transmit_skb()``, sockops header-option callbacks
     - runs
     - runs
     - runs
   * - IP header
     - built from the cached route
     - built from the cached route
     - built from the cached route
   * - cgroup egress program
     - runs
     - runs
     - runs
   * - netfilter LOCAL_OUT and POST_ROUTING, conntrack, NAT
     - skipped
     - skipped
     - skipped
   * - XFRM output, IP options, L3 master devices, lightweight tunnels
     - refused, see note 6
     - refused
     - refused
   * - netfilter egress hook, TC egress and ``tcx``
     - skipped
     - skipped
     - skipped
   * - qdisc, packet taps, GSO and TSO, checksum offload, driver
     - runs
     - runs
     - runs

6. At admission; a socket that acquires one of these later is no longer
   served, see `The send path`_.

The path belongs to the socket, not to a call: once a connection is served,
every segment it sends takes it, including what the application writes with
``send()`` and what the stack sends by itself, and on every device the
segment crosses on the way out, the lower device of a VLAN, bond or macvlan
included. One kind of segment still meets the hooks marked skipped: a
segment the path hands back to ``ip_queue_xmit()`` passes all of them, see
`The send path`_.

Sockets and segments left to the stack
--------------------------------------

Per segment, the kfuncs take only what the stack's own fast path would, and
leave the rest to ``XDP_PASS``:

* pure ACKs and control segments;
* segments with ECE or CWR set;
* segments with any TCP option other than an aligned timestamp, which
  excludes SACK blocks and signatures;
* IPv4 options and IPv6 extension headers;
* segments whose checksum fails;
* segments that span more than one receive buffer;
* segments for a closed receive window;
* anything for a socket that is not established.

A segment left to the stack queues there, and the kfuncs take nothing more
of the connection until the application has read it. In an ECN network data
under congestion carries ECE, so that happens often.

Per socket, the kfuncs refuse, and do nothing to:

* a socket in a sockmap, under a ULP such as kTLS, or in MPTCP;
* one with an MD5 or AO key;
* one with AccECN negotiated, urgent data pending, or in ``TCP_REPAIR``;
* one with IP options or IPv6 extension headers;
* one under an XFRM policy, in either direction, set on the socket or
  anywhere in its namespace;
* one whose route goes through an L3 master device (VRF) or a lightweight
  tunnel;
* with ``CONFIG_IPV6=m``, every ``AF_INET6`` socket, the IPv4 connections a
  dual-stack listener on ``::`` accepts included, since the send path needs
  parts of IPv6 that a module keeps to itself.

Consequences for host policy
----------------------------

After the handshake, netfilter and TC see none of a served connection's
data: not what the program takes, and nothing the host sends. They still see
the peer's pure ACKs and whatever the program passes to the stack. What
follows from that:

* **conntrack** sees the handshake, the peer's pure ACKs and whatever the
  program passes to the stack, and nothing else: no data in either
  direction and neither FIN. What it does see acknowledges replies it never
  saw, so with ``net.netfilter.nf_conntrack_tcp_be_liberal`` at its default
  of 0 it marks those segments invalid, and a ruleset that drops the invalid
  state drops the peer's ACKs. Because no FIN is seen, the entry stays
  established until ``nf_conntrack_tcp_timeout_established``, five days by
  default; a busy service fills the table, and conntrack then drops new
  connections to every service on the host. The sysctl cures the first
  problem and not the second. Exempt the service instead: a ``notrack`` rule
  for its port in the raw table, in PREROUTING and OUTPUT so that the
  handshake is not tracked either, and an INPUT rule that accepts the
  untracked state for it. A stateful firewall for the port is then the
  program's job.
* **NAT** does not apply: the kfuncs find a connection by the addresses and
  ports a segment carries on the wire, which NAT on this host has changed,
  so a connection this host translates is never found and stays on the
  stack's path in both directions.
* **IPsec** is safe: any XFRM policy, in either direction, in the namespace
  makes the kfuncs refuse every socket, so no segment is sent in the clear
  that policy would have protected.
* **TC** egress programs, classifiers and policers do not see a served
  connection's segments on any device they cross, nor do TC ingress
  programs see what the program takes. A TC program that classifies for the
  qdisc, HTB classes or a BPF bandwidth manager setting departure times,
  does not run for them either: served segments go to the default class.
* **Socket filters, cgroup ingress programs and the LSM** do not see what
  the program takes: a ``SO_ATTACH_FILTER`` program, a ``cgroup_skb/ingress``
  program such as the ones behind systemd's ``IPAddressDeny=`` and
  ``IPAccounting=``, and ``security_sock_rcv_skb()``, through which SELinux
  checks peer labels and SECMARK. On the way out the cgroup egress program
  runs; SELinux's netfilter hooks do not.
* **tcpdump** sees the segments the host sends, since packet taps run from
  the device layer, and not the data the program takes: a capture shows the
  host acknowledging data that is not in it.
* **Tracing** of ``tcp_v4_rcv()`` and ``tcp_rcv_established()``, and the
  ``tcp:tcp_probe`` tracepoint, misses taken segments.
* **Accounting** at the IP layer counts the segments sent
  (``IpOutRequests``, ``IpExtOutOctets``) and not those taken; the TCP MIB
  and the socket's own counters count both. Drivers that count XDP actions
  count each taken segment the program drops as an XDP drop. Memory the
  program holds in frames is not charged to the socket, to the TCP memory
  limits or to memcg.

A way to tell that a connection is served: ``ss -ti`` shows ``segs_in`` and
``bytes_received`` growing while ``recv()`` on the socket returns nothing,
and ``TCPHPHits`` in ``nstat`` grows with them.

Receiving
=========

``bpf_xdp_tcp_sock_recv(ctx, &sock, &payload)`` returns true, with a live
handle, for a data segment or a FIN of an established connection the kfuncs
serve, and false, with no handle, for any other packet. The status says what
was done with the segment, under the socket lock:

.. list-table::
   :header-rows: 1

   * - Status
     - What happened
     - What the program does
     - Return
   * - ``BPF_XDP_TCP_RECEIVED``
     - The segment was next in sequence and was taken. ``payload`` covers
       the new bytes, any old prefix trimmed and D-SACKed, until the program
       returns or steals the packet. ``bpf_xdp_tcp_sock_eof()`` says
       whether the peer's stream ends with them; a bare FIN is taken with a
       length of 0.
     - Reads or copies the bytes, answers, or redirects the packet
     - Anything but ``XDP_PASS``: ``XDP_DROP``, a redirect, or
       ``XDP_CONSUME`` after a frame reply
   * - ``BPF_XDP_TCP_OUT_OF_ORDER``
     - Within the window, beyond the receive cursor. Nothing was done.
     - Holds the frame, see `Holding frames`_, or passes it
     - What the hold returned, or ``XDP_PASS``
   * - ``BPF_XDP_TCP_BUSY``
     - Next in sequence, but the socket is busy. Nothing was done.
     - Holds the frame or passes it
     - What the hold returned, or ``XDP_PASS``
   * - ``BPF_XDP_TCP_DUPLICATE``
     - Nothing new in it; it was D-SACKed and acknowledged.
     - Nothing
     - ``XDP_DROP``
   * - ``BPF_XDP_TCP_PASS``
     - Outside the window, or something the kfuncs do not handle. Nothing
       was done.
     - Nothing
     - ``XDP_PASS``

.. important::

   When the status is ``BPF_XDP_TCP_RECEIVED``, the kernel has moved both
   cursors past the payload and will acknowledge it. The bytes in the packet
   are the only copy: the application cannot read them from the socket, and
   the peer will not send them again. Copy them, answer them, or redirect
   the packet before the program returns. Anything that loses them after the
   take, a full AF_XDP ring, a reply that is never retried, a program bug,
   is a silent hole in the stream. The receive window does not shrink while
   the program or a user-space consumer falls behind; to push back on the
   peer, do not take the segment, see `Backpressure`_.

The split path
--------------

A program that inspects a segment before accepting it, or that has to know
whether it can place the bytes before it takes them, uses two calls.
``bpf_xdp_tcp_sock_lookup(ctx, &sock)`` finds the connection of a segment
``recv()`` would take, next in sequence with nothing in the way, without the
socket lock and without taking it; ``bpf_xdp_tcp_sock_payload()`` exposes the
bytes; ``bpf_xdp_tcp_sock_consume(&sock, ctx)`` takes the segment under the
lock, making the checks again. A failed consume, ``-EAGAIN``, leaves the
segment to ``XDP_PASS``; a successful one is a take as above. It costs a
second parse.

Holding frames
==============

A program that wants to keep a connection across a lost segment holds the
frames that arrive beyond the hole, and the frames that arrive while the
socket is busy, and delivers them once their turn comes.

State
  A ``struct bpf_xdp_tcp_conn``, in a global for one connection or in a map
  value keyed by the cookie for many, one per map value, since it contains
  the ``bpf_spin_lock`` that guards its tree of frames. The struct holds up
  to ``BPF_XDP_TCP_HOLD_MAX`` frames, 64 by default, a compile-time constant
  of the header. Holding needs native XDP: under generic XDP the buffer is
  an skb's and cannot be stolen, and ``bpf_xdp_tcp_sock_hold()`` returns
  ``XDP_PASS``.
Holding
  ``bpf_xdp_tcp_sock_hold(ctx, &sock, &conn)`` steals the frame, admits it,
  which processes its ACK and SACKs its data, and files it in ``conn``. It
  returns the action to return once the handle is released:
  ``XDP_CONSUME`` when the frame was taken, which includes frames dropped
  as duplicates, over the budget or outside the window, where the peer's
  retransmission recovers; ``XDP_PASS`` when the frame could not be taken.
  The packet is gone after the call. A frame that arrives while the socket
  is busy is held unadmitted and admitted on the next attempt. The first
  hold keeps a reference to the connection in ``conn``. While frames are
  held, a segment the stack takes, one carrying ECE for instance, leaves
  their SACK blocks in place and the stack's header prediction off.
Delivering
  ``bpf_xdp_tcp_sock_next(&sock, &conn, &payload)`` delivers the held
  segments one per call, in sequence, trimmed of anything already received,
  and returns the number of new bytes; 0 when nothing is due, because no
  frame is held, a hole remains before the first, or the socket is busy;
  or a negative error. The payload lives until the next call or the
  release. ``bpf_xdp_tcp_sock_eof()`` reports a FIN delivered this way. Call
  it after every take while frames are held, which
  ``bpf_xdp_tcp_sock_sacked()`` hints at for peers that SACK.
Retrying
  Nothing tells the program that the socket has become free or that a hole
  has been filled by a segment it passed to the stack. A timer is required:
  ``bpf_xdp_tcp_sock_resume(&conn, &sock)`` gives the timer a handle on the
  connection, and ``next()`` from there delivers what is due. The example
  arms the timer every millisecond while frames are held.
Pruning
  ``bpf_xdp_tcp_sock_purge(&sock, &conn)`` gives every held frame back and
  resets the SACK state that advertised them; it does nothing, and returns
  ``-EAGAIN``, while the socket is busy. A frame that was admitted,
  and so SACKed, and then dropped without the reset is recovered only after
  the peer's retransmission timeout; the kernel's reset tells the peer to
  send sooner.
Closing
  ``bpf_xdp_tcp_sock_closed(&sock)`` is true once the socket is closed or
  the application has closed its descriptor, which can be while the
  connection is still in a FIN state. Until ``bpf_xdp_tcp_conn_destroy()``
  runs, the reference in ``conn`` keeps the socket allocated and the held
  frames keep their receive buffers. The example's timer checks every
  second and reaps. Unloading the program frees both through the kptr
  destructors.
Memory
  Held frames are the driver's receive buffers, page-pool pages on most
  drivers. The window bounds what one connection can hold; the total is
  bounded only by the program's budget, and a program that holds many
  frames on many connections starves the receive ring for every flow.
  Nothing is charged to the socket, to the TCP memory limits or to memcg.

Sending
=======

Two ways to answer. ``bpf_xdp_tcp_sock_send(&sock, buffer, len)`` copies an
arena buffer of 1 to 65536 bytes into page fragments on the write queue and
pushes it; the call queues all of ``len`` or nothing. A reply that fits the
request's buffer can go out of it with no copy: the program writes the
reply into the packet, growing it with ``bpf_xdp_adjust_tail()`` if the
reply is longer than the request, and calls
``bpf_xdp_tcp_sock_send_frame(ctx, &sock, off, len)``, ``off`` usually being
``bpf_xdp_tcp_sock_offset()``. The frame is stolen, becomes the segment's
head, and goes back to the driver's pool once the peer has acknowledged it;
the program returns ``XDP_CONSUME``.

.. list-table:: ``bpf_xdp_tcp_sock_send()``
   :header-rows: 1

   * - Return
     - Meaning
     - What the program does
   * - ``len``
     - Queued and pushed
     - Nothing
   * - ``-EAGAIN``
     - The socket is busy or the send buffer is full; nothing was queued
     - Keeps the data and retries from a timer: no signal says when there
       is room again, and in request/response the next segment may never
       come
   * - ``-ENOTCONN``
     - The connection is neither established nor in ``CLOSE_WAIT``
     - Gives up on it
   * - ``-EINVAL``
     - A socket the kfuncs refuse, or a length of 0 or over 64 KiB
     - A program bug
   * - ``-EFAULT``, ``-ENOMEM``
     - The buffer runs past the arena, or memory
     - Final

.. list-table:: ``bpf_xdp_tcp_sock_send_frame()``
   :header-rows: 1

   * - Return
     - ``bpf_xdp_tcp_sock_error()``
     - What the program does
   * - NULL
     - 0
     - The reply is queued; return ``XDP_CONSUME``
   * - NULL
     - ``-EOPNOTSUPP``
     - The buffer could not be stolen: generic XDP, or a test run without
       live frames. Nothing was sent, and the packet is gone with the
       context: return ``XDP_DROP``. The reply written into it is lost,
       which is why the choice is made before the call, see below
   * - the frame
     - ``-EAGAIN``
     - Keeps the frame in a ``struct xdp_frame __kptr`` field of a map
       value, with a reference from ``bpf_xdp_tcp_sock_acquire()`` next to
       it, and retries from a timer with the kfunc
       ``bpf_xdp_tcp_send_frame()`` on the two, as ``retry_timer()`` in the
       example does; return ``XDP_CONSUME``
   * - the frame
     - ``-EINVAL``, ``-ENOTCONN``, ``-ENOMEM``
     - Releases the frame with ``bpf_xdp_frame_release()``; return
       ``XDP_CONSUME``. ``-EINVAL`` includes a reply that does not lie within
       the frame's data, a frame with fragments, and too little room before
       ``off`` for the headers, which a ``bpf_xdp_adjust_head()`` before the
       call can cause

The frame reply consumes the XDP context whatever its outcome, like every
steal, so a program decides between the two ways before the call: one that
may run under generic XDP, where no buffer can be stolen, answers through
the arena. The loader knows the attach mode. Sending is allowed in
``CLOSE_WAIT``, after the peer's FIN; receiving needs an established
connection. A frame reply keeps the receive buffer until the peer
acknowledges it, several retransmission timeouts under loss, so a reply of
a few bytes may be cheaper through the arena. ``reply_in_frame()``,
``defer_reply()`` and ``retry_timer()`` in the example show both ways and
the retry.

A segment the program queued goes to ``tcp_write_xmit()`` at once; Nagle,
``TCP_CORK`` and autocorking do not apply, since a reply is complete when it
is queued. ``-EAGAIN`` means a busy socket or a full send buffer, never a
segment that is queued and waiting on the congestion window, pacing or TCP
small queues.

The send path
-------------

A served connection's segments leave the host on a path of
``tcp_xdp.c``'s. The first time a kfunc acts on a socket, under the socket
lock, the socket's address-family operations are replaced by a copy whose
``queue_xmit`` does, in this order:

1. checks the socket for the things the path does not do, see below, and
   finds the cached route, or routes the socket again when the cache is
   stale, as ``ip_queue_xmit()`` would; a segment over the path MTU, one
   that needs more link-layer headroom than the socket reserved, or a route
   the socket should not have been adopted with, is handed to
   ``ip_queue_xmit()`` or ``inet6_csk_xmit()`` here;
2. builds the IPv4 or IPv6 header, with the socket's TOS or traffic class,
   TTL or hop limit, DF bit and IP id, and the flow label for IPv6, sets the
   socket's mark and priority on the segment, and counts it in the IP MIBs;
3. runs the cgroup egress program, which sees the segment as
   ``ip_finish_output()`` shows it; its drop verdict frees the segment, and
   the retransmission timer resends it later, as for the stack;
4. marks the segment for the device layer, looks the next hop up in the
   neighbour table, creating the entry if it is missing, confirms it when
   TCP has asked for that, and hands the segment to the neighbour layer,
   which puts the link-layer header on from its cache and calls
   ``dev_queue_xmit()``, or resolves the address first when the entry is not
   in a connected state; the mark survives that queue;
5. ``dev_queue_xmit()`` leaves out the netfilter egress hook and TC egress,
   on this device and on every lower device the segment crosses, and the
   qdisc, packet taps, GSO and TSO, checksum offload and the driver take it
   from there as they take any segment, with the ``NET_XMIT_CN`` congestion
   report that puts the connection in CWR and the qdisc's handling of a
   full transmit queue included. A socket without a route drops the
   segment, as the stack's path does, and the retransmission timer keeps
   trying.

Because the operations are the socket's, every segment of the connection
takes the path: the replies, what the application writes with ``send()``,
and the stack's own pure ACKs, window updates, retransmissions, keepalives,
the FIN and a RST sent from the socket. What remains the stack's is sent
without the socket: the handshake, which precedes the serving; the ACK of a
retransmitted FIN once the connection is in ``TIME-WAIT``; and resets for
segments that match no socket. A socket that is disconnected for reuse gets
the stack's operations back, so a later connection on it, or a listener's
children, are not served unless a kfunc acts on them.

The path does not do IP options or IPv6 extension headers, XFRM, L3 master
devices or lightweight tunnels, netfilter or TC egress. A socket that needs
one of the first four is refused when the kfuncs first see it. A socket
that acquires one of them afterwards, by ``setsockopt()``, or by a policy or
route change in the namespace, is no longer served: ``recv()`` and
``lookup()`` stop finding it, its segments go to the stack, and what it
sends goes through ``ip_queue_xmit()`` or ``inet6_csk_xmit()`` with the
options or transformation applied. Frames already held for it can still be
delivered.

A segment that would exceed the path MTU, or that needs more link-layer
headroom than the socket reserved, is also sent through ``ip_queue_xmit()``.
Such a segment passes netfilter's LOCAL_OUT and POST_ROUTING, conntrack and
TC egress like any other, and conntrack, which has seen nothing of the
connection, will usually mark it invalid.

Segmentation and checksum offload
---------------------------------

A reply longer than the MSS is one segment on the write queue and one skb
on the way down, with ``gso_size`` set to the MSS, until the device layer.
How much of a long reply goes down in one such skb is the stack's TSO
autosizing: about a millisecond's worth of the pacing rate, grown for short
round trips, never more than the device's ``gso_max_size`` and never fewer
than ``tcp_min_tso_segs`` segments, and a congestion control may say
otherwise. The split into wire-sized segments happens in
``validate_xmit_skb()``, after the qdisc: a device with TSO
(``NETIF_F_TSO``, ``NETIF_F_TSO6``) is handed the skb whole and segments it
itself; any other device gets it segmented in software by GSO, which builds
one skb per segment and copies the headers. The checksum is left to the
device (``CHECKSUM_PARTIAL``), or computed in software by
``skb_checksum_help()`` when the device cannot. The send path enters the
device layer above that point, so a served connection has the offloads the
stack path has, and nothing more is asked of the device. The socket's view
of the device's capabilities, ``sk_route_caps``, comes from the route as
before, since the path keeps ``sk_setup_caps()`` when it routes.

The arena send and the frame reply differ only in the memory below the
headers: page fragments for the first, the frame's linear buffer for the
second. TSO reads either by DMA; software GSO copies either into new skbs.
A frame reply longer than the MSS is possible, within the frame's buffer,
and is segmented the same way.

The receive side has no offload at all. XDP sees the frames the device
delivers, so a peer's TSO burst arrives as individual segments, each a lock
section; hardware GRO and LRO are off for the device while an XDP program
is attached; and the TCP checksum is verified in software on every parse,
since the device's verdict is not visible to the program.

Delivering the stream to user space
===================================

A program can hand the bytes the kernel takes to an AF_XDP socket bound to
the same device and queue, instead of answering them itself. The kernel
keeps the connection and acknowledges the data; the consumer reads the
payload from the ring and answers through the connection's own socket, with
``send()``, or from the program. Per data segment, in this order:

1. ``bpf_xdp_tcp_sock_lookup(ctx, &sock)`` finds the connection of an
   in-order segment without taking it;
2. ``bpf_xsk_rx_space(ctx, &xsks, queue)`` asks whether a redirect to the
   socket at ``queue`` in the ``XSKMAP`` would be delivered; when it returns
   0, release the handle and return ``XDP_DROP`` without taking the
   segment, see `Backpressure`_;
3. make room for the record in front of the packet with
   ``bpf_xdp_adjust_meta()``; where that fails, the driver has no XDP
   metadata, and the segment is passed to the stack for the consumer to read
   from the socket;
4. ``bpf_xdp_tcp_sock_consume(&sock, ctx)`` takes the segment. It fails with
   ``-EAGAIN``, taking nothing, when the socket has become busy since the
   lookup, as it is while the consumer is inside ``send()`` on it; the
   segment is then passed, lands in the socket, and the connection stays off
   the ring until the consumer has read the socket, so a consumer that
   answers with ``send()`` reads the socket as well as the ring. From here
   on nothing may fail, since the bytes are taken;
5. strip the headers with ``bpf_xdp_adjust_head(ctx,
   bpf_xdp_tcp_sock_offset(&sock))``, less the shortfall for a payload under
   ``ETH_HLEN``, see below, and fill the record: the cookie,
   ``bpf_xdp_tcp_sock_seq()``, the length and ``bpf_xdp_tcp_sock_eof()``;
6. release the handle and return ``bpf_redirect_map()`` into the
   ``XSKMAP``.

The consumer reads the record at the descriptor's address minus its size
and places the payload by sequence number. It learns the end of the stream
from the record's flag, for a FIN that rides on data, or from the
connection's socket, which it polls next to the ring, for a bare FIN, which
is taken and dropped since there is nothing to deliver.
``bpf_xdp_adjust_head()`` leaves at least ``ETH_HLEN`` bytes in a frame, so a
payload shorter than that keeps a tail of the headers in front of it, and
the record carries that offset. ``xsk_input()`` and ``deliver_xsk()`` in the
example do this, and the ``af_xdp`` and ``af_xdp_backpressure`` subtests
drive them in copy mode on a TAP device.

Segments of one connection reach one queue as long as the device steers the
flow consistently, which RSS does; with aRFS or a steering change they can
move, and a consumer with one socket per queue reorders by sequence number
across its rings. The segments go in order per queue in any case.

Backpressure
------------

A redirect is applied after the program returns, and a frame the socket
cannot take then, because its RX ring is full or, in copy mode, its fill
ring has no buffer, is dropped there and counted in the socket's
``XDP_STATISTICS``. Had the segment been taken, its bytes would be gone from
the stream. ``bpf_xsk_rx_space(ctx, map, key)`` answers before the take: it
returns how many frames a redirect to the socket at ``key`` from this device
and queue would deliver, bounded by the RX ring's free entries and, in copy
mode, the buffers the fill ring can supply, and 0 when there is no socket at
``key`` or it is bound to another device or queue. In native XDP the answer
holds until the program returns, since nothing else produces into the ring
from the queue's NAPI context; in generic XDP, where one queue's program may
run on several CPUs, it is an estimate.

When the answer is 0 the program does not take the segment and returns
``XDP_DROP``: the peer retransmits it after a timeout and treats the loss as
congestion, which is how a slow consumer slows the sender. The alternative,
``XDP_PASS``, puts the segment in the socket's receive queue, where the
consumer reads it with ``recv()`` and the stack's receive buffer gives
window backpressure, at the price of taking the connection off the ring
until the consumer has drained the socket. Either way, the check turns a
full ring into a retransmission or a fallback, not into a smaller window.

Copies
------

.. list-table::
   :header-rows: 1

   * - Path
     - AF_XDP in copy mode
     - AF_XDP in zero-copy mode
   * - In-order segment, redirected
     - one copy, into the UMEM frame
     - none: the NIC received it into the UMEM
   * - Held frame, delivered later
     - none when stolen; the program copies what ``next()`` delivers into a
       channel of its own
     - one, to a kernel page when stolen, and the UMEM buffer goes back to
       the pool; then the program's own channel
   * - Frame reply
     - none
     - one, to a kernel page when stolen
   * - Segment passed to the stack
     - one, to user space, by ``recv()``
     - two: into an skb by the driver, then to user space

Zero-copy is a property of the device queue, set when the AF_XDP socket is
bound; a frame stolen on such a queue is copied to a kernel page first,
because a frame structure cannot be kept in memory that user space maps,
and segments that arrive in order after a hole is filled are zero-copy
again. A held frame cannot be redirected after the fact: there is no XDP
context to redirect from, so a program that holds frames and delivers to
user space copies what ``next()`` delivers into a ring of its own, or passes
out-of-order segments to the stack and lets the consumer read them from the
socket.

Concurrency and execution context
=================================

.. list-table:: Where each kfunc may be called
   :header-rows: 1

   * - kfunc
     - XDP, native
     - XDP, generic
     - ``bpf_timer`` or ``bpf_wq`` callback of an XDP program
     - syscall program
   * - ``recv``, ``lookup``, ``consume``, ``send``
     - yes
     - yes
     - ``send`` only
     - no
   * - ``hold``, ``consume_frame``, ``dup``, ``ooo_reset``,
       ``ack_pending``, ``acquire``, ``release``
     - yes
     - yes, but there is no frame to hold
     - yes
     - yes
   * - ``send_frame``
     - yes
     - no frame to send
     - yes
     - yes
   * - ``bpf_xdp_frame_steal()``
     - yes
     - returns NULL
     - no
     - no
   * - ``bpf_xdp_frame_release()``, ``bpf_dynptr_from_xdp_frame()``
     - yes
     - yes
     - yes
     - yes, and from no other program type
   * - ``bpf_xsk_rx_space()``
     - yes
     - yes
     - no
     - no

A timer or workqueue callback is checked as the program type that armed it.
Tracing programs do not get the kfuncs, since the function being traced may
hold the socket lock. Under generic XDP the program runs on an skb after
GRO, and a merged segment fails the parse, so only unmerged segments are
taken there.

Every kfunc that touches connection state takes the socket's spinlock with
bottom halves disabled, and never acts while a process owns the socket.
That is the state the stack is in when an incoming ACK, a TX completion or
a retransmission timer runs ``tcp_write_xmit()`` from softirq, and the send
kfuncs do nothing the stack does not already do from there; what is new is
only that the write queue is appended to in that context. Where the stack
would queue an skb to the backlog of a user-owned socket, the kfuncs have
no skb to queue, and return ``-EAGAIN`` or the busy status instead, for the
program to retry from a timer. Kfuncs that can be reached from process
context disable bottom halves themselves. Allocations are ``GFP_ATOMIC``,
and memcg charging for send memory does not block.

The kernel delivers the bytes of a connection in sequence and never twice,
whichever CPUs its segments arrive on: every step rechecks the cursor under
the socket lock. The kfuncs take no lock of the program's. If the program's
handling of consecutive segments must not overlap, as for a byte-stream
consumer, the program serializes it: steer the flow to one CPU, or take a
lock of its own. Calls on one connection's state from a timer and from XDP
are serialized the same way.

Performance characteristics
===========================

The in-order take costs one header parse, including the TCP checksum
verified in software since the device does not verify it for XDP, one
socket lookup, one lock section, and the release. A held frame is parsed
and checksummed again when it is admitted and when it is delivered; the
split path parses twice.

The stack receives bulk TCP through GRO, which merges consecutive segments
of a flow into one skb before TCP sees it, so that the lock section, ACK
processing and queueing run once per up to 45 segments. XDP runs before
GRO, and a NIC's hardware GRO is off for the whole device while an XDP
program is attached, for the bulk flows the program passes as much as for
the ones it serves. A segment taken here therefore costs its parse, lookup
and lock section on its own, every MSS. For request/response traffic that is
the right trade: a request is one segment. For a bulk receiver it is not;
the stack with GRO spends less. Frames redirected to another CPU through
cpumap get GRO there, but they are the stack's; nothing merges segments the
kfuncs take. Holding does not amortize either: a held frame is parsed,
checksummed and locked twice more, at admission and at delivery, and only
the ACK for a run of delivered frames is sent once.

A segment is taken on the CPU its packet arrived on and the reply is pushed
from there; with XPS and RSS the connection's socket lock stays on one core
unless the program drives held frames from a timer elsewhere. Replies over
the MSS are segmented by the device or by GSO, see `Segmentation and
checksum offload`_; a device without TSO pays a copy per wire segment.

Compared with other interfaces
==============================

The kernel's zero-copy TCP interfaces remove the copy and keep the rest of
the path; XDP TCP keeps the connection and removes the rest of the path.

.. list-table:: Receive
   :header-rows: 1

   * - Interface
     - skb, GRO, IP input
     - TCP state machine
     - Receive queue, wakeup
     - Delivery to the consumer
     - Copy
   * - ``recv()``
     - yes
     - yes
     - yes
     - syscall
     - yes
   * - ``TCP_ZEROCOPY_RECEIVE``
     - yes
     - yes
     - yes
     - syscall
     - page remap
   * - devmem TCP, io_uring zero-copy receive
     - yes
     - yes
     - yes
     - completion ring
     - no, header split by the NIC
   * - XDP TCP, program
     - no
     - yes, under the socket lock
     - no
     - the program, in the driver's buffer
     - no
   * - XDP TCP, AF_XDP
     - no
     - yes, under the socket lock
     - no
     - user-space ring
     - no in zero-copy mode, one in copy mode
   * - AF_XDP
     - no
     - no
     - no
     - user-space ring
     - no in zero-copy mode, one in copy mode

``TCP_ZEROCOPY_RECEIVE`` remaps the payload pages into the process; devmem
TCP and io_uring's zero-copy receive have the NIC split headers from payload
and hand the payload pages to the application through a completion ring.
All three keep skb construction, GRO, IP input, the socket queue and the
wakeup or ring completion. XDP TCP delivers the bytes to a BPF program in
the driver's receive buffer, with no skb, and the receive duties of the TCP
state machine still run under the socket lock. AF_XDP bypasses the stack
entirely and leaves TCP to the application; XDP TCP over AF_XDP keeps the
kernel socket, with its handshake, congestion control, retransmission,
keepalive, ``TCP_INFO`` and ``ss`` visibility, and the application keeps
the descriptor for everything the program does not do.

.. list-table:: Send
   :header-rows: 1

   * - Interface
     - Syscall, process-context lock
     - Copy
     - Buffer held until
     - Below ``tcp_write_xmit()``
   * - ``send()``
     - yes
     - yes
     - the copy returns
     - the stack's output path
   * - ``MSG_ZEROCOPY``
     - yes
     - no, pages pinned
     - the error-queue completion
     - the stack's output path
   * - arena send
     - no
     - yes
     - the copy returns
     - `The send path`_
   * - frame reply
     - no
     - no
     - the peer's ACK
     - `The send path`_

``MSG_ZEROCOPY`` pins the user pages behind a ``sendmsg()`` and reports
completion through the error queue; it saves the copy and nothing else. The
arena send saves the syscall and the process-context lock and still copies
once; the frame reply saves the copy too.

Verifier rules and runtime checks
=================================

The verifier rejects:

* use of a handle or a frame after its release, and a leak of either;
* a write to a frame after it was admitted: admission invalidates the
  frame's dynptrs and slices and marks it read-only, so the headers the
  kernel checked cannot change under it;
* use of the XDP context, of any packet pointer or dynptr derived from it,
  in any function of the call chain, after a kfunc stole the frame, and a
  tail call after that point, which could run another program on a buffer
  that is no longer the driver's;
* a call to a kfunc that takes the frame from a global function or from an
  extension program: their callers keep copies of the context that the
  verifier cannot invalidate from there.

The kfuncs check at run time that a socket is one they do not refuse and
that a frame or a segment is the connection's. These hold for a program
that calls the kfuncs directly as much as for one that uses the header.

Limitations and future work
===========================

* **Multi-buffer and jumbo frames.** The parser checks the whole segment
  against the first buffer, so a segment that spans fragments, as every
  segment above about 3.5 KiB does on a driver with one page per buffer,
  and most do with a 9000-byte MTU, goes to the stack, with no status to
  say why.
* **GRO.** There is no batched take, and no coalescing engine in the
  program; see `Performance characteristics`_.
* **Receive checksum offload.** XDP exposes no checksum verdict, so every
  segment is checksummed in software; an RX metadata kfunc for the device's
  verdict would remove that on devices that verify TCP checksums.
* **Zero-copy AF_XDP.** Holding a frame on a zero-copy queue copies it,
  and a held frame cannot be posted to the ring, see `Copies`_.
* **Window backpressure.** The consumer's progress is not reflected in the
  advertised window; a slow consumer slows the sender through loss, see
  `Backpressure`_.
* **IPv6 as a module.** With ``CONFIG_IPV6=m`` every ``AF_INET6`` socket is
  refused, see `Sockets and segments left to the stack`_.

Reference
=========

.. list-table:: Wrappers and the kfuncs they call
   :header-rows: 1

   * - Wrapper
     - Kfuncs
   * - ``bpf_xdp_tcp_sock_recv()``
     - ``bpf_xdp_tcp_recv()``, and a dynptr over the payload
   * - ``bpf_xdp_tcp_sock_lookup()``, ``bpf_xdp_tcp_sock_payload()``,
       ``bpf_xdp_tcp_sock_consume()``
     - ``bpf_xdp_tcp_lookup()``, a dynptr, ``bpf_xdp_tcp_consume()``
   * - ``bpf_xdp_tcp_sock_status()``, ``_len()``, ``_seq()``, ``_eof()``,
       ``_sacked()``, ``_cookie()``, ``_offset()``, ``_error()``,
       ``_closed()``
     - fields of ``struct bpf_xdp_tcp_info``, and the socket's state
   * - ``bpf_xdp_tcp_sock_send()``
     - ``bpf_xdp_tcp_send()``
   * - ``bpf_xdp_tcp_sock_send_frame()``, ``bpf_xdp_tcp_sock_resend()``
     - ``bpf_xdp_frame_steal()``, ``bpf_xdp_tcp_send_frame()``
   * - ``bpf_xdp_tcp_sock_hold()``
     - ``bpf_xdp_frame_steal()``, ``bpf_xdp_tcp_hold()``,
       ``bpf_xdp_tcp_dup()``, ``bpf_xdp_tcp_acquire()``, and the rbtree
   * - ``bpf_xdp_tcp_sock_next()``
     - ``bpf_xdp_tcp_hold()`` for frames held unadmitted,
       ``bpf_xdp_tcp_consume_frame()``, ``bpf_dynptr_from_xdp_frame()``,
       ``bpf_xdp_frame_release()``
   * - ``bpf_xdp_tcp_sock_purge()``
     - ``bpf_xdp_tcp_ooo_reset()``
   * - ``bpf_xdp_tcp_sock_resume()``, ``bpf_xdp_tcp_conn_destroy()``
     - the reference kept in ``struct bpf_xdp_tcp_conn``,
       ``bpf_xdp_tcp_release()``
   * - ``bpf_xdp_tcp_sock_acquire()``
     - ``bpf_xdp_tcp_acquire()``
   * - ``bpf_xdp_tcp_sock_release()``
     - ``bpf_xdp_frame_release()``, ``bpf_xdp_tcp_ack_pending()``,
       ``bpf_xdp_tcp_release()``

.. kernel-doc:: net/ipv4/tcp_xdp.c
   :identifiers: bpf_xdp_tcp_recv bpf_xdp_tcp_lookup bpf_xdp_tcp_consume
                 bpf_xdp_tcp_hold bpf_xdp_tcp_consume_frame bpf_xdp_tcp_dup
                 bpf_xdp_tcp_ooo_reset bpf_xdp_tcp_ack_pending
                 bpf_xdp_tcp_send bpf_xdp_tcp_send_frame
                 bpf_xdp_tcp_acquire bpf_xdp_tcp_release

.. kernel-doc:: net/core/xdp.c
   :identifiers: bpf_xdp_frame_steal bpf_xdp_frame_release
                 bpf_dynptr_from_xdp_frame

.. kernel-doc:: net/xdp/xsk.c
   :identifiers: bpf_xsk_rx_space

Examples and tests
==================

``tools/testing/selftests/bpf/progs/xdp_tcp.c``: ``xdp_tcp_echo()`` is the
in-order service; ``hold_input()``, ``drain()`` and ``conn_timer()`` hold
out-of-order frames in a map keyed by the cookie and retry from a timer;
``reply_in_frame()``, ``defer_reply()`` and ``retry_timer()`` answer from
the request's frame and keep a reply the socket could not take;
``xsk_input()`` and ``deliver_xsk()`` deliver the stream to an AF_XDP
socket with the ring-space check. ``prog_tests/xdp_tcp.c`` drives them with
a scripted peer over a TAP device, and ``progs/xdp_tcp_hooks.c`` holds the
observers that check which hooks a served connection's segments pass.
