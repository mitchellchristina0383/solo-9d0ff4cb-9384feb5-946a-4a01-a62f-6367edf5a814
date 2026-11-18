"""Dual-point forwarding cross-check between two captures of one gateway.

The network operator takes one capture on each side of a gateway (ingress and
egress).  Both captures cover the same time window, the same Ethernet/IPv4/TCP
traffic and there is no NAT, so the 4-tuple and the TCP sequence numbers are
identical on both sides.

The job of this module is to find TCP payload bytes that *entered* the gateway
but never show up on the egress side, without ever guessing:

* connections are demultiplexed by the **full three-way handshake**, so a
  4-tuple that is reused (e.g. after TIME_WAIT) yields separate connection
  instances distinguished by their ISNs;
* each direction is merged by sequence number: different segmentation and
  arrival order are normalised, identical retransmissions / duplicate mirror
  copies are counted once, disagreeing overlaps are recorded as conflicts;
* ingress and egress bytes are compared by direction, absolute sequence space
  and byte content;
* anything ambiguous (non-unique pairing, same-sequence byte conflict,
  snaplen-truncated relevant packets, capture windows that do not overlap) is
  reported as ``review`` (待核), never as packet loss.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .pcap import ACK, SYN, TcpSegment

_MOD32 = 1 << 32
_HALF32 = 1 << 31


# ---------------------------------------------------------------------------
# sequence-space coverage of one direction of one connection
# ---------------------------------------------------------------------------

@dataclass
class Fragment:
    """One captured payload-bearing segment placed in sequence space."""

    offset: int
    data: bytes
    packet_index: int  # 0-based frame number inside its capture file
    truncated: bool


@dataclass
class DirectionCoverage:
    """Merged view of every payload byte of one direction of one connection.

    ``buf[pos]`` is only meaningful where ``present[pos]`` is set; uncovered
    positions hold NUL filler so absolute offsets stay valid.  ``owners[pos]``
    lists every (deduplicated) ingress/egress frame that carried that byte,
    which is what lets a reported missing range name the ingress frame numbers.
    """

    length: int = 0
    buf: bytearray = field(default_factory=bytearray)
    present: bytearray = field(default_factory=bytearray)  # bitmap, 1/0
    owners: list[list[int] | None] = field(default_factory=list)
    conflict_offsets: set[int] = field(default_factory=set)
    truncated: bool = False

    def add(self, fragment: Fragment) -> None:
        if fragment.truncated:
            self.truncated = True
        data = fragment.data
        if not data:
            return
        off, end = fragment.offset, fragment.offset + len(data)
        if end > self.length:
            grow = end - self.length
            self.buf.extend(b"\x00" * grow)
            self.present.extend(b"\x00" * grow)
            self.owners.extend([None] * grow)
            self.length = end
        pkt = fragment.packet_index
        for pos in range(off, end):
            byte = data[pos - off]
            if not self.present[pos]:
                self.buf[pos] = byte
                self.present[pos] = 1
                self.owners[pos] = [pkt]
            else:
                if self.buf[pos] != byte:
                    self.conflict_offsets.add(pos)
                owner = self.owners[pos]
                if pkt not in owner:  # duplicate mirror / retransmission: count once
                    owner.append(pkt)

    def ranges_where(self, want_present: bool) -> list[tuple[int, int]]:
        """Coalesced (offset, length) ranges matching a presence condition."""
        ranges: list[tuple[int, int]] = []
        start: int | None = None
        for pos in range(self.length):
            ok = bool(self.present[pos]) == want_present
            if ok:
                if start is None:
                    start = pos
            elif start is not None:
                ranges.append((start, pos - start))
                start = None
        if start is not None:
            ranges.append((start, self.length - start))
        return ranges

    @property
    def gaps(self) -> list[tuple[int, int]]:
        """Internal holes: offsets this side never received at all."""
        return self.ranges_where(False)

    @property
    def conflict_ranges(self) -> list[tuple[int, int]]:
        return _coalesce(sorted(self.conflict_offsets))

    @property
    def covered_bytes(self) -> int:
        return sum(self.present)


def _coalesce(offsets: list[int]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    start = prev = None
    for off in offsets:
        if start is None:
            start = prev = off
        elif off == prev + 1:
            prev = off
        else:
            ranges.append((start, prev - start + 1))
            start = prev = off
    if start is not None:
        ranges.append((start, prev - start + 1))
    return ranges


# ---------------------------------------------------------------------------
# connection demultiplexing (handshake-anchored, 4-tuple reuse safe)
# ---------------------------------------------------------------------------

@dataclass
class ConnInstance:
    """One TCP connection instance inside one capture."""

    key: tuple  # normalised ((ip, port), (ip, port))
    client: tuple
    server: tuple
    c_isn: int | None = None
    s_isn: int | None = None
    syn: TcpSegment | None = None
    synack: TcpSegment | None = None
    ack3: TcpSegment | None = None
    segments: list[TcpSegment] = field(default_factory=list)

    @property
    def handshake_complete(self) -> bool:
        return self.syn is not None and self.synack is not None and self.ack3 is not None

    @property
    def signature(self) -> tuple:
        """Cross-capture identity: 4-tuple plus both ISNs (no NAT assumed)."""
        return (self.key, self.c_isn, self.s_isn)

    @property
    def first_ts(self) -> float:
        return min(s.ts for s in self.segments)

    @property
    def last_ts(self) -> float:
        return max(s.ts for s in self.segments)


def _flow_key(seg: TcpSegment) -> tuple:
    a = (seg.src_ip, seg.src_port)
    b = (seg.dst_ip, seg.dst_port)
    return (a, b) if a <= b else (b, a)


def extract_connections(segments: list[TcpSegment]) -> list[ConnInstance]:
    """Split a capture's segments into handshake-anchored connection instances.

    Segments are walked in capture order.  A pure SYN opens a new instance even
    when the 4-tuple was used before (TIME_WAIT reuse); subsequent segments are
    attached to the most recently opened instance with matching endpoints.
    Segments with no preceding SYN become an unanchored group that can never be
    paired reliably and is therefore surfaced as ``review`` later.
    """
    ordered = sorted(segments, key=lambda s: (s.ts, s.index))
    by_key: dict[tuple, list[ConnInstance]] = {}
    unanchored: list[ConnInstance] = []

    for seg in ordered:
        key = _flow_key(seg)
        instances = by_key.setdefault(key, [])
        is_syn = bool(seg.flags & SYN)
        is_ack = bool(seg.flags & ACK)

        if is_syn and not is_ack:
            if (instances
                    and instances[-1].syn is not None
                    and instances[-1].c_isn == seg.seq
                    and instances[-1].client == (seg.src_ip, seg.src_port)
                    and instances[-1].server == (seg.dst_ip, seg.dst_port)):
                # Retransmission of the same SYN before the handshake moved
                # on: attach instead of opening a second connection instance.
                instances[-1].segments.append(seg)
                continue
            inst = ConnInstance(
                key=key,
                client=(seg.src_ip, seg.src_port),
                server=(seg.dst_ip, seg.dst_port),
                c_isn=seg.seq,
                syn=seg,
                segments=[seg],
            )
            instances.append(inst)
            continue

        target = instances[-1] if instances else None
        if is_syn and is_ack and target is not None:
            # SYN-ACK belongs to the pending handshake of this 4-tuple.
            if ((seg.src_ip, seg.src_port) == target.server
                    and (seg.ack - target.c_isn) % _MOD32 == 1):
                target.synack = seg
                target.s_isn = seg.seq
                target.segments.append(seg)
                continue

        if target is not None and (
            (seg.src_ip, seg.src_port) in (target.client, target.server)
        ):
            if (target.ack3 is None and target.synack is not None
                    and (seg.src_ip, seg.src_port) == target.client
                    and not is_syn and is_ack
                    and (seg.ack - target.s_isn) % _MOD32 == 1):
                target.ack3 = seg
            target.segments.append(seg)
            continue

        # No handshake to anchor it: keep it in a dedicated unanchored group.
        if not unanchored or _flow_key(seg) != unanchored[-1].key:
            group = ConnInstance(
                key=key,
                client=(seg.src_ip, seg.src_port),
                server=(seg.dst_ip, seg.dst_port),
                segments=[],
            )
            unanchored.append(group)
        unanchored[-1].segments.append(seg)

    return [inst for instances in by_key.values() for inst in instances] + unanchored


def build_coverage(inst: ConnInstance) -> dict[str, DirectionCoverage]:
    """Merge both directions of a connection instance into sequence space."""
    base_c2s = (inst.c_isn + 1) % _MOD32 if inst.c_isn is not None else None
    base_s2c = (inst.s_isn + 1) % _MOD32 if inst.s_isn is not None else None
    dirs = {"client_to_server": DirectionCoverage(),
            "server_to_client": DirectionCoverage()}
    for seg in inst.segments:
        if (seg.src_ip, seg.src_port) == inst.client:
            name, base = "client_to_server", base_c2s
        elif (seg.src_ip, seg.src_port) == inst.server:
            name, base = "server_to_client", base_s2c
        else:
            continue
        if not seg.payload:
            continue
        if base is None:  # unanchored group: sequence space is unknown
            continue
        offset = (seg.seq - base) % _MOD32
        if offset >= _HALF32:  # pre-handshake sequence number, cannot place
            continue
        dirs[name].add(Fragment(
            offset=offset,
            data=seg.payload,
            packet_index=seg.index,
            truncated=seg.truncated and seg.wire_payload_len > 0,
        ))
    return dirs


# ---------------------------------------------------------------------------
# per-connection comparison
# ---------------------------------------------------------------------------

def _range_json(ing: DirectionCoverage, ranges: list[tuple[int, int]], base: int) -> list[dict]:
    out = []
    for offset, length in ranges:
        packets: set[int] = set()
        for pos in range(offset, offset + length):
            for pkt in ing.owners[pos] or ():
                packets.add(pkt)
        out.append({
            "offset": offset,
            "length": length,
            "seq_start": (base + offset) % _MOD32,
            "seq_end": (base + offset + length - 1) % _MOD32,
            # capture frame numbers are 1-based, matching Wireshark/tcpdump
            "ingress_packet_numbers": sorted(p + 1 for p in packets),
        })
    return out


def compare_direction(ing: DirectionCoverage, eg: DirectionCoverage, base: int) -> dict:
    """Compare one direction; missing ranges plus every 待核 reason."""
    review: list[str] = []
    if ing.truncated:
        review.append("ingress packet truncated by snaplen in this direction")
    if eg.truncated:
        review.append("egress packet truncated by snaplen in this direction")
    if ing.conflict_offsets:
        review.append("ingress has conflicting bytes for the same sequence range")
    if eg.conflict_offsets:
        review.append("egress has conflicting bytes for the same sequence range")

    missing_offsets: list[int] = []
    cross_conflict_offsets: list[int] = []
    matched = 0
    for pos in range(ing.length):
        if not ing.present[pos]:
            continue  # a hole inside the ingress capture itself is not forwarding loss
        if pos >= eg.length or not eg.present[pos]:
            missing_offsets.append(pos)
        elif eg.buf[pos] != ing.buf[pos]:
            cross_conflict_offsets.append(pos)
        else:
            matched += 1
    if cross_conflict_offsets:
        review.append("ingress and egress carry different content at the same sequence")

    missing = _coalesce(missing_offsets)
    cross = _coalesce(cross_conflict_offsets)
    return {
        "ingress_covered_bytes": ing.covered_bytes,
        "egress_covered_bytes": eg.covered_bytes,
        "matched_bytes": matched,
        "missing_bytes": sum(length for _off, length in missing),
        "missing_ranges": _range_json(ing, missing, base),
        "cross_conflict_ranges": [
            {"offset": off, "length": length,
             "seq_start": (base + off) % _MOD32,
             "seq_end": (base + off + length - 1) % _MOD32}
            for off, length in cross
        ],
        "ingress_internal_gaps": [
            {"offset": off, "length": length} for off, length in ing.gaps
        ],
        "ingress_conflict_ranges": [
            {"offset": off, "length": length} for off, length in ing.conflict_ranges
        ],
        "egress_conflict_ranges": [
            {"offset": off, "length": length} for off, length in eg.conflict_ranges
        ],
        "truncated_ingress": ing.truncated,
        "truncated_egress": eg.truncated,
        "review_reasons": review,
    }


# ---------------------------------------------------------------------------
# top-level orchestration
# ---------------------------------------------------------------------------

def _endpoint_json(inst: ConnInstance) -> dict:
    return {
        "client": f"{inst.client[0]}:{inst.client[1]}",
        "server": f"{inst.server[0]}:{inst.server[1]}",
        "client_ip": inst.client[0],
        "client_port": inst.client[1],
        "server_ip": inst.server[0],
        "server_port": inst.server[1],
        "client_isn": inst.c_isn,
        "server_isn": inst.s_isn,
    }


def _side_json(inst: ConnInstance | None, packets: int) -> dict | None:
    if inst is None:
        return None
    return {
        "packets": packets,
        "handshake_complete": inst.handshake_complete,
        "first_seen": inst.first_ts,
        "last_seen": inst.last_ts,
    }


def cross_check(ingress_segments: list[TcpSegment],
                egress_segments: list[TcpSegment]) -> dict:
    """Compare two captures and return the forwarding cross-check report."""
    if not ingress_segments:
        raise ValueError("ingress capture contains no decodable TCP segments")
    if not egress_segments:
        raise ValueError("egress capture contains no decodable TCP segments")

    ing_insts = extract_connections(ingress_segments)
    eg_insts = extract_connections(egress_segments)

    ing_window = (min(s.ts for s in ingress_segments), max(s.ts for s in ingress_segments))
    eg_window = (min(s.ts for s in egress_segments), max(s.ts for s in egress_segments))
    windows_overlap = not (ing_window[1] < eg_window[0] or eg_window[1] < ing_window[0])

    global_review: list[str] = []
    if not windows_overlap:
        global_review.append(
            "ingress and egress capture windows do not overlap in time; "
            "every connection below is 待核 (review), none is classified as loss"
        )

    # --- pair handshake-complete instances by (4-tuple, ISN, ISN) ------------
    ing_by_sig: dict[tuple, list[ConnInstance]] = {}
    eg_by_sig: dict[tuple, list[ConnInstance]] = {}
    ing_other: list[ConnInstance] = []
    eg_other: list[ConnInstance] = []
    for inst in ing_insts:
        if inst.handshake_complete:
            ing_by_sig.setdefault(inst.signature, []).append(inst)
        else:
            ing_other.append(inst)
    for inst in eg_insts:
        if inst.handshake_complete:
            eg_by_sig.setdefault(inst.signature, []).append(inst)
        else:
            eg_other.append(inst)

    rows: list[dict] = []
    consumed_eg: set[int] = set()
    pair_count = 0
    missing_total = 0

    for sig, ings in ing_by_sig.items():
        egs = eg_by_sig.get(sig, [])
        consumed_eg.update(id(e) for e in egs)
        if len(ings) == 1 and len(egs) == 1:
            row = _paired_row(rows, ings[0], egs[0], ing_window, eg_window,
                              global_review)
            rows.append(row)
            pair_count += 1
            if row["status"] == "gap_found":
                # review rows (conflict, truncation, window mismatch, ...)
                # expose raw missing ranges but never count as confirmed loss
                missing_total += row["missing_total_bytes"]
        elif not egs:
            # Complete ingress connection with no egress counterpart: 待核,
            # never loss (capture scope / tap placement still to verify).
            for inst in ings:
                rows.append(_single_row(
                    rows, inst, "ingress",
                    ["no egress connection with matching 4-tuple and ISNs; "
                     "cannot prove forwarding loss (capture scope/setup to verify)"]))
        else:
            # Non-unique pairing (duplicates on either side): every involved
            # instance is 待核, never loss.
            reason = (f"connection pairing not unique: {len(ings)} ingress / "
                      f"{len(egs)} egress instance(s) share 4-tuple and ISNs")
            for inst in ings:
                rows.append(_single_row(rows, inst, "ingress", [reason]))
            for inst in egs:
                rows.append(_single_row(rows, inst, "egress", [reason]))

    # Complete egress instances never matched to an ingress instance.
    for sig, egs in eg_by_sig.items():
        for inst in egs:
            if id(inst) not in consumed_eg:
                rows.append(_single_row(
                    rows, inst, "egress",
                    ["egress connection without an ingress counterpart; "
                     "capture scope to verify"]))

    # Handshake-incomplete groups can never be paired: 待核.
    for inst in ing_other:
        rows.append(_single_row(
            rows, inst, "ingress",
            ["no complete three-way handshake captured; connection cannot be "
             "anchored or paired reliably"]))
    for inst in eg_other:
        rows.append(_single_row(
            rows, inst, "egress",
            ["no complete three-way handshake captured; connection cannot be "
             "anchored or paired reliably"]))

    rows.sort(key=lambda r: (r["first_seen"] if r["first_seen"] is not None else 0.0,
                             r["id"]))
    for new_id, row in enumerate(rows):
        row["id"] = new_id

    summary = {
        "ingress_packets": len(ingress_segments),
        "egress_packets": len(egress_segments),
        "ingress_connections": len(ing_insts),
        "egress_connections": len(eg_insts),
        "paired_connections": pair_count,
        "verified": sum(1 for r in rows if r["status"] == "verified"),
        "gap_found": sum(1 for r in rows if r["status"] == "gap_found"),
        "review": sum(1 for r in rows if r["status"] == "review"),
        "missing_bytes_total": missing_total,
    }
    return {
        "summary": summary,
        "capture_windows": {
            "ingress": {"start": ing_window[0], "end": ing_window[1],
                        "packets": len(ingress_segments)},
            "egress": {"start": eg_window[0], "end": eg_window[1],
                       "packets": len(egress_segments)},
            "overlap": windows_overlap,
        },
        "review_reasons": global_review,
        "connections": rows,
    }


def _paired_row(rows: list[dict], ing: ConnInstance, eg: ConnInstance,
                ing_window: tuple, eg_window: tuple,
                global_review: list[str]) -> dict:
    ing_dirs = build_coverage(ing)
    eg_dirs = build_coverage(eg)
    bases = {
        "client_to_server": (ing.c_isn + 1) % _MOD32,
        "server_to_client": (ing.s_isn + 1) % _MOD32,
    }
    directions = {}
    review: list[str] = list(global_review)
    missing_total = 0
    for name in ("client_to_server", "server_to_client"):
        report = compare_direction(ing_dirs[name], eg_dirs[name], bases[name])
        review.extend(report.pop("review_reasons"))
        missing_total += report["missing_bytes"]
        directions[name] = report

    # Per-connection time-window check on top of the global one.
    if ing.last_ts < eg_window[0] or ing.first_ts > eg_window[1]:
        review.append("ingress connection lies outside the egress capture window")
    if eg.last_ts < ing_window[0] or eg.first_ts > ing_window[1]:
        review.append("egress connection lies outside the ingress capture window")

    if review:
        status = "review"
    elif missing_total:
        status = "gap_found"
    else:
        status = "verified"
    return {
        "id": len(rows),
        "status": status,
        "review_reasons": review,
        "connection": _endpoint_json(ing),
        "ingress": _side_json(ing, len(ing.segments)),
        "egress": _side_json(eg, len(eg.segments)),
        "directions": directions,
        "missing_total_bytes": missing_total,
        "first_seen": ing.first_ts,
    }


def _single_row(rows: list[dict], inst: ConnInstance, side: str,
                reasons: list[str]) -> dict:
    """A row that could not be paired cleanly: always 待核."""
    return {
        "id": len(rows),
        "status": "review",
        "review_reasons": reasons,
        "connection": _endpoint_json(inst),
        "ingress": _side_json(inst, len(inst.segments)) if side == "ingress" else None,
        "egress": _side_json(inst, len(inst.segments)) if side == "egress" else None,
        "directions": None,
        "missing_total_bytes": 0,
        "first_seen": inst.first_ts if inst.segments else None,
    }
