"""Unit tests for the dual-point forwarding cross-check."""

import pytest

from app.crosscheck import (
    DirectionCoverage,
    Fragment,
    build_coverage,
    compare_direction,
    cross_check,
    extract_connections,
)
from app.pcap import ACK, FIN, PSH, SYN, TcpSegment

_idx = [0]


def seg(src_ip, sport, dst_ip, dport, seq, ack, flags, payload=b"",
        wire_len=None, ts=1.0):
    _idx[0] += 1
    return TcpSegment(
        ts=ts + _idx[0] * 0.001,
        index=_idx[0],
        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
        seq=seq, ack=ack, flags=flags, payload=payload,
        wire_payload_len=len(payload) if wire_len is None else wire_len,
    )


C = ("10.0.0.1", 40000)
S = ("93.184.216.34", 80)
C_ISN, S_ISN = 100, 900
DATA_BASE = C_ISN + 1
RESP_BASE = S_ISN + 1

# sentinel segment lists used when stubbing extract_connections
_ING = [seg(*C, *S, C_ISN, 0, SYN, ts=1.0)]
_EG = [seg(*S, *C, S_ISN, C_ISN + 1, SYN | ACK, ts=1.01)]


def handshake(c_isn=C_ISN, s_isn=S_ISN, ts0=1.0):
    return [
        seg(*C, *S, c_isn, 0, SYN, ts=ts0),
        seg(*S, *C, s_isn, c_isn + 1, SYN | ACK, ts=ts0 + 0.01),
        seg(*C, *S, c_isn + 1, s_isn + 1, ACK, ts=ts0 + 0.02),
    ]


def cdata(payload, seq=None, **kw):
    seq = DATA_BASE if seq is None else seq
    return seg(*C, *S, seq, RESP_BASE, PSH | ACK, payload, **kw)


def sdata(payload, seq=None, **kw):
    seq = RESP_BASE if seq is None else seq
    return seg(*S, *C, seq, DATA_BASE + 200, PSH | ACK, payload, **kw)


REQ = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def full_pair(req=REQ, resp=RESP):
    """Identical clean ingress/egress segment lists for one connection."""
    segs = handshake() + [
        cdata(req[:15]), cdata(req[15:], seq=DATA_BASE + 15),
        sdata(resp),
    ]
    return list(segs), list(segs)


# ---------------------------------------------------------------------------
# DirectionCoverage: segmentation, ordering, duplicates, conflicts
# ---------------------------------------------------------------------------

class TestDirectionCoverage:
    def test_different_segmentation_matches_byte_for_byte(self):
        ing = DirectionCoverage()
        for off, chunk in [(0, REQ[:10]), (10, REQ[10:25]), (25, REQ[25:])]:
            ing.add(Fragment(off, chunk, packet_index=off, truncated=False))
        eg = DirectionCoverage()
        eg.add(Fragment(0, REQ[:20], packet_index=1, truncated=False))
        eg.add(Fragment(20, REQ[20:], packet_index=2, truncated=False))
        rep = compare_direction(ing, eg, DATA_BASE)
        assert rep["matched_bytes"] == len(REQ)
        assert rep["missing_bytes"] == 0
        assert rep["missing_ranges"] == []
        assert rep["cross_conflict_ranges"] == []
        assert rep["review_reasons"] == []

    def test_out_of_order_and_duplicates_counted_once(self):
        cov = DirectionCoverage()
        cov.add(Fragment(10, REQ[10:], packet_index=2, truncated=False))
        cov.add(Fragment(0, REQ[:10], packet_index=1, truncated=False))
        cov.add(Fragment(0, REQ[:10], packet_index=1, truncated=False))  # dup
        cov.add(Fragment(10, REQ[10:], packet_index=3, truncated=False))  # dup
        assert cov.covered_bytes == len(REQ)
        assert bytes(cov.buf) == REQ
        assert cov.conflict_offsets == set()

    def test_identical_overlap_not_a_conflict(self):
        cov = DirectionCoverage()
        cov.add(Fragment(0, b"abcdef", packet_index=1, truncated=False))
        cov.add(Fragment(3, b"def", packet_index=2, truncated=False))
        assert cov.conflict_offsets == set()
        assert cov.covered_bytes == 6

    def test_disagreeing_overlap_is_conflict_and_review(self):
        ing = DirectionCoverage()
        ing.add(Fragment(0, b"abcdef", packet_index=1, truncated=False))
        eg = DirectionCoverage()
        eg.add(Fragment(0, b"abcXYZ", packet_index=1, truncated=False))
        rep = compare_direction(ing, eg, DATA_BASE)
        assert any("different content" in r for r in rep["review_reasons"])
        assert rep["cross_conflict_ranges"] == [
            {"offset": 3, "length": 3, "seq_start": DATA_BASE + 3,
             "seq_end": DATA_BASE + 5}
        ]
        # conflicting bytes must not also be reported as a forwarding gap
        assert rep["missing_bytes"] == 0

    def test_truncation_is_review_even_when_egress_has_fewer_bytes(self):
        ing = DirectionCoverage()
        ing.add(Fragment(0, REQ, packet_index=1, truncated=False))
        eg = DirectionCoverage()
        eg.add(Fragment(0, REQ[:10], packet_index=1, truncated=True))
        rep = compare_direction(ing, eg, DATA_BASE)
        assert rep["truncated_egress"]
        assert any("truncated" in r for r in rep["review_reasons"])

    def test_ingress_internal_hole_is_not_forwarding_loss(self):
        ing = DirectionCoverage()
        ing.add(Fragment(0, REQ[:10], packet_index=1, truncated=False))
        ing.add(Fragment(20, REQ[20:], packet_index=2, truncated=False))
        eg = DirectionCoverage()
        eg.add(Fragment(0, REQ[:10], packet_index=1, truncated=False))
        eg.add(Fragment(20, REQ[20:], packet_index=2, truncated=False))
        rep = compare_direction(ing, eg, DATA_BASE)
        assert rep["missing_bytes"] == 0
        assert rep["ingress_internal_gaps"] == [{"offset": 10, "length": 10}]

    def test_missing_range_names_ingress_packet_numbers_one_based(self):
        ing = DirectionCoverage()
        ing.add(Fragment(0, REQ[:15], packet_index=9, truncated=False))   # frame 10
        ing.add(Fragment(15, REQ[15:], packet_index=10, truncated=False))  # frame 11
        eg = DirectionCoverage()
        eg.add(Fragment(0, REQ[:15], packet_index=4, truncated=False))
        rep = compare_direction(ing, eg, DATA_BASE)
        (rng,) = rep["missing_ranges"]
        assert rng["offset"] == 15
        assert rng["length"] == len(REQ) - 15
        assert rng["ingress_packet_numbers"] == [11]
        assert rng["seq_start"] == (DATA_BASE + 15) % (1 << 32)


# ---------------------------------------------------------------------------
# handshake-anchored demultiplexing and 4-tuple reuse
# ---------------------------------------------------------------------------

class TestDemultiplexing:
    def test_reused_four_tuple_splits_into_two_instances(self):
        segs = handshake(c_isn=100, s_isn=900, ts0=1.0)
        segs += [cdata(REQ), sdata(RESP)]
        # full close of instance 1
        segs += [
            seg(*C, *S, DATA_BASE + len(REQ), RESP_BASE + len(RESP), FIN | ACK, ts=2.0),
            seg(*S, *C, RESP_BASE + len(RESP), DATA_BASE + len(REQ) + 1, FIN | ACK, ts=2.01),
            seg(*C, *S, DATA_BASE + len(REQ) + 1, RESP_BASE + len(RESP) + 1, ACK, ts=2.02),
        ]
        # same 4-tuple, brand new ISNs
        segs += handshake(c_isn=500, s_isn=700, ts0=3.0)
        segs += [
            seg(*C, *S, 501, 701, PSH | ACK, REQ, ts=3.1),
            seg(*S, *C, 701, 501 + len(REQ), PSH | ACK, RESP, ts=3.2),
        ]
        insts = extract_connections(segs)
        assert len(insts) == 2
        assert {i.c_isn for i in insts} == {100, 500}
        assert {i.s_isn for i in insts} == {900, 700}
        assert all(i.handshake_complete for i in insts)
        # every segment is attached to exactly one instance
        assert sum(len(i.segments) for i in insts) == len(segs)

    def test_unanchored_segments_form_review_group(self):
        segs = [cdata(REQ)]  # no SYN at all
        insts = extract_connections(segs)
        assert len(insts) == 1
        assert not insts[0].handshake_complete

    def test_retransmitted_syn_does_not_open_a_second_instance(self):
        segs = [
            seg(*C, *S, C_ISN, 0, SYN, ts=1.0),
            seg(*C, *S, C_ISN, 0, SYN, ts=1.05),  # SYN retransmission
            seg(*S, *C, S_ISN, C_ISN + 1, SYN | ACK, ts=1.1),
            seg(*C, *S, C_ISN + 1, S_ISN + 1, ACK, ts=1.15),
            cdata(REQ),
        ]
        insts = extract_connections(segs)
        assert len(insts) == 1
        assert insts[0].handshake_complete
        assert len(insts[0].segments) == len(segs)

    def test_build_coverage_offsets_relative_to_isn(self):
        inst = extract_connections(handshake() + [cdata(REQ)])[0]
        dirs = build_coverage(inst)
        c2s = dirs["client_to_server"]
        assert c2s.covered_bytes == len(REQ)
        assert bytes(c2s.buf) == REQ


# ---------------------------------------------------------------------------
# end-to-end cross_check classification
# ---------------------------------------------------------------------------

class TestCrossCheck:
    def test_clean_pair_is_verified(self):
        ing, eg = full_pair()
        r = cross_check(ing, eg)
        assert r["summary"]["verified"] == 1
        row = r["connections"][0]
        assert row["status"] == "verified"
        assert row["review_reasons"] == []

    def test_gap_found_with_packet_numbers(self):
        ing = handshake() + [cdata(REQ[:15]), cdata(REQ[15:], seq=DATA_BASE + 15),
                             sdata(RESP)]
        eg = handshake() + [cdata(REQ[:15]), sdata(RESP)]  # second c2s missing
        r = cross_check(ing, eg)
        row = r["connections"][0]
        assert row["status"] == "gap_found"
        d = row["directions"]["client_to_server"]
        (rng,) = d["missing_ranges"]
        assert rng["offset"] == 15 and rng["length"] == len(REQ) - 15
        missing_frame = [s.index + 1 for s in ing
                         if s.payload == REQ[15:]][0]
        assert rng["ingress_packet_numbers"] == [missing_frame]
        assert r["summary"]["missing_bytes_total"] == len(REQ) - 15

    def test_cross_segment_gap_spanning_two_ingress_packets(self):
        # egress only kept the first 5 and the last 5 bytes; the hole spans
        # parts of two differently segmented ingress packets
        ing = handshake() + [
            cdata(REQ[:20], seq=DATA_BASE),
            cdata(REQ[20:], seq=DATA_BASE + 20),
            sdata(RESP),
        ]
        eg = handshake() + [
            cdata(REQ[:5], seq=DATA_BASE),
            cdata(REQ[-5:], seq=DATA_BASE + len(REQ) - 5),
            sdata(RESP),
        ]
        r = cross_check(ing, eg)
        row = r["connections"][0]
        assert row["status"] == "gap_found"
        # frames carrying the two halves of the request (1-based)
        c2s_frames = sorted(s.index + 1 for s in ing
                            if (s.src_ip, s.src_port) == C and s.payload)
        ranges = row["directions"]["client_to_server"]["missing_ranges"]
        assert ranges == [{"offset": 5, "length": len(REQ) - 10,
                           "seq_start": DATA_BASE + 5,
                           "seq_end": DATA_BASE + len(REQ) - 6,
                           "ingress_packet_numbers": c2s_frames}]

    def test_reused_tuple_pairing_keeps_instances_independent(self):
        def side(second_egress_complete: bool):
            segs = handshake(c_isn=100, s_isn=900, ts0=1.0)
            segs += [cdata(REQ), sdata(RESP)]
            segs += handshake(c_isn=500, s_isn=700, ts0=3.0)
            second_req = seg(*C, *S, 501, 701, PSH | ACK, REQ, ts=3.1)
            segs.append(second_req)
            if second_egress_complete:
                segs.append(seg(*S, *C, 701, 501 + len(REQ), PSH | ACK, RESP, ts=3.2))
            return segs
        ing = side(True)
        eg = side(False)  # second instance's response missing on egress
        r = cross_check(ing, eg)
        by_isn = {c["connection"]["client_isn"]: c for c in r["connections"]}
        assert by_isn[100]["status"] == "verified"
        # the second instance is a gap, not a pairing ambiguity
        assert by_isn[500]["status"] == "gap_found"
        assert by_isn[500]["directions"]["server_to_client"]["missing_bytes"] == len(RESP)

    def test_same_sequence_content_conflict_is_review_not_loss(self):
        ing = handshake() + [cdata(REQ), sdata(RESP)]
        bad_resp = b"HTTP/1.1 500 ERR\r\nContent-Length: 0\r\n\r\n"
        eg = handshake() + [cdata(REQ), sdata(bad_resp)]
        r = cross_check(ing, eg)
        row = r["connections"][0]
        assert row["status"] == "review"
        assert any("different content" in x for x in row["review_reasons"])
        assert r["summary"]["gap_found"] == 0

    def test_truncated_egress_packet_is_review(self):
        ing = handshake() + [cdata(REQ), sdata(RESP)]
        eg = handshake() + [
            cdata(REQ[:10], wire_len=len(REQ)),  # snaplen cut
            sdata(RESP),
        ]
        r = cross_check(ing, eg)
        row = r["connections"][0]
        assert row["status"] == "review"
        assert any("truncated" in x for x in row["review_reasons"])

    def test_truncated_ingress_packet_is_review(self):
        ing = handshake() + [
            cdata(REQ[:10], wire_len=len(REQ)),
            sdata(RESP),
        ]
        eg = handshake() + [cdata(REQ), sdata(RESP)]
        r = cross_check(ing, eg)
        assert r["connections"][0]["status"] == "review"
        assert any("ingress packet truncated" in x
                   for x in r["connections"][0]["review_reasons"])

    def test_missing_egress_connection_is_review_not_loss(self):
        ing = handshake() + [cdata(REQ), sdata(RESP)]
        # egress sees a different, unrelated connection only
        c2, s2 = ("10.0.0.9", 41000), ("93.184.216.99", 80)
        eg = [
            seg(*c2, *s2, 300, 0, SYN, ts=1.0),
            seg(*s2, *c2, 600, 301, SYN | ACK, ts=1.01),
            seg(*c2, *s2, 301, 601, ACK, ts=1.02),
        ]
        r = cross_check(ing, eg)
        statuses = {c["status"] for c in r["connections"]}
        assert statuses == {"review"}
        assert r["summary"]["gap_found"] == 0
        reasons = " ".join(x for c in r["connections"] for x in c["review_reasons"])
        assert "no egress connection" in reasons or "without an ingress" in reasons

    def test_non_overlapping_capture_windows_force_global_review(self):
        old = [_with_ts(s, s.ts - 100.0) for s in (handshake() + [cdata(REQ), sdata(RESP)])]
        new = [_with_ts(s, s.ts + 100.0) for s in (handshake() + [cdata(REQ), sdata(RESP)])]
        r = cross_check(old, new)
        assert r["capture_windows"]["overlap"] is False
        assert r["review_reasons"]
        assert all(c["status"] == "review" for c in r["connections"])
        assert r["summary"]["gap_found"] == 0

    def test_duplicate_ingress_frames_do_not_double_count(self):
        base = handshake()
        ing = base + [
            cdata(REQ), cdata(REQ),  # exact retransmission
            sdata(RESP), sdata(RESP),  # mirror duplicate
        ]
        eg = handshake() + [cdata(REQ), sdata(RESP)]
        r = cross_check(ing, eg)
        row = r["connections"][0]
        assert row["status"] == "verified"
        d = row["directions"]["client_to_server"]
        assert d["ingress_covered_bytes"] == len(REQ)
        assert d["matched_bytes"] == len(REQ)

    def test_non_unique_pairing_is_review(self):
        # Two genuinely distinct ingress connection instances share one
        # signature bucket with a single egress instance: pairing is no longer
        # 1:1, so every involved instance must be 待核, never loss.
        from app.crosscheck import ConnInstance
        from app import crosscheck as cc

        def make_inst(c_isn, s_isn):
            inst = ConnInstance(key=(C, S), client=C, server=S,
                                c_isn=c_isn, s_isn=s_isn)
            # mark the handshake complete with the three real handshake frames
            inst.syn, inst.synack, inst.ack3 = handshake(c_isn, s_isn)
            inst.segments = list(handshake(c_isn, s_isn))
            return inst

        a, b = make_inst(100, 900), make_inst(100, 900)
        only_eg = make_inst(100, 900)
        assert a.signature == b.signature == only_eg.signature

        real_extract = cc.extract_connections
        cc.extract_connections = lambda segs: (  # noqa: E731
            [a, b] if segs is _ING else [only_eg])
        try:
            r = cross_check(_ING, _EG)
        finally:
            cc.extract_connections = real_extract
        assert all(c["status"] == "review" for c in r["connections"])
        assert any("not unique" in x
                   for c in r["connections"] for x in c["review_reasons"])
        assert r["summary"]["gap_found"] == 0

    def test_empty_capture_raises(self):
        with pytest.raises(ValueError):
            cross_check([], handshake())
        with pytest.raises(ValueError):
            cross_check(handshake(), [])


def _with_ts(segment: TcpSegment, ts: float) -> TcpSegment:
    return TcpSegment(
        ts=ts, index=segment.index, src_ip=segment.src_ip, dst_ip=segment.dst_ip,
        src_port=segment.src_port, dst_port=segment.dst_port, seq=segment.seq,
        ack=segment.ack, flags=segment.flags, payload=segment.payload,
        wire_payload_len=segment.wire_payload_len,
    )
