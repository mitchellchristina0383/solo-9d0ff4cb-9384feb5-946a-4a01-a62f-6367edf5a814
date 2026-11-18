#!/usr/bin/env python3
"""Generate the dual-point cross-check sample captures.

Writes two classic-pcap files covering the same conversations as seen on the
two sides of a gateway (no NAT, so 4-tuples and sequence numbers match):

  samples/crosscheck-ingress.pcap
  samples/crosscheck-egress.pcap

Scenarios (one client port each):

  51001 clean flow, different segmentation + arrival order on the two sides,
        identical retransmissions duplicated by the mirror tap -> verified
  51002 one ingress data segment is missing on egress           -> gap_found
  51003 4-tuple reused twice (two full handshakes, different ISNs);
        second instance loses an egress segment                  -> one
        verified + one gap_found, proving instances stay separate
  51004 egress carries different bytes at the same sequence      -> review
        (same-sequence content conflict, must not be called loss)
  51005 egress packet snaplen-truncated                          -> review
  51006 whole connection exists only on ingress                  -> review
        (no egress counterpart: not classified as loss)
  51007 second data segment missing on egress, but the egress
        capture window ends before that segment was sent         -> review
        (capture windows do not overlap for this connection)
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ip_packet(src: str, dst: str, payload: bytes, proto: int = 6) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, 64, proto, 0, src_b, dst_b,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                         5 << 4, flags, 65535, 0, 0)
    pseudo = (bytes(int(x) for x in src_ip.split("."))
              + bytes(int(x) for x in dst_ip.split("."))
              + struct.pack("!BBH", 0, 6, len(header) + len(payload)))
    csum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return header + payload


def eth_frame(src_ip: str, dst_ip: str, tcp: bytes) -> bytes:
    return SERVER_MAC + CLIENT_MAC + b"\x08\x00" + ip_packet(src_ip, dst_ip, tcp)


class PcapWriter:
    def __init__(self, start_ts: float = 1_700_001_000.0) -> None:
        self.records: list[tuple[float, bytes, int]] = []
        self._ts = start_ts

    def tick(self, dt: float = 0.001) -> float:
        self._ts += dt
        return self._ts

    @property
    def now(self) -> float:
        return self._ts

    def add(self, frame: bytes, ts: float | None = None, cut: int | None = None) -> None:
        ts = self.tick() if ts is None else ts
        if cut is not None:
            self.records.append((ts, frame[:cut], len(frame)))
        else:
            self.records.append((ts, frame, len(frame)))

    def to_bytes(self) -> bytes:
        out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for ts, data, orig_len in self.records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            out.append(struct.pack("<IIII", sec, usec, len(data), orig_len))
            out.append(data)
        return b"".join(out)


class DualFlow:
    """Emit frames of one conversation into ingress/egress writers.

    Sequence numbers are shared between the two sides (no NAT); each side is
    free to segment, order, duplicate, truncate or drop frames differently.
    """

    def __init__(self, ing: PcapWriter, eg: PcapWriter, c_ip: str, c_port: int,
                 s_ip: str = "203.0.113.10", s_port: int = 80,
                 c_isn: int = 1000, s_isn: int = 5000) -> None:
        self.ing, self.eg = ing, eg
        self.c = (c_ip, c_port)
        self.s = (s_ip, s_port)
        self.c_seq, self.s_seq = c_isn, s_isn

    def _frame(self, src, dst, seq, ack, flags, payload=b""):
        return eth_frame(src[0], dst[0],
                         tcp_segment(src[0], dst[0], src[1], dst[1],
                                     seq, ack, flags, payload))

    def _emit(self, side, frame, cut=None):
        w = self.ing if side == "ing" else self.eg
        # keep both timestamps comparable: derive from the writer's clock
        w.add(frame, cut=cut)

    def handshake(self, sides=("ing", "eg")):
        f1 = self._frame(self.c, self.s, self.c_seq, 0, SYN)
        f2 = self._frame(self.s, self.c, self.s_seq, self.c_seq + 1, SYN | ACK)
        f3 = self._frame(self.c, self.s, self.c_seq + 1, self.s_seq + 1, ACK)
        for side in sides:
            self._emit(side, f1)
            self._emit(side, f2)
            self._emit(side, f3)
        self.c_seq += 1
        self.s_seq += 1

    def c2s(self, payload: bytes, seq: int | None = None,
            sides=("ing", "eg"), cuts: dict | None = None,
            retransmit: tuple = ()) -> int:
        seq = self.c_seq if seq is None else seq
        frame = self._frame(self.c, self.s, seq, self.s_seq, PSH | ACK, payload)
        cuts = cuts or {}
        for side in sides:
            self._emit(side, frame, cut=cuts.get(side))
            if side in retransmit:  # identical retransmission / mirror duplicate
                self._emit(side, frame, cut=cuts.get(side))
        self.c_seq = max(self.c_seq, seq + len(payload))
        return seq

    def s2c(self, payload: bytes, seq: int | None = None,
            sides=("ing", "eg"), cuts: dict | None = None,
            retransmit: tuple = (), override: dict | None = None) -> int:
        seq = self.s_seq if seq is None else seq
        for side in sides:
            data = (override or {}).get(side, payload)
            frame = self._frame(self.s, self.c, seq, self.c_seq, PSH | ACK, data)
            self._emit(side, frame, cut=(cuts or {}).get(side))
            if side in retransmit:
                self._emit(side, frame, cut=(cuts or {}).get(side))
        self.s_seq = max(self.s_seq, seq + len(payload))
        return seq

    def close(self, sides=("ing", "eg")):
        f1 = self._frame(self.c, self.s, self.c_seq, self.s_seq, FIN | ACK)
        f2 = self._frame(self.s, self.c, self.s_seq, self.c_seq + 1, FIN | ACK)
        f3 = self._frame(self.c, self.s, self.c_seq + 1, self.s_seq + 1, ACK)
        for side in sides:
            self._emit(side, f1)
            self._emit(side, f2)
            self._emit(side, f3)


def _build_pair() -> tuple[bytes, bytes]:
    ing, eg = PcapWriter(), PcapWriter()

    # --- 51001: clean, different segmentation / order / duplicates ------------
    f = DualFlow(ing, eg, "10.1.0.1", 51001)
    f.handshake()
    req = b"GET /one HTTP/1.1\r\nHost: clean.example\r\n\r\n"
    base = f.c_seq
    p1, p2, p3 = req[:15], req[15:30], req[30:]
    # ingress: three in-order segments, p1 duplicated by the mirror tap
    f.c2s(p1, seq=base, sides=("ing",), retransmit=("ing",))
    f.c2s(p2, seq=base + 15, sides=("ing",))
    f.c2s(p3, seq=base + 30, sides=("ing",))
    # egress: same bytes split 20/remainder, second half captured first
    eg.add(f._frame(f.c, f.s, base + 20, f.s_seq, PSH | ACK, req[20:]))
    eg.add(f._frame(f.c, f.s, base, f.s_seq, PSH | ACK, req[:20]))
    eg.add(f._frame(f.c, f.s, base, f.s_seq, PSH | ACK, req[:20]))  # dup
    f.c_seq = base + len(req)
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    rbase = f.s_seq
    f.s2c(resp[:22], sides=("ing",))
    f.s2c(resp[22:], seq=rbase + 22, sides=("ing",))
    eg.add(f._frame(f.s, f.c, rbase, f.c_seq, PSH | ACK, resp))  # one segment
    f.s_seq = rbase + len(resp)
    f.close()

    # --- 51002: one ingress segment never leaves the gateway ------------------
    f = DualFlow(ing, eg, "10.1.0.2", 51002)
    f.handshake()
    req = b"POST /two HTTP/1.1\r\nHost: gap.example\r\nContent-Length: 12\r\n\r\nhello-world!"
    base = f.c_seq
    q1, q2, q3 = req[:20], req[20:40], req[40:]
    f.c2s(q1, seq=base)                       # both sides
    f.c2s(q2, seq=base + 20, sides=("ing",))  # missing on egress -> gap
    f.c2s(q3, seq=base + 40)                  # both sides
    f.s2c(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- 51003: 4-tuple reused by two successive connections -------------------
    shared = ("10.1.0.3", 51003)
    # instance 1: clean
    f = DualFlow(ing, eg, *shared, c_isn=2000, s_isn=8000)
    f.handshake()
    f.c2s(b"GET /reuse-1 HTTP/1.1\r\nHost: reuse.example\r\n\r\n")
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    f.close()
    # instance 2: same 4-tuple, new ISNs, egress loses a segment
    f = DualFlow(ing, eg, *shared, c_isn=4000, s_isn=9000)
    f.handshake()
    req = b"GET /reuse-2 HTTP/1.1\r\nHost: reuse.example\r\n\r\n"
    base = f.c_seq
    f.c2s(req[:25], seq=base)
    f.c2s(req[25:], seq=base + 25, sides=("ing",))  # absent on egress
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- 51004: same sequence, different content on egress --------------------
    f = DualFlow(ing, eg, "10.1.0.4", 51004)
    f.handshake()
    f.c2s(b"GET /four HTTP/1.1\r\nHost: conflict.example\r\n\r\n")
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde"
    rbase = f.s_seq
    f.s2c(resp[:25], seq=rbase, sides=("ing",))
    f.s2c(resp[25:], seq=rbase + 25, sides=("ing",))
    mutated = resp[:25] + b"XYZW!"  # diverging bytes in the second segment
    eg.add(f._frame(f.s, f.c, rbase, f.c_seq, PSH | ACK, mutated))
    f.s_seq = rbase + len(resp)
    f.close()

    # --- 51005: egress packet truncated by snaplen ----------------------------
    f = DualFlow(ing, eg, "10.1.0.5", 51005)
    f.handshake()
    req = b"GET /five HTTP/1.1\r\nHost: trunc.example\r\n\r\n"
    header_len = 14 + 20 + 20
    f.c2s(req, cuts={"eg": header_len + 18})  # egress loses tail of payload
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- 51006: connection present only on ingress ----------------------------
    f = DualFlow(ing, eg, "10.1.0.6", 51006)
    f.handshake(sides=("ing",))
    f.c2s(b"GET /six HTTP/1.1\r\nHost: only-ingress.example\r\n\r\n",
          sides=("ing",))
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", sides=("ing",))
    f.close(sides=("ing",))

    # --- 51007: gap on egress while the per-connection windows miss each other -
    # Only this flow's egress frames are moved into an earlier time region, so
    # the other scenarios stay perfectly aligned.
    f = DualFlow(ing, eg, "10.1.0.7", 51007)
    eg_suffix_start = len(eg.records)
    f.handshake()
    req = b"GET /seven HTTP/1.1\r\nHost: window.example\r\n\r\n"
    base = f.c_seq
    f.c2s(req[:25], seq=base)
    late_ing_ts = ing.now
    f.c2s(req[25:], seq=base + 25, sides=("ing",))  # only ingress, late
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # Move flow 51007's egress frames so its window ends ~2 s before the late
    # ingress-only segment; the missing range then cannot be classified as loss.
    eg_suffix = eg.records[eg_suffix_start:]
    eg_end = max(ts for ts, _d, _o in eg_suffix)
    shift = (eg_end - late_ing_ts) + 2.0
    eg.records[eg_suffix_start:] = [
        (ts - shift, data, orig) for ts, data, orig in eg_suffix
    ]

    return ing.to_bytes(), eg.to_bytes()


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "samples"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    ingress, egress = _build_pair()
    (out_dir / "crosscheck-ingress.pcap").write_bytes(ingress)
    (out_dir / "crosscheck-egress.pcap").write_bytes(egress)
    print(f"wrote {out_dir / 'crosscheck-ingress.pcap'} ({len(ingress)} bytes)")
    print(f"wrote {out_dir / 'crosscheck-egress.pcap'} ({len(egress)} bytes)")


if __name__ == "__main__":
    main()
