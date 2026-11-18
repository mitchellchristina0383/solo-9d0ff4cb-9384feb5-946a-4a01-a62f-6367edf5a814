"""Capture-level orchestration: decode, group into flows, analyse."""

from __future__ import annotations

from .crosscheck import cross_check
from .flows import analyze_flow, group_flows
from .pcap import read_segments


def analyze_capture(data: bytes) -> dict:
    segments = read_segments(data)
    flows = group_flows(segments)
    results = [
        analyze_flow(flow_id, segs)
        for flow_id, (_key, segs) in enumerate(
            sorted(flows.items(), key=lambda kv: min(s.ts for s in kv[1]))
        )
    ]
    summary = {
        "tcp_segments": len(segments),
        "flows": len(results),
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "unreliable": sum(1 for r in results if r["status"] == "unreliable"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
    }
    return {"summary": summary, "flows": results}


def cross_check_captures(ingress_data: bytes, egress_data: bytes) -> dict:
    """Decode two captures and run the dual-point forwarding cross-check."""
    ingress_segments = read_segments(ingress_data)
    egress_segments = read_segments(egress_data)
    return cross_check(ingress_segments, egress_segments)
