"""End-to-end tests for the dual-point /crosscheck endpoints."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
INGRESS = SAMPLES / "crosscheck-ingress.pcap"
EGRESS = SAMPLES / "crosscheck-egress.pcap"

client = TestClient(app)


def post_pair(ingress: Path, egress: Path) -> dict:
    with ingress.open("rb") as fi, egress.open("rb") as fe:
        resp = client.post(
            "/crosscheck",
            files={"ingress": ("ingress.pcap", fi),
                   "egress": ("egress.pcap", fe)},
        )
    assert resp.status_code == 200, resp.text
    return resp.json()


def row_by_port(result: dict, port: int, client_isn: int | None = None) -> dict:
    for row in result["connections"]:
        conn = row["connection"]
        if conn["client_port"] == port and (
            client_isn is None or conn["client_isn"] == client_isn
        ):
            return row
    raise AssertionError(f"connection with client port {port} not found")


def test_docs_and_root_list_crosscheck():
    assert client.get("/docs").status_code == 200
    root = client.get("/").json()
    assert "POST /crosscheck" in root["endpoints"]


def test_sample_download_endpoints():
    ri = client.get("/samples/crosscheck/ingress")
    re = client.get("/samples/crosscheck/egress")
    assert ri.status_code == re.status_code == 200
    assert ri.content == INGRESS.read_bytes()
    assert re.content == EGRESS.read_bytes()


def test_crosscheck_sample_endpoint():
    resp = client.post("/crosscheck/sample")
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["filenames"] == {
        "ingress": "crosscheck-ingress.pcap",
        "egress": "crosscheck-egress.pcap",
    }


def test_sample_summary_classification():
    result = post_pair(INGRESS, EGRESS)
    summary = result["summary"]
    # 7 distinct connections: 51003 carries two instances on one 4-tuple
    assert summary["ingress_connections"] == 8
    assert summary["egress_connections"] == 7
    assert summary["paired_connections"] == 7
    assert summary["verified"] == 2     # 51001 + first 51003 instance
    assert summary["gap_found"] == 2    # 51002 + second 51003 instance
    assert summary["review"] == 4       # 51004, 51005, 51006, 51007
    # only confirmed gaps feed the total; review rows never count as loss.
    # Review rows may still *show* raw ranges for the operator, but the
    # summary total must equal the gap_found rows' bytes alone.
    gap_total = sum(r["missing_total_bytes"]
                    for r in result["connections"] if r["status"] == "gap_found")
    assert summary["missing_bytes_total"] == gap_total == 20 + 21
    assert sum(1 for r in result["connections"]
               if r["status"] not in ("verified", "gap_found", "review")) == 0


def test_clean_flow_with_different_segmentation_verified():
    row = row_by_port(post_pair(INGRESS, EGRESS), 51001)
    assert row["status"] == "verified"
    for report in row["directions"].values():
        assert report["missing_ranges"] == []
        assert report["cross_conflict_ranges"] == []


def test_gap_flow_reports_range_and_ingress_frame():
    result = post_pair(INGRESS, EGRESS)
    row = row_by_port(result, 51002)
    assert row["status"] == "gap_found"
    ranges = row["directions"]["client_to_server"]["missing_ranges"]
    assert len(ranges) == 1
    rng = ranges[0]
    assert rng["offset"] == 20 and rng["length"] == 20
    assert rng["ingress_packet_numbers"]  # concrete frame numbers present
    assert all(isinstance(n, int) and n >= 1 for n in rng["ingress_packet_numbers"])
    assert rng["seq_start"] < rng["seq_end"] or rng["length"] == 1


def test_four_tuple_reuse_stays_separate():
    result = post_pair(INGRESS, EGRESS)
    first = row_by_port(result, 51003, client_isn=2000)
    second = row_by_port(result, 51003, client_isn=4000)
    assert first["status"] == "verified"
    assert second["status"] == "gap_found"
    assert first["id"] != second["id"]


def test_content_conflict_is_review_never_loss():
    row = row_by_port(post_pair(INGRESS, EGRESS), 51004)
    assert row["status"] == "review"
    s2c = row["directions"]["server_to_client"]
    assert s2c["cross_conflict_ranges"]
    assert any("different content" in r for r in row["review_reasons"])


def test_truncation_is_review():
    row = row_by_port(post_pair(INGRESS, EGRESS), 51005)
    assert row["status"] == "review"
    assert any("truncated" in r for r in row["review_reasons"])
    assert row["directions"]["client_to_server"]["truncated_egress"]


def test_ingress_only_connection_is_review():
    row = row_by_port(post_pair(INGRESS, EGRESS), 51006)
    assert row["status"] == "review"
    assert row["egress"] is None
    assert any("no egress connection" in r for r in row["review_reasons"])


def test_window_mismatch_connection_is_review_with_gap_still_shown():
    result = post_pair(INGRESS, EGRESS)
    row = row_by_port(result, 51007)
    assert row["status"] == "review"
    assert any("capture window" in r for r in row["review_reasons"])
    # the raw missing range is still visible to the operator, but the
    # connection is explicitly NOT classified as loss
    assert row["directions"]["client_to_server"]["missing_ranges"]


def test_empty_upload_rejected():
    resp = client.post(
        "/crosscheck",
        files={"ingress": ("e.pcap", b""), "egress": ("g.pcap", b"x")},
    )
    assert resp.status_code == 400


def test_garbage_upload_rejected():
    resp = client.post(
        "/crosscheck",
        files={"ingress": ("a.bin", b"not a pcap"),
               "egress": ("b.bin", b"also not a pcap")},
    )
    assert resp.status_code == 400


def test_original_analyze_endpoint_unchanged():
    # regression guard: the HTTP analysis API must keep working
    with (SAMPLES / "sample.pcap").open("rb") as fh:
        resp = client.post("/analyze", files={"file": ("sample.pcap", fh)})
    assert resp.status_code == 200
    summary = resp.json()["summary"]
    assert summary["flows"] == 9
    assert summary["ok"] == 2 and summary["unreliable"] == 3 and summary["skipped"] == 4
