"""FastAPI application: single-capture HTTP analysis and dual-point
forwarding cross-check between an ingress and an egress capture."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from .analyze import analyze_capture, cross_check_captures

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "samples" / "sample.pcap"
INGRESS_SAMPLE_PATH = (
    Path(__file__).resolve().parent.parent / "samples" / "crosscheck-ingress.pcap"
)
EGRESS_SAMPLE_PATH = (
    Path(__file__).resolve().parent.parent / "samples" / "crosscheck-egress.pcap"
)
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB per file

app = FastAPI(
    title="PCAP HTTP/1.1 Flow Analyzer + Gateway Forwarding Cross-Check",
    description=(
        "Single capture: upload an Ethernet/IPv4/TCP packet capture (pcap or "
        "pcapng) and get per-flow HTTP/1.1 request/response analysis. "
        "Dual-point cross-check: upload two captures of the same period taken "
        "on both sides of one gateway (no NAT). Connections are demultiplexed "
        "by the full three-way handshake (4-tuple reuse is safe), payloads are "
        "compared by direction, TCP sequence number and content, and the API "
        "reports byte ranges seen on ingress but absent on egress together "
        "with the ingress frame numbers. Ambiguous cases (non-unique pairing, "
        "same-sequence content conflicts, truncated packets, non-overlapping "
        "capture windows) are reported as 'review' (待核), never as loss."
    ),
    version="2.0.0",
)


def _read_upload(file: UploadFile) -> bytes:
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=400, detail=f"uploaded file '{file.filename}' is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"file '{file.filename}' too large (100 MiB max)")
    return data


@app.get("/", summary="Service info")
def root() -> dict:
    return {
        "service": "pcap-http-analyzer",
        "docs": "/docs",
        "endpoints": {
            "POST /analyze": "upload one pcap/pcapng file (form field 'file')",
            "GET /sample": "download the bundled single-capture sample",
            "POST /analyze/sample": "analyse the bundled single-capture sample",
            "POST /crosscheck": (
                "upload ingress + egress pcap/pcapng files "
                "(form fields 'ingress' and 'egress')"
            ),
            "GET /samples/crosscheck/ingress": "download the cross-check ingress sample",
            "GET /samples/crosscheck/egress": "download the cross-check egress sample",
            "POST /crosscheck/sample": "run the cross-check on the bundled sample pair",
        },
    }


# ---------------------------------------------------------------------------
# single-capture HTTP analysis (unchanged behaviour)
# ---------------------------------------------------------------------------

@app.post("/analyze", summary="Analyse an uploaded capture")
async def analyze(file: UploadFile = File(...)) -> dict:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="file too large (100 MiB max)")
    try:
        result = analyze_capture(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["filename"] = file.filename
    return result


@app.get("/sample", summary="Download the bundled sample pcap")
def sample() -> FileResponse:
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    return FileResponse(
        SAMPLE_PATH,
        media_type="application/vnd.tcpdump.pcap",
        filename="sample.pcap",
    )


@app.post("/analyze/sample", summary="Analyse the bundled sample pcap")
def analyze_sample() -> dict:
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    result = analyze_capture(SAMPLE_PATH.read_bytes())
    result["filename"] = SAMPLE_PATH.name
    return result


# ---------------------------------------------------------------------------
# dual-point forwarding cross-check
# ---------------------------------------------------------------------------

@app.post("/crosscheck", summary="Cross-check ingress vs egress captures")
async def crosscheck(
    ingress: UploadFile = File(..., description="capture taken on the gateway ingress side"),
    egress: UploadFile = File(..., description="capture taken on the gateway egress side"),
) -> dict:
    ingress_data = _read_upload(ingress)
    egress_data = _read_upload(egress)
    try:
        result = cross_check_captures(ingress_data, egress_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["filenames"] = {"ingress": ingress.filename, "egress": egress.filename}
    return result


@app.get(
    "/samples/crosscheck/ingress",
    summary="Download the bundled cross-check ingress sample",
)
def crosscheck_ingress_sample() -> FileResponse:
    if not INGRESS_SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    return FileResponse(
        INGRESS_SAMPLE_PATH,
        media_type="application/vnd.tcpdump.pcap",
        filename="crosscheck-ingress.pcap",
    )


@app.get(
    "/samples/crosscheck/egress",
    summary="Download the bundled cross-check egress sample",
)
def crosscheck_egress_sample() -> FileResponse:
    if not EGRESS_SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    return FileResponse(
        EGRESS_SAMPLE_PATH,
        media_type="application/vnd.tcpdump.pcap",
        filename="crosscheck-egress.pcap",
    )


@app.post("/crosscheck/sample", summary="Cross-check the bundled sample pair")
def crosscheck_sample() -> dict:
    if not INGRESS_SAMPLE_PATH.exists() or not EGRESS_SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample captures not found")
    result = cross_check_captures(
        INGRESS_SAMPLE_PATH.read_bytes(), EGRESS_SAMPLE_PATH.read_bytes()
    )
    result["filenames"] = {
        "ingress": INGRESS_SAMPLE_PATH.name,
        "egress": EGRESS_SAMPLE_PATH.name,
    }
    return result
