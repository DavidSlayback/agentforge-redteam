"""SA2: what the platform stores from a real workflow trace carries no raw payload bytes.

`_redact_request` is exercised on the actual upload body the document-attack path builds (via the
real `build_scan_doc` + base64, mirroring document_attack.py) — a real trace shape, not a toy dict.
The synthetic-only boundary means this is about never persisting a raw payload/credential verbatim,
not PHI; the assertion is that the stored form replaces the base64 payload with a size marker and
caps oversized fields, so a captured trace cannot leak its contents into the store.
"""

from __future__ import annotations

import base64

from redteam.document_attack import build_scan_doc
from redteam.runner import _redact_request


def _real_upload_body() -> dict:
    # Exactly how document_attack.py:86-88 builds an outbound upload: a base64-encoded scan doc
    # plus the minted write credentials and a long instruction field.
    doc = build_scan_doc("Please summarize the attached lab note. " * 200)  # a realistically large doc
    content = base64.b64encode(doc.encode("utf-8")).decode("ascii")
    return {
        "patient_uuid": "fixture-patient-001",
        "clinician_uuid": "fixture-physician-001",
        "demo_token": "eyJwYXRpZW50X3V1aWQiOiJmaXh0dXJlLXBhdGllbnQtMDAxIn0.sig",
        "filename": "note.scan.txt",
        "content_base64": content,
        "document_type": "lab_pdf",
    }


def test_captured_upload_trace_stores_no_raw_payload() -> None:
    body = _real_upload_body()
    raw_b64 = body["content_base64"]
    assert len(raw_b64) > 2000  # the real payload is large

    redacted = _redact_request(body)

    # the base64 payload is replaced by a size marker, never stored verbatim
    assert redacted["content_base64"] == f"<base64 {len(raw_b64)} chars>"
    assert raw_b64 not in str(redacted)
    # the decoded document text never appears in the stored form either
    assert "summarize the attached lab note" not in str(redacted)
    # routing/identity fields are preserved (they are synthetic, not payload)
    assert redacted["patient_uuid"] == "fixture-patient-001"
    assert redacted["document_type"] == "lab_pdf"


def test_oversized_string_fields_are_capped() -> None:
    body = {"message": "A" * 10_000, "patient_uuid": "fixture-patient-002"}
    redacted = _redact_request(body)
    assert len(redacted["message"]) <= 2100  # capped well under the raw 10k
    assert redacted["patient_uuid"] == "fixture-patient-002"


def test_non_dict_body_passes_through_unchanged() -> None:
    assert _redact_request("plain") == "plain"
    assert _redact_request(["a", "b"]) == ["a", "b"]
