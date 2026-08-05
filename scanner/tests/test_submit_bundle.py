from pathlib import Path

import httpx
import pytest

from scanner.scripts.submit_bundle import response_detail, submit


def test_submit_bundle_reports_safe_api_rejection_detail(tmp_path: Path):
    token_path = tmp_path / "token"
    token_path.write_text("lsa_ingest_secret-value", encoding="utf-8")
    bundle_path = tmp_path / "report.zip"
    bundle_path.write_bytes(b"zip bytes")

    def reject(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer lsa_ingest_secret-value"
        return httpx.Response(
            422,
            json={"detail": "Bundle signature verification failed"},
            request=request,
        )

    with pytest.raises(RuntimeError) as error:
        submit(
            "https://lsa.example.test:8444",
            token_path,
            bundle_path,
            verify_tls=False,
            transport=httpx.MockTransport(reject),
        )

    message = str(error.value)
    assert "HTTP 422" in message
    assert "Bundle signature verification failed" in message
    assert "lsa_ingest_secret-value" not in message


def test_submit_bundle_returns_accepted_response(tmp_path: Path):
    token_path = tmp_path / "token"
    token_path.write_text("token", encoding="utf-8")
    bundle_path = tmp_path / "report.zip"
    bundle_path.write_bytes(b"zip bytes")
    payload = {
        "status": "accepted",
        "report_id": "report-id",
        "host_id": "host-id",
        "findings_imported": 390,
        "new_findings": 12,
        "resolved_findings": 0,
    }

    result = submit(
        "https://lsa.example.test:8444/",
        token_path,
        bundle_path,
        transport=httpx.MockTransport(lambda request: httpx.Response(202, json=payload, request=request)),
    )

    assert result == payload


def test_response_detail_bounds_non_json_errors():
    request = httpx.Request("POST", "https://lsa.example.test")
    response = httpx.Response(502, text="gateway\nerror " * 500, request=request)

    assert len(response_detail(response)) == 2000
    assert "\n" not in response_detail(response)
