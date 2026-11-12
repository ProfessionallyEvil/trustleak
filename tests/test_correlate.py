"""
Tests for trustleak.correlate.correlate_all — the orchestration layer that
runs every analyzer and hands out globally unique finding_id values.
"""
import os
from unittest import mock

from trustleak import correlate, importer
from trustleak.importer import ImportResult

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


def _synthetic_mixed_result():
    """
    One asset referencing the target via CSP, another via a
    non-wildcard Access-Control-Allow-Origin — deliberately exercising
    both analyzers in a single ImportResult, unlike any individual
    analyzer's own test fixtures.
    """
    csp_source = {
        "hostname": "app.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": {
            "content-security-policy": "default-src 'self'; script-src blog.empresa.com",
        },
        "raw": {},
    }
    cors_source = {
        "hostname": "api.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.5",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": {
            "access-control-allow-origin": "https://blog.empresa.com",
            "access-control-allow-credentials": "true",
        },
        "raw": {},
    }
    suspicious_target = {
        "hostname": "blog.empresa.com",
        "classification": "suspicious",
        "dns_active": True,
        "dns_target": "dangling-project.vercel.app",
        "http_status": 404,
        "takeover_possible": True,
        "confidence": "high",
        "relevant_headers": {},
        "raw": {},
    }
    return ImportResult(
        source_summary={"total_subdomains": 3, "potential_takeovers": 1, "targets_scanned": 1},
        assets=[csp_source, cors_source, suspicious_target],
        skipped=[],
    )


def test_correlate_all_active_analyzers_registry_has_js_content():
    # js_analyzer.py is the first active-probe analyzer (see NOTES.md) —
    # confirms it's actually registered, by name, rather than silently
    # missing from _ACTIVE_ANALYZERS.
    names = [name for name, _fn in correlate._ACTIVE_ANALYZERS]
    assert "js_content" in names


def test_correlate_all_default_never_runs_active_analyzers():
    # The single most important guarantee in this module: without
    # allow_active=True, correlate_all() must never invoke an active
    # analyzer — regardless of what's registered in _ACTIVE_ANALYZERS.
    # Patch the active analyzer to raise if called at all; a default
    # call must complete without ever reaching it.
    with mock.patch.object(correlate, "_ACTIVE_ANALYZERS", (
        ("js_content", mock.Mock(side_effect=AssertionError("must not be called by default"))),
    )):
        result = _import("sunresorts_full_scan.json")
        correlate.correlate_all(result)  # no allow_active — must not raise


def test_correlate_all_allow_active_true_runs_active_analyzers():
    with mock.patch.object(correlate, "_ACTIVE_ANALYZERS", (
        ("fake_active", lambda _result, finding_id_start=1: ["sentinel"]),
    )):
        result = _import("sunresorts_full_scan.json")
        default_findings = correlate.correlate_all(result)
        active_findings = correlate.correlate_all(result, allow_active=True)

        assert "sentinel" not in default_findings
        assert "sentinel" in active_findings


def test_correlate_all_runs_both_analyzers():
    result = _synthetic_mixed_result()
    findings = correlate.correlate_all(result)

    relationship_types = {f["relationship"]["type"] for f in findings}
    assert "csp_script_src" in relationship_types
    assert "cors_allowed_origin" in relationship_types
    assert len(findings) == 2


def test_correlate_all_finding_ids_are_unique_and_sequential():
    result = _synthetic_mixed_result()
    findings = correlate.correlate_all(result)

    ids = [f["finding_id"] for f in findings]
    assert ids == ["TL-0001", "TL-0002"]
    assert len(set(ids)) == len(ids)  # no collisions, even in principle


def test_correlate_all_cors_ids_continue_after_csp_not_restart():
    # With multiple CSP matches before any CORS match, CORS ids must pick
    # up where CSP left off (TL-0003+), never reset to TL-0001.
    result = _synthetic_mixed_result()
    # Add a second CSP-referencing source so CSP alone produces 2 findings.
    second_csp_source = dict(result.assets[0], hostname="app2.empresa.com")
    result.assets.append(second_csp_source)

    findings = correlate.correlate_all(result)
    csp_ids = [f["finding_id"] for f in findings if f["relationship"]["type"] == "csp_script_src"]
    cors_ids = [f["finding_id"] for f in findings if f["relationship"]["type"] == "cors_allowed_origin"]

    assert csp_ids == ["TL-0001", "TL-0002"]
    assert cors_ids == ["TL-0003"]


def test_correlate_all_empty_when_no_suspicious_targets():
    result = _synthetic_mixed_result()
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    assert correlate.correlate_all(result) == []


def test_correlate_all_against_real_sunresorts_scan():
    # Confirms correlate_all's output matches what analyze_csp alone
    # produces here (CORS contributes nothing on this fixture — every ACAO
    # is "*"), with ids still contiguous from TL-0001.
    result = _import("sunresorts_full_scan.json")
    findings = correlate.correlate_all(result)

    assert len(findings) == 28  # same count as the CSP-only test established
    assert findings[0]["finding_id"] == "TL-0001"
    assert findings[-1]["finding_id"] == "TL-0028"
    assert all(f["relationship"]["type"] in ("csp_connect_src", "csp_frame_src") for f in findings)


def test_correlate_all_against_real_brightretail_scan():
    result = _import("brightretail_scan.json")
    findings = correlate.correlate_all(result)

    assert len(findings) == 98
    assert findings[0]["finding_id"] == "TL-0001"
    assert findings[-1]["finding_id"] == "TL-0098"


def test_correlate_all_against_secureideas_yields_nothing():
    # secureideas_enum.json has zero suspicious targets at all — both
    # analyzers should no-op, and correlate_all should too.
    result = _import("secureideas_enum.json")
    assert correlate.correlate_all(result) == []
