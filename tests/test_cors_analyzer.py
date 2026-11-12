"""
Tests for trustleak.cors_analyzer.

Like the CSP analyzer, neither real fixture contains a natural positive
match today — ShadowSaaS's probe sends no Origin header, so a server that
only sets Access-Control-Allow-Origin in response to one is invisible to
this passive analyzer by design (see the module docstring). The
end-to-end correlation tests are synthetic for the same reason the CSP
ones are; the real-fixture test documents today's honest baseline (zero
findings) so a future regression is caught.
"""
import os

from trustleak import cors_analyzer, importer
from trustleak.importer import ImportResult

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _synthetic_import_result(acao="https://blog.empresa.com", credentials=None):
    headers = {"access-control-allow-origin": acao}
    if credentials is not None:
        headers["access-control-allow-credentials"] = credentials

    active_source = {
        "hostname": "app.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": headers,
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
        source_summary={"total_subdomains": 2, "potential_takeovers": 1, "targets_scanned": 1},
        assets=[active_source, suspicious_target],
        skipped=[],
    )


# ---------------------------------------------------------------------------
# End to end (synthetic — see module docstring)
# ---------------------------------------------------------------------------

def test_finds_specific_origin_matching_suspicious_target():
    findings = cors_analyzer.analyze_cors(_synthetic_import_result())
    assert len(findings) == 1

    finding = findings[0]
    assert finding["source"]["hostname"] == "app.empresa.com"
    assert finding["target"]["hostname"] == "blog.empresa.com"
    assert finding["relationship"]["type"] == "cors_allowed_origin"
    assert finding["relationship"]["category"] == "cross_origin_trust"
    assert finding["relationship"]["status"] == "potential_risk"
    assert finding["evidence"]["header"] == "Access-Control-Allow-Origin"
    assert finding["evidence"]["matched_value"] == "blog.empresa.com"
    assert finding["evidence"]["collected_via"] == "shadowsaas_probe"
    # Target confidence high, specific (non-wildcard) origin -> high
    # evidence_confidence. No Access-Control-Allow-Credentials header ->
    # not "true" -> potential_impact stays at cross_origin_trust's
    # "medium" default rather than escalating.
    assert finding["assessment"]["evidence_confidence"] == "high"
    assert finding["assessment"]["potential_impact"] == "medium"


def test_credentials_true_escalates_potential_impact_to_high():
    result = _synthetic_import_result(credentials="true")
    findings = cors_analyzer.analyze_cors(result)
    assert len(findings) == 1
    # evidence_confidence is about certainty, unaffected by credentials.
    assert findings[0]["assessment"]["evidence_confidence"] == "high"
    assert findings[0]["assessment"]["potential_impact"] == "high"


def test_credentials_false_stays_at_default_impact():
    result = _synthetic_import_result(credentials="false")
    findings = cors_analyzer.analyze_cors(result)
    assert findings[0]["assessment"]["potential_impact"] == "medium"


def test_wildcard_origin_is_skipped_not_matched():
    result = _synthetic_import_result(acao="*")
    assert cors_analyzer.analyze_cors(result) == []


def test_unrelated_origin_does_not_match():
    result = _synthetic_import_result(acao="https://totally-unrelated.other.com")
    assert cors_analyzer.analyze_cors(result) == []


def test_missing_acao_header_yields_no_finding():
    result = _synthetic_import_result(acao=None)
    # Simulate the header simply not being present at all, not an empty string.
    del result.assets[0]["relevant_headers"]["access-control-allow-origin"]
    assert cors_analyzer.analyze_cors(result) == []


def test_no_suspicious_targets_yields_no_findings():
    result = _synthetic_import_result()
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    assert cors_analyzer.analyze_cors(result) == []


# ---------------------------------------------------------------------------
# Real-fixture baseline
# ---------------------------------------------------------------------------

def test_analyze_cors_against_real_fixtures_yields_no_findings():
    # Honest baseline: ShadowSaaS's probe never sends an Origin header, so
    # neither real scan on hand has an Access-Control-Allow-Origin value
    # captured at all. This documents that fact so a future fixture update
    # that accidentally introduces a spurious match gets caught.
    for name in ("sunresorts_direct.json", "secureideas_enum.json"):
        result = importer.import_shadowsaas_output(os.path.join(FIXTURES, name))
        assert cors_analyzer.analyze_cors(result) == []


def test_finding_ids_increment_from_custom_start():
    # Confirms the finding_id_start handoff works for chaining after
    # analyze_csp() in a real TrustLeak run (CSP findings claim TL-0001..N,
    # CORS findings should continue from there, not restart at TL-0001).
    result = _synthetic_import_result()
    findings = cors_analyzer.analyze_cors(result, finding_id_start=5)
    assert findings[0]["finding_id"] == "TL-0005"
