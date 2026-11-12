"""Tests for trustleak.correlate.explain_empty."""
import os

from trustleak import correlate, importer

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


def test_none_when_findings_present():
    result = _import("sunresorts_full_scan.json")
    findings = correlate.correlate_all(result)
    assert findings  # sanity: this fixture does produce findings
    assert correlate.explain_empty(result, findings) is None


def test_no_suspicious_targets_at_all():
    # secureideas_enum.json: zero takeover candidates in the source scan.
    result = _import("secureideas_enum.json")
    findings = correlate.correlate_all(result)
    assert findings == []

    explanation = correlate.explain_empty(result, findings)
    assert explanation is not None
    assert "No takeover candidates" in explanation


def test_suspicious_targets_exist_but_nothing_references_them():
    # mural.co's real scan: 0 potential_takeovers, so this actually hits
    # the same "no suspicious targets" branch — but we also want the
    # OTHER branch (takeovers exist, nothing found) covered explicitly
    # with a synthetic case, since no fixture on hand has one.
    from trustleak.importer import ImportResult

    suspicious_target = {
        "hostname": "dangling.empresa.com",
        "classification": "suspicious",
        "dns_active": True,
        "dns_target": "dead-project.vercel.app",
        "http_status": 404,
        "takeover_possible": True,
        "confidence": "high",
        "relevant_headers": {},
        "raw": {},
    }
    unrelated_active = {
        "hostname": "app.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": {},  # no CSP/CORS/cookie at all
        "raw": {},
    }
    result = ImportResult(
        source_summary={"total_subdomains": 2, "potential_takeovers": 1, "targets_scanned": 1},
        assets=[suspicious_target, unrelated_active],
        skipped=[],
    )
    findings = correlate.correlate_all(result)
    assert findings == []

    explanation = correlate.explain_empty(result, findings)
    assert explanation is not None
    assert "1 takeover candidate(s) were found" in explanation
    assert "no further blast radius" in explanation
