"""
Tests for trustleak.html_analyzer.
"""
import os

from trustleak import html_analyzer, importer
from trustleak.importer import ImportResult

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


# ---------------------------------------------------------------------------
# _extract_hostname
# ---------------------------------------------------------------------------

def test_extract_hostname_from_absolute_url():
    assert html_analyzer._extract_hostname("https://blog.empresa.com/embed") == "blog.empresa.com"


def test_extract_hostname_from_protocol_relative_url():
    assert html_analyzer._extract_hostname("//blog.empresa.com/embed") == "blog.empresa.com"


def test_extract_hostname_relative_path_returns_none():
    # No host component — same-origin reference, no cross-host signal.
    assert html_analyzer._extract_hostname("/static/app.js") is None


def test_extract_hostname_empty_string_returns_none():
    assert html_analyzer._extract_hostname("") is None
    assert html_analyzer._extract_hostname("   ") is None


def test_extract_hostname_percent_encoded_url():
    # Common shape for a redirect_uri captured out of a query string.
    encoded = "https%3A%2F%2Fblog.empresa.com%2Fcallback"
    assert html_analyzer._extract_hostname(encoded) == "blog.empresa.com"


# ---------------------------------------------------------------------------
# End to end (synthetic)
# ---------------------------------------------------------------------------

def _synthetic_import_result(body_refs, target_confidence="high"):
    active_source = {
        "hostname": "app.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": {},
        "relevant_body_refs": body_refs,
        "raw": {},
    }
    suspicious_target = {
        "hostname": "blog.empresa.com",
        "classification": "suspicious",
        "dns_active": True,
        "dns_target": "dangling-project.vercel.app",
        "http_status": 404,
        "takeover_possible": True,
        "confidence": target_confidence,
        "relevant_headers": {},
        "raw": {},
    }
    return ImportResult(
        source_summary={"total_subdomains": 2, "potential_takeovers": 1, "targets_scanned": 1},
        assets=[active_source, suspicious_target],
        skipped=[],
    )


def test_finds_iframe_embed_of_suspicious_target():
    result = _synthetic_import_result({"iframe_src": ["https://blog.empresa.com/embed"]})
    findings = html_analyzer.analyze_html(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"]["hostname"] == "app.empresa.com"
    assert finding["target"]["hostname"] == "blog.empresa.com"
    assert finding["relationship"]["type"] == "html_iframe_embed"
    assert finding["relationship"]["category"] == "framing_dependency"
    assert finding["evidence"]["header"] == "HTML <iframe src>"
    assert finding["evidence"]["matched_value"] == "blog.empresa.com"
    assert finding["evidence"]["collected_via"] == "shadowsaas_probe"
    # Specific, non-wildcard match + high target confidence -> high confidence.
    assert finding["assessment"]["evidence_confidence"] == "high"
    # framing_dependency's default impact.
    assert finding["assessment"]["potential_impact"] == "medium"


def test_finds_script_reference_as_execution_dependency():
    result = _synthetic_import_result({"script_src": ["https://blog.empresa.com/widget.js"]})
    findings = html_analyzer.analyze_html(result)

    assert len(findings) == 1
    assert findings[0]["relationship"]["type"] == "html_script_reference"
    assert findings[0]["relationship"]["category"] == "execution_dependency"
    assert findings[0]["assessment"]["potential_impact"] == "high"


def test_finds_form_action_as_navigation_dependency():
    result = _synthetic_import_result({"form_action": ["https://blog.empresa.com/login"]})
    findings = html_analyzer.analyze_html(result)

    assert len(findings) == 1
    assert findings[0]["relationship"]["type"] == "html_form_action"
    assert findings[0]["relationship"]["category"] == "navigation_dependency"
    assert findings[0]["assessment"]["potential_impact"] == "medium"


def test_finds_oauth_redirect_uri_reference_as_authentication_dependency():
    result = _synthetic_import_result({"oauth_redirect_uri": ["https://blog.empresa.com/callback"]})
    findings = html_analyzer.analyze_html(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["relationship"]["type"] == "html_oauth_redirect_uri_reference"
    assert finding["relationship"]["category"] == "authentication_dependency"
    assert finding["evidence"]["header"] == "OAuth redirect_uri (query-string reference)"
    assert finding["evidence"]["matched_value"] == "blog.empresa.com"
    assert finding["assessment"]["potential_impact"] == "high"


def test_finds_saml_acs_reference_as_authentication_dependency():
    result = _synthetic_import_result({"saml_acs_url": ["https://blog.empresa.com/saml/acs"]})
    findings = html_analyzer.analyze_html(result)

    assert len(findings) == 1
    assert findings[0]["relationship"]["type"] == "html_saml_acs_reference"
    assert findings[0]["relationship"]["category"] == "authentication_dependency"
    assert findings[0]["assessment"]["potential_impact"] == "high"


def test_finds_js_style_redirect_uri_reference():
    # Real gap found on a live engagement: Okta's Sign-In Widget (and
    # many other OAuth JS SDKs) configure this as a camelCase JS object
    # property, not a query-string parameter — a genuinely different
    # capture pattern (oauth_redirect_uri_js) feeding the SAME
    # relationship type as the query-string variant.
    result = _synthetic_import_result({"oauth_redirect_uri_js": ["https://blog.empresa.com/callback"]})
    findings = html_analyzer.analyze_html(result)

    assert len(findings) == 1
    assert findings[0]["relationship"]["type"] == "html_oauth_redirect_uri_reference"
    assert findings[0]["relationship"]["category"] == "authentication_dependency"
    assert findings[0]["evidence"]["header"] == "OAuth redirectUri (JS config reference)"


def test_percent_encoded_redirect_uri_still_matches_target():
    # The real-world shape: redirect_uri captured raw from a query string
    # is percent-encoded, not a plain URL.
    result = _synthetic_import_result({
        "oauth_redirect_uri": ["https%3A%2F%2Fblog.empresa.com%2Fcallback"]
    })
    findings = html_analyzer.analyze_html(result)
    assert len(findings) == 1
    assert findings[0]["evidence"]["matched_value"] == "blog.empresa.com"


def test_relative_path_reference_produces_no_finding():
    result = _synthetic_import_result({"script_src": ["/static/app.js"]})
    assert html_analyzer.analyze_html(result) == []


def test_unrelated_hostname_reference_produces_no_finding():
    result = _synthetic_import_result({"iframe_src": ["https://totally-unrelated.other.com/x"]})
    assert html_analyzer.analyze_html(result) == []


def test_no_suspicious_targets_yields_no_findings():
    result = _synthetic_import_result({"iframe_src": ["https://blog.empresa.com/embed"]})
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    assert html_analyzer.analyze_html(result) == []


def test_missing_relevant_body_refs_key_handled_gracefully():
    # Older ShadowSaaS output (before this patch) won't have the key at
    # all — must not KeyError, must just find nothing from that asset.
    result = _synthetic_import_result({})
    del result.assets[0]["relevant_body_refs"]
    assert html_analyzer.analyze_html(result) == []


def test_multiple_refs_same_type_each_evaluated():
    result = _synthetic_import_result({
        "script_src": ["https://blog.empresa.com/a.js", "https://blog.empresa.com/b.js"]
    })
    findings = html_analyzer.analyze_html(result)
    assert len(findings) == 2
    assert {f["evidence"]["matched_value"] for f in findings} == {"blog.empresa.com"}


def test_finding_ids_increment_from_custom_start():
    result = _synthetic_import_result({"iframe_src": ["https://blog.empresa.com/embed"]})
    findings = html_analyzer.analyze_html(result, finding_id_start=5)
    assert findings[0]["finding_id"] == "TL-0005"


# ---------------------------------------------------------------------------
# Real-fixture baseline — honest zero, same reasoning as the other analyzers
# ---------------------------------------------------------------------------

def test_real_fixtures_yield_no_html_findings_today():
    # None of the existing fixtures have relevant_body_refs at all (they
    # predate this patch) — importer.py must tolerate the missing key
    # (see test_missing_relevant_body_refs_key_handled_gracefully above),
    # and the analyzer must find nothing rather than error.
    for name in ("sunresorts_full_scan.json", "brightretail_scan.json", "secureideas_enum.json"):
        result = _import(name)
        assert html_analyzer.analyze_html(result) == []
