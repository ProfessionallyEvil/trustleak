"""
Tests for trustleak.csp_analyzer.

Neither real fixture (sunresorts_direct.json, secureideas_enum.json) contains
a natural positive match: secureideas has zero suspicious targets, and
sunresorts is a standalone single-record scan with no 'active' source in the
same file to correlate against. The end-to-end correlation tests below are
therefore synthetic — built from the same shape importer.ImportResult
produces, not from a real capture. They're clearly labeled as such; when a
real cross-correlation shows up in a future scan, it should be captured as
a new fixture and these synthetic cases can stay as the parser-level
regression tests.
"""
from trustleak import csp_analyzer
from trustleak.importer import ImportResult


# ---------------------------------------------------------------------------
# extract_csp_hostnames — parser unit tests
# ---------------------------------------------------------------------------

def test_extracts_img_src_hostname():
    result = csp_analyzer.extract_csp_hostnames("default-src 'self'; img-src blog.empresa.com")
    assert ("csp_img_src", "blog.empresa.com") in result


def test_ignores_keywords_and_data_uris():
    result = csp_analyzer.extract_csp_hostnames(
        "script-src 'self' 'unsafe-inline' data: blob:; img-src *"
    )
    assert result == []


def test_strips_scheme_and_wildcard_label():
    result = csp_analyzer.extract_csp_hostnames("connect-src https://*.blog.empresa.com:443")
    assert result == [("csp_connect_src", "blog.empresa.com")]


def test_unknown_directive_maps_to_other():
    result = csp_analyzer.extract_csp_hostnames("frame-ancestors evil-looking.empresa.com")
    assert result == [("csp_other_directive", "evil-looking.empresa.com")]


def test_real_secureideas_csp_value_yields_no_hostnames():
    # The actual CSP value captured from hsemail/helpdesk.secureideas.com —
    # "upgrade-insecure-requests" is a directive with no source list at all,
    # just a bare keyword directive. Confirms the parser doesn't choke on it
    # or hallucinate a hostname out of nothing.
    result = csp_analyzer.extract_csp_hostnames("upgrade-insecure-requests")
    assert result == []


# ---------------------------------------------------------------------------
# _hostname_matches_target
# ---------------------------------------------------------------------------

def test_exact_match():
    assert csp_analyzer._hostname_matches_target("blog.empresa.com", "blog.empresa.com")


def test_wildcard_covers_subdomain():
    # CSP "*.empresa.com" (cleaned to "empresa.com") should cover a deeper
    # target like "old.blog.empresa.com".
    assert csp_analyzer._hostname_matches_target("empresa.com", "old.blog.empresa.com")


def test_unrelated_hostnames_do_not_match():
    assert not csp_analyzer._hostname_matches_target("cdn.other.com", "blog.empresa.com")


def test_bare_domain_and_its_wildcard_in_same_directive_deduplicate():
    # Real-world bug found on brightretail.example: a directive listing both
    # "example.com" and "*.example.com" together (a defensive pattern
    # covering apex + subdomains explicitly) normalizes both tokens to the
    # same cleaned hostname — without dedup this produced two
    # identical-looking findings for one actual trust relationship.
    result = csp_analyzer.extract_csp_hostnames(
        "script-src 'self' brightretail.example *.brightretail.example *.googletagmanager.com;"
    )
    assert result == [
        ("csp_script_src", "brightretail.example"),
        ("csp_script_src", "googletagmanager.com"),
    ]


# ---------------------------------------------------------------------------
# analyze_csp — end to end (synthetic, see module docstring)
# ---------------------------------------------------------------------------

def _synthetic_import_result():
    active_source = {
        "hostname": "app.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": {
            "content-security-policy": "default-src 'self'; img-src blog.empresa.com",
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
        source_summary={"total_subdomains": 2, "potential_takeovers": 1, "targets_scanned": 1},
        assets=[active_source, suspicious_target],
        skipped=[],
    )


def test_analyze_csp_finds_the_synthetic_reference():
    findings = csp_analyzer.analyze_csp(_synthetic_import_result())
    assert len(findings) == 1

    finding = findings[0]
    assert finding["source"]["hostname"] == "app.empresa.com"
    assert finding["target"]["hostname"] == "blog.empresa.com"
    assert finding["target"]["asset_status"] == "potential_takeover"
    assert finding["target"]["shadowsaas_confidence"] == "high"
    assert finding["relationship"]["type"] == "csp_img_src"
    assert finding["relationship"]["category"] == "resource_dependency"
    assert finding["relationship"]["status"] == "potential_risk"
    assert finding["evidence"]["collected_via"] == "shadowsaas_probe"
    assert finding["evidence"]["matched_value"] == "blog.empresa.com"
    # Target confidence is "high", match is specific (not a broad apex
    # wildcard), policy is enforced (not Report-Only) -> evidence_confidence
    # is "high" regardless of directive. img-src is a resource_dependency,
    # though, so potential_impact stays "low" even with that high confidence.
    assert finding["assessment"]["evidence_confidence"] == "high"
    assert finding["assessment"]["potential_impact"] == "low"
    assert finding["assessment"]["validation_status"] == "not_validated"


def test_potential_impact_depends_on_directive_not_evidence_confidence():
    # The thing schema v2 exists to fix: evidence_confidence must NOT
    # depend on which directive matched — only potential_impact should.
    # Switching img-src -> script-src keeps evidence_confidence identical
    # (same target, same specificity, same enforcement) but escalates
    # potential_impact from "low" (resource_dependency) to "high"
    # (execution_dependency).
    result = _synthetic_import_result()
    result.assets[0]["relevant_headers"]["content-security-policy"] = (
        "default-src 'self'; script-src blog.empresa.com"
    )
    findings = csp_analyzer.analyze_csp(result)
    assert len(findings) == 1
    assert findings[0]["relationship"]["type"] == "csp_script_src"
    assert findings[0]["relationship"]["category"] == "execution_dependency"
    assert findings[0]["assessment"]["evidence_confidence"] == "high"  # unchanged from img-src case
    assert findings[0]["assessment"]["potential_impact"] == "high"  # escalated


def test_analyze_csp_returns_nothing_when_no_suspicious_targets():
    # Exercises the real secureideas.com shape: active assets with CSP, but
    # zero suspicious targets to correlate against.
    result = _synthetic_import_result()
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    assert csp_analyzer.analyze_csp(result) == []


def test_analyze_csp_against_real_fixtures_yields_no_findings():
    # Documents the current real-world baseline: neither real scan on hand
    # produces a CSP finding today. secureideas.com has no suspicious
    # targets; sunresorts.example's scan is a standalone record. This test
    # exists so that if a future fixture update accidentally introduces a
    # spurious match, it's caught here.
    import os
    from trustleak import importer

    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    for name in ("sunresorts_direct.json", "secureideas_enum.json"):
        result = importer.import_shadowsaas_output(os.path.join(fixtures, name))
        assert csp_analyzer.analyze_csp(result) == []


def test_finding_ids_increment_and_are_unique():
    result = _synthetic_import_result()
    # Duplicate the active source so the same CSP reference is seen twice —
    # confirms finding_id increments instead of colliding.
    result.assets.append(dict(result.assets[0], hostname="app2.empresa.com"))
    findings = csp_analyzer.analyze_csp(result)
    assert [f["finding_id"] for f in findings] == ["TL-0001", "TL-0002"]
