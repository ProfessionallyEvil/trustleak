"""
Tests for trustleak.cookie_analyzer.

None of the three real fixtures on hand produce a positive correlation
here — not a bug, just what the data shows: secureideas_enum.json has
zero suspicious targets to correlate against at all (despite several
hosts there genuinely sharing Domain=secureideas.com — see
test_importer.py's cookie_domain_scope test), and in both large scans
every cookie observed is either host-only (no Domain= at all) or scoped
to its own exact hostname, never broad enough to reach one of the
confirmed takeover targets. This is documented explicitly below rather
than silently asserting zero, so a future fixture update that introduces
a real match is expected to require updating these tests.
"""
import os

from trustleak import cookie_analyzer, importer
from trustleak.importer import ImportResult

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------

def test_split_handles_comma_inside_expires_date():
    # The exact shape ShadowSaaS captures: two cookies joined by ", ", the
    # first one's own Expires value also containing a comma.
    value = (
        "XSRF-TOKEN=abc123; expires=Wed, 04 Nov 2026 14:12:38 GMT; Max-Age=3600; "
        "path=/; secure; samesite=lax, "
        "session_id=def456; expires=Wed, 04 Nov 2026 14:12:38 GMT; secure; httponly"
    )
    parts = cookie_analyzer.split_set_cookie_header(value)
    assert len(parts) == 2
    assert parts[0].startswith("XSRF-TOKEN=abc123")
    assert parts[1].startswith("session_id=def456")


def test_split_single_cookie_returns_one_part():
    parts = cookie_analyzer.split_set_cookie_header("foo=bar; Secure; HttpOnly")
    assert parts == ["foo=bar; Secure; HttpOnly"]


def test_split_empty_returns_empty_list():
    assert cookie_analyzer.split_set_cookie_header("") == []
    assert cookie_analyzer.split_set_cookie_header(None) == []


def test_parse_cookie_extracts_name_and_domain():
    name, domain, _ = cookie_analyzer.parse_cookie(
        "__cf_bm=xyz; HttpOnly; SameSite=None; Secure; Path=/; Domain=secureideas.com"
    )
    assert name == "__cf_bm"
    assert domain == "secureideas.com"


def test_parse_cookie_strips_leading_dot_from_domain():
    # ".example.com" and "example.com" are the same per RFC 6265.
    _name, domain, _ = cookie_analyzer.parse_cookie("foo=bar; Domain=.example.com")
    assert domain == "example.com"


def test_parse_cookie_no_domain_attribute_returns_none():
    _name, domain, _ = cookie_analyzer.parse_cookie("foo=bar; Secure; HttpOnly")
    assert domain is None


def test_parse_cookie_incapsula_visid_is_not_session_like():
    # Real false positive found on a live engagement: "visid_incap_<id>"
    # is Imperva/Incapsula's WAF visitor-tracking cookie, not an
    # application session — it only matched the "sid" substring
    # heuristic by coincidence ("vi-SID-_incap").
    _name, _domain, is_session_like = cookie_analyzer.parse_cookie(
        "visid_incap_3357717=abc123; Domain=example.com"
    )
    assert is_session_like is False


def test_parse_cookie_phpsessid_and_jsessionid_still_detected():
    # Confirms the exclusion above doesn't collateral-damage the real
    # cookies "sid" is there to catch — both only contain "sid" as part
    # of a longer word, same shape as the Incapsula false positive, but
    # these ARE genuinely session cookies.
    _name, _domain, php_session = cookie_analyzer.parse_cookie(
        "PHPSESSID=abc123; Domain=example.com"
    )
    _name, _domain, java_session = cookie_analyzer.parse_cookie(
        "JSESSIONID=abc123; Domain=example.com"
    )
    assert php_session is True
    assert java_session is True


def test_parse_cookie_detects_session_like_names():
    for name_prefix in ("session_id", "AUTH_TOKEN", "JSESSIONID", "csrf_token", "XSRF-TOKEN"):
        _name, _domain, is_session_like = cookie_analyzer.parse_cookie(f"{name_prefix}=value")
        assert is_session_like, f"{name_prefix} should be detected as session-like"


def test_parse_cookie_tracking_cookie_not_session_like():
    _name, _domain, is_session_like = cookie_analyzer.parse_cookie("__cf_bm=value; Secure")
    assert not is_session_like


# ---------------------------------------------------------------------------
# End to end (synthetic)
# ---------------------------------------------------------------------------

def _synthetic_import_result(set_cookie, target_confidence="high"):
    active_source = {
        "hostname": "app.empresa.com",
        "classification": "active",
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": False,
        "confidence": "low",
        "relevant_headers": {"set-cookie": set_cookie},
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


def test_finds_session_cookie_scoped_to_target():
    result = _synthetic_import_result("session_id=abc123; Secure; HttpOnly; Domain=blog.empresa.com")
    findings = cookie_analyzer.analyze_cookies(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"]["hostname"] == "app.empresa.com"
    assert finding["target"]["hostname"] == "blog.empresa.com"
    assert finding["relationship"]["type"] == "cookie_domain_scope"
    assert finding["relationship"]["category"] == "shared_scope"
    assert finding["evidence"]["header"] == "Set-Cookie"
    assert finding["evidence"]["matched_value"] == "blog.empresa.com"
    # High target confidence + specific (non-wildcard) domain -> high
    # evidence_confidence. Session-like name escalates potential_impact
    # above shared_scope's "low" default.
    assert finding["assessment"]["evidence_confidence"] == "high"
    assert finding["assessment"]["potential_impact"] == "high"


def test_tracking_cookie_scoped_to_target_has_low_impact_not_confidence():
    result = _synthetic_import_result("__cf_bm=xyz; Secure; Domain=blog.empresa.com")
    findings = cookie_analyzer.analyze_cookies(result)

    assert len(findings) == 1
    # Same specificity/certainty as the session-cookie case above — a
    # tracking cookie is just as *real* an observation, it's simply a
    # lower-impact *kind* of relationship. evidence_confidence must not
    # drop just because the cookie isn't session-like.
    assert findings[0]["assessment"]["evidence_confidence"] == "high"
    assert findings[0]["assessment"]["potential_impact"] == "low"


def test_evidence_directive_carries_the_cookie_name():
    # Real-world case found on a live engagement: two cookies scoped to
    # the same Domain, one session-like (high impact) and one tracking
    # (low impact).
    # Without the cookie's own name visible in the evidence, these two
    # findings looked like an unexplained duplicate rather than two
    # distinct, correctly-differentiated findings.
    result = _synthetic_import_result(
        "session_id=abc123; Secure; Domain=blog.empresa.com, "
        "__cf_bm=xyz789; Secure; Domain=blog.empresa.com"
    )
    findings = cookie_analyzer.analyze_cookies(result)
    assert len(findings) == 2

    by_impact = {f["assessment"]["potential_impact"]: f for f in findings}
    assert by_impact["high"]["evidence"]["directive"] == "session_id"
    assert by_impact["low"]["evidence"]["directive"] == "__cf_bm"


def test_broad_apex_domain_demotes_confidence_not_impact():
    # "empresa.com" is the bare apex (1 dot) — covers blog.empresa.com by
    # construction, so evidence_confidence is demoted from the tier-2 base
    # down to medium. potential_impact is untouched by wildcard breadth —
    # a session cookie is still a session cookie regardless of how broad
    # its Domain scope is.
    result = _synthetic_import_result("session_id=abc123; Secure; Domain=empresa.com")
    findings = cookie_analyzer.analyze_cookies(result)

    assert len(findings) == 1
    assert findings[0]["assessment"]["evidence_confidence"] == "medium"
    assert findings[0]["assessment"]["potential_impact"] == "high"


def test_host_only_cookie_no_domain_produces_no_finding():
    result = _synthetic_import_result("session_id=abc123; Secure; HttpOnly")  # no Domain=
    assert cookie_analyzer.analyze_cookies(result) == []


def test_unrelated_domain_produces_no_finding():
    result = _synthetic_import_result("session_id=abc123; Domain=totally-unrelated.other.com")
    assert cookie_analyzer.analyze_cookies(result) == []


def test_no_suspicious_targets_yields_no_findings():
    result = _synthetic_import_result("session_id=abc123; Domain=blog.empresa.com")
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    assert cookie_analyzer.analyze_cookies(result) == []


def test_multiple_cookies_in_one_header_each_evaluated():
    value = (
        "tracking=xyz; Secure; Domain=empresa.com, "
        "session_id=abc; Secure; HttpOnly; Domain=blog.empresa.com"
    )
    result = _synthetic_import_result(value)
    findings = cookie_analyzer.analyze_cookies(result)

    assert len(findings) == 2
    matched_values = {f["evidence"]["matched_value"] for f in findings}
    assert matched_values == {"empresa.com", "blog.empresa.com"}


# ---------------------------------------------------------------------------
# Real-fixture baseline — honest zero, explained in the module docstring
# ---------------------------------------------------------------------------

def test_real_fixtures_yield_no_cookie_findings_today():
    for name in ("sunresorts_full_scan.json", "brightretail_scan.json", "secureideas_enum.json"):
        result = _import(name)
        assert cookie_analyzer.analyze_cookies(result) == [], (
            f"{name} unexpectedly produced a cookie finding — "
            "update this test's docstring if that's now intentional"
        )
