"""
Tests for trustleak.js_analyzer — the first active-probe analyzer.

requests.get is always mocked in this file: no test here ever makes a
real network call, both so the suite stays fast/offline and so a stray
real request is never a risk of running these tests.
"""
import os
from unittest import mock

import requests

from trustleak import importer, js_analyzer
from trustleak.importer import ImportResult

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


def _asset(hostname, classification, script_src=None, confidence="low", takeover_possible=False):
    return {
        "hostname": hostname,
        "classification": classification,
        "dns_active": True,
        "dns_target": "1.2.3.4",
        "http_status": 200,
        "takeover_possible": takeover_possible,
        "confidence": confidence,
        "relevant_headers": {},
        "relevant_body_refs": {"script_src": script_src} if script_src else {},
        "raw": {},
    }


def _synthetic_import_result(active_assets, target_confidence="high"):
    suspicious = _asset(
        "blog.empresa.com", "suspicious",
        confidence=target_confidence, takeover_possible=True,
    )
    return ImportResult(
        source_summary={"total_subdomains": len(active_assets) + 1, "potential_takeovers": 1, "targets_scanned": 1},
        assets=active_assets + [suspicious],
        skipped=[],
    )


# ---------------------------------------------------------------------------
# _resolve_absolute_url
# ---------------------------------------------------------------------------

def test_resolve_relative_path_against_source_host():
    assert js_analyzer._resolve_absolute_url("/assets/app.js", "app.empresa.com") == "https://app.empresa.com/assets/app.js"


def test_resolve_protocol_relative_url():
    assert js_analyzer._resolve_absolute_url("//cdn.empresa.com/app.js", "app.empresa.com") == "https://cdn.empresa.com/app.js"


def test_resolve_absolute_url_kept_as_is():
    url = "https://cdn.empresa.com/app.js"
    assert js_analyzer._resolve_absolute_url(url, "app.empresa.com") == url


def test_resolve_empty_string_returns_none():
    assert js_analyzer._resolve_absolute_url("", "app.empresa.com") is None


# ---------------------------------------------------------------------------
# _collect_in_scope_script_urls — the automatic scope rule
# ---------------------------------------------------------------------------

def test_relative_path_always_in_scope():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    pairs = js_analyzer._collect_in_scope_script_urls(result)
    assert pairs == [("app.empresa.com", "https://app.empresa.com/app.js")]


def test_absolute_url_sharing_apex_is_in_scope():
    result = _synthetic_import_result([
        _asset("app.empresa.com", "active", script_src=["https://cdn.empresa.com/lib.js"])
    ])
    pairs = js_analyzer._collect_in_scope_script_urls(result)
    assert pairs == [("app.empresa.com", "https://cdn.empresa.com/lib.js")]


def test_third_party_cdn_is_out_of_scope():
    result = _synthetic_import_result([
        _asset("app.empresa.com", "active", script_src=["https://code.jquery.com/jquery.min.js"])
    ])
    assert js_analyzer._collect_in_scope_script_urls(result) == []


def test_duplicate_url_across_sources_deduplicated():
    result = _synthetic_import_result([
        _asset("a.empresa.com", "active", script_src=["https://cdn.empresa.com/shared.js"]),
        _asset("b.empresa.com", "active", script_src=["https://cdn.empresa.com/shared.js"]),
    ])
    pairs = js_analyzer._collect_in_scope_script_urls(result)
    assert len(pairs) == 1
    assert pairs[0][1] == "https://cdn.empresa.com/shared.js"


# ---------------------------------------------------------------------------
# analyze_js_content — end to end, requests.get always mocked
# ---------------------------------------------------------------------------

def test_no_suspicious_targets_yields_no_findings_and_no_requests():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    with mock.patch("requests.get") as mocked_get:
        findings = js_analyzer.analyze_js_content(result)
    assert findings == []
    mocked_get.assert_not_called()


def test_no_script_refs_yields_no_findings_and_no_requests():
    result = _synthetic_import_result([_asset("app.empresa.com", "active")])
    with mock.patch("requests.get") as mocked_get:
        findings = js_analyzer.analyze_js_content(result)
    assert findings == []
    mocked_get.assert_not_called()


def test_finds_target_hostname_inside_downloaded_js_content():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    fake_response = mock.Mock()
    fake_response.text = "const API = 'https://blog.empresa.com/api';"

    with mock.patch("requests.get", return_value=fake_response) as mocked_get:
        findings = js_analyzer.analyze_js_content(result)

    mocked_get.assert_called_once()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"]["hostname"] == "app.empresa.com"
    assert finding["target"]["hostname"] == "blog.empresa.com"
    assert finding["relationship"]["type"] == "js_content_reference"
    assert finding["relationship"]["category"] == "js_content_dependency"
    assert finding["relationship"]["status"] == "potential_risk"
    assert finding["evidence"]["collected_via"] == "trustleak_active_request"
    assert finding["evidence"]["source_url"] == "https://app.empresa.com/app.js"
    assert finding["assessment"]["potential_impact"] == "high"


def test_content_without_target_hostname_yields_no_finding():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    fake_response = mock.Mock()
    fake_response.text = "const API = 'https://totally-unrelated.other.com/api';"

    with mock.patch("requests.get", return_value=fake_response):
        findings = js_analyzer.analyze_js_content(result)
    assert findings == []


def test_match_is_case_insensitive():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    fake_response = mock.Mock()
    fake_response.text = "const API = 'HTTPS://BLOG.EMPRESA.COM/api';"

    with mock.patch("requests.get", return_value=fake_response):
        findings = js_analyzer.analyze_js_content(result)
    assert len(findings) == 1


def test_request_exception_is_skipped_not_fatal():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    with mock.patch("requests.get", side_effect=requests.ConnectionError("boom")):
        findings = js_analyzer.analyze_js_content(result)  # must not raise
    assert findings == []


def test_above_threshold_asks_for_confirmation_before_fetching():
    many_scripts = [f"/script{i}.js" for i in range(js_analyzer._CONFIRM_THRESHOLD + 1)]
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=many_scripts)])

    confirm_fn = mock.Mock(return_value=False)
    with mock.patch("requests.get") as mocked_get:
        findings = js_analyzer.analyze_js_content(result, confirm_fn=confirm_fn)

    confirm_fn.assert_called_once_with(js_analyzer._CONFIRM_THRESHOLD + 1)
    mocked_get.assert_not_called()
    assert findings == []


def test_above_threshold_proceeds_when_confirmed():
    many_scripts = [f"/script{i}.js" for i in range(js_analyzer._CONFIRM_THRESHOLD + 1)]
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=many_scripts)])

    confirm_fn = mock.Mock(return_value=True)
    fake_response = mock.Mock()
    fake_response.text = "nothing relevant here"
    with mock.patch("requests.get", return_value=fake_response) as mocked_get, \
            mock.patch("time.sleep"):
        js_analyzer.analyze_js_content(result, confirm_fn=confirm_fn)

    confirm_fn.assert_called_once()
    assert mocked_get.call_count == js_analyzer._CONFIRM_THRESHOLD + 1


def test_below_threshold_never_asks_for_confirmation():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    confirm_fn = mock.Mock()
    fake_response = mock.Mock()
    fake_response.text = "nothing relevant"
    with mock.patch("requests.get", return_value=fake_response):
        js_analyzer.analyze_js_content(result, confirm_fn=confirm_fn)
    confirm_fn.assert_not_called()


def test_finding_ids_increment_from_custom_start():
    result = _synthetic_import_result([_asset("app.empresa.com", "active", script_src=["/app.js"])])
    fake_response = mock.Mock()
    fake_response.text = "https://blog.empresa.com/api"
    with mock.patch("requests.get", return_value=fake_response):
        findings = js_analyzer.analyze_js_content(result, finding_id_start=7)
    assert findings[0]["finding_id"] == "TL-0007"


# ---------------------------------------------------------------------------
# Real-fixture baseline — these fixtures predate relevant_body_refs
# entirely, so there's nothing to fetch; zero is the only honest result.
# ---------------------------------------------------------------------------

def test_real_fixtures_yield_no_js_findings_today():
    for name in ("sunresorts_full_scan.json", "brightretail_scan.json", "secureideas_enum.json"):
        result = _import(name)
        with mock.patch("requests.get") as mocked_get:
            findings = js_analyzer.analyze_js_content(result)
        assert findings == []
        mocked_get.assert_not_called()
