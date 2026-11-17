"""
Tests for trustleak.oauth_discovery_analyzer.

requests.get is always mocked: no test here ever makes a real network
call.
"""
import json
import os
import shutil
import tempfile
from unittest import mock

import requests

from trustleak import oauth_discovery_analyzer
from trustleak.importer import ImportResult


def _asset(hostname, classification, confidence="low"):
    return {"hostname": hostname, "classification": classification, "confidence": confidence}


def _result(active_hostnames, target_confidence="high"):
    active = [_asset(h, "active") for h in active_hostnames]
    suspicious = _asset("blog.example.com", "suspicious", confidence=target_confidence)
    return ImportResult(source_summary={}, assets=active + [suspicious], skipped=[])


def _json_response(payload):
    resp = mock.Mock()
    resp.json.return_value = payload
    return resp


def _non_json_response():
    resp = mock.Mock()
    resp.json.side_effect = ValueError("not JSON")
    return resp


# ---------------------------------------------------------------------------

def test_no_suspicious_targets_yields_no_findings_and_no_requests():
    result = _result(["app.example.com"])
    result.assets = [a for a in result.assets if a["classification"] != "suspicious"]
    with mock.patch("requests.get") as mocked_get:
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []
    mocked_get.assert_not_called()


def test_no_active_hosts_yields_no_findings_and_no_requests():
    result = ImportResult(source_summary={}, assets=[_asset("blog.example.com", "suspicious", confidence="high")], skipped=[])
    with mock.patch("requests.get") as mocked_get:
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []
    mocked_get.assert_not_called()


def test_non_json_response_is_skipped_silently_not_a_failure():
    result = _result(["app.example.com"])
    with mock.patch("requests.get", return_value=_non_json_response()):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []


def test_json_without_issuer_field_is_not_treated_as_a_real_oidc_document(capsys):
    # Valid JSON, but missing "issuer" (required by RFC 8414) — e.g. some
    # unrelated API returning a JSON error body on this exact path. Must
    # not be announced as "a real identity provider lives here".
    result = _result(["app.example.com"])
    payload = {"error": "not found"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []
    assert "Valid OIDC document found" not in capsys.readouterr().out


def test_valid_oidc_document_is_announced_even_without_a_match(capsys):
    # The actual fix: distinguishes "a real identity provider lives here,
    # just no match" from "nothing responded at all" — both used to look
    # identical (0 findings) without this line.
    result = _result(["app.example.com"])
    payload = {"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/auth"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []
    assert "Valid OIDC document found" in capsys.readouterr().out


def test_json_response_without_target_hostname_yields_no_finding():
    result = _result(["app.example.com"])
    payload = {"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/auth"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []


def test_finds_target_hostname_in_issuer_field():
    result = _result(["app.example.com"])
    payload = {"issuer": "https://blog.example.com", "authorization_endpoint": "https://blog.example.com/auth"}
    with mock.patch("requests.get", return_value=_json_response(payload)) as mocked_get:
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)

    mocked_get.assert_called_once_with(
        "https://app.example.com/.well-known/openid-configuration", timeout=oauth_discovery_analyzer._REQUEST_TIMEOUT_SECONDS
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"]["hostname"] == "app.example.com"
    assert finding["target"]["hostname"] == "blog.example.com"
    assert finding["relationship"]["type"] == "oauth_discovery_reference"
    assert finding["relationship"]["category"] == "authentication_dependency"
    assert finding["relationship"]["status"] == "potential_risk"
    assert finding["evidence"]["collected_via"] == "trustleak_active_request"
    assert finding["evidence"]["source_url"] == "https://app.example.com/.well-known/openid-configuration"
    assert finding["assessment"]["potential_impact"] == "high"


def test_match_is_case_insensitive():
    result = _result(["app.example.com"])
    payload = {"issuer": "HTTPS://BLOG.EXAMPLE.COM"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert len(findings) == 1


def test_connection_failure_is_skipped_not_fatal(capsys):
    result = _result(["app.example.com"])
    with mock.patch("requests.get", side_effect=requests.ConnectionError("boom")):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert findings == []
    assert "Failed" in capsys.readouterr().out


def test_one_request_per_active_host_not_per_pair():
    # The key volume characteristic: O(active hosts), not O(active x
    # suspicious) — one fetch per host covers every suspicious target.
    result = ImportResult(source_summary={}, assets=[
        _asset("app1.example.com", "active"),
        _asset("app2.example.com", "active"),
        _asset("blog.example.com", "suspicious", confidence="high"),
        _asset("old.example.com", "suspicious", confidence="high"),
    ], skipped=[])
    with mock.patch("requests.get", return_value=_non_json_response()) as mocked_get:
        oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert mocked_get.call_count == 2  # not 4


def test_progress_is_printed_per_check(capsys):
    result = _result(["a.example.com", "b.example.com"])
    with mock.patch("requests.get", return_value=_non_json_response()):
        oauth_discovery_analyzer.analyze_oauth_discovery(result)
    out = capsys.readouterr().out
    assert "[1/2]" in out and "[2/2]" in out


def test_above_threshold_asks_for_confirmation_before_fetching():
    hosts = [f"app{i}.example.com" for i in range(oauth_discovery_analyzer._CONFIRM_THRESHOLD + 1)]
    result = _result(hosts)
    confirm_fn = mock.Mock(return_value=False)
    with mock.patch("requests.get") as mocked_get:
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result, confirm_fn=confirm_fn)
    confirm_fn.assert_called_once_with(oauth_discovery_analyzer._CONFIRM_THRESHOLD + 1)
    mocked_get.assert_not_called()
    assert findings == []


def test_below_threshold_never_asks_for_confirmation():
    result = _result(["app.example.com"])
    confirm_fn = mock.Mock()
    with mock.patch("requests.get", return_value=_non_json_response()):
        oauth_discovery_analyzer.analyze_oauth_discovery(result, confirm_fn=confirm_fn)
    confirm_fn.assert_not_called()


def test_finding_ids_increment_from_custom_start():
    result = _result(["app.example.com"])
    payload = {"issuer": "https://blog.example.com"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result, finding_id_start=42)
    assert findings[0]["finding_id"] == "TL-0042"


# ---------------------------------------------------------------------------
# Save-to-disk + manifest
# ---------------------------------------------------------------------------

def test_output_dir_none_saves_nothing():
    result = _result(["app.example.com"])
    payload = {"issuer": "https://idp.example.com"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        oauth_discovery_analyzer.analyze_oauth_discovery(result, output_dir=None)
    # Nothing to assert on disk — documents the default is a no-op.


def test_output_dir_saves_only_valid_oidc_documents_not_404s():
    tmp_dir = tempfile.mkdtemp()
    try:
        result = ImportResult(source_summary={}, assets=[
            _asset("real-idp.example.com", "active"),
            _asset("plain-app.example.com", "active"),
            _asset("blog.example.com", "suspicious", confidence="high"),
        ], skipped=[])

        def fake_get(url, timeout):
            if "real-idp" in url:
                return _json_response({"issuer": "https://real-idp.example.com"})
            return _non_json_response()

        with mock.patch("requests.get", side_effect=fake_get):
            oauth_discovery_analyzer.analyze_oauth_discovery(result, output_dir=tmp_dir)

        saved_files = [f for f in os.listdir(tmp_dir) if f.endswith(".json") and f != "manifest.json"]
        assert len(saved_files) == 1  # only real-idp.example.com, not the plain 404 one

        manifest = json.load(open(os.path.join(tmp_dir, "manifest.json"), encoding="utf-8"))
        assert len(manifest) == 1
        entry = next(iter(manifest.values()))
        assert entry["host"] == "real-idp.example.com"
        assert entry["issuer"] == "https://real-idp.example.com"
    finally:
        shutil.rmtree(tmp_dir)


def test_no_manifest_written_when_no_valid_oidc_document_found():
    tmp_dir = tempfile.mkdtemp()
    try:
        result = _result(["app.example.com"])
        with mock.patch("requests.get", return_value=_non_json_response()):
            oauth_discovery_analyzer.analyze_oauth_discovery(result, output_dir=tmp_dir)
        assert not os.path.isfile(os.path.join(tmp_dir, "manifest.json"))
    finally:
        shutil.rmtree(tmp_dir)


def test_multiple_suspicious_targets_each_checked_against_same_document():
    result = ImportResult(source_summary={}, assets=[
        _asset("app.example.com", "active"),
        _asset("blog.example.com", "suspicious", confidence="high"),
        _asset("old.example.com", "suspicious", confidence="high"),
    ], skipped=[])
    payload = {"issuer": "https://blog.example.com", "jwks_uri": "https://old.example.com/jwks"}
    with mock.patch("requests.get", return_value=_json_response(payload)):
        findings = oauth_discovery_analyzer.analyze_oauth_discovery(result)
    assert len(findings) == 2
    targets_found = {f["target"]["hostname"] for f in findings}
    assert targets_found == {"blog.example.com", "old.example.com"}