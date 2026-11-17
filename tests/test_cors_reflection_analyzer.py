"""
Tests for trustleak.cors_reflection_analyzer.

requests.get is always mocked: no test here ever makes a real network
call.
"""
import json
import os
import shutil
import tempfile
from unittest import mock

import requests

from trustleak import cors_reflection_analyzer
from trustleak.importer import ImportResult


def _asset(hostname, classification, confidence="low"):
    return {"hostname": hostname, "classification": classification, "confidence": confidence}


def _result(active_hostnames, target_confidence="high"):
    active = [_asset(h, "active") for h in active_hostnames]
    suspicious = _asset("blog.example.com", "suspicious", confidence=target_confidence)
    return ImportResult(source_summary={}, assets=active + [suspicious], skipped=[])


def _response(headers=None, status_code=200):
    resp = mock.Mock()
    resp.headers = headers or {}
    resp.status_code = status_code
    return resp


# ---------------------------------------------------------------------------

def test_no_suspicious_targets_yields_no_findings_and_no_requests():
    result = ImportResult(source_summary={}, assets=[_asset("app.example.com", "active")], skipped=[])
    with mock.patch("requests.get") as mocked_get:
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []
    mocked_get.assert_not_called()


def test_no_active_hosts_yields_no_findings_and_no_requests():
    result = ImportResult(source_summary={}, assets=[_asset("blog.example.com", "suspicious", confidence="high")], skipped=[])
    with mock.patch("requests.get") as mocked_get:
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []
    mocked_get.assert_not_called()


def test_no_reflection_yields_no_finding():
    result = _result(["app.example.com"])
    with mock.patch("requests.get", return_value=_response({"Access-Control-Allow-Origin": "*"})):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []


def test_missing_acao_header_yields_no_finding():
    result = _result(["app.example.com"])
    with mock.patch("requests.get", return_value=_response({})):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []


def test_exact_reflection_confirmed():
    result = _result(["app.example.com"])
    fake_response = _response({"Access-Control-Allow-Origin": "https://blog.example.com"})
    with mock.patch("requests.get", return_value=fake_response) as mocked_get:
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)

    mocked_get.assert_called_once_with(
        "https://app.example.com/",
        headers={"Origin": "https://blog.example.com"},
        timeout=cors_reflection_analyzer._REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source"]["hostname"] == "app.example.com"
    assert finding["target"]["hostname"] == "blog.example.com"
    assert finding["relationship"]["type"] == "cors_allowed_origin"
    assert finding["relationship"]["category"] == "cross_origin_trust"
    assert finding["relationship"]["status"] == "validated"  # the key distinction
    assert finding["evidence"]["collected_via"] == "trustleak_active_request"
    assert finding["evidence"]["matched_value"] == "https://blog.example.com"


def test_reflection_without_credentials_gets_default_impact():
    result = _result(["app.example.com"])
    fake_response = _response({"Access-Control-Allow-Origin": "https://blog.example.com"})
    with mock.patch("requests.get", return_value=fake_response):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings[0]["assessment"]["potential_impact"] == "medium"


def test_reflection_with_credentials_gets_high_impact():
    result = _result(["app.example.com"])
    fake_response = _response({
        "Access-Control-Allow-Origin": "https://blog.example.com",
        "Access-Control-Allow-Credentials": "true",
    })
    with mock.patch("requests.get", return_value=fake_response):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings[0]["assessment"]["potential_impact"] == "high"


def test_credentials_header_case_and_whitespace_insensitive():
    result = _result(["app.example.com"])
    fake_response = _response({
        "Access-Control-Allow-Origin": "https://blog.example.com",
        "Access-Control-Allow-Credentials": "  TRUE  ",
    })
    with mock.patch("requests.get", return_value=fake_response):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings[0]["assessment"]["potential_impact"] == "high"


def test_wildcard_acao_is_not_a_reflection():
    # ACAO: * is a real, common, and much less severe configuration —
    # must not be confused with reflecting the exact forged Origin.
    result = _result(["app.example.com"])
    with mock.patch("requests.get", return_value=_response({"Access-Control-Allow-Origin": "*"})):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []


def test_reflection_of_a_different_origin_is_not_a_match():
    # The server reflects SOME origin, but not the one we sent — must
    # not be confused with reflecting our forged value.
    result = _result(["app.example.com"])
    with mock.patch("requests.get", return_value=_response({"Access-Control-Allow-Origin": "https://not-our-target.com"})):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []


def test_connection_failure_is_skipped_not_fatal(capsys):
    result = _result(["app.example.com"])
    with mock.patch("requests.get", side_effect=requests.ConnectionError("boom")):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings == []
    assert "Failed" in capsys.readouterr().out


def test_redirects_are_never_followed():
    result = _result(["app.example.com"])
    with mock.patch("requests.get", return_value=_response({})) as mocked_get:
        cors_reflection_analyzer.analyze_cors_reflection(result)
    assert mocked_get.call_args.kwargs["allow_redirects"] is False


def test_volume_is_active_times_suspicious_not_just_active():
    result = ImportResult(source_summary={}, assets=[
        _asset("app1.example.com", "active"),
        _asset("app2.example.com", "active"),
        _asset("blog.example.com", "suspicious", confidence="high"),
        _asset("old.example.com", "suspicious", confidence="high"),
    ], skipped=[])
    with mock.patch("requests.get", return_value=_response({})) as mocked_get:
        cors_reflection_analyzer.analyze_cors_reflection(result)
    assert mocked_get.call_count == 4  # 2 active x 2 suspicious, not 2 or 4-deduplicated


def test_progress_is_printed_per_pair(capsys):
    result = ImportResult(source_summary={}, assets=[
        _asset("app1.example.com", "active"),
        _asset("app2.example.com", "active"),
        _asset("blog.example.com", "suspicious", confidence="high"),
    ], skipped=[])
    with mock.patch("requests.get", return_value=_response({})):
        cors_reflection_analyzer.analyze_cors_reflection(result)
    out = capsys.readouterr().out
    assert "[1/2]" in out and "[2/2]" in out


def test_above_threshold_asks_for_confirmation_before_testing():
    hosts = [f"app{i}.example.com" for i in range(cors_reflection_analyzer._CONFIRM_THRESHOLD + 1)]
    result = _result(hosts)
    confirm_fn = mock.Mock(return_value=False)
    with mock.patch("requests.get") as mocked_get:
        findings = cors_reflection_analyzer.analyze_cors_reflection(result, confirm_fn=confirm_fn)
    confirm_fn.assert_called_once_with(cors_reflection_analyzer._CONFIRM_THRESHOLD + 1)
    mocked_get.assert_not_called()
    assert findings == []


def test_below_threshold_never_asks_for_confirmation():
    result = _result(["app.example.com"])
    confirm_fn = mock.Mock()
    with mock.patch("requests.get", return_value=_response({})):
        cors_reflection_analyzer.analyze_cors_reflection(result, confirm_fn=confirm_fn)
    confirm_fn.assert_not_called()


def test_finding_ids_increment_from_custom_start():
    result = _result(["app.example.com"])
    fake_response = _response({"Access-Control-Allow-Origin": "https://blog.example.com"})
    with mock.patch("requests.get", return_value=fake_response):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result, finding_id_start=42)
    assert findings[0]["finding_id"] == "TL-0042"


def test_low_shadowsaas_confidence_target_gets_medium_evidence_confidence():
    result = _result(["app.example.com"], target_confidence="low")
    fake_response = _response({"Access-Control-Allow-Origin": "https://blog.example.com"})
    with mock.patch("requests.get", return_value=fake_response):
        findings = cors_reflection_analyzer.analyze_cors_reflection(result)
    assert findings[0]["assessment"]["evidence_confidence"] == "medium"


# ---------------------------------------------------------------------------
# Save-to-disk + manifest
# ---------------------------------------------------------------------------

def test_output_dir_saves_only_confirmed_reflections():
    tmp_dir = tempfile.mkdtemp()
    try:
        result = ImportResult(source_summary={}, assets=[
            _asset("reflects.example.com", "active"),
            _asset("plain.example.com", "active"),
            _asset("blog.example.com", "suspicious", confidence="high"),
        ], skipped=[])

        def fake_get(url, headers, timeout, allow_redirects):
            if "reflects" in url:
                return _response({
                    "Access-Control-Allow-Origin": "https://blog.example.com",
                    "Access-Control-Allow-Credentials": "true",
                })
            return _response({})

        with mock.patch("requests.get", side_effect=fake_get):
            cors_reflection_analyzer.analyze_cors_reflection(result, output_dir=tmp_dir)

        saved_files = [f for f in os.listdir(tmp_dir) if f.endswith(".json") and f != "manifest.json"]
        assert len(saved_files) == 1

        manifest = json.load(open(os.path.join(tmp_dir, "manifest.json"), encoding="utf-8"))
        assert len(manifest) == 1
        entry = next(iter(manifest.values()))
        assert entry["active_host"] == "reflects.example.com"
        assert entry["credentials"] is True
    finally:
        shutil.rmtree(tmp_dir)


def test_no_manifest_written_when_nothing_confirmed():
    tmp_dir = tempfile.mkdtemp()
    try:
        result = _result(["app.example.com"])
        with mock.patch("requests.get", return_value=_response({})):
            cors_reflection_analyzer.analyze_cors_reflection(result, output_dir=tmp_dir)
        assert not os.path.isfile(os.path.join(tmp_dir, "manifest.json"))
    finally:
        shutil.rmtree(tmp_dir)