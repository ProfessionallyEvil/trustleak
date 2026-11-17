import os
import shutil
import tempfile
from unittest import mock

from trustleak import correlate
from trustleak.importer import ImportResult


def _asset(hostname, classification, script_src=None, confidence="high"):
    return {
        "hostname": hostname,
        "classification": classification,
        "confidence": confidence,
        "relevant_headers": {},
        "relevant_body_refs": {"script_src": script_src} if script_src else {},
    }


def test_active_analyzer_kwargs_routes_output_dir_to_js_content_only():
    tmp_dir = tempfile.mkdtemp()
    try:
        result = ImportResult(source_summary={}, assets=[
            _asset("app.example.com", "active", script_src=["/a.js"]),
            _asset("blog.example.com", "suspicious"),
        ], skipped=[])
        fake_response = mock.Mock()
        fake_response.json.side_effect = ValueError('not JSON')
        fake_response.text = "nothing relevant"
        with mock.patch("requests.get", return_value=fake_response), mock.patch("time.sleep"):
            correlate.correlate_all(
                result, allow_active=True,
                active_analyzer_kwargs={"js_content": {"output_dir": tmp_dir}},
            )
        assert os.path.isfile(os.path.join(tmp_dir, "manifest.json"))
    finally:
        shutil.rmtree(tmp_dir)


def test_no_active_analyzer_kwargs_js_analyzer_still_runs_without_saving():
    result = ImportResult(source_summary={}, assets=[
        _asset("app.example.com", "active", script_src=["/a.js"]),
        _asset("blog.example.com", "suspicious"),
    ], skipped=[])
    fake_response = mock.Mock()
    fake_response.json.side_effect = ValueError('not JSON')
    fake_response.text = "nothing relevant"
    with mock.patch("requests.get", return_value=fake_response), mock.patch("time.sleep"):
        findings = correlate.correlate_all(result, allow_active=True)
    assert findings == []  # ran fine, no kwargs needed, nothing saved anywhere


def test_allow_active_false_js_content_never_runs_even_with_kwargs():
    result = ImportResult(source_summary={}, assets=[
        _asset("app.example.com", "active", script_src=["/a.js"]),
        _asset("blog.example.com", "suspicious"),
    ], skipped=[])
    with mock.patch("requests.get") as mocked_get:
        correlate.correlate_all(
            result, allow_active=False,
            active_analyzer_kwargs={"js_content": {"output_dir": "/tmp/should-not-be-used"}},
        )
    mocked_get.assert_not_called()