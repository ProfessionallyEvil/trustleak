"""
Tests for trustleak.state — cross-run finding persistence.
"""
import os

from trustleak import correlate, importer, state

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


def test_load_state_missing_file_returns_fresh_state(tmp_path):
    loaded = state.load_state(str(tmp_path / "does_not_exist.json"))
    assert loaded == {"next_id": 1, "keys": {}}


def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "state.json")
    original = {"next_id": 5, "keys": {"abc123": "TL-0001"}}
    state.save_state(path, original)
    loaded = state.load_state(path)
    assert loaded == original


def test_same_run_twice_keeps_same_ids(tmp_path):
    # The core guarantee: running against the exact same scan twice must
    # produce identical finding_ids both times, not a fresh TL-0001.. each
    # time.
    path = str(tmp_path / "state.json")
    result = _import("sunresorts_full_scan.json")

    first_run = correlate.correlate_all(result)
    s1 = state.load_state(path)
    stable_first = state.assign_stable_ids(first_run, s1)
    state.save_state(path, s1)

    second_run = correlate.correlate_all(result)  # same input, fresh provisional ids
    s2 = state.load_state(path)
    stable_second = state.assign_stable_ids(second_run, s2)

    ids_first = [f["finding_id"] for f in stable_first]
    ids_second = [f["finding_id"] for f in stable_second]
    assert ids_first == ids_second
    assert s2["next_id"] == s1["next_id"]  # no new ids were consumed


def test_new_finding_in_later_run_gets_next_id_not_restart():
    path_state = {"next_id": 1, "keys": {}}

    first_finding = {
        "source": {"hostname": "app.empresa.com"},
        "target": {"hostname": "blog.empresa.com"},
        "relationship": {"type": "csp_script_src"},
        "evidence": {"header": "Content-Security-Policy", "directive": "script-src", "matched_value": "blog.empresa.com"},
    }
    run_one = state.assign_stable_ids([first_finding], path_state)
    assert run_one[0]["finding_id"] == "TL-0001"
    assert path_state["next_id"] == 2

    second_finding = {
        "source": {"hostname": "other.empresa.com"},
        "target": {"hostname": "blog.empresa.com"},
        "relationship": {"type": "cors_allowed_origin"},
        "evidence": {"header": "Access-Control-Allow-Origin", "directive": None, "matched_value": "blog.empresa.com"},
    }
    # Run two: the old finding reappears (must keep TL-0001) alongside one
    # genuinely new finding (must get TL-0002, not restart at TL-0001).
    run_two = state.assign_stable_ids([first_finding, second_finding], path_state)
    ids = {f["evidence"]["matched_value"] + f["relationship"]["type"]: f["finding_id"] for f in run_two}

    assert run_two[0]["finding_id"] == "TL-0001"  # same finding, same id
    assert run_two[1]["finding_id"] == "TL-0002"  # new finding, next id, not TL-0001 again
    assert path_state["next_id"] == 3


def test_assign_stable_ids_does_not_mutate_input_findings():
    original = [{
        "finding_id": "TL-9999",
        "source": {"hostname": "a.com"},
        "target": {"hostname": "b.com"},
        "relationship": {"type": "csp_img_src"},
        "evidence": {"header": "CSP", "directive": "img-src", "matched_value": "b.com"},
    }]
    s = {"next_id": 1, "keys": {}}
    result = state.assign_stable_ids(original, s)
    assert original[0]["finding_id"] == "TL-9999"  # untouched
    assert result[0]["finding_id"] == "TL-0001"  # new list has the stable id


def test_content_key_ignores_confidence_changes():
    # Same underlying finding, confidence differs between runs (plausible
    # if ShadowSaaS re-scores the target differently on a re-scan) — must
    # still be recognized as the same finding.
    finding_v1 = {
        "source": {"hostname": "a.com"}, "target": {"hostname": "b.com"},
        "relationship": {"type": "csp_img_src"},
        "evidence": {"header": "CSP", "directive": "img-src", "matched_value": "b.com"},
        "confidence": "medium",
    }
    finding_v2 = {**finding_v1, "confidence": "high"}
    s = {"next_id": 1, "keys": {}}
    r1 = state.assign_stable_ids([finding_v1], s)
    r2 = state.assign_stable_ids([finding_v2], s)
    assert r1[0]["finding_id"] == r2[0]["finding_id"]
    assert s["next_id"] == 2  # only counted once
