"""
TrustLeak — cross-run finding persistence / deduplication.

Without this, running TrustLeak twice against updated scans of the same
target restarts finding_id at TL-0001 every time, and the exact same
underlying trust relationship (same source, target, relationship type,
and matched evidence) gets a different ID on every run — there's no way
to tell "is this the same finding as last week's scan" from IDs alone.

This module remaps the finding_ids correlate_all() just assigned (unique
only *within* one run) into stable, content-based IDs that persist
across runs: a finding seen before keeps its original ID; a genuinely
new finding gets the next unused ID, continuing from the highest ID ever
assigned — never restarting at TL-0001 once a state file exists.

Entirely optional. Without a --state file, callers get exactly the
behavior they had before this module existed.
"""
import hashlib
import json
import os


def _content_key(finding):
    """
    A stable identity for 'the same underlying finding', independent of
    which run produced it or what order analyzers ran in. Two findings
    with the same source, target, relationship type, and matched
    evidence are the same finding across runs — even if confidence or
    other derived fields changed between scans.
    """
    parts = (
        finding["source"]["hostname"],
        finding["target"]["hostname"],
        finding["relationship"]["type"],
        finding["evidence"].get("header") or "",
        finding["evidence"].get("directive") or "",
        finding["evidence"].get("matched_value") or "",
    )
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_state(path):
    """
    Return the persisted state dict, or a fresh empty one if the file
    doesn't exist yet. A missing file means "first run", not an error.
    """
    if not os.path.isfile(path):
        return {"next_id": 1, "keys": {}}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(path, state):
    """Write the state dict back to disk, pretty-printed for readability."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def assign_stable_ids(findings, state):
    """
    Remap each finding's finding_id to a stable, content-based ID using
    `state`, mutating `state` in place as new findings are seen (callers
    should save_state() afterward to persist that). Returns a NEW list —
    the input findings are not mutated.

    A finding whose content_key already exists in state keeps the ID
    state recorded for it, even if this run's correlate_all() happened to
    assign it a different provisional ID. A new content_key gets
    state["next_id"], which is then incremented.
    """
    remapped = []
    for finding in findings:
        key = _content_key(finding)
        if key in state["keys"]:
            stable_id = state["keys"][key]
        else:
            stable_id = f"TL-{state['next_id']:04d}"
            state["keys"][key] = stable_id
            state["next_id"] += 1

        remapped.append({**finding, "finding_id": stable_id})

    return remapped
