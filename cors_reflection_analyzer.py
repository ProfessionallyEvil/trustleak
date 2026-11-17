"""
TrustLeak — CORS Origin-Reflection Analyzer (M7, ACTIVE).

Third active-probe analyzer in this codebase. For each (active,
suspicious) PAIR, sends a single GET request to the active host with a
forged Origin header set to "https://<suspicious_hostname>", and checks
whether the response's Access-Control-Allow-Origin header reflects that
EXACT value back.

This is different in kind from every other analyzer in this codebase:
it doesn't correlate already-observed data for a *plausible* match — it
actively PROVES server behavior, live, right now. That's why a
confirmed reflection gets relationship.status = "validated" (not
"potential_risk" like every passive finding, and every other active
finding so far in this codebase) — the schema has reserved this value
since v2 for exactly this case: a live-confirmed behavior, not an
inference from static data.

Scope: the host CONTACTED is always the active application (same "only
ever touch a host ShadowSaaS already confirmed active in this scan"
principle as js_analyzer.py and oauth_discovery_analyzer.py) — the
suspicious target's hostname is only ever used as the *value* of the
forged Origin header, never as a host TrustLeak itself connects to.

Volume: O(active applications x suspicious targets) — the most
expensive analyzer in this codebase. A single request can only carry
one Origin value, so there's no way to batch multiple suspicious
targets into one check the way oauth_discovery_analyzer.py does (one
fetch covering every target at once); a separate request is needed per
pair.

Reuses cors_analyzer.py's own relationship_type (cors_allowed_origin)
and category (cross_origin_trust) rather than inventing new ones — this
confirms the exact same underlying relationship the passive analyzer
infers from static header data, just proven instead of inferred.
evidence.collected_via and relationship.status are what distinguish an
active-confirmed finding from a passive one, not a different
type/category.

Redirects are never followed (allow_redirects=False): following one
could send the crafted Origin header to a different, unintended host
entirely outside scope.
"""
import hashlib
import json
import os
import time

import requests

from trustleak import categories
from trustleak import schema

_REQUEST_TIMEOUT_SECONDS = 5
_DELAY_BETWEEN_REQUESTS_SECONDS = 0.1

# Above this many (active, suspicious) pairs, ask before testing — below
# it, just proceed (same philosophy as every other active analyzer here).
_CONFIRM_THRESHOLD = 20


def _default_confirm(count):
    answer = input(
        f"\n[?] About to test {count} (active, suspicious) combination(s) "
        f"for CORS origin reflection — this sends new requests beyond "
        f"what ShadowSaaS collected. Continue? [y/N] "
    )
    return answer.strip().lower() == "y"


def _save_path_for(output_dir, active_host, suspicious_host):
    """
    Deterministic, filesystem-safe path for one confirmed reflection's
    evidence — a hash of the (active_host, suspicious_host) pair, same
    reasoning as the other active analyzers' _save_path_for(): safe
    characters, and re-confirming the same pair overwrites the same
    file rather than accumulating duplicates.
    """
    digest = hashlib.sha256(f"{active_host}|{suspicious_host}".encode("utf-8")).hexdigest()[:16]
    return os.path.join(output_dir, f"{digest}.json")


def _write_manifest(output_dir, manifest_entries):
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest_entries, fh, indent=2)
    return manifest_path


def analyze_cors_reflection(import_result, finding_id_start=1, confirm_fn=None, output_dir=None):
    """
    For every (active, suspicious) pair, send Origin: https://<target>
    to the active host and check whether it's reflected back verbatim
    in Access-Control-Allow-Origin. Returns a list of TrustLeak findings
    — each one relationship.status="validated", since this confirms
    live server behavior rather than inferring a plausible match.

    confirm_fn: optional callable(count) -> bool, asked before testing
    when the number of pairs exceeds _CONFIRM_THRESHOLD. Defaults to an
    interactive input() prompt; tests pass a stub to avoid blocking and
    to avoid making real network requests.

    output_dir: optional directory to save evidence for every CONFIRMED
    reflection (not every pair tested — a non-match is not evidence of
    anything), plus a manifest.json mapping each saved file back to the
    pair and whether credentials were allowed. Created if it doesn't
    already exist. When None (the default), nothing is written to disk.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious
    active_hosts = [a["hostname"] for a in import_result.active]

    if not suspicious_targets or not active_hosts:
        return findings

    pairs = [(active_host, target) for active_host in active_hosts for target in suspicious_targets]

    if len(pairs) > _CONFIRM_THRESHOLD:
        ask = confirm_fn if confirm_fn else _default_confirm
        if not ask(len(pairs)):
            return findings

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    manifest_entries = {}

    category = categories.category_for("cors_allowed_origin")
    default_impact = categories.default_impact_for(category)

    total = len(pairs)
    for i, (active_host, target) in enumerate(pairs, start=1):
        forged_origin = f"https://{target['hostname']}"
        url = f"https://{active_host}/"
        print(f"[*] [{i}/{total}] Testing {active_host} with Origin: {forged_origin}")

        try:
            response = requests.get(
                url,
                headers={"Origin": forged_origin},
                timeout=_REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            print(f"[!] [{i}/{total}] Failed: {exc}")
            time.sleep(_DELAY_BETWEEN_REQUESTS_SECONDS)
            continue
        time.sleep(_DELAY_BETWEEN_REQUESTS_SECONDS)

        acao = response.headers.get("Access-Control-Allow-Origin")
        if acao != forged_origin:
            # Not reflected — the overwhelmingly common case (most hosts
            # don't echo an arbitrary Origin back), not a failure.
            continue

        acac = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        print(
            f"[+] [{i}/{total}] CONFIRMED: {active_host} reflects Origin "
            f"{forged_origin}" + (" (WITH credentials!)" if acac else "")
        )

        if output_dir:
            save_path = _save_path_for(output_dir, active_host, target["hostname"])
            with open(save_path, "w", encoding="utf-8") as fh:
                json.dump({
                    "active_host": active_host,
                    "suspicious_target": target["hostname"],
                    "origin_sent": forged_origin,
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                }, fh, indent=2)
            manifest_entries[os.path.basename(save_path)] = {
                "active_host": active_host,
                "suspicious_target": target["hostname"],
                "credentials": acac,
            }

        # Confirmed live behavior against the EXACT target hostname —
        # there's no wildcard ambiguity possible in an active probe (we
        # always test one specific hostname at a time), so confidence
        # here tracks only ShadowSaaS's own confidence that the target
        # is genuinely dangling, not specificity of the match itself.
        evidence_confidence = "high" if target["confidence"] == "high" else "medium"
        potential_impact = "high" if acac else default_impact

        findings.append(schema.build_finding(
            finding_id=f"TL-{finding_counter:04d}",
            source_hostname=active_host,
            target_hostname=target["hostname"],
            target_asset_status="potential_takeover",
            target_shadowsaas_confidence=target["confidence"],
            relationship_type="cors_allowed_origin",
            relationship_status="validated",
            evidence_source_url=url,
            evidence_header="Access-Control-Allow-Origin (active reflection test)",
            evidence_matched_value=forged_origin,
            evidence_collected_via="trustleak_active_request",
            evidence_confidence=evidence_confidence,
            potential_impact=potential_impact,
        ))
        finding_counter += 1

    if output_dir and manifest_entries:
        manifest_path = _write_manifest(output_dir, manifest_entries)
        print(
            f"[+] {len(manifest_entries)} confirmed CORS reflection(s) "
            f"saved to {output_dir} ({manifest_path})"
        )

    return findings