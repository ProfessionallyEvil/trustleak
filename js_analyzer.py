"""
TrustLeak — JS Content Analyzer (M5, ACTIVE).

The first active-probe analyzer in this codebase: downloads a
referenced `.js` file's own content — something ShadowSaaS itself never
fetches — and searches the downloaded text for a suspicious target's
hostname appearing as a substring. Same correlation principle as every
passive analyzer, just applied to content that required a new HTTP
request to obtain.

Deliberately its own module, registered only in correlate.py's
_ACTIVE_ANALYZERS (never _PASSIVE_ANALYZERS) — only runs when a caller
passes allow_active=True. See NOTES.md for the full rationale and the
requirements active-probe features must satisfy.

Scope (automatic, no separate scope file): a script reference is only
fetched if —
  - it's a relative path (e.g. "/assets/app.js") — same host ShadowSaaS
    already contacted, always in scope, or
  - its absolute hostname shares an apex domain with some hostname
    already present in THIS scan (see hostnames.shares_apex_with_any()).
A generic third-party library/CDN host (code.jquery.com,
googletagmanager.com, cdn.jsdelivr.net, etc.) never shares the scanned
organization's apex domain, so it's automatically excluded without
needing a blocklist. This is a sanity check that a derived host is
actually part of the engagement's own infrastructure — not a substitute
for the operator's own authorization to run active probes at all, which
is what --allow-active-probes confirms.
"""
import hashlib
import json
import os
import time
from urllib.parse import urlparse

import requests

from trustleak import categories
from trustleak import confidence as confidence_tiering
from trustleak import schema
from trustleak.hostnames import shares_apex_with_any

_REQUEST_TIMEOUT_SECONDS = 5
_DELAY_BETWEEN_REQUESTS_SECONDS = 0.1

# Above this many in-scope, deduplicated .js URLs, ask before fetching —
# below it, just proceed (same "never block automation for a small,
# ordinary run" philosophy as the rest of this project).
_CONFIRM_THRESHOLD = 20


def _resolve_absolute_url(ref, source_hostname):
    """
    Turn a raw script_src reference into an absolute URL, or None if it
    has no usable host component. A relative path resolves against its
    own source host (always in scope — see module docstring).
    """
    ref = ref.strip()
    if not ref:
        return None
    if ref.startswith("//"):
        return "https:" + ref
    if ref.startswith("http://") or ref.startswith("https://"):
        return ref
    return f"https://{source_hostname}/{ref.lstrip('/')}"


def _collect_in_scope_script_urls(import_result):
    """
    Return a deduplicated list of (source_hostname, absolute_script_url)
    pairs worth fetching. Dedup is by URL: when the same script URL
    appears under many source hosts (a shared CDN asset referenced by
    dozens of pages), only the first source host encountered is kept as
    the attribution for that URL — fetching it once is enough, and the
    resulting finding still names a real application that references it.
    """
    known_hostnames = {a["hostname"] for a in import_result.active} | {
        a["hostname"] for a in import_result.suspicious
    }

    seen_urls = set()
    pairs = []
    for asset in import_result.active:
        for ref in asset.get("relevant_body_refs", {}).get("script_src", []):
            absolute = _resolve_absolute_url(ref, asset["hostname"])
            if not absolute:
                continue

            hostname = urlparse(absolute).hostname
            if not hostname:
                continue
            if not shares_apex_with_any(hostname, known_hostnames):
                continue  # generic third-party library/CDN — out of scope

            if absolute in seen_urls:
                continue
            seen_urls.add(absolute)
            pairs.append((asset["hostname"], absolute))

    return pairs


def _default_confirm(count):
    answer = input(
        f"\n[?] About to fetch {count} referenced .js file(s) — this sends new "
        f"requests beyond what ShadowSaaS collected. Continue? [y/N] "
    )
    return answer.strip().lower() == "y"


def _save_path_for(output_dir, script_url):
    """
    Deterministic, filesystem-safe path to save one fetched .js file's
    content at — a hash of the URL, not the URL itself, since a URL can
    contain characters invalid in a filename (query strings, colons) and
    can be arbitrarily long. The hash is stable across runs: fetching the
    same URL again overwrites the same file rather than accumulating
    duplicates.
    """
    digest = hashlib.sha256(script_url.encode("utf-8")).hexdigest()[:16]
    return os.path.join(output_dir, f"{digest}.js")


def _write_manifest(output_dir, manifest_entries):
    """
    manifest.json maps each saved file back to the URL it came from and
    which source application referenced it — the hash-named .js files
    alone would be meaningless as evidence without this.
    """
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest_entries, fh, indent=2)
    return manifest_path


def analyze_js_content(import_result, finding_id_start=1, confirm_fn=None, output_dir=None):
    """
    Download in-scope referenced .js files and correlate their content
    against suspicious target hostnames. Returns a list of validated
    TrustLeak findings.

    confirm_fn: optional callable(count) -> bool, asked before fetching
    when the number of in-scope URLs exceeds _CONFIRM_THRESHOLD. Defaults
    to an interactive input() prompt; tests pass a stub to avoid
    blocking, and to avoid making real network requests.

    output_dir: optional directory to save every fetched .js file's
    content into (not just the ones that produced a finding), plus a
    manifest.json mapping each saved file back to its source URL and
    referencing application — evidence for the engagement, not just a
    correlation result. Created if it doesn't already exist. When None
    (the default), nothing is written to disk.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious

    if not suspicious_targets:
        return findings

    pairs = _collect_in_scope_script_urls(import_result)
    if not pairs:
        return findings

    if len(pairs) > _CONFIRM_THRESHOLD:
        ask = confirm_fn if confirm_fn else _default_confirm
        if not ask(len(pairs)):
            return findings

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    manifest_entries = {}

    category = categories.category_for("js_content_reference")
    potential_impact = categories.default_impact_for(category)

    total = len(pairs)
    for i, (source_hostname, script_url) in enumerate(pairs, start=1):
        print(f"[*] [{i}/{total}] Fetching {script_url}")

        try:
            response = requests.get(script_url, timeout=_REQUEST_TIMEOUT_SECONDS)
            content = response.text
        except requests.RequestException as exc:
            print(f"[!] [{i}/{total}] Failed: {exc}")
            continue
        finally:
            time.sleep(_DELAY_BETWEEN_REQUESTS_SECONDS)

        if output_dir:
            save_path = _save_path_for(output_dir, script_url)
            with open(save_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            manifest_entries[os.path.basename(save_path)] = {
                "url": script_url,
                "source_hostname": source_hostname,
            }

        content_lower = content.lower()
        for target in suspicious_targets:
            if target["hostname"] not in content_lower:
                continue

            evidence_confidence = confidence_tiering.evidence_confidence_tier(
                target["confidence"] == "high",
                broad_wildcard=confidence_tiering.is_broad_wildcard(target["hostname"]),
            )

            findings.append(schema.build_finding(
                finding_id=f"TL-{finding_counter:04d}",
                source_hostname=source_hostname,
                target_hostname=target["hostname"],
                target_asset_status="potential_takeover",
                target_shadowsaas_confidence=target["confidence"],
                relationship_type="js_content_reference",
                relationship_status="potential_risk",
                evidence_source_url=script_url,
                evidence_header="JS file content",
                evidence_matched_value=target["hostname"],
                evidence_collected_via="trustleak_active_request",
                evidence_confidence=evidence_confidence,
                potential_impact=potential_impact,
            ))
            finding_counter += 1

    if output_dir and manifest_entries:
        manifest_path = _write_manifest(output_dir, manifest_entries)
        print(f"[+] {len(manifest_entries)} fetched .js file(s) saved to {output_dir} ({manifest_path})")

    return findings