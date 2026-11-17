"""
TrustLeak — OAuth/OIDC Discovery Analyzer (M6, ACTIVE).

Second active-probe analyzer in this codebase. For each 'active'
application, fetches its own `/.well-known/openid-configuration`
document — a standard, well-known path (RFC 8414 / OpenID Connect
Discovery) that ShadowSaaS itself never visits — and checks its JSON
content for a suspicious target's hostname appearing anywhere inside
(issuer, authorization_endpoint, token_endpoint, jwks_uri, etc.).

This extends the PASSIVE html_oauth_redirect_uri_reference coverage
(html_analyzer.py) to a structured endpoint that's never embedded in
page HTML at all — a redirect_uri might be visible in a login link, but
an OIDC discovery document is JSON served at its own fixed path, never
scraped by the passive HTML pass.

Scope: always every 'active' application — unlike js_analyzer.py, there
is no derived host to scope-check here. The host contacted is always
one ShadowSaaS already confirmed as active in this exact scan; the
well-known path is fixed, not extracted from page content.

Volume: O(active applications), NOT O(active x suspicious) — cheaper
than js_analyzer.py or a hypothetical CORS-reflection analyzer, since
one fetch per active host covers every suspicious target at once (the
same document is checked against all of them).

SAML metadata discovery is DELIBERATELY NOT included here, and not
planned as a simple addition to this module: unlike OIDC, there is no
universal standard path for SAML SP/IdP metadata (implementations vary
widely — /saml/metadata, /simplesaml/module.php/saml/sp/metadata.php/...,
/Shibboleth.sso/Metadata, and more). A blind probe would have to guess
among many non-standard paths, trading a small number of reliable
requests for a much larger number of speculative ones with a high
false-negative rate. Revisit only if a reliable, generic SAML discovery
mechanism is identified — see NOTES.md.

Deliberately its own module, registered only in correlate.py's
_ACTIVE_ANALYZERS — only runs when a caller passes allow_active=True.
See NOTES.md for the full rationale and the requirements active-probe
features must satisfy.
"""
import hashlib
import json
import os
import time

import requests

from trustleak import categories
from trustleak import confidence as confidence_tiering
from trustleak import schema

_REQUEST_TIMEOUT_SECONDS = 5
_DELAY_BETWEEN_REQUESTS_SECONDS = 0.1

# Above this many active applications, ask before fetching — below it,
# just proceed (same "never block automation for a small, ordinary run"
# philosophy as js_analyzer.py).
_CONFIRM_THRESHOLD = 20


def _default_confirm(count):
    answer = input(
        f"\n[?] About to check {count} active application(s) for an OAuth/OIDC "
        f"discovery document (.well-known/openid-configuration) — this sends "
        f"new requests beyond what ShadowSaaS collected. Continue? [y/N] "
    )
    return answer.strip().lower() == "y"


def _save_path_for(output_dir, host):
    """
    Deterministic, filesystem-safe path to save one host's OIDC discovery
    document at — a hash of the hostname, not the hostname itself, for
    the same reason as js_analyzer.py's _save_path_for(): consistent
    naming, safe characters, and fetching the same host again overwrites
    the same file rather than accumulating duplicates.
    """
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
    return os.path.join(output_dir, f"{digest}.json")


def _write_manifest(output_dir, manifest_entries):
    """
    manifest.json maps each saved file back to the host and URL it came
    from, plus its issuer — same purpose as js_analyzer.py's manifest:
    the hash-named files alone would be meaningless as evidence without it.
    """
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest_entries, fh, indent=2)
    return manifest_path


def analyze_oauth_discovery(import_result, finding_id_start=1, confirm_fn=None, output_dir=None):
    """
    Fetch /.well-known/openid-configuration from every active application
    and correlate its content against suspicious target hostnames.
    Returns a list of TrustLeak findings.

    confirm_fn: optional callable(count) -> bool, asked before fetching
    when the number of active applications exceeds _CONFIRM_THRESHOLD.
    Defaults to an interactive input() prompt; tests pass a stub to
    avoid blocking, and to avoid making real network requests.

    output_dir: optional directory to save every VALID OIDC discovery
    document found (one with an "issuer" field — see the RFC 8414 check
    below), not just the ones that produced a finding, plus a
    manifest.json mapping each saved file back to its host/URL/issuer —
    evidence for the engagement, same philosophy as js_analyzer.py's
    output_dir. A 404 or non-OIDC JSON response is never saved — there's
    nothing there worth keeping. Created if it doesn't already exist.
    When None (the default), nothing is written to disk.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious

    if not suspicious_targets:
        return findings

    active_hosts = [a["hostname"] for a in import_result.active]
    if not active_hosts:
        return findings

    if len(active_hosts) > _CONFIRM_THRESHOLD:
        ask = confirm_fn if confirm_fn else _default_confirm
        if not ask(len(active_hosts)):
            return findings

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    manifest_entries = {}

    category = categories.category_for("oauth_discovery_reference")
    potential_impact = categories.default_impact_for(category)

    total = len(active_hosts)
    for i, host in enumerate(active_hosts, start=1):
        url = f"https://{host}/.well-known/openid-configuration"
        print(f"[*] [{i}/{total}] Checking {url}")

        try:
            response = requests.get(url, timeout=_REQUEST_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            print(f"[!] [{i}/{total}] Failed: {exc}")
            time.sleep(_DELAY_BETWEEN_REQUESTS_SECONDS)
            continue
        time.sleep(_DELAY_BETWEEN_REQUESTS_SECONDS)

        try:
            data = response.json()
        except ValueError:
            # Not an OIDC provider here — the overwhelmingly common case
            # for a regular web app (most of them 404 or return HTML on
            # this path), not a failure worth flagging.
            continue

        if not isinstance(data, dict) or "issuer" not in data:
            # Valid JSON, but doesn't look like a real OIDC discovery
            # document — the spec (RFC 8414) requires "issuer". Some
            # unrelated API could coincidentally return JSON on this
            # exact path; without this check, that would look identical
            # in the final output to "nothing here", hiding the
            # difference between the two.
            continue

        # Distinguishes, in the console, "a real identity provider lives
        # here" from "nothing responded" — without this, both cases look
        # identical afterward if neither produces a finding, making a
        # clean "0 findings" result impossible to tell apart from a
        # scan that silently never actually found an OIDC provider.
        print(f"[+] [{i}/{total}] Valid OIDC document found (issuer: {data.get('issuer')})")

        if output_dir:
            save_path = _save_path_for(output_dir, host)
            with open(save_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            manifest_entries[os.path.basename(save_path)] = {
                "host": host,
                "url": url,
                "issuer": data.get("issuer"),
            }

        content_lower = json.dumps(data).lower()
        for target in suspicious_targets:
            if target["hostname"] not in content_lower:
                continue

            evidence_confidence = confidence_tiering.evidence_confidence_tier(
                target["confidence"] == "high",
                broad_wildcard=confidence_tiering.is_broad_wildcard(target["hostname"]),
            )

            findings.append(schema.build_finding(
                finding_id=f"TL-{finding_counter:04d}",
                source_hostname=host,
                target_hostname=target["hostname"],
                target_asset_status="potential_takeover",
                target_shadowsaas_confidence=target["confidence"],
                relationship_type="oauth_discovery_reference",
                relationship_status="potential_risk",
                evidence_source_url=url,
                evidence_header="OIDC discovery document (.well-known/openid-configuration)",
                evidence_matched_value=target["hostname"],
                evidence_collected_via="trustleak_active_request",
                evidence_confidence=evidence_confidence,
                potential_impact=potential_impact,
            ))
            finding_counter += 1

    if output_dir and manifest_entries:
        manifest_path = _write_manifest(output_dir, manifest_entries)
        print(f"[+] {len(manifest_entries)} OIDC document(s) saved to {output_dir} ({manifest_path})")

    return findings