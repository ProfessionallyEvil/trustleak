"""
# ============================================================================
# FUTURE WORK NOTICE — read before extending this module
# ============================================================================
# This file only ever makes the ShadowSaaS-already-collected passive
# correlation below. A planned future feature — CORS origin-reflection
# testing (sending a forged Origin header to see if the server reflects it
# back) — is DELIBERATELY NOT implemented here. That feature sends new,
# active traffic against a target that may belong to a client, which is a
# different risk/authorization profile than "correlate what ShadowSaaS
# already observed passively." It must ship as its own explicitly opt-in
# feature, gated behind scope-authorization controls, never silently
# folded into analyze_cors() or correlate_all(). See the TrustLeak design
# conversation for the full reasoning. If you're adding that feature,
# start a new module (e.g. cors_active_probe.py), not this one.
# ============================================================================

TrustLeak — CORS Analyzer (static correlation only).

Correlates an already-observed Access-Control-Allow-Origin value on an
'active' asset against 'suspicious' ShadowSaaS targets. This is the
PASSIVE half of CORS analysis only: it reads whatever ACAO value
ShadowSaaS's own probe happened to receive from a plain GET (which sends
no Origin header) — it never sends a forged Origin to test for
reflection. That active reflection test is intentionally a separate,
explicitly opt-in feature (not built here), because it sends new traffic
against a target that may belong to a client — a different risk profile
than "correlate what we already observed during the ShadowSaaS scan."

Because of that constraint, this analyzer will find nothing on a server
that only sets ACAO when a request actually includes an Origin header
(the common case) — which is an honest, expected limitation, not a bug.
It still catches a server that unconditionally returns a fixed,
non-wildcard ACAO regardless of what the client sent, which does happen
in the wild (e.g. an internal API that always allows one specific
frontend origin).

A wildcard ("*") ACAO carries no hostname-specific signal — it isn't a
reference to any particular target, so it's skipped rather than matched.
"""
from trustleak import categories
from trustleak import confidence as confidence_tiering
from trustleak import schema
from trustleak.hostnames import clean_hostname, hostname_matches_target


def analyze_cors(import_result, finding_id_start=1):
    """
    Correlate every 'active' asset's Access-Control-Allow-Origin header
    against every 'suspicious' asset's hostname. Returns a list of
    validated TrustLeak findings (schema.build_finding validates each one).

    finding_id_start lets a caller running multiple analyzers in sequence
    keep finding_id values unique across the whole TrustLeak run — e.g.
    pass len(csp_findings) + 1 after running analyze_csp() first.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious

    if not suspicious_targets:
        return findings

    for source_asset in import_result.active:
        acao = source_asset["relevant_headers"].get("access-control-allow-origin")
        if not acao or acao.strip() == "*":
            continue

        acao_hostname = clean_hostname(acao.strip())

        for target in suspicious_targets:
            if not hostname_matches_target(acao_hostname, target["hostname"]):
                continue

            allows_credentials = (
                source_asset["relevant_headers"]
                .get("access-control-allow-credentials", "")
                .strip()
                .lower()
                == "true"
            )

            # evidence_confidence: purely about how certain/specific this
            # match is — same broad-wildcard demotion CSP applies, for
            # consistency (an ACAO value is always one exact origin, never
            # a CSP-style "*.company.com" wildcard, but it can still be
            # the bare apex itself).
            evidence_confidence = confidence_tiering.evidence_confidence_tier(
                target["confidence"] == "high",
                broad_wildcard=confidence_tiering.is_broad_wildcard(acao_hostname),
            )

            # potential_impact: credentials allowed alongside a
            # specific-origin allowlist means cookies/session tokens would
            # be readable cross-origin by whoever controls that origin —
            # escalates above cross_origin_trust's "medium" default (see
            # categories.py). A credential-less allowance only shares
            # non-sensitive response bodies, so it stays at the default.
            potential_impact = (
                "high" if allows_credentials
                else categories.default_impact_for("cross_origin_trust")
            )

            findings.append(schema.build_finding(
                finding_id=f"TL-{finding_counter:04d}",
                source_hostname=source_asset["hostname"],
                target_hostname=target["hostname"],
                target_asset_status="potential_takeover",
                target_shadowsaas_confidence=target["confidence"],
                relationship_type="cors_allowed_origin",
                relationship_status="potential_risk",
                evidence_source_url=f"https://{source_asset['hostname']}",
                evidence_header="Access-Control-Allow-Origin",
                evidence_matched_value=acao_hostname,
                evidence_collected_via="shadowsaas_probe",
                evidence_confidence=evidence_confidence,
                potential_impact=potential_impact,
            ))
            finding_counter += 1

    return findings
