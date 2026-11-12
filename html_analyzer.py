"""
TrustLeak — HTML Analyzer (M5, passive only).

Correlates iframe/script/form/OAuth/SAML references found in the HTML
body of 'active' assets against 'suspicious' ShadowSaaS targets. Purely
passive: reads relevant_body_refs, which ShadowSaaS's own http_probe()
already captured from the page it fetched anyway — no new HTTP request.

Two of the relationship types here deliberately reuse the SAME category
as their CSP counterparts, since they represent the identical underlying
risk mechanism, just a different kind of evidence for it (see
categories.py for the full reasoning):
  - html_script_reference -> execution_dependency (same as csp_script_src)
  - html_iframe_embed     -> framing_dependency   (same as csp_frame_src)
Two more are genuinely new categories:
  - html_form_action: navigation_dependency — submitting a form to a
    taken-over host is a phishing/credential-harvesting risk, not code
    execution or framing.
  - html_oauth_redirect_uri_reference / html_saml_acs_reference:
    authentication_dependency — a redirect_uri or
    AssertionConsumerServiceURL string that already appears in the page
    (a login link's query string), pointing at a target. If the dangling
    subdomain is where an identity provider would send an authorization
    code or SAML assertion, a takeover could let an attacker intercept a
    login flow.

# ============================================================================
# FUTURE WORK NOTICE — read before extending this module
# ============================================================================
# Active DISCOVERY of OAuth/SAML configuration (fetching
# /.well-known/openid-configuration, a SAML metadata XML document, etc.)
# is DELIBERATELY NOT implemented here — same reasoning as the CORS
# reflection-test notice in NOTES.md: that requires a new request to a
# path ShadowSaaS never visits during its own scan, a different
# risk/authorization profile than "correlate what was already fetched."
# This module only reads a redirect_uri/AssertionConsumerServiceURL
# string that ALREADY appears inside the HTML ShadowSaaS fetched — it
# never fetches a new URL to go looking for one. See NOTES.md for the
# four requirements active-probe features must meet before they get
# built.
# ============================================================================
"""
from urllib.parse import unquote, urlparse

from trustleak import categories
from trustleak import confidence as confidence_tiering
from trustleak import schema
from trustleak.hostnames import hostname_matches_target

# Maps a relevant_body_refs key (set by ShadowSaaS's
# extract_relevant_body_refs()) to its relationship.type and a readable
# evidence label. Add a new pattern here only after ShadowSaaS itself
# captures it — this module never invents a reference kind on its own.
_REF_TYPE_TO_RELATIONSHIP = {
    "iframe_src": "html_iframe_embed",
    "script_src": "html_script_reference",
    "form_action": "html_form_action",
    "oauth_redirect_uri": "html_oauth_redirect_uri_reference",
    "oauth_redirect_uri_js": "html_oauth_redirect_uri_reference",
    "saml_acs_url": "html_saml_acs_reference",
}

_REF_TYPE_TO_EVIDENCE_LABEL = {
    "iframe_src": "HTML <iframe src>",
    "script_src": "HTML <script src>",
    "form_action": "HTML <form action>",
    "oauth_redirect_uri": "OAuth redirect_uri (query-string reference)",
    "oauth_redirect_uri_js": "OAuth redirectUri (JS config reference)",
    "saml_acs_url": "SAML AssertionConsumerServiceURL (page reference)",
}


def _extract_hostname(ref):
    """
    Pull a hostname out of a raw href/src/action/redirect_uri/ACS value,
    or None if it has no host component — a same-origin relative path
    (e.g. "/app.js") carries no cross-host trust signal to correlate.

    unquote() handles the common case where a redirect_uri or ACS URL is
    percent-encoded as a query-string parameter value (e.g.
    "https%3A%2F%2Fblog.empresa.com%2Fcallback") — a no-op on values that
    aren't encoded, like a plain iframe/script src.
    """
    ref = ref.strip()
    if not ref:
        return None
    ref = unquote(ref)
    if ref.startswith("//"):
        ref = "https:" + ref  # protocol-relative URL
    return urlparse(ref).hostname


def analyze_html(import_result, finding_id_start=1):
    """
    Correlate every 'active' asset's iframe/script/form references
    against every 'suspicious' asset's hostname. Returns a list of
    validated TrustLeak findings.

    finding_id_start lets a caller running multiple analyzers in sequence
    keep finding_id values unique across the whole TrustLeak run.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious

    if not suspicious_targets:
        return findings

    for source_asset in import_result.active:
        body_refs = source_asset.get("relevant_body_refs") or {}

        for ref_type, refs in body_refs.items():
            relationship_type = _REF_TYPE_TO_RELATIONSHIP.get(ref_type)
            if not relationship_type:
                continue  # a ref kind ShadowSaaS captures that this module doesn't map yet
            category = categories.category_for(relationship_type)
            evidence_header = _REF_TYPE_TO_EVIDENCE_LABEL[ref_type]

            for ref in refs:
                hostname = _extract_hostname(ref)
                if not hostname:
                    continue
                broad_wildcard = confidence_tiering.is_broad_wildcard(hostname)

                for target in suspicious_targets:
                    if not hostname_matches_target(hostname, target["hostname"]):
                        continue

                    evidence_confidence = confidence_tiering.evidence_confidence_tier(
                        target["confidence"] == "high",
                        broad_wildcard=broad_wildcard,
                    )
                    potential_impact = categories.default_impact_for(category)

                    findings.append(schema.build_finding(
                        finding_id=f"TL-{finding_counter:04d}",
                        source_hostname=source_asset["hostname"],
                        target_hostname=target["hostname"],
                        target_asset_status="potential_takeover",
                        target_shadowsaas_confidence=target["confidence"],
                        relationship_type=relationship_type,
                        relationship_status="potential_risk",
                        evidence_source_url=f"https://{source_asset['hostname']}",
                        evidence_header=evidence_header,
                        evidence_matched_value=hostname,
                        evidence_collected_via="shadowsaas_probe",
                        evidence_confidence=evidence_confidence,
                        potential_impact=potential_impact,
                    ))
                    finding_counter += 1

    return findings
