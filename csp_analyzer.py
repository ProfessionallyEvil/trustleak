"""
TrustLeak — CSP Analyzer (M3).

Correlates CSP (and CSP-Report-Only) directives found on 'active' assets
against the hostnames of 'suspicious' assets (ShadowSaaS takeover
candidates that aren't --speculative guesses — see importer.classify_asset).

Deliberately does NOT make any new HTTP request: both sides of this
correlation come from data the importer already loaded from ShadowSaaS's
own http_probe() output (relevant_headers), per the whole point of
reusing that data instead of re-fetching every host.

A Report-Only policy is tracked separately via evidence.header, never
silently merged with an enforced policy — a report-only CSP describes
what the app's team is *monitoring*, not what the browser actually
blocks, and conflating the two would overstate how real the trust
relationship is.
"""
from trustleak import categories
from trustleak import confidence as confidence_tiering
from trustleak import schema
from trustleak.hostnames import clean_hostname as _clean_hostname
from trustleak.hostnames import hostname_matches_target as _hostname_matches_target

# Directives we look inside for a hostname reference. Each maps to its own
# relationship.type in the schema — never invent a type at correlation
# time, only ever pick from this table. worker-src is split out from the
# catch-all on purpose: unlike img-src/font-src/etc., a worker can execute
# code, so it belongs in execution_dependency, not resource_dependency
# (see categories.py).
_DIRECTIVE_TO_RELATIONSHIP = {
    "img-src": "csp_img_src",
    "script-src": "csp_script_src",
    "worker-src": "csp_worker_src",
    "connect-src": "csp_connect_src",
    "frame-src": "csp_frame_src",
    "default-src": "csp_default_src",
}

# CSP source-list keywords that are never a hostname. Checked case-sensitively
# per the CSP spec (keywords are always quoted, e.g. 'self').
_CSP_KEYWORDS = {
    "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
    "'unsafe-hashes'", "'wasm-unsafe-eval'", "data:", "blob:", "filesystem:",
    "mediastream:", "*",
}

def _is_hostname_token(token):
    if token in _CSP_KEYWORDS:
        return False
    if token.startswith(("'", '"')):
        return False  # any other quoted keyword we haven't enumerated
    return "." in token or token.startswith("*.")


def extract_csp_hostnames(csp_value):
    """
    Parse one CSP header value into a list of (relationship_type, hostname)
    tuples. Intentionally simple: a full CSP parser handles nonces,
    hashes, and scheme-source grammar we don't need here — we only need
    to find hostnames that could match a known target, not validate the
    policy.

    Deduplicated before returning: a single directive commonly lists both
    the bare apex and its wildcard form together (e.g. "script-src
    example.com *.example.com ...", a defensive pattern covering the root
    domain and its subdomains explicitly) — both normalize to the same
    cleaned hostname via _clean_hostname(), and without deduplication here
    analyze_csp() would create two identical-looking findings for what is
    really one trust relationship.
    """
    found = []
    seen = set()
    for directive_block in csp_value.split(";"):
        parts = directive_block.strip().split()
        if not parts:
            continue
        directive_name = parts[0].lower()
        relationship_type = _DIRECTIVE_TO_RELATIONSHIP.get(directive_name, "csp_other_directive")

        for token in parts[1:]:
            if _is_hostname_token(token):
                pair = (relationship_type, _clean_hostname(token))
                if pair not in seen:
                    seen.add(pair)
                    found.append(pair)

    return found


def analyze_csp(import_result, finding_id_start=1):
    """
    Correlate every 'active' asset's CSP headers against every 'suspicious'
    asset's hostname. Returns a list of validated TrustLeak findings
    (schema.build_finding already runs jsonschema validation on each one,
    so a malformed finding fails loudly here, not downstream in the
    Graph Analyzer).

    finding_id_start lets a caller running multiple analyzers in sequence
    keep finding_id values unique across the whole TrustLeak run.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious

    if not suspicious_targets:
        return findings

    for source_asset in import_result.active:
        for header_name in ("content-security-policy", "content-security-policy-report-only"):
            csp_value = source_asset["relevant_headers"].get(header_name)
            if not csp_value:
                continue
            report_only = header_name == "content-security-policy-report-only"

            for relationship_type, csp_hostname in extract_csp_hostnames(csp_value):
                broad_wildcard = confidence_tiering.is_broad_wildcard(csp_hostname)
                category = categories.category_for(relationship_type)

                for target in suspicious_targets:
                    if not _hostname_matches_target(csp_hostname, target["hostname"]):
                        continue

                    evidence_confidence = confidence_tiering.evidence_confidence_tier(
                        target["confidence"] == "high",
                        unenforced=report_only,
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
                        evidence_header=(
                            "Content-Security-Policy"
                            if header_name == "content-security-policy"
                            else "Content-Security-Policy-Report-Only"
                        ),
                        evidence_directive=relationship_type.replace("csp_", "").replace("_", "-")
                        if relationship_type != "csp_other_directive" else None,
                        evidence_matched_value=csp_hostname,
                        evidence_collected_via="shadowsaas_probe",
                        evidence_confidence=evidence_confidence,
                        potential_impact=potential_impact,
                    ))
                    finding_counter += 1

    return findings
