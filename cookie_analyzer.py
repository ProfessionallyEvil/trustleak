"""
TrustLeak — Cookie Domain Scope Analyzer (static correlation only).

Correlates the Domain= attribute of a Set-Cookie header on an 'active'
asset against 'suspicious' ShadowSaaS targets. Purely passive — reads
whatever Set-Cookie value ShadowSaaS's own probe already received, same
as the CSP and CORS analyzers.

A cookie with NO Domain attribute is host-only (scoped to the exact
hostname that set it, never inherited by any subdomain) and carries no
cross-host trust signal at all — it's skipped, not treated as a weak
match. Only an explicit Domain= that happens to cover one of the
suspicious targets is a finding.

Multiple Set-Cookie headers collapsed into one comma-joined string (as
ShadowSaaS's extract_relevant_headers() produces, since Python's header
dict can only hold one value per key) are split back into individual
cookies before parsing — naively splitting on every comma would also
split inside an Expires date ("Wed, 04 Nov 2026 ..."), so the split only
triggers on a comma immediately followed by what looks like the start of
a new cookie ("name=value").
"""
import re

from trustleak import categories
from trustleak import confidence as confidence_tiering
from trustleak import schema
from trustleak.hostnames import hostname_matches_target

# Splits "cookieA=...; attrs..., cookieB=...; attrs..." back into separate
# cookie strings. Only splits on a comma followed by a bare name=value
# start — a comma inside "Wed, 04 Nov 2026" is never followed by "word=",
# so it's left alone.
_COOKIE_SPLIT = re.compile(r",\s*(?=[A-Za-z0-9_\-]+=)")

_DOMAIN_ATTR = re.compile(r"domain=([^;,\s]+)", re.IGNORECASE)
_SAMESITE_NONE = re.compile(r"samesite=none", re.IGNORECASE)

# Name substrings suggesting this cookie carries session/auth state, not
# just a preference or tracking value. Heuristic, not exhaustive — a
# cookie named something unusual that still carries a session is simply
# treated as the (safer) medium-impact default instead. Deliberately
# substring (not word-boundary) matching: real session cookies like
# PHPSESSID and JSESSIONID only contain "sid" as part of a longer word,
# with no separator to anchor a word-boundary match against.
_SESSION_LIKE_NAME_PARTS = ("session", "auth", "token", "sid", "jwt", "csrf", "xsrf", "login")

# Known cookie-name prefixes that would otherwise false-positive against
# _SESSION_LIKE_NAME_PARTS above purely by coincidence — confirmed on a
# real engagement: Incapsula/Imperva's "visid_incap_<id>" (a WAF/CDN
# visitor-tracking cookie, not an application session) contains "sid"
# only because "vi-SID-_incap" happens to spell it, not because it's
# session-like. Add another entry here only once a real false positive
# is confirmed — don't guess at vendor cookie names speculatively.
_KNOWN_NON_SESSION_PREFIXES = (
    "visid_incap_",
)


def split_set_cookie_header(value):
    """Split a (possibly multi-cookie) Set-Cookie header value into parts, one per cookie."""
    if not value:
        return []
    return [part.strip() for part in _COOKIE_SPLIT.split(value) if part.strip()]


def parse_cookie(cookie_str):
    """
    Parse one cookie string into (name, domain, is_session_like).
    `domain` is None when no Domain= attribute is present (host-only
    cookie) — cleaned of a leading '.' per RFC 6265's "domain-matching"
    rule, which treats ".example.com" and "example.com" identically.
    """
    name = cookie_str.split("=", 1)[0].strip()
    match = _DOMAIN_ATTR.search(cookie_str)
    domain = match.group(1).strip().lstrip(".").lower() if match else None
    name_lower = name.lower()
    if name_lower.startswith(_KNOWN_NON_SESSION_PREFIXES):
        is_session_like = False
    else:
        is_session_like = any(part in name_lower for part in _SESSION_LIKE_NAME_PARTS)
    return name, domain, is_session_like


def analyze_cookies(import_result, finding_id_start=1):
    """
    Correlate every 'active' asset's Set-Cookie Domain scope against every
    'suspicious' asset's hostname. Returns a list of validated TrustLeak
    findings.
    """
    findings = []
    finding_counter = finding_id_start
    suspicious_targets = import_result.suspicious

    if not suspicious_targets:
        return findings

    for source_asset in import_result.active:
        set_cookie = source_asset["relevant_headers"].get("set-cookie")
        if not set_cookie:
            continue

        for cookie_str in split_set_cookie_header(set_cookie):
            name, domain, is_session_like = parse_cookie(cookie_str)
            if not domain:
                continue  # host-only cookie — no cross-host signal to correlate

            for target in suspicious_targets:
                if not hostname_matches_target(domain, target["hostname"]):
                    continue

                # evidence_confidence: purely about certainty/specificity —
                # whether the Domain= value is a broad apex or a specific
                # subdomain, and how confident ShadowSaaS is in the target.
                evidence_confidence = confidence_tiering.evidence_confidence_tier(
                    target["confidence"] == "high",
                    broad_wildcard=confidence_tiering.is_broad_wildcard(domain),
                )

                # potential_impact: a session/auth-like cookie name escalates
                # above shared_scope's "low" default (see categories.py) —
                # if this scope were abused, session hijack/fixation is a
                # real risk. A tracking cookie (__cf_bm, etc.) stays low.
                potential_impact = (
                    "high" if is_session_like
                    else categories.default_impact_for("shared_scope")
                )

                findings.append(schema.build_finding(
                    finding_id=f"TL-{finding_counter:04d}",
                    source_hostname=source_asset["hostname"],
                    target_hostname=target["hostname"],
                    target_asset_status="potential_takeover",
                    target_shadowsaas_confidence=target["confidence"],
                    relationship_type="cookie_domain_scope",
                    relationship_status="potential_risk",
                    evidence_source_url=f"https://{source_asset['hostname']}",
                    evidence_header="Set-Cookie",
                    # The cookie's own name is what actually explains why
                    # this finding's potential_impact differs from another
                    # finding sharing the same source and Domain value — two
                    # cookies scoped to the same domain can have very
                    # different risk (a session cookie vs. a tracking one),
                    # and without the name visible, two such rows looked
                    # like an unexplained duplicate rather than two distinct,
                    # correctly-differentiated findings.
                    evidence_directive=name,
                    evidence_matched_value=domain,
                    evidence_collected_via="shadowsaas_probe",
                    evidence_confidence=evidence_confidence,
                    potential_impact=potential_impact,
                ))
                finding_counter += 1

    return findings
