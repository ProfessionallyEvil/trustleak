"""
TrustLeak — shared evidence-confidence tiering.

Schema v2 split what used to be a single "confidence" field into two
independent dimensions (see trustleak-schema-v2-design.md): this module
now computes ONLY evidence_confidence — how sure we are the evidence is
real and applies to this exact target. potential_impact (how bad it would
be if exploited) is a separate, mostly-static lookup by category — see
categories.py — and does not belong in this tiering at all.

v1 had a `high_impact_signal` input here that mixed the two dimensions
together; it's gone. A directive being "high impact" is a statement about
severity, not about how certain the evidence is.
"""

_TIERS = {2: "high", 1: "medium", 0: "low"}


def is_broad_wildcard(hostname):
    """
    True if `hostname` looks like a bare apex/root domain (<=2 labels,
    e.g. "company.com") rather than a specific subdomain reference (e.g.
    "cetus.company.com"). A bare apex reference matches every subdomain
    under that company's domain by construction — it says "this trusts
    our own company," not anything specific about one particular target.

    Imperfect for multi-part public suffixes (e.g. "company.co.uk" has 3
    labels but is still an apex) — acceptable for now since every
    confirmed target in this codebase uses a simple .com apex. Revisit
    with a public-suffix-list lookup if that stops being true.
    """
    return hostname.count(".") <= 1


def evidence_confidence_tier(target_confidence_is_high, *, unenforced=False, broad_wildcard=False):
    """
    Return evidence_confidence ('high' / 'medium' / 'low') from three
    specificity factors only — never from what kind of relationship this
    is:

    - target_confidence_is_high: ShadowSaaS's own confidence in the
      target being a real takeover candidate. Tier starts at 2 (high)
      only when this is true; otherwise 1 (medium) — a finding never
      starts at tier 0 from this alone.
    - unenforced: the policy/header doesn't actually restrict or grant
      anything right now (e.g. Content-Security-Policy-Report-Only,
      which is telemetry a team is testing, not an enforced rule). Caps
      the tier at medium regardless of anything else.
    - broad_wildcard: see is_broad_wildcard(). Demotes the tier by one
      step, since the reference isn't specific to this one target.

    Both down-weights can apply at once (a Report-Only policy referencing
    a bare apex domain), in which case they stack: capped to medium, then
    demoted again to low.
    """
    tier = 2 if target_confidence_is_high else 1
    if unenforced:
        tier = min(tier, 1)
    if broad_wildcard:
        tier = max(tier - 1, 0)
    return _TIERS[tier]
