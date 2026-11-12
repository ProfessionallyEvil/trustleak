"""
Shared hostname utilities for TrustLeak analyzers.

Extracted once a second analyzer (CORS) needed the exact same cleanup and
matching logic that csp_analyzer.py already had — keeping "what counts as
a hostname reference" and "does a reference cover this target" in one
place, so CSP and CORS can never quietly disagree on either question.
"""
import re

_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def clean_hostname(token):
    """Strip scheme, path, port, and a leading wildcard label (e.g. '*.')."""
    token = _SCHEME_PREFIX.sub("", token)
    token = token.split("/", 1)[0]
    token = token.split(":", 1)[0]
    if token.startswith("*."):
        token = token[2:]
    return token.lower()


def hostname_matches_target(reference_hostname, target_hostname):
    """
    True if reference_hostname points at target_hostname — either exactly,
    or target_hostname is a subdomain that a wildcard reference (already
    cleaned by clean_hostname) would cover.
    """
    reference_hostname = reference_hostname.lower()
    target_hostname = target_hostname.lower()
    return (
        reference_hostname == target_hostname
        or target_hostname.endswith("." + reference_hostname)
    )


def _apex(hostname):
    """Last two labels of a hostname (e.g. 'cdn.empresa.com' -> 'empresa.com')."""
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def shares_apex_with_any(hostname, known_hostnames):
    """
    True if hostname's apex domain matches the apex of at least one
    hostname in known_hostnames.

    Used as an automatic, zero-configuration scope check before an
    active-probe analyzer derives a NEW host to contact from scan data
    (e.g. an absolute script src URL found in a page) — not a substitute
    for authorization to test the engagement at all (that's the
    operator's responsibility, confirmed by passing
    --allow-active-probes explicitly), just a sanity check that the
    derived host is actually part of the same organization's
    infrastructure this scan already covers, rather than an unrelated
    third-party library/CDN host (jquery.com, googletagmanager.com,
    jsdelivr.net, etc.) that happened to be referenced on the page.

    Same multi-label-TLD simplification as is_broad_wildcard() in
    confidence.py — a hostname under e.g. "empresa.co.uk" technically has
    a 3-label apex, not 2, but every confirmed target in this codebase
    uses a simple .com apex. Revisit with a public-suffix-list lookup if
    that stops being true.
    """
    target_apex = _apex(hostname)
    return any(_apex(k) == target_apex for k in known_hostnames)
