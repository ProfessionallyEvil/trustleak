"""
TrustLeak — correlate_all().

Runs every available analyzer against one ImportResult and returns a
single, ordered list of findings with globally unique finding_id values.
This is the function anything outside TrustLeak (a CLI entry point, the
future Graph Analyzer) should call — individual analyzers stay importable
and testable on their own, but a caller wanting "everything TrustLeak
knows how to find" calls this one function instead of wiring the
finding_id handoff between analyzers itself.

Analyzer order here is the order finding_ids are assigned in, not a
priority order — nothing downstream should assume TL-0001 is more
important than TL-0050.

Passive and active analyzers are registered in two SEPARATE tuples on
purpose — see NOTES.md. _ACTIVE_ANALYZERS is empty today (no active-probe
analyzer exists yet); once one does, it only ever runs when a caller
explicitly passes allow_active=True, never by default.
"""
from trustleak import cookie_analyzer, cors_analyzer, csp_analyzer, html_analyzer, js_analyzer

# Each entry is (name, analyze_fn). Add a new PASSIVE analyzer here — and
# nowhere else — when one is written; correlate_all() doesn't need to
# change. An analyzer belongs here only if it makes zero new network
# requests — see NOTES.md for what qualifies as passive vs. active.
_PASSIVE_ANALYZERS = (
    ("csp", csp_analyzer.analyze_csp),
    ("cors", cors_analyzer.analyze_cors),
    ("cookie", cookie_analyzer.analyze_cookies),
    ("html", html_analyzer.analyze_html),
)

# Active-probe analyzers (see NOTES.md's four requirements). Adding an
# entry here is a real, considered step, never a side effect of writing
# the analyzer module itself — js_analyzer.py is the first.
_ACTIVE_ANALYZERS = (
    ("js_content", js_analyzer.analyze_js_content),
)


def correlate_all(import_result, allow_active=False):
    """
    Run every registered passive analyzer against import_result, in the
    order _PASSIVE_ANALYZERS lists them, threading finding_id_start
    through so IDs never collide or restart at TL-0001 partway through
    the run. Active-probe analyzers (_ACTIVE_ANALYZERS) only run when
    allow_active=True is passed explicitly — the default behavior never
    sends a new network request, regardless of what's registered there.

    Returns the combined, ordered list of findings.
    """
    analyzers = _PASSIVE_ANALYZERS + (_ACTIVE_ANALYZERS if allow_active else ())
    findings = []
    for _name, analyze_fn in analyzers:
        findings.extend(analyze_fn(import_result, finding_id_start=len(findings) + 1))
    return findings


def explain_empty(import_result, findings):
    """
    Return a one-line explanation of why `findings` is empty, or None if
    it isn't (nothing to explain). A bare "0 finding(s)" is easy to
    mistake for a tool that silently failed — this distinguishes the two
    genuinely different reasons it can happen:

    - No takeover candidates at all: there was nothing to correlate
      against in the first place. A clean result, not a weak one.
    - Takeover candidates exist, but no active application in this scan
      was found referencing them through CSP, CORS, cookie scope, or
      HTML (iframe/script/form). This can mean the dangling subdomain
      genuinely has no further blast radius — or that the reference
      exists through a mechanism TrustLeak doesn't look at yet (active
      OAuth/SAML discovery, or a referenced .js file's own content —
      see NOTES.md).
    """
    if findings:
        return None

    if not import_result.suspicious:
        return (
            "No takeover candidates in this scan, so there was nothing to "
            "correlate trust relationships against."
        )

    return (
        f"{len(import_result.suspicious)} takeover candidate(s) were found, "
        f"but no active application in this scan was found referencing them "
        f"via CSP, CORS, cookie scope, or HTML. This can mean the dangling "
        f"subdomain has no further blast radius through those paths — or "
        f"that the reference exists through something TrustLeak doesn't "
        f"look at yet (e.g. active OAuth/SAML discovery, or a referenced "
        f".js file's own content)."
    )
