"""
Tests against the two large real-world scans (sunresorts.example, 82 hosts /
4 confirmed Vercel takeovers; brightretail.example, 54 hosts / 2 confirmed
Heroku takeovers). Unlike the earlier fixtures, these produce real
positive CSP correlations — which is what motivated the confidence
down-weighting logic in _csp_finding_confidence(): a bare root-domain
wildcard (e.g. "*.company.com") matches every subdomain under that
company by construction, and Content-Security-Policy-Report-Only enforces
nothing. Both scans are dominated by exactly those two patterns, so
without the down-weighting every one of these would have come out "high".
"""
import os
from collections import Counter

from trustleak import csp_analyzer, importer

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _import(name):
    return importer.import_shadowsaas_output(os.path.join(FIXTURES, name))


def test_sunresorts_finds_wildcard_references_to_all_four_takeovers():
    result = _import("sunresorts_full_scan.json")
    findings = csp_analyzer.analyze_csp(result)

    assert len(findings) > 0
    targets_referenced = {f["target"]["hostname"] for f in findings}
    assert targets_referenced == {
        "preview.riviera-maya.sunresorts.example",
        "preview.tickets.sunresorts.example",
        "preview.nuevo-vallarta.sunresorts.example",
        "preview.booking.sunresorts.example",
    }


def test_sunresorts_root_wildcard_matches_are_demoted_from_high():
    # Every match here comes from "*.sunresorts.example" or "sunresorts.example"
    # — the bare apex, covering all four takeovers by construction. None of
    # it is enforced Content-Security-Policy-Report-Only, so the only
    # down-weight in play is the broad-wildcard one: tier 2 (target high,
    # enforced) demoted one step to "medium" evidence_confidence, same for
    # every finding here regardless of which directive matched.
    result = _import("sunresorts_full_scan.json")
    findings = csp_analyzer.analyze_csp(result)
    confidences = Counter(f["assessment"]["evidence_confidence"] for f in findings)

    assert confidences["high"] == 0
    assert confidences["medium"] == len(findings)
    assert all(f["evidence"]["matched_value"] == "sunresorts.example" for f in findings)
    assert all(f["evidence"]["header"] == "Content-Security-Policy" for f in findings)


def test_sunresorts_potential_impact_splits_by_directive_not_wildcard():
    # Unlike evidence_confidence (uniformly "medium" above), potential_impact
    # is unaffected by the broad-wildcard demotion — it only depends on
    # relationship.category. connect-src (data_exfiltration_dependency) and
    # frame-src (framing_dependency) genuinely differ in what a takeover
    # could do here, and schema v2 exists precisely so that distinction
    # doesn't get lost inside a single averaged confidence number.
    result = _import("sunresorts_full_scan.json")
    findings = csp_analyzer.analyze_csp(result)
    impacts = Counter(f["assessment"]["potential_impact"] for f in findings)
    types = Counter(f["relationship"]["type"] for f in findings)

    assert impacts["high"] == types["csp_connect_src"]
    assert impacts["medium"] == types["csp_frame_src"]
    assert impacts["low"] == 0
    assert set(types) == {"csp_connect_src", "csp_frame_src"}


def test_brightretail_report_only_plus_broad_wildcard_floors_to_low():
    # Almost everything here is Content-Security-Policy-Report-Only AND a
    # bare "*.brightretail.example" reference — both down-weights stack,
    # flooring tier 2 down to tier 0 ("low") evidence_confidence.
    result = _import("brightretail_scan.json")
    findings = csp_analyzer.analyze_csp(result)
    confidences = Counter(f["assessment"]["evidence_confidence"] for f in findings)

    assert confidences["high"] == 0
    assert confidences["low"] > confidences["medium"]
    low_findings = [f for f in findings if f["assessment"]["evidence_confidence"] == "low"]
    assert all(f["evidence"]["header"] == "Content-Security-Policy-Report-Only" for f in low_findings)
    assert all(f["evidence"]["matched_value"] == "brightretail.example" for f in low_findings)


def test_brightretail_potential_impact_still_varies_despite_uniform_low_confidence():
    # 96 of the 98 findings here share the exact same (low) evidence_confidence
    # — but they are NOT all equally bad if exploited. connect-src/script-src
    # matches are execution/data-exfiltration risks (high impact) even
    # though we're not very sure the Report-Only policy reflects reality;
    # the catch-all csp_other_directive matches (font-src, etc.) are
    # resource_dependency (low impact) regardless of confidence.
    result = _import("brightretail_scan.json")
    findings = csp_analyzer.analyze_csp(result)
    impacts = Counter(f["assessment"]["potential_impact"] for f in findings)

    assert impacts["medium"] == 0  # no framing_dependency/cross_origin_trust matches in this fixture
    assert impacts["high"] > 0
    assert impacts["low"] > 0
    other_directive_findings = [f for f in findings if f["relationship"]["type"] == "csp_other_directive"]
    assert all(f["assessment"]["potential_impact"] == "low" for f in other_directive_findings)


def test_brightretail_specific_cetus_wildcard_outranks_the_generic_one():
    # "*.cetus.brightretail.example" (from latency.cetus.brightretail.example's
    # CSPRO) is a narrower, more specific reference than the generic
    # "*.brightretail.example" noise. It only covers the "cetus" subtree, so
    # it correctly matches email-webhooks.cetus.brightretail.example and NOT
    # io.brightretail.example (a different subtree entirely) — and it should
    # survive as "medium" (only the Report-Only down-weight applies, not
    # the broad-wildcard one) rather than being floored to "low" like the
    # 96 generic "*.brightretail.example" matches.
    result = _import("brightretail_scan.json")
    findings = csp_analyzer.analyze_csp(result)

    cetus_specific = [f for f in findings if f["evidence"]["matched_value"] == "cetus.brightretail.example"]
    assert len(cetus_specific) == 2  # two directives (script-src, font-src->other) on the same target
    assert all(f["assessment"]["evidence_confidence"] == "medium" for f in cetus_specific)
    assert {f["target"]["hostname"] for f in cetus_specific} == {"email-webhooks.cetus.brightretail.example"}


def test_cors_still_finds_nothing_even_with_real_acao_headers_present():
    # Unlike the earlier small fixtures, both large scans DO have
    # Access-Control-Allow-Origin headers captured — but every single one
    # is "*", which carries no hostname-specific signal and is correctly
    # skipped (see cors_analyzer module docstring). This confirms that
    # behavior against real ACAO data, not just its absence.
    from trustleak import cors_analyzer

    for name in ("sunresorts_full_scan.json", "brightretail_scan.json"):
        result = _import(name)
        assert cors_analyzer.analyze_cors(result) == []
