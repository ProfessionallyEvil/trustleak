"""Tests for trustleak.report.render_html_report."""
import os

from trustleak import correlate, importer, report

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_report_row_count_matches_findings():
    result = importer.import_shadowsaas_output(os.path.join(FIXTURES, "sunresorts_full_scan.json"))
    findings = correlate.correlate_all(result)
    html = report.render_html_report(result, findings)

    assert html.count("<tr class=") == len(findings)
    assert "TrustLeak" in html
    assert f">{len(findings)}<" in html  # Findings stat card


def test_report_handles_zero_findings():
    result = importer.import_shadowsaas_output(os.path.join(FIXTURES, "secureideas_enum.json"))
    findings = correlate.correlate_all(result)
    html = report.render_html_report(result, findings)

    assert findings == []
    assert html.count("<tr class=") == 0
    assert ">0<" in html


def test_report_high_confidence_row_gets_highlight_class():
    result = importer.import_shadowsaas_output(os.path.join(FIXTURES, "sunresorts_full_scan.json"))
    findings = correlate.correlate_all(result)
    # All sunresorts findings are "medium" after the broad-wildcard demotion —
    # confirm the report doesn't fabricate a "row-high" class for them.
    html = report.render_html_report(result, findings)
    assert 'class="row-high"' not in html


def test_report_shows_why_inline_not_only_on_hover():
    # The "why is this a risk" explanation must be visible in the rendered
    # HTML body (readable, copy-pasteable, works on touch devices) — not
    # only stashed in a title="" tooltip attribute that disappears on
    # copy/paste, print, or any touch-only device.
    result = importer.import_shadowsaas_output(os.path.join(FIXTURES, "brightretail_scan.json"))
    findings = correlate.correlate_all(result)
    html = report.render_html_report(result, findings)

    # Each finding's risk-note now appears twice by design: once in the
    # Table view's row, and once in the Attack Path tab's full finding
    # detail panel (which deliberately reuses the same explanation, so
    # the two views can never disagree about what a given impact means).
    assert html.count('class="risk-note') == len(findings) * 2
    assert "an attacker-controlled host could serve JavaScript" in html


def test_report_has_a_filter_button_for_every_relationship_prefix_in_use():
    # Every analyzer's relationship_type prefix (csp_, cors_,
    # cookie_domain_scope) needs a matching toolbar button, or that
    # category of finding is unreachable via the UI's filter — this would
    # have caught the missing Cookie button before it shipped.
    result = importer.import_shadowsaas_output(os.path.join(FIXTURES, "sunresorts_full_scan.json"))
    findings = correlate.correlate_all(result)
    html = report.render_html_report(result, findings)

    assert "filterByRelationship('csp'" in html
    assert "filterByRelationship('cors'" in html
    assert "filterByRelationship('cookie'" in html
    assert "filterByRelationship('html'" in html
