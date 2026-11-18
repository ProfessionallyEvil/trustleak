"""
TrustLeak — HTML report generator.

Deliberately mirrors shadow_saas_surface.py's _render_html_report(): same
dark theme, same CSS tokens, same toolbar/filter/search pattern — so a
reader already familiar with a ShadowSaaS report recognizes this one
immediately. Only the table columns and filters change, to match what a
TrustLeak finding actually carries (source -> target relationship,
confidence, evidence) instead of a single subdomain's takeover verdict.
"""
import re

from trustleak import __version__

_RELATIONSHIP_LABELS = {
    "csp_img_src": "CSP img-src",
    "csp_script_src": "CSP script-src",
    "csp_worker_src": "CSP worker-src",
    "csp_connect_src": "CSP connect-src",
    "csp_frame_src": "CSP frame-src",
    "csp_default_src": "CSP default-src",
    "csp_other_directive": "CSP (other)",
    "cors_allowed_origin": "CORS allowed origin",
    "cookie_domain_scope": "Cookie domain scope",
    "html_iframe_embed": "HTML iframe",
    "html_script_reference": "HTML script",
    "html_form_action": "HTML form action",
    "html_oauth_redirect_uri_reference": "OAuth redirect_uri",
    "html_saml_acs_reference": "SAML ACS URL",
    "js_content_reference": "JS file content (active)",
    "oauth_discovery_reference": "OAuth discovery (.well-known, active)",
    # Reserved for a future, not-yet-implemented active-discovery
    # analyzer — see html_analyzer.py's FUTURE WORK notice and NOTES.md.
    "oauth_redirect_uri": "OAuth redirect URI",
    "saml_acs_endpoint": "SAML ACS endpoint",
}

_STATUS_LABELS = {
    "observed": "Observed",
    "potential_risk": "Potential risk",
    "validated": "Validated",
}


def _badge(css_class, label):
    return f'<span class="cf-badge {css_class}">{label}</span>'


_TIER_CLASSES = {
    "high": "cf-badge-high",
    "medium": "cf-badge-medium",
    "low": "cf-badge-low",
}


def _collection_badge(is_active):
    """
    Visible PASSIVE/ACTIVE marker next to "Collected via" — not just text,
    so the distinction NOTES.md requires (never silently mixing passive
    and active evidence) is obvious at a glance in the report, not only
    inspectable by reading the raw JSON's evidence.collected_via field.
    """
    if is_active:
        return '<span class="cf-badge cf-badge-high" title="This evidence came from a new request TrustLeak sent itself, not data ShadowSaaS already collected.">ACTIVE</span>'
    return '<span class="cf-badge cf-badge-low" title="This evidence is data ShadowSaaS already collected during its own passive scan — TrustLeak sent no new request.">PASSIVE</span>'


def _tier_badge(value, prefix="", explanation=None):
    title_attr = f' title="{explanation}"' if explanation else ""
    css_class = _TIER_CLASSES.get(value, "cf-badge-low")
    return f'<span class="cf-badge {css_class}"{title_attr}>{prefix}{value.upper()}</span>'


# Fixed, per-category explanation of what potential_impact is actually
# about — paired at render time with the specific relationship.category,
# so the badge's hover text says something concrete rather than just
# repeating the tier word.
_CATEGORY_IMPACT_EXPLANATIONS = {
    "execution_dependency": "If this subdomain is taken over, an attacker-controlled host could serve JavaScript that executes in this application's origin.",
    "data_exfiltration_dependency": "If this subdomain is taken over, this application could send requests to (or receive data from) an attacker-controlled host.",
    "cross_origin_trust": "If this subdomain is taken over, an attacker-controlled origin would be allowed to read this application's responses via CORS.",
    "shared_scope": "If this subdomain is taken over, it would sit within the same cookie Domain scope as this application.",
    "framing_dependency": "If this subdomain is taken over, an attacker-controlled host could be embedded in an iframe here (content/UI control, not DOM access — Same-Origin Policy still applies).",
    "resource_dependency": "If this subdomain is taken over, an attacker-controlled host could only serve passive resources here (images, fonts, styles, etc.) — no code execution.",
    "fallback_dependency": "Matched via a default-src fallback rather than a directive naming a specific resource type — actual risk depends on what the browser would request here.",
    "navigation_dependency": "If this subdomain is taken over, this application's form submissions here would go to an attacker-controlled host — a phishing/credential-harvesting risk, not code execution.",
    "authentication_dependency": "If this subdomain is taken over, an attacker could potentially intercept an OAuth authorization code or SAML assertion meant for this application's login flow.",
    "js_content_dependency": "If this subdomain is taken over, an attacker-controlled host is referenced inside this application's own JavaScript code — the exact mechanism (code execution vs. a data endpoint) depends on how the script uses that reference.",
}


def _explain_potential_impact(category):
    return _CATEGORY_IMPACT_EXPLANATIONS.get(category, "Impact depends on the specific relationship category.")


def _explain_evidence_confidence(finding):
    """
    Reconstruct, in plain language, exactly which of the factors in
    confidence.evidence_confidence_tier() applied to THIS finding, and the
    effect each one has on the tier — mirroring the real formula directly
    rather than crafting a narrative about it, so this can never claim a
    reason that didn't actually apply (or fail to mention one that did).
    Two findings sharing a tier label can have reached it via different
    combinations of these factors; this spells out which ones were live.
    """
    evidence = finding["evidence"]
    target = finding["target"]
    tier_label = finding["assessment"]["evidence_confidence"]
    header = evidence.get("header", "")
    matched_value = evidence.get("matched_value", "")
    shadowsaas_conf = target.get("shadowsaas_confidence", "—")

    target_confidence_is_high = shadowsaas_conf == "high"
    is_unenforced = "report-only" in header.lower()
    is_broad = matched_value.count(".") <= 1 if matched_value else False

    notes = []
    if not target_confidence_is_high:
        notes.append(f"ShadowSaaS's own confidence in this target is only '{shadowsaas_conf}', so this never starts above MEDIUM")
    if is_unenforced:
        notes.append("the policy is Report-Only (not enforced by the browser), which caps this at MEDIUM")
    if is_broad:
        notes.append(f"the matched reference ('{matched_value}') is a broad, company-wide wildcard, not specific to this target, which demotes this by one tier")

    if not notes:
        return "Confidence is HIGH: enforced policy, a specific (non-wildcard) reference, and a high-confidence ShadowSaaS target all agree."

    sentences = ". ".join(n[0].upper() + n[1:] for n in notes)
    return f"Confidence is {tier_label.upper()}. {sentences}."


def _status_badge(status):
    classes = {
        "observed": "cf-badge-low",
        "potential_risk": "cf-badge-medium",
        "validated": "cf-badge-high",
    }
    label = _STATUS_LABELS.get(status, status)
    return _badge(classes.get(status, "cf-badge-low"), label.upper())


def _evidence_summary(evidence):
    parts = []
    if evidence.get("header"):
        parts.append(evidence["header"])
    if evidence.get("directive"):
        parts.append(evidence["directive"])
    if evidence.get("matched_value"):
        parts.append(f"→ {evidence['matched_value']}")
    return " ".join(parts) or "—"


_TIER_ORDER = {"high": 0, "medium": 1, "low": 2}


def _finding_row(finding):
    """
    One row inside an asset group's table — no Target column, since the
    group's <summary> already names the target once for every row under it.
    """
    source = finding["source"]["hostname"]
    relationship_type = finding["relationship"]["type"]
    relationship_label = _RELATIONSHIP_LABELS.get(relationship_type, relationship_type)
    category = finding["relationship"]["category"]
    status = finding["relationship"]["status"]
    assessment = finding["assessment"]
    evidence_confidence = assessment["evidence_confidence"]
    potential_impact = assessment["potential_impact"]
    evidence = finding["evidence"]
    is_active = evidence.get("collected_via") == "trustleak_active_request"
    collection_source = "TrustLeak direct request" if is_active else "ShadowSaaS probe"

    row_cls = "row-high" if (evidence_confidence == "high" and potential_impact == "high") else ""

    return f"""
            <tr class="{row_cls}" data-confidence="{evidence_confidence}" data-impact="{potential_impact}" data-relationship="{relationship_type}" data-category="{category}" data-status="{status}">
              <td class="td-mono">{finding['finding_id']}</td>
              <td class="td-sub"><span class="subdomain">{source}</span></td>
              <td>{relationship_label}<br/><span class="td-dim">{category}</span></td>
              <td>{_status_badge(status)}</td>
              <td>{_tier_badge(evidence_confidence, explanation=_explain_evidence_confidence(finding))}</td>
              <td>{_tier_badge(potential_impact, explanation=_explain_potential_impact(category))}</td>
              <td class="td-mono">{_evidence_summary(evidence)}<br/><span class="risk-note risk-note-{potential_impact}">{_explain_potential_impact(category)}</span></td>
              <td>{_collection_badge(is_active)}<br/><span class="td-dim">{collection_source}</span></td>
            </tr>"""


def _asset_group(target_hostname, group_findings, open_by_default):
    """
    One collapsible section per 'potential takeover' target asset, per the
    design discussion: the question a pentester actually asks is "if I
    took over this subdomain, what would be affected?" — so the report is
    organized by target, with every referencing application nested inside,
    rather than one flat table repeating the target on every row.
    """
    first = group_findings[0]
    target_status = first["target"]["asset_status"]
    shadowsaas_conf = first["target"].get("shadowsaas_confidence", "—")
    affected_apps = len({f["source"]["hostname"] for f in group_findings})
    has_high_priority = any(
        f["assessment"]["evidence_confidence"] == "high" and f["assessment"]["potential_impact"] == "high"
        for f in group_findings
    )

    group_cls = "asset-group-high" if has_high_priority else ""
    open_attr = "open" if (open_by_default or has_high_priority) else ""
    rows_html = "\n".join(_finding_row(f) for f in group_findings)

    return f"""
    <details class="asset-group {group_cls}" {open_attr} data-target="{target_hostname}">
      <summary class="asset-summary">
        <span class="subdomain">{target_hostname}</span>
        <span class="asset-meta">{target_status} &middot; ShadowSaaS confidence: {shadowsaas_conf}</span>
        <span class="asset-count">{affected_apps} app(s) &middot; {len(group_findings)} finding(s)</span>
      </summary>
      <div class="asset-body">
        <table>
          <thead>
            <tr>
              <th>Finding ID</th>
              <th>Source</th>
              <th>Relationship</th>
              <th>Status</th>
              <th>Evidence Confidence</th>
              <th>Potential Impact</th>
              <th>Evidence</th>
              <th>Collected via</th>
            </tr>
          </thead>
          <tbody>
{rows_html}
          </tbody>
        </table>
      </div>
    </details>"""


def _safe_id(*parts):
    """A DOM-id-safe string built from arbitrary hostnames/relationship
    types — only word characters survive, everything else becomes '_'.
    Doesn't need to be reversible, only unique and stable for one render."""
    joined = "_".join(parts)
    return re.sub(r"[^a-zA-Z0-9_]", "_", joined)


def _finding_detail_panel(finding, back_to_bucket_id):
    """
    The deepest level of the Attack Path drill-down: one finding's full
    detail, reusing the exact same badge/explanation functions the Table
    view's rows use — so the two views can never disagree about what a
    confidence or impact badge means, since they're rendered by the same
    code. A "Back" link returns to the member list (bucket) this finding
    came from, which is always computable directly from the finding's own
    target+relationship_type (a finding belongs to exactly one bucket).
    """
    source = finding["source"]["hostname"]
    target = finding["target"]["hostname"]
    relationship_type = finding["relationship"]["type"]
    relationship_label = _RELATIONSHIP_LABELS.get(relationship_type, relationship_type)
    category = finding["relationship"]["category"]
    status = finding["relationship"]["status"]
    assessment = finding["assessment"]
    evidence_confidence = assessment["evidence_confidence"]
    potential_impact = assessment["potential_impact"]
    evidence = finding["evidence"]
    is_active = evidence.get("collected_via") == "trustleak_active_request"
    collection_source = "TrustLeak direct request" if is_active else "ShadowSaaS probe"
    panel_id = _safe_id("finding", finding["finding_id"])

    return f"""
    <div class="finding-detail-panel" id="{panel_id}">
      <a class="back-link" onclick="showPanel('{back_to_bucket_id}')">&larr; Back to {relationship_label}</a>
      <div class="detail-header">
        <span class="subdomain">{source}</span>
        <span class="detail-arrow">&#8594;</span>
        <span class="subdomain">{target}</span>
      </div>
      <div class="detail-id">{finding['finding_id']}</div>
      <div class="detail-badges">
        {_status_badge(status)}
        {_tier_badge(evidence_confidence, prefix="Confidence: ", explanation=_explain_evidence_confidence(finding))}
        {_tier_badge(potential_impact, prefix="Impact: ", explanation=_explain_potential_impact(category))}
        {_collection_badge(is_active)}
      </div>
      <div class="detail-section">
        <div class="detail-label">Relationship</div>
        <div>{relationship_label} <span class="td-dim">({category})</span></div>
      </div>
      <div class="detail-section">
        <div class="detail-label">Evidence</div>
        <div class="td-mono">{_evidence_summary(evidence)}</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">What this means if the subdomain is taken over</div>
        <div class="risk-note risk-note-{potential_impact}">{_explain_potential_impact(category)}</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">Collected via</div>
        <div>{collection_source}</div>
      </div>
    </div>"""


def _bucket_panel(bucket_id, target_hostname, rel_label, members_findings):
    """
    The member list shown when a relationship-type box is clicked — one
    row per application, each opening that application's full finding
    detail (never a graph explosion — just a plain, scrollable list).
    """
    rows = []
    for f in members_findings:
        source = f["source"]["hostname"]
        is_active = f["evidence"].get("collected_via") == "trustleak_active_request"
        finding_panel_id = _safe_id("finding", f["finding_id"])
        rows.append(f"""
          <div class="member-row" onclick="showPanel('{finding_panel_id}')">
            <span class="subdomain">{source}</span>
            {_collection_badge(is_active)}
          </div>""")
    rows_html = "\n".join(rows)

    return f"""
    <div class="bucket-panel" id="{bucket_id}">
      <div class="detail-breadcrumb">{target_hostname} &#8594; {rel_label} ({len(members_findings)})</div>
      <div class="member-list">
{rows_html}
      </div>
    </div>"""


def _target_card(target_hostname, group_findings):
    """
    One compact card per suspicious target: a header naming the asset,
    then one clickable row per relationship type present, each showing
    its label and a count badge. Validated (live-confirmed) relationship
    types are always pinned first and visually distinct — never buried
    behind a count, consistent with the Table view's "Validated Only"
    filter treating them as the strongest evidence tier.

    Returns (card_html, panels_html) — the card for the left column, and
    the HTML for every bucket-panel + finding-detail-panel this target's
    findings produce, destined for the shared detail pane on the right.
    """
    first = group_findings[0]
    target_status = first["target"]["asset_status"]
    shadowsaas_conf = first["target"].get("shadowsaas_confidence", "—")

    buckets = {}
    for f in group_findings:
        buckets.setdefault(f["relationship"]["type"], []).append(f)

    def _bucket_sort_key(rel_type):
        is_validated = buckets[rel_type][0]["relationship"]["status"] == "validated"
        return (0 if is_validated else 1, -len(buckets[rel_type]))

    bucket_rows = []
    panels = []
    for rel_type in sorted(buckets, key=_bucket_sort_key):
        members_findings = buckets[rel_type]
        rel_label = _RELATIONSHIP_LABELS.get(rel_type, rel_type)
        is_validated = members_findings[0]["relationship"]["status"] == "validated"
        bucket_id = _safe_id("bucket", target_hostname, rel_type)

        icon = '<span class="bucket-icon">&#10003;</span> ' if is_validated else ""
        row_cls = "bucket-row bucket-validated" if is_validated else "bucket-row"
        bucket_rows.append(f"""
          <div class="{row_cls}" onclick="showPanel('{bucket_id}')">
            <span class="bucket-label">{icon}{rel_label}</span>
            <span class="bucket-count">{len(members_findings)}</span>
          </div>""")

        panels.append(_bucket_panel(bucket_id, target_hostname, rel_label, members_findings))
        for f in members_findings:
            panels.append(_finding_detail_panel(f, bucket_id))

    rows_html = "\n".join(bucket_rows)
    card_html = f"""
    <div class="target-card">
      <svg class="path-connectors"></svg>
      <div class="target-node" onclick="showPanel('path-placeholder')" title="Back to overview">
        <span class="subdomain">{target_hostname}</span>
        <span class="asset-meta">{target_status}</span>
      </div>
      <div class="bucket-list">
{rows_html}
      </div>
    </div>"""
    return card_html, "\n".join(panels)


def render_html_report(import_result, findings):
    """
    Render a self-contained HTML report for one TrustLeak run: the asset
    classification summary from `import_result`, plus every finding
    `correlate.correlate_all()` (or an individual analyzer) produced,
    grouped by target asset (see _asset_group()'s docstring).
    """
    summary = import_result.summary()
    total_assets = summary["total_assets"]
    suspicious = summary["suspicious"]
    total_findings = len(findings)
    # "High priority" here means both dimensions agree — see
    # _finding_row()'s row_cls comment for why evidence_confidence alone
    # isn't the bar.
    high_priority = sum(
        1 for f in findings
        if f["assessment"]["evidence_confidence"] == "high" and f["assessment"]["potential_impact"] == "high"
    )

    groups = {}
    for f in findings:
        groups.setdefault(f["target"]["hostname"], []).append(f)

    def _group_sort_key(candidate_target):
        candidate_findings = groups[candidate_target]
        has_high = any(
            gf["assessment"]["evidence_confidence"] == "high" and gf["assessment"]["potential_impact"] == "high"
            for gf in candidate_findings
        )
        best_impact = min(_TIER_ORDER.get(gf["assessment"]["potential_impact"], 9) for gf in candidate_findings)
        return 0 if has_high else 1, best_impact, candidate_target

    sorted_targets = sorted(groups, key=_group_sort_key)
    affected_targets = len(sorted_targets)

    group_blocks = []
    for i, target_hostname in enumerate(sorted_targets):
        group_findings = sorted(
            groups[target_hostname],
            key=lambda f: (
                _TIER_ORDER.get(f["assessment"]["potential_impact"], 9),
                _TIER_ORDER.get(f["assessment"]["evidence_confidence"], 9),
                f["finding_id"],
            ),
        )
        group_blocks.append(_asset_group(target_hostname, group_findings, open_by_default=i == 0))
    groups_html = "\n".join(group_blocks)

    # Attack Path tab: one compact card per target (left column) plus a
    # shared detail pane (right column) holding every bucket's member list
    # and every finding's full detail, all pre-rendered and hidden except
    # whichever one showPanel() last activated -- see _target_card()'s
    # docstring for why this replaced an earlier force-directed-graph
    # design (it got unreadable past a handful of relationship types).
    target_cards = []
    detail_panels = []
    for target_hostname in sorted_targets:
        card_html, panels_html = _target_card(target_hostname, groups[target_hostname])
        target_cards.append(card_html)
        detail_panels.append(panels_html)
    target_cards_html = "\n".join(target_cards)
    detail_panels_html = "\n".join(detail_panels)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>TrustLeak Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Lato:wght@300;400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<style>
  :root {{
    --bg:        #031B26;
    --surface:   #01161E;
    --surface2:  #063348;
    --border:    #0a4a63;
    --teal:      #004E63;
    --teal-lt:   #006b87;
    --red:       #D32027;
    --red-dk:    #a81820;
    --text:      #cdd9e0;
    --text-dim:  #7a9aaa;
    --muted:     #3d6070;
    --takeover:  rgba(211,32,39,.08);
    --radius:    5px;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Lato', sans-serif;
    font-size: 13px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  a {{ color: var(--teal-lt); text-decoration: none; transition: color .15s; }}
  a:hover {{ color: #fff; }}

  .header {{
    background: linear-gradient(160deg, #020f18 0%, var(--teal) 100%);
    border-bottom: 3px solid var(--red);
    padding: 36px 48px 28px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: "";
    position: absolute; inset: 0;
    background:
      repeating-linear-gradient(0deg,transparent,transparent 39px,rgba(0,78,99,.15) 40px),
      repeating-linear-gradient(90deg,transparent,transparent 39px,rgba(0,78,99,.15) 40px);
    pointer-events: none;
  }}
  .header::after {{
    content: "";
    position: absolute;
    right: -60px; top: -60px;
    width: 320px; height: 320px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(211,32,39,.18) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-inner {{ position: relative; z-index: 1; }}
  .logo {{
    font-size: 11px;
    letter-spacing: .22em;
    text-transform: uppercase;
    color: rgba(255,255,255,.55);
    margin-bottom: 8px;
    font-family: 'Share Tech Mono', monospace;
  }}
  h1 {{
    font-family: 'Lato', sans-serif;
    font-size: 42px;
    font-weight: 900;
    color: #fff;
    letter-spacing: -1px;
    line-height: 1;
    text-transform: uppercase;
  }}
  h1 .red {{ color: var(--red); }}
  .subtitle {{
    font-size: 12px;
    color: rgba(255,255,255,.45);
    margin-top: 8px;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: .04em;
  }}
  .subtitle a {{
    color: rgba(255,255,255,.65);
    border-bottom: 1px solid rgba(255,255,255,.2);
    padding-bottom: 1px;
  }}
  .subtitle a:hover {{ color: #fff; border-color: #fff; }}

  .stats {{
    display: flex;
    gap: 16px;
    padding: 28px 48px;
    flex-wrap: wrap;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 22px 28px;
    min-width: 160px;
    flex: 1;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--border);
  }}
  .stat-card.teal::before  {{ background: var(--teal-lt); }}
  .stat-card.danger::before {{ background: var(--red); }}
  .stat-card.neutral::before {{ background: var(--muted); }}
  .stat-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .18em;
    color: var(--text-dim);
    font-weight: 700;
  }}
  .stat-value {{
    font-family: 'Lato', sans-serif;
    font-size: 54px;
    font-weight: 900;
    color: #fff;
    line-height: 1;
    margin-top: 6px;
    letter-spacing: -2px;
  }}
  .stat-card.teal   .stat-value {{ color: var(--teal-lt); }}
  .stat-card.danger .stat-value {{ color: var(--red); }}

  .view-tabs {{
    padding: 0 48px;
    display: flex;
    gap: 8px;
    border-bottom: 1px solid var(--border);
  }}
  .view-tab {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-bottom: none;
    color: var(--text-dim);
    padding: 10px 20px;
    cursor: pointer;
    font-weight: 700;
    font-family: 'Lato', sans-serif;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .06em;
    border-radius: var(--radius) var(--radius) 0 0;
  }}
  .view-tab.active {{
    background: var(--teal);
    color: #fff;
    border-color: var(--teal-lt);
  }}

  .toolbar {{
    padding: 0 48px 18px;
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
  }}
  .filter-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 6px 16px;
    border-radius: 20px;
    cursor: pointer;
    font-size: 11px;
    font-family: 'Lato', sans-serif;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    transition: all .15s;
  }}
  .filter-btn:hover {{
    border-color: var(--teal-lt);
    color: #fff;
  }}
  .filter-btn.active {{
    background: var(--teal);
    border-color: var(--teal-lt);
    color: #fff;
  }}
  .filter-btn.active-danger {{
    background: var(--red-dk);
    border-color: var(--red);
    color: #fff;
  }}
  #search {{
    margin-left: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 14px;
    border-radius: var(--radius);
    font-size: 12px;
    font-family: 'Lato', sans-serif;
    width: 240px;
    outline: none;
    transition: border .15s;
  }}
  #search:focus {{ border-color: var(--teal-lt); }}
  #search::placeholder {{ color: var(--muted); }}

  .table-wrap {{
    padding: 16px 48px 48px;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  thead tr {{
    background: var(--surface2);
    border-bottom: 2px solid var(--teal);
  }}
  th {{
    padding: 11px 12px;
    text-align: left;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .14em;
    color: var(--teal-lt);
    font-weight: 700;
    white-space: nowrap;
    font-family: 'Lato', sans-serif;
  }}
  td {{
    padding: 10px 12px;
    border-bottom: 1px solid rgba(10,74,99,.5);
    vertical-align: top;
  }}
  tr:hover td {{ background: rgba(0,78,99,.12); }}
  .row-high td {{ background: var(--takeover); }}
  .row-high:hover td {{ background: rgba(211,32,39,.14); }}

  .subdomain {{
    font-family: 'Share Tech Mono', monospace;
    color: #fff;
    font-size: 12px;
    word-break: break-all;
  }}
  .td-mono {{
    font-family: 'Share Tech Mono', monospace;
    color: var(--text-dim);
    font-size: 11px;
    word-break: break-all;
    max-width: 260px;
  }}
  .td-dim {{
    color: var(--muted);
    font-size: 10px;
  }}
  .risk-note {{
    display: block;
    margin-top: 4px;
    font-family: 'Lato', sans-serif;
    font-size: 11px;
    line-height: 1.4;
    white-space: normal;
    word-break: normal;
  }}
  .risk-note-high   {{ color: #f07070; }}
  .risk-note-medium {{ color: #e07b00; }}
  .risk-note-low    {{ color: var(--text-dim); }}

  .cf-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: .12em;
    font-family: 'Lato', sans-serif;
    text-transform: uppercase;
  }}
  .cf-badge-high   {{ background: rgba(211,32,39,.22);  color: #f07070; }}
  .cf-badge-medium {{ background: rgba(224,123,0,.18);  color: #e07b00; }}
  .cf-badge-low    {{ background: rgba(61,96,112,.35);  color: #7a9aaa; }}

  tr.hidden {{ display: none; }}

  .asset-group {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 12px;
    overflow: hidden;
  }}
  .asset-group.hidden {{ display: none; }}
  .asset-group[open] {{ border-color: var(--teal-lt); }}
  .asset-group-high {{ border-color: var(--red); }}
  .asset-summary {{
    list-style: none;
    cursor: pointer;
    padding: 14px 20px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    background: var(--surface2);
  }}
  .asset-summary::-webkit-details-marker {{ display: none; }}
  .asset-summary::before {{
    content: "▸";
    color: var(--teal-lt);
    font-size: 13px;
    display: inline-block;
    transition: transform .15s;
    flex-shrink: 0;
  }}
  .asset-group[open] .asset-summary::before {{ transform: rotate(90deg); }}
  .asset-meta {{ color: var(--text-dim); font-size: 11px; }}
  .asset-count {{ margin-left: auto; color: var(--text-dim); font-size: 11px; white-space: nowrap; }}
  .asset-body {{ padding: 8px 20px 4px; overflow-x: auto; }}
  .asset-body table {{ width: 100%; }}

  /* --- Attack Path: master-detail layout --- */
  .path-layout {{
    display: flex;
    gap: 20px;
    padding: 16px 48px 48px;
    align-items: flex-start;
  }}
  .path-targets {{
    display: flex;
    flex-direction: column;
    gap: 16px;
    width: 540px;
    flex-shrink: 0;
  }}
  .target-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    position: relative;
    display: flex;
    align-items: center;
    gap: 48px;
    padding: 24px;
  }}
  .path-connectors {{
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    overflow: visible;
  }}
  .target-node {{
    position: relative;
    flex-shrink: 0;
    width: 210px;
    background: rgba(211,32,39,.14);
    border: 1px solid var(--red);
    border-radius: 8px;
    padding: 14px 16px;
    cursor: pointer;
    transition: background .15s;
  }}
  .target-node:hover {{ background: rgba(211,32,39,.24); }}
  .target-node .subdomain {{ display: block; margin-bottom: 4px; font-size: 12px; line-height: 1.35; word-break: break-all; }}
  .target-node .asset-meta {{ font-size: 10.5px; }}
  .bucket-list {{
    position: relative;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}
  .bucket-row {{
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
    height: 42px;
    padding: 0 16px;
    border-radius: 6px;
    cursor: pointer;
    background: var(--surface2);
    border: 1px solid var(--border);
    transition: background .15s;
  }}
  .bucket-row:hover {{ background: rgba(0,78,99,.4); }}
  .bucket-row.bucket-validated {{
    background: rgba(211,32,39,.16);
    border-color: var(--red);
  }}
  .bucket-row.bucket-validated:hover {{ background: rgba(211,32,39,.26); }}
  .bucket-icon {{ color: #f07070; font-weight: 700; flex-shrink: 0; }}
  .bucket-label {{
    flex: 1;
    font-size: 12.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}
  .bucket-count {{
    background: var(--surface);
    color: var(--text-dim);
    font-size: 11px;
    font-weight: 700;
    padding: 2px 9px;
    border-radius: 10px;
    min-width: 22px;
    text-align: center;
  }}
  .bucket-row.bucket-validated .bucket-count {{ background: rgba(211,32,39,.3); color: #f07070; }}

  .path-detail {{
    flex: 1;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px;
    min-height: 440px;
  }}
  .path-detail > div {{ display: none; }}
  .path-detail > div.active-panel {{ display: block; }}
  .path-detail-placeholder {{
    color: var(--text-dim);
    font-size: 13px;
    padding: 60px 20px;
    text-align: center;
  }}
  .detail-breadcrumb {{
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-bottom: 18px;
    font-weight: 700;
  }}
  .member-list {{ display: flex; flex-direction: column; gap: 4px; max-height: 500px; overflow-y: auto; }}
  .member-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 14px;
    border-radius: 4px;
    cursor: pointer;
    border: 1px solid transparent;
    transition: all .15s;
  }}
  .member-row:hover {{ background: rgba(0,78,99,.25); border-color: var(--border); }}

  .back-link {{ display: inline-block; color: var(--teal-lt); cursor: pointer; font-size: 12px; margin-bottom: 20px; }}
  .back-link:hover {{ color: #fff; }}
  .detail-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 4px; flex-wrap: wrap; }}
  .detail-arrow {{ color: var(--muted); }}
  .detail-id {{ color: var(--muted); font-family: 'Share Tech Mono', monospace; font-size: 11px; margin-bottom: 18px; }}
  .detail-badges {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 22px; }}
  .detail-section {{ margin-bottom: 18px; }}
  .detail-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: .1em; color: var(--text-dim); font-weight: 700; margin-bottom: 5px; }}

  .footer {{
    text-align: center;
    padding: 24px 48px;
    font-size: 11px;
    color: var(--muted);
    font-family: 'Lato', sans-serif;
    letter-spacing: .04em;
    border-top: 1px solid var(--border);
  }}
  .footer a {{
    color: var(--text-dim);
    border-bottom: 1px solid var(--muted);
    padding-bottom: 1px;
  }}
  .footer a:hover {{ color: #fff; border-color: #fff; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">&#9632; Secure Ideas · Professionally Evil</div>
    <h1>Trust<span class="red">Leak</span></h1>
    <div class="subtitle">
      Trust Relationship Findings &nbsp;·&nbsp; v{__version__}
      &nbsp;·&nbsp;
      <a href="https://www.linkedin.com/in/jordan-bonagura" target="_blank" rel="noopener noreferrer">Jordan Bonagura</a>
      &nbsp;·&nbsp;
      <a href="https://www.secureideas.com" target="_blank" rel="noopener noreferrer">Secure Ideas - Professionally Evil</a>
    </div>
  </div>
</div>

<div class="stats">
  <div class="stat-card teal">
    <div class="stat-label">Assets Imported</div>
    <div class="stat-value">{total_assets}</div>
  </div>
  <div class="stat-card neutral">
    <div class="stat-label">Suspicious Targets</div>
    <div class="stat-value">{suspicious}</div>
  </div>
  <div class="stat-card neutral">
    <div class="stat-label">Affected Targets</div>
    <div class="stat-value">{affected_targets}</div>
  </div>
  <div class="stat-card danger">
    <div class="stat-label">Findings</div>
    <div class="stat-value">{total_findings}</div>
  </div>
  <div class="stat-card danger">
    <div class="stat-label">High Confidence + Impact</div>
    <div class="stat-value">{high_priority}</div>
  </div>
</div>

<div class="view-tabs">
  <button class="view-tab active" onclick="switchView('table', this)">Table</button>
  <button class="view-tab" onclick="switchView('path', this)">Attack Path</button>
</div>

<div id="view-table">
  <div class="toolbar">
    <button class="filter-btn active" onclick="filterRows('all',this)">All</button>
    <button class="filter-btn" onclick="filterRows('high',this)">&#9888; High confidence + impact</button>
    <button class="filter-btn" onclick="filterByRelationship('csp',this)">CSP</button>
    <button class="filter-btn" onclick="filterByRelationship('cors',this)">CORS</button>
    <button class="filter-btn" onclick="filterByRelationship('cookie',this)">Cookie</button>
    <button class="filter-btn" onclick="filterByRelationship('html',this)">HTML</button>
    <button class="filter-btn" onclick="filterByRelationship('js',this)">JS (active)</button>
    <button class="filter-btn" onclick="filterByRelationship('oauth_discovery',this)">OAuth Discovery (active)</button>
    <button class="filter-btn" onclick="filterByStatus('validated',this)">&#10003; Validated Only</button>
    <input id="search" type="text" placeholder="Search source / target…" oninput="searchRows(this.value)"/>
  </div>

  <div class="table-wrap">
    <div id="results-body">
{groups_html}
    </div>
  </div>
</div>

<div id="view-path" style="display:none">
  <div class="path-layout">
    <div class="path-targets">
{target_cards_html}
    </div>
    <div class="path-detail" id="path-detail">
      <div class="path-detail-placeholder active-panel" id="path-placeholder">Click a relationship type on the left to see which applications are affected.</div>
{detail_panels_html}
    </div>
  </div>
</div>

<div class="footer">
  Generated by TrustLeak v{__version__} &nbsp;&middot;&nbsp;
  <a href="https://www.linkedin.com/in/jordan-bonagura" target="_blank" rel="noopener noreferrer">Jordan Bonagura</a>
  &nbsp;&middot;&nbsp;
  <a href="https://www.secureideas.com" target="_blank" rel="noopener noreferrer">Secure Ideas - Professionally Evil</a>
</div>

<script>
  const groupEls = Array.from(document.querySelectorAll('.asset-group'));
  let currentFilter = 'all';
  let currentRelationshipFilter = null;
  let currentStatusFilter = null;
  let currentSearch = '';

  function applyFilters() {{
    const filterActive = currentFilter !== 'all' || !!currentRelationshipFilter || !!currentSearch;

    groupEls.forEach(group => {{
      const headerMatches = currentSearch && group.dataset.target.toLowerCase().includes(currentSearch);
      let anyVisible = false;

      Array.from(group.querySelectorAll('tbody tr')).forEach(r => {{
        const confidence = r.dataset.confidence;
        const impact = r.dataset.impact;
        const relationship = r.dataset.relationship;
        const status = r.dataset.status;
        const text = r.textContent.toLowerCase();

        let show = true;
        if (currentFilter === 'high' && !(confidence === 'high' && impact === 'high')) show = false;
        if (currentRelationshipFilter && !relationship.startsWith(currentRelationshipFilter)) show = false;
        if (currentStatusFilter && status !== currentStatusFilter) show = false;
        if (currentSearch && !headerMatches && !text.includes(currentSearch)) show = false;

        r.classList.toggle('hidden', !show);
        if (show) anyVisible = true;
      }});

      group.classList.toggle('hidden', !anyVisible);
      if (filterActive && anyVisible) {{
        group.open = true;
      }}
    }});
  }}

  function filterRows(type, btn) {{
    currentFilter = type;
    currentRelationshipFilter = null;
    currentStatusFilter = null;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active','active-danger'));
    btn.classList.add(type === 'high' ? 'active-danger' : 'active');
    applyFilters();
  }}

  function filterByRelationship(prefix, btn) {{
    currentFilter = 'all';
    currentRelationshipFilter = prefix;
    currentStatusFilter = null;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active','active-danger'));
    btn.classList.add('active');
    applyFilters();
  }}

  function filterByStatus(status, btn) {{
    currentFilter = 'all';
    currentRelationshipFilter = null;
    currentStatusFilter = status;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active','active-danger'));
    btn.classList.add('active');
    applyFilters();
  }}

  function searchRows(val) {{
    currentSearch = val.toLowerCase();
    applyFilters();
  }}

  function switchView(view, btn) {{
    document.querySelectorAll('.view-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('view-table').style.display = view === 'table' ? '' : 'none';
    document.getElementById('view-path').style.display = view === 'path' ? '' : 'none';
    if (view === 'path') {{
      drawPathConnectors();
    }}
  }}

  // Draws one real arrow per relationship-type box, from the target
  // header down to that box -- a ONE-TIME measurement-and-draw pass
  // using actual rendered positions (getBoundingClientRect), not a
  // physics/layout engine. Safe to call repeatedly (e.g. every time the
  // tab is opened): it just clears and redraws from scratch, and the
  // list never changes shape after the page loads, so nothing ever goes
  // stale. Only runs once the tab's container is actually visible --
  // measuring a display:none element would return a collapsed 0x0 rect.
  function drawPathConnectors() {{
    document.querySelectorAll('.target-card').forEach(card => {{
      const node = card.querySelector('.target-node');
      const rows = card.querySelectorAll('.bucket-row');
      const svg = card.querySelector('.path-connectors');
      if (!node || !rows.length || !svg) return;

      const cardRect = card.getBoundingClientRect();
      const nodeRect = node.getBoundingClientRect();
      // The arrowhead lands ON THE TARGET, not on the relationship box --
      // it's the referencing app/relationship that trusts the dangling
      // target, not the other way around (e.g. a CORS-reflecting app
      // trusts the target, the target doesn't trust it back). So the
      // line's (x1,y1) origin is each row, and (x2,y2) -- where
      // marker-end draws the arrowhead -- is the target node.
      const targetX = nodeRect.right - cardRect.left;
      const targetY = nodeRect.top - cardRect.top + nodeRect.height / 2;

      let linesHtml = (
        '<defs><marker id="path-arrow" viewBox="0 0 10 10" refX="8" refY="5" ' +
        'markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
        '<path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" ' +
        'stroke-linecap="round" stroke-linejoin="round"/></marker></defs>'
      );
      rows.forEach(row => {{
        const r = row.getBoundingClientRect();
        const rowX = r.left - cardRect.left;
        const rowY = r.top - cardRect.top + r.height / 2;
        const validated = row.classList.contains('bucket-validated');
        const colour = validated ? '#D32027' : '#5c7a8a';
        const width = validated ? 2.5 : 1.5;
        linesHtml += (
          '<line x1="' + rowX + '" y1="' + rowY + '" x2="' + targetX + '" y2="' + targetY + '" ' +
          'stroke="' + colour + '" stroke-width="' + width + '" marker-end="url(#path-arrow)"/>'
        );
      }});
      svg.innerHTML = linesHtml;
    }});
  }}

  // Attack Path drill-down: exactly one child of #path-detail is visible
  // at a time (the placeholder, a bucket's member list, or one finding's
  // full detail) -- no graph, no layout engine, just a simple panel swap.
  function showPanel(id) {{
    document.querySelectorAll('#path-detail > div').forEach(p => p.classList.remove('active-panel'));
    const el = document.getElementById(id);
    if (el) el.classList.add('active-panel');
  }}
</script>
</body>
</html>"""