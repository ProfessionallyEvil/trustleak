# Changelog

All notable changes to TrustLeak are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); project follows
[Semantic Versioning](https://semver.org/) once it reaches a public release
(pre-1.0 here, so breaking changes may still happen between 0.x versions).

## [0.4.0] - 2026-11-11 (unreleased — local development only)

### Added

- `js_analyzer.py` — TrustLeak's first ACTIVE-probe analyzer. Downloads
  a referenced `.js` file's own content (never fetched by ShadowSaaS)
  and correlates it against suspicious targets. Only runs when
  `correlate_all(allow_active=True)` is passed; registered in the new
  `_ACTIVE_ANALYZERS` entry in `correlate.py`.
- Automatic, zero-configuration scope check:
  `hostnames.shares_apex_with_any()` — a script reference is only
  fetched if it's a relative path (same host ShadowSaaS already
  contacted) or its absolute hostname shares an apex domain with some
  hostname already present in the scan. A generic third-party
  library/CDN host (jquery.com, googletagmanager.com, jsdelivr.net,
  etc.) is automatically excluded without a blocklist. A separate
  scope-file mechanism was considered and deliberately dropped — see
  NOTES.md.
- Request-volume confirmation: above `_CONFIRM_THRESHOLD` (20) in-scope,
  deduplicated `.js` URLs, asks before fetching; below it, proceeds
  automatically (same "never block automation for an ordinary run"
  philosophy as the rest of this project).
- New category `js_content_dependency` (default `potential_impact`:
  high) — deliberately ambiguous by design: without executing the
  script, there's no way to tell whether a matched reference is an
  execution-style dependency or a data-exfiltration-style one, so the
  worse case is assumed.
- `requirements.txt`: added `requests>=2.28.0` — TrustLeak's first
  runtime dependency beyond `jsonschema`, needed to actually send the
  new request this analyzer makes. Same library ShadowSaaS already uses.
- Schema v2: `relationship.type` enum gains `js_content_reference`;
  `relationship.category` enum gains `js_content_dependency`.
- `report.py`: relationship label and impact explanation for the new
  type; new "JS (active)" filter button (the only type starting with
  `js_`, so it needed its own prefix button rather than reusing an
  existing one).
- `correlate.py`: tests rewritten to verify active analyzers never run
  without `allow_active=True` regardless of what's registered (rather
  than asserting the registry stays empty, which was only ever true
  until this exact change).

## [0.3.0] - 2026-11-11 (unreleased — local development only)

### Added

- `html_analyzer.py`: two new passive relationship types,
  `html_oauth_redirect_uri_reference` and `html_saml_acs_reference` —
  correlate a `redirect_uri` or `AssertionConsumerServiceURL` string that
  already appears somewhere in a page's HTML (a login link's query
  string) against suspicious targets. Still purely passive: no new
  request is made, no `.well-known/openid-configuration` or SAML
  metadata document is fetched (that remains unbuilt active-probe work —
  see NOTES.md). `_extract_hostname()` now calls `unquote()` first, since
  these values are commonly percent-encoded as query-string parameters.
- `categories.py`: new category `authentication_dependency` (default
  `potential_impact`: high) — intercepting an OAuth authorization code or
  SAML assertion via a taken-over subdomain is a login-flow-interception
  risk, a mechanism distinct from every existing category.
- ShadowSaaS's `extract_relevant_body_refs()`: two new patterns,
  `oauth_redirect_uri` and `saml_acs_url`, matched anywhere in the page
  body text (not anchored to a specific HTML tag, since these can appear
  in a plain link's query string, an inline script, or a form field).
  Deliberately does NOT capture `SAMLRequest=` — that parameter is a
  base64-encoded XML blob, not a URL, so it carries no hostname to
  correlate.
- Schema v2: `relationship.type` enum gains the two new types;
  `relationship.category` enum gains `authentication_dependency`.
- `report.py`: relationship labels and an impact explanation for the two
  new types; the existing `html` relationship-prefix filter button
  already covers them (both new types start with `html_`).

### Fixed (same unreleased cycle)

- ShadowSaaS's `extract_relevant_body_refs()`: added a second
  `redirect_uri` pattern, `oauth_redirect_uri_js`
  (`redirecturi\s*[:=]\s*["']...["']`), alongside the original
  query-string one. Found on a real engagement: Okta's Sign-In Widget
  (and most OAuth JS SDKs) configure this as a camelCase JS object
  property/assignment (`redirectUri: '...'` or
  `config.redirectUri = "...";`), not the snake_case query-string
  parameter (`redirect_uri=...`) the original pattern looked for — a
  page using the widget produced zero findings despite a real,
  in-scope reference being present in the page text the whole time.
  Both patterns feed the same `html_oauth_redirect_uri_reference`
  relationship type in `html_analyzer.py`; the query-string pattern is
  kept since it's still the correct shape for a classic OAuth2
  authorization-request link.

## [0.2.0] - 2026-11-09 (unreleased — local development only)

### Added (post-schema-v2 follow-ups, same unreleased cycle)

- `report.py`: Evidence Confidence and Potential Impact badges now carry a
  hover tooltip (`title` attribute) explaining, in plain language
  reconstructed from the finding's own data, exactly which factors (target
  confidence, enforcement, wildcard breadth; relationship category)
  produced that specific tier — not a generic description of the tier
  word, so two findings sharing a label but differing in which factors
  applied show different, accurate explanations.

### Changed (same unreleased cycle)

- `report.py`: findings are now grouped by target asset (the dangling
  subdomain) instead of one flat table — each target gets a collapsible
  section listing the applications that reference it, matching the
  question a pentester actually asks ("if I take over this subdomain,
  what's affected?") instead of requiring a scan of a flat table for a
  repeated hostname. New "Affected Targets" stat card (how many suspicious
  targets actually have ≥1 referencing finding, vs. all suspicious
  targets ShadowSaaS flagged). Search now also matches the target
  hostname shown only in the group header, not repeated per row.

### Fixed (same unreleased cycle)

- `csp_analyzer.py`: `extract_csp_hostnames()` now deduplicates
  `(relationship_type, hostname)` pairs found within a single directive. A
  directive listing both the bare apex and its wildcard form together
  (e.g. `script-src example.com *.example.com ...`, a defensive pattern
  covering apex + subdomains explicitly) normalizes both tokens to the
  same cleaned hostname; without dedup this silently produced two
  identical-looking findings for one real trust relationship. Confirmed
  this specific token pattern does not occur in the brightretail.example
  policy investigated during this session — what looked like a duplicate
  there was in fact two distinct, correct findings (same source
  application, same relationship type, but two *different* confirmed
  takeover targets both matched by the same company-wide wildcard). The
  dedup fix itself is still a genuine correctness fix for the general
  case; it just wasn't the explanation for that particular observation.
- `run_trustleak.py`: added `_ensure_trustleak_importable()`, mirroring
  `shadow_saas_surface.py`'s `_locate_trustleak()`. Running the script
  directly from inside a "flat" package layout — where `run_trustleak.py`
  sits alongside `__init__.py` in the same folder, rather than one level
  above a nested `trustleak/` folder — previously raised
  `ModuleNotFoundError: No module named 'trustleak'`, since Python's
  default `sys.path` only covers the nested-layout case.

### Changed — breaking

- **Schema v2.** The flat top-level `confidence` field is replaced by
  `relationship.category` plus `assessment.{evidence_confidence,
  potential_impact, validation_status}`. Motivated by a design review that
  identified `confidence` was secretly conflating two unrelated questions:
  *how sure are we this evidence applies* (driven by enforcement/specificity)
  vs. *how bad would this be if exploited* (driven by the kind of
  relationship). No v1 compatibility shim is provided — this is a clean
  break, not an additive change; `schema_version` moves from `"1.0"` to
  `"2.0"` specifically so a v1 consumer rejects a v2 finding loudly instead
  of silently misreading a missing field. See
  `trustleak-schema-v2-design.md` for the full design rationale and the
  five open questions it resolved before implementation started.
- `confidence.py`: `base_tier()`/`tier_to_confidence()` replaced by a single
  `evidence_confidence_tier()` — the `high_impact_signal` input is gone,
  since impact is no longer part of confidence at all.
- `csp_analyzer.py`: `worker-src` is now its own relationship type
  (`csp_worker_src`, category `execution_dependency`) instead of falling
  into the `csp_other_directive` catch-all — a worker can execute code,
  unlike `font-src`/`img-src`/etc., which stay in `csp_other_directive`.
  `csp_default_src` now maps to its own category, `fallback_dependency`,
  rather than `execution_dependency` — provisional pending real-world data
  on how it actually behaves.
- `report.py`: the single confidence badge/column is now two
  (Evidence Confidence, Potential Impact); the "High Confidence" stat card
  is now "High Confidence + Impact" and only counts findings where both
  dimensions are `"high"`; the high-confidence filter button does the same.

### Added

- `categories.py` — the single source of truth mapping each
  `relationship.type` to its `relationship.category`, and each category to
  its default `potential_impact`. `schema.py`'s `validate_finding()` uses
  this same mapping to reject a finding whose `type`/`category` pair
  disagrees, catching the kind of mismatch a future analyzer could
  introduce (Option C from the design doc: enforced in Python against one
  dict, rather than via parallel `if`/`then` blocks in the JSON Schema).
- `schemas/trustleak-finding-v2.schema.json` — the v2 contract. The v1
  schema file is kept, unmodified, for reference.

## [0.1.0] - 2026-11-04 (unreleased — local development only)

### Added
- `trustleak-finding-v1.schema.json` — the finding contract, with
  `schema_version`, provenance tracking (`evidence.collected_via`), and a
  deliberately restricted `relationship.status` vocabulary (`observed` /
  `potential_risk` / `validated` — never `confirmed`, which is reserved
  for a human-reviewed report finding, not an automated correlation).
- `shadowsaas-output-v1.schema.json` — formal contract for ShadowSaaS's
  own output, so a future ShadowSaaS change that breaks this shape is
  caught at import time.
- `importer.py` — loads and classifies ShadowSaaS output into
  `suspicious` / `active` / `inconclusive` buckets. A malformed record is
  skipped (recorded in `ImportResult.skipped`), never aborts the whole
  import. `speculative`-confidence takeover candidates are excluded from
  `suspicious` — a `--speculative` wordlist guess isn't a target worth
  correlating against yet.
- `hostnames.py` — shared hostname cleanup/matching, extracted before CSP
  and CORS duplicated the same logic.
- `csp_analyzer.py` — correlates CSP/CSP-Report-Only directives on
  `active` assets against `suspicious` targets.
- `cors_analyzer.py` — static-only CORS correlation (reads
  `Access-Control-Allow-Origin` already captured by ShadowSaaS's probe;
  does not send a forged `Origin` header — see [NOTES.md](NOTES.md)).
- `cookie_analyzer.py` — correlates `Set-Cookie` `Domain=` scope against
  suspicious targets; distinguishes session/auth-like cookie names from
  tracking cookies for confidence purposes.
- `confidence.py` — shared confidence-tiering logic (`base_tier`,
  `is_broad_wildcard`, `tier_to_confidence`), extracted from the CSP
  analyzer before Cookie needed the same rules.
- `correlate.py` — `correlate_all()` runs every registered analyzer in
  order, threading `finding_id_start` so IDs never collide or restart
  mid-run.
- `state.py` — optional cross-run persistence (`--state FILE`): remaps
  each run's provisional finding_ids to stable, content-based ones, so
  the same underlying finding keeps the same ID across repeated scans of
  the same target instead of restarting at `TL-0001` every run.
- `report.py` — self-contained HTML report, matching ShadowSaaS's visual
  template (same dark theme, same filter/search toolbar pattern).
  Includes a filter button per analyzer (CSP / CORS / Cookie).
- `run_trustleak.py` — runnable CLI entry point (`argparse`-based, same
  banner/description/epilog style as ShadowSaaS's CLI).

### Design decisions worth remembering
- **Confidence down-weighting**: a Content-Security-Policy-Report-Only
  match (enforces nothing) is capped at `medium`; a reference to a bare
  apex domain (e.g. `*.company.com`, matches every subdomain under that
  company by construction) is demoted one tier. Both were added after
  real scan data (not synthetic fixtures) showed nearly every match
  would otherwise have come out `high` regardless of actual specificity.
- **No analyzer makes a new network request.** The one planned exception
  (CORS origin-reflection testing) is intentionally unbuilt — see
  [NOTES.md](NOTES.md) for the three requirements that must exist first.
- **`evidence.source_url` is an approximation** (`https://{hostname}`),
  since ShadowSaaS doesn't record which scheme (`http`/`https`)
  ultimately answered. Usually correct (ShadowSaaS tries `https` first),
  not guaranteed.
