# TrustLeak — design notes for future work

## Passive vs. active — the distinction this project is built around

A **passive** analyzer only correlates data ShadowSaaS already collected
during its own scan — it never sends a new network request. CSP, CORS
(static correlation), Cookie Domain Scope, and HTML are all passive.

An **active-probe** analyzer sends a new request to a path ShadowSaaS
never visits during its own scan — a fundamentally different
risk/authorization profile than "correlate what was already fetched".
Three of these are now built: JS content, OAuth/OIDC discovery, and CORS
origin-reflection (see their own sections below). A fourth candidate,
SAML metadata discovery, was considered and consciously declined — see
its own section.

Note: a `redirect_uri` or `AssertionConsumerServiceURL` string that
merely *appears* inside HTML already fetched is NOT active — that's
still passive, and is implemented in `html_analyzer.py`
(`html_oauth_redirect_uri_reference` / `html_saml_acs_reference`). Only
the deliberate act of fetching a *new* URL the ShadowSaaS scan never
visited counts as active.

## Requirements every active-probe feature satisfies

Agreed on when the project was scoped, and followed by all three built
active analyzers:

- Ships as its own module, registered separately from the passive
  analyzers in `correlate.py` (see `_PASSIVE_ANALYZERS` /
  `_ACTIVE_ANALYZERS`) — never silently pulled into a normal run.
- Explicitly opt-in — the person running TrustLeak must ask for it by
  name (`--allow-active-probes`), not get it as a side effect of a
  normal run.
- A host a new request is about to be sent to must share an apex domain
  with some hostname already present in the scan (see
  `hostnames.shares_apex_with_any()`) — an automatic, zero-configuration
  sanity check that a derived host (e.g. an absolute script src URL) is
  actually part of the engagement's own infrastructure, not a generic
  third-party library/CDN. This is NOT a substitute for the operator's
  own authorization to run active probes against the engagement at all
  — that's `--allow-active-probes` itself, backed by whatever
  authorization the client has already given for the engagement. A
  separate scope-file mechanism was considered and deliberately dropped:
  it would duplicate authorization the operator already has, for no
  real safety gain. (oauth_discovery_analyzer.py and
  cors_reflection_analyzer.py don't need this specific check — the host
  contacted is always one ShadowSaaS already confirmed active in the
  scan, never a derived one.)
- Evidence from an active probe is always tagged
  `evidence.collected_via = "trustleak_active_request"`, never mixed
  silently with passive evidence in the same bucket. The HTML report
  shows this distinction visibly (a PASSIVE/ACTIVE badge next to
  "Collected via"), not just in the raw JSON.
- Above a request-volume threshold (20, consistently across all three),
  ask the operator before sending the batch of requests. Below it,
  proceed automatically — never block routine use for a small, ordinary
  scan.

## js_analyzer.py — the first active-probe analyzer (built)

Downloads a referenced `.js` file's own content and correlates it
against suspicious targets, same principle as every passive analyzer,
applied to content that required a new request to obtain. Scope: only
URLs sharing an apex domain with the scan (or relative paths). Volume:
O(in-scope deduplicated script URLs). Saves fetched content with
`--js-output-dir` (auto-named by default) plus a `manifest.json`.

## oauth_discovery_analyzer.py — the second active-probe analyzer (built)

Fetches every active application's own `/.well-known/openid-configuration`
(RFC 8414 / OpenID Connect Discovery — a real, standard path) and
correlates its JSON content against suspicious targets. Volume: O(active
applications), not O(active × suspicious) — one fetch per host covers
every suspicious target at once. Requires the document to contain an
`issuer` field (per spec) before treating it as a real discovery
document, distinguishing "a real identity provider lives here, no
match" from "nothing responded" in the console. Saves every valid
document found (matching or not) with `--oidc-output-dir` (auto-named
by default) plus a `manifest.json`.

## cors_reflection_analyzer.py — the third active-probe analyzer (built)

For each (active, suspicious) **pair**, sends a forged `Origin` header
set to `https://<suspicious_hostname>` to the active host, and checks
whether the response's `Access-Control-Allow-Origin` reflects that exact
value back. Volume: O(active × suspicious) — the most expensive analyzer
here, since one request can only carry one Origin value (no way to
batch multiple targets the way oauth_discovery_analyzer.py does).

This is different in kind from every other analyzer: it **proves** live
server behavior rather than inferring a plausible match from static
data. A confirmed reflection gets `relationship.status = "validated"`
(not `"potential_risk"` like every other finding, passive or active) —
the schema reserved this value since v2 for exactly this case. Reuses
`cors_analyzer.py`'s own `relationship_type` (`cors_allowed_origin`) and
category (`cross_origin_trust`) rather than inventing new ones;
`evidence.collected_via` and `relationship.status` are what distinguish
an active-confirmed finding from a passive one, not a different
type/category. `potential_impact` is `"high"` when
`Access-Control-Allow-Credentials` is also `true`, `"medium"` otherwise
— the classic dangerous CORS misconfiguration combination.

Redirects are never followed (`allow_redirects=False`): following one
could send the crafted Origin header to an unintended third host
outside scope.

The HTML report has a dedicated "✓ Validated Only" filter
(`filterByStatus`), separate from the relationship-type filters, since
`cors_allowed_origin` shares its type with the passive CORS analyzer and
can't be isolated by type alone — this isolates any live-confirmed
finding regardless of which analyzer produced it.

Saves evidence for every CONFIRMED reflection only (a non-match produces
nothing worth keeping) with `--cors-output-dir` (auto-named by default)
plus a `manifest.json`.

## SAML metadata discovery — considered, declined (not deferred)

Unlike OIDC, there is no universal standard path for SAML SP/IdP
metadata (implementations vary — `/saml/metadata`,
`/simplesaml/module.php/saml/sp/metadata.php/...`,
`/Shibboleth.sso/Metadata`, and more). A blind probe would have to guess
among many non-standard paths, trading reliable coverage for a lot of
speculative, mostly-wasted requests, with a high false-negative rate
even when a SAML IdP genuinely exists at the host. This is a closed
decision, not a pending item — revisit only if a reliable, generic SAML
discovery mechanism is identified.

All four of the project's original active-probe candidates are now
resolved: three built (JS, OAuth/OIDC discovery, CORS reflection), one
consciously declined (SAML).

## Future active-probe candidates (not started, not scoped yet)

Two more active-probe ideas came up after CORS reflection was built —
recorded here so they aren't lost, but neither has a design doc yet and
neither is scheduled:

### OAuth redirect_uri acceptance test
Tests the OTHER side of what oauth_discovery_analyzer.py tests: instead
of asking "does the active host expose an OIDC discovery document?",
this would ask "does the real identity provider (Okta, Auth0,
Salesforce — already seen in live scans) accept a suspicious subdomain
as a valid redirect_uri?" For each suspicious target that already has a
passive oauth_redirect_uri reference (html_analyzer.py), start an OAuth
flow against the real IdP using that subdomain as redirect_uri and
inspect the response.

Harder than the three built analyzers because every provider's
rejection format differs (Okta/Auth0/Salesforce/Azure AD all respond
differently to an unauthorized redirect_uri), and some providers
redirect even on rejection (to an error page, not the redirect_uri
itself) — false-positive risk is real and provider-specific parsing
would be needed.

### postMessage origin-validation check
Reuses JS content js_analyzer.py already downloads (no new request) —
search it for `addEventListener("message", ...)` without a matching
`event.origin` check, when a passive iframe-embed reference
(html_iframe_embed) already ties the script's host to a suspicious
target. A classic vulnerability pattern when combined with iframe trust.

Harder than the three built analyzers because this is lightweight
static JS analysis, not a simple substring/header check — real risk of
both false positives (origin checked in a form the regex won't
recognize) and false negatives.

Neither idea is scoped for implementation; revisit only if a concrete
engagement makes OAuth-flow or iframe/postMessage trust the dominant
risk surface.