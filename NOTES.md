# TrustLeak — design notes for future work

## Everything built so far is passive

Every analyzer in this codebase (CSP, CORS, Cookie Domain Scope, HTML)
only correlates data ShadowSaaS already collected during its normal,
passive scan. **No TrustLeak analyzer sends a new network request today.**

## Active-probe features — not yet built

Several planned features require TrustLeak to send a new request to a
path ShadowSaaS never visits during its own scan — a fundamentally
different risk/authorization profile than "correlate what was already
fetched":

- CORS origin-reflection testing (sending a forged `Origin` header to
  check whether a server reflects it back in `Access-Control-Allow-Origin`,
  especially combined with `Access-Control-Allow-Credentials: true`)
- Downloading a referenced `.js` file's content to search for endpoints,
  API URLs, or other hostname references inside it
- Fetching `/.well-known/openid-configuration` (OAuth/OIDC discovery)
- Fetching a SAML metadata XML document

Note: a `redirect_uri` or `AssertionConsumerServiceURL` string that
merely *appears* inside HTML already fetched is NOT in this category —
that's still passive, and is now implemented in `html_analyzer.py`
(`html_oauth_redirect_uri_reference` / `html_saml_acs_reference`), same
as any other reference type. A future `js_analyzer.py` would extend this
further for references appearing inside a downloaded `.js` file's
content specifically. Only the deliberate act of fetching a *new* URL
the ShadowSaaS scan never visited counts as active — the four items
listed above remain unbuilt.

Requirements before any active-probe feature gets built, agreed on when
the project was scoped:

- Ships as its own module, registered separately from the passive
  analyzers in `correlate.py` (see `_PASSIVE_ANALYZERS` /
  `_ACTIVE_ANALYZERS`) — never silently pulled into a normal run.
- Explicitly opt-in — the person running TrustLeak must ask for it by
  name (`--allow-active-probes`), not get it as a side effect of a
  normal run.
- A host a new request is about to be sent to must share an apex domain
  with some hostname already present in the scan (see
  `hostnames.shares_apex_with_any()`) — an automatic, zero-configuration
  sanity check that a derived host (e.g. an absolute script src URL)
  is actually part of the engagement's own infrastructure, not a
  generic third-party library/CDN. This is NOT a substitute for the
  operator's own authorization to run active probes against the
  engagement at all — that's `--allow-active-probes` itself, backed by
  whatever authorization the client has already given for the
  engagement. A separate scope-file mechanism was considered and
  deliberately dropped: it would duplicate authorization the operator
  already has, for no real safety gain.
- Evidence from an active probe is always tagged
  `evidence.collected_via = "trustleak_active_request"`, never mixed
  silently with passive evidence in the same bucket. The HTML report
  shows this distinction visibly (a PASSIVE/ACTIVE badge next to
  "Collected via"), not just in the raw JSON.

Until all four of those exist, no active-probe feature gets built,
however small the incremental addition might look.

## js_analyzer.py — the first active-probe analyzer (built)

Downloads a referenced `.js` file's own content and correlates it
against suspicious targets, same principle as every passive analyzer,
applied to content that required a new request to obtain. See its module
docstring for the exact scope rule and request-volume confirmation
(`--allow-active-probes` enables it; below ~20 in-scope URLs it proceeds
automatically, above that it asks before fetching).

Still unbuilt from the four candidates above: CORS origin-reflection
testing, OAuth/OIDC discovery, SAML metadata discovery.

## oauth_discovery_analyzer.py — the second active-probe analyzer (built)

Fetches every active application's own `/.well-known/openid-configuration`
(RFC 8414 / OpenID Connect Discovery — a real, standard path) and
correlates its JSON content against suspicious targets. O(active
applications), not O(active × suspicious) — cheaper than js_analyzer.py.

SAML metadata discovery is deliberately NOT built, and not planned as a
simple extension of this module: unlike OIDC, there is no universal
standard path for SAML SP/IdP metadata (implementations vary —
/saml/metadata, /simplesaml/module.php/saml/sp/metadata.php/...,
/Shibboleth.sso/Metadata, and more). A blind probe would have to guess
among many non-standard paths, trading reliable coverage for a lot of
speculative, mostly-wasted requests. Revisit only if a reliable, generic
discovery mechanism is identified.

Still unbuilt from the four original candidates: CORS origin-reflection
testing. SAML metadata discovery is now considered closed/declined
rather than merely deferred (see reasoning above).