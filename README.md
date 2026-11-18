# TrustLeak

Correlates [ShadowSaaS Surface Scanner](https://github.com/jbonagura/shadowsaas-surface-scanner)
output against itself: given a scan with one or more confirmed/potential
subdomain takeovers, TrustLeak looks for live applications under the same
scan that reference those dangling subdomains through a real trust
relationship — a Content-Security-Policy directive, a CORS allowlist
entry, a shared cookie domain scope, an HTML iframe/script/form
reference, an OAuth/SAML login reference, a reference found inside a
downloaded `.js` file's own content, or a live-confirmed OAuth/OIDC
discovery document or CORS reflection.

A dangling subdomain is one risk. A live, trusted application that
actively references it is a larger one — the takeover inherits whatever
trust that reference implies (script execution, a shared cookie, a
CORS-allowed origin with credentials, an embedded iframe, or an
intercepted login redirect).

## Status

Published, actively developed. Seven analyzer relationship paths are
implemented and tested against real scan data across multiple
engagements:

| Analyzer | Relationship types | Notes |
|---|---|---|
| CSP | `csp_img_src`, `csp_script_src`, `csp_worker_src`, `csp_connect_src`, `csp_frame_src`, `csp_default_src`, `csp_other_directive` | Covers both enforced CSP and CSP-Report-Only (down-weighted — see below) |
| CORS (static) | `cors_allowed_origin` | Passive correlation against already-collected headers |
| Cookie | `cookie_domain_scope` | Reads `Set-Cookie`'s `Domain=` attribute |
| HTML | `html_iframe_embed`, `html_script_reference`, `html_form_action`, `html_oauth_redirect_uri_reference`, `html_saml_acs_reference` | Reads iframe/script `src`, form `action`, and OAuth/SAML strings (`redirect_uri=`, camelCase `redirectUri:`/`redirectUri =`, `AssertionConsumerServiceURL=`) already present in the page's HTML |
| JS (active) | `js_content_reference` | Downloads a referenced `.js` file and searches its content for a suspicious target's hostname |
| OAuth/OIDC discovery (active) | `oauth_discovery_reference` | Fetches every active application's own `/.well-known/openid-configuration` and correlates it against suspicious targets |
| CORS reflection (active, validated) | `cors_allowed_origin` | Sends a forged `Origin` header per (active, suspicious) pair and checks whether it's reflected back — a confirmed match gets `relationship.status: "validated"`, TrustLeak's strongest evidence tier, distinct from every inferred ("potential_risk") finding |

**CSP, CORS (static), Cookie, and HTML are passive** — no analyzer makes
a new network request, every signal comes from data ShadowSaaS's own
scan already collected. **JS, OAuth/OIDC discovery, and CORS reflection
are active** — each sends new requests (only within the automatic scope
checks described in [NOTES.md](NOTES.md)), and none of the three runs
unless explicitly enabled with `--allow-active-probes`. Each active
analyzer has its own request-volume confirmation threshold and its own
evidence-saving flag (`--js-output-dir`, `--oidc-output-dir`,
`--cors-output-dir`) — all auto-named if not given, so nothing has to be
typed in just to keep the evidence.

The HTML report groups findings by target asset, with a dedicated
"✓ Validated Only" filter that isolates any live-confirmed finding
(today, only CORS reflection produces one) regardless of which analyzer
found it.

## Requirements

- Python 3.8+
- `jsonschema` and `requests` (see `requirements.txt`) — `requests` is
  used by all three active analyzers (JS, OAuth/OIDC discovery, CORS
  reflection), and is a hard import-time dependency of the `trustleak`
  package regardless of whether you ever pass `--allow-active-probes`.
- A ShadowSaaS Surface Scanner output file, saved with `-o`, from a
  version that includes the `relevant_headers` and `relevant_body_refs`
  fields (added after the ShadowSaaS v1.1.0 proxy-support release — if
  your output doesn't have them, re-run ShadowSaaS first).

```bash
pip install -r requirements.txt
```

## Usage

```bash
python run_trustleak.py shadowsaas_output.json
python run_trustleak.py shadowsaas_output.json --pretty
python run_trustleak.py shadowsaas_output.json --html report.html

# Allow all three active-probe analyzers (JS, OAuth/OIDC discovery, CORS
# reflection); each asks before sending more than ~20 requests
python run_trustleak.py shadowsaas_output.json --allow-active-probes --html report.html
```

Run `python run_trustleak.py --help` for the full option list, including
`--state` for persisting findings across repeated scans of the same
target (keeps a finding's ID stable across runs instead of restarting at
`TL-0001` every time — see below).

### Persisting findings across runs

```bash
python run_trustleak.py shadowsaas_output.json --state trustleak_state.json
```

Without `--state`, every run is independent: the same underlying finding
gets a different `finding_id` depending on what else was found in that
run, and there's no way to tell "is this the same finding as last week's
scan" from the IDs alone. With `--state`, TrustLeak keeps a small JSON
file mapping each finding's content (source, target, relationship type,
and matched evidence) to a stable ID — a finding seen before keeps its
original ID, and a genuinely new one gets the next unused ID, continuing
from the highest ID ever assigned rather than restarting at `TL-0001`.

## Companion project

TrustLeak is a separate, standalone project from
[ShadowSaaS Surface Scanner](https://github.com/jbonagura/shadowsaas-surface-scanner)
— not bundled with it. ShadowSaaS can hand its results off to TrustLeak
automatically (`--trustleak`) when both are laid out as sibling folders
(or one nested inside the other); see ShadowSaaS's own README for the
exact layout.

## Why this exists

Written as a companion to ShadowSaaS Surface Scanner, continuing the
"Detecting Dangling SaaS Subdomains and Real Subdomain Takeovers" line of
work — see the [Secure Ideas blog](https://www.secureideas.com) for the
background.

## License

MIT — see [LICENSE](LICENSE).