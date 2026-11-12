# TrustLeak

Correlates [ShadowSaaS Surface Scanner](https://github.com/jbonagura/shadowsaas-surface-scanner)
output against itself: given a scan with one or more confirmed/potential
subdomain takeovers, TrustLeak looks for live applications under the same
scan that reference those dangling subdomains through a real trust
relationship — a Content-Security-Policy directive, a CORS allowlist
entry, a shared cookie domain scope, an HTML iframe/script/form
reference, an OAuth/SAML login reference, or a reference found inside a
downloaded `.js` file's own content.

A dangling subdomain is one risk. A live, trusted application that
actively references it is a larger one — the takeover inherits whatever
trust that reference implies (script execution, a shared cookie, a
CORS-allowed origin, an embedded iframe, or an intercepted login
redirect).

## Status

Early, local-only development. Five analyzers are implemented and
tested against real scan data:

| Analyzer | Relationship types | Notes |
|---|---|---|
| CSP | `csp_img_src`, `csp_script_src`, `csp_worker_src`, `csp_connect_src`, `csp_frame_src`, `csp_default_src`, `csp_other_directive` | Covers both enforced CSP and CSP-Report-Only (down-weighted — see below) |
| CORS | `cors_allowed_origin` | Static correlation only — see [NOTES.md](NOTES.md) for the planned active-reflection feature this deliberately does *not* include yet |
| Cookie | `cookie_domain_scope` | Reads `Set-Cookie`'s `Domain=` attribute |
| HTML | `html_iframe_embed`, `html_script_reference`, `html_form_action`, `html_oauth_redirect_uri_reference`, `html_saml_acs_reference` | Reads iframe/script `src`, form `action`, and OAuth/SAML strings (`redirect_uri=`, camelCase `redirectUri:`/`redirectUri =`, `AssertionConsumerServiceURL=`) already present in the page's HTML — actively *discovering* OAuth/SAML configuration (fetching `/.well-known/openid-configuration` or SAML metadata) is a separate, not-yet-built active-probe feature (see [NOTES.md](NOTES.md)) |
| JS (active) | `js_content_reference` | **The only active analyzer today** — downloads a referenced `.js` file and searches its content for a suspicious target's hostname. Only runs with `--allow-active-probes`; see [NOTES.md](NOTES.md) for the automatic scope check and request-volume confirmation |

**CSP/CORS/Cookie/HTML are passive** — no analyzer makes a new network
request, every signal comes from data ShadowSaaS's own scan already
collected. **JS is active** — it does send a new request (to a referenced
`.js` file only, and only within the automatic scope check described in
[NOTES.md](NOTES.md)), and only runs when explicitly enabled with
`--allow-active-probes`.

## Requirements

- Python 3.8+
- `jsonschema` and `requests` (see `requirements.txt`) — `requests` is
  only actually used by the JS active analyzer, but is a hard import-time
  dependency of the `trustleak` package regardless of whether you ever
  pass `--allow-active-probes`.
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

## Why this exists

Written as a companion to ShadowSaaS Surface Scanner, continuing the
"Detecting Dangling SaaS Subdomains and Real Subdomain Takeovers" line of
work — see the [Secure Ideas blog](https://www.secureideas.com) for the
background.

## License

Not yet published. Local development only.
