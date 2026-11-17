"""
TrustLeak — quick runnable entry point.

Not the final CLI (that's a later milestone), just enough to point this
at a real ShadowSaaS -o output file and see what TrustLeak finds, instead
of only ever seeing results inside pytest assertions.
"""
import argparse
import datetime
import json
import os
import sys


def _trustleak_is_importable():
    """
    Return True if 'trustleak' is importable as a real package (one that
    has a __file__), False otherwise — including when it only resolves
    to an empty/broken namespace package (a bare "import trustleak" can
    succeed yet be useless: if some OTHER directory earlier on sys.path
    is also, or only, named "trustleak" but has no real package files in
    it — e.g. a stray empty folder, or a namespace package merged in from
    site-packages — Python resolves the import without error, but the
    result has no __file__ and none of the real submodules).

    Isolated in its own function, with no code after the try/except, so
    the name bound by "import trustleak" is only ever referenced inside
    the try block that binds it.
    """
    try:
        import trustleak
        return bool(getattr(trustleak, "__file__", None))
    except ImportError:
        return False


def _ensure_trustleak_importable():
    """
    Make 'import trustleak' work regardless of which of the two layouts
    this script was laid out in — same reasoning as
    shadow_saas_surface.py's _locate_trustleak():

    - nested: this script sits one level above the package folder (e.g.
      trustleak_prep/run_trustleak.py, trustleak_prep/trustleak/*.py) —
      Python's default sys.path already covers this, nothing to do.
    - flat: this script sits directly INSIDE the package folder itself
      (e.g. trustleak/run_trustleak.py, trustleak/__init__.py side by
      side) — "import trustleak" then looks for a 'trustleak' folder
      *inside* this one, which doesn't exist. Add the parent directory
      to sys.path so this folder itself resolves as the package.
    """
    if _trustleak_is_importable():
        return

    # A broken/empty "trustleak" (even a namespace-package stand-in with
    # no real content) still gets registered in sys.modules. Without
    # clearing it, a later "from trustleak import ..." would just return
    # that same cached, empty module instead of re-searching sys.path
    # after the fix below runs — making the fix a no-op even once
    # sys.path is correct.
    for _name in list(sys.modules):
        if _name == "trustleak" or _name.startswith("trustleak."):
            del sys.modules[_name]

    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.isfile(os.path.join(here, "__init__.py")):
        parent = os.path.dirname(here)
        if parent not in sys.path:
            sys.path.insert(0, parent)


_ensure_trustleak_importable()

from trustleak import __version__, correlate, importer, report  # noqa: E402
from trustleak import state as state_module  # noqa: E402

# Shared between --help's description and the banner printed at the start
# of every real run, so the two can never drift out of sync with each
# other.
_BANNER = f"""┌─────────────────────────────────────────────────────────────────┐
│                       TrustLeak  v{__version__}                         │
│      Trust Relationship Correlator for ShadowSaaS Findings      │
│                      Jordan Bonagura                            │
│               Secure Ideas - Professionally Evil                │
└─────────────────────────────────────────────────────────────────┘"""


def _default_js_output_dir(source_name):
    """
    Auto-generated default for where the JS active analyzer saves fetched
    files, so the person running this never HAS to think of a directory
    name themselves — only --js-output-dir overrides it, for whoever
    wants to pick their own. Named after the scan file (so evidence from
    different engagements doesn't land in the same place by accident)
    plus a timestamp (so re-running against the same file twice doesn't
    silently overwrite the previous run's evidence).
    """
    slug = os.path.splitext(os.path.basename(source_name))[0] if source_name else "scan"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"trustleak_js_{slug}_{timestamp}"


def _default_oidc_output_dir(source_name):
    """
    Same auto-naming philosophy as _default_js_output_dir(), for
    oauth_discovery_analyzer.py's own evidence (the OIDC discovery
    documents it finds).
    """
    slug = os.path.splitext(os.path.basename(source_name))[0] if source_name else "scan"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"trustleak_oidc_{slug}_{timestamp}"

def _summarize_findings(findings):
    """
    One short line breaking findings down by potential_impact, printed
    unconditionally (regardless of --html) so a run without --html isn't
    just a wall of raw JSON with no quick way to tell, at a glance,
    whether anything here actually matters.
    """
    if not findings:
        return None
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        impact = f.get("assessment", {}).get("potential_impact", "low")
        counts[impact] = counts.get(impact, 0) + 1
    parts = [f"{counts[level]} {level} impact" for level in ("high", "medium", "low") if counts[level]]
    return ", ".join(parts)


def main():
    parser = argparse.ArgumentParser(
        prog="run_trustleak.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"""
{_BANNER}

Reads a ShadowSaaS Surface Scanner output file and correlates active
applications against suspicious (takeover candidate) subdomains,
looking for trust relationships that extend risk beyond the dangling
subdomain itself.

Analyzers covered — passive (see NOTES.md):
  CSP     — Content-Security-Policy / Report-Only directive references
  CORS    — Access-Control-Allow-Origin (static correlation only)
  Cookie  — Set-Cookie Domain attribute scope
  HTML    — iframe/script src/form action references, plus OAuth
            redirect_uri and SAML AssertionConsumerServiceURL strings
            already present in the page text

Analyzers covered — ACTIVE, requires --allow-active-probes:
  JS      — downloads a referenced .js file and searches its content
            for a suspicious target's hostname. Automatic scope check
            (see NOTES.md); asks before fetching past ~20 in-scope URLs.

The passive analyzers only correlate data ShadowSaaS already collected
during its own scan — no new network request. JS does send a new
request (only to in-scope hosts) and only runs when
--allow-active-probes is passed explicitly.

Output options:
  --pretty               — Pretty-print JSON output
  --html FILE            — Generate a self-contained HTML report
  --state FILE           — Persist findings across runs with stable finding_ids
  --allow-active-probes  — Allow active-probe analyzers (JS) to run
  --js-output-dir DIR    — Save every fetched .js file's content (plus a
                           manifest.json) to DIR. Requires --allow-active-probes.

Intended for authorized security testing only.
        """,
        epilog="""
Examples:
  # Correlate a ShadowSaaS output file, print JSON to stdout
  python run_trustleak.py shadowsaas_output.json

  # Pretty-print the JSON
  python run_trustleak.py shadowsaas_output.json --pretty

  # Also write a self-contained HTML report
  python run_trustleak.py shadowsaas_output.json --html trustleak_report.html

  # Both at once
  python run_trustleak.py shadowsaas_output.json --pretty --html report.html

  # Persist findings across repeated scans of the same target, keeping
  # stable finding_ids instead of restarting at TL-0001 every run
  python run_trustleak.py shadowsaas_output.json --state trustleak_state.json

  # Allow the JS active-probe analyzer to run, saving every fetched
  # .js file's content (plus a manifest.json) for evidence
  python run_trustleak.py shadowsaas_output.json --allow-active-probes --js-output-dir ./js_evidence
        """,
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        help="ShadowSaaS -o output file to correlate (must include relevant_headers)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output (indent=2).",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Write a self-contained HTML report to FILE (e.g. report.html).",
    )
    parser.add_argument(
        "--state",
        metavar="FILE",
        help=(
            "Persist findings across runs in FILE, keeping stable finding_ids "
            "for the same underlying finding seen again, instead of "
            "restarting at TL-0001 every run."
        ),
    )
    parser.add_argument(
        "--allow-active-probes",
        action="store_true",
        help=(
            "Allow active-probe analyzers to send new requests against "
            "scoped targets, beyond what ShadowSaaS already collected. "
            "Today this enables the JS analyzer (downloads a referenced "
            ".js file and searches its content)."
        ),
    )
    parser.add_argument(
        "--js-output-dir",
        metavar="DIR",
        help=(
            "Override where the JS active analyzer saves every fetched .js "
            "file (plus a manifest.json). Optional — with "
            "--allow-active-probes and no override, this defaults "
            "automatically to a folder named after the scan file and the "
            "current time, so nothing has to be typed in just to get the "
            "evidence saved."
        ),
    )
    parser.add_argument(
        "--oidc-output-dir",
        metavar="DIR",
        help=(
            "Override where the OAuth/OIDC discovery analyzer saves every "
            "valid discovery document it finds (plus a manifest.json). "
            "Optional — same auto-naming default as --js-output-dir."
        ),
    )

    args = parser.parse_args()

    if not args.input_file:
        parser.print_help()
        sys.exit(0)

    print(_BANNER + "\n")

    try:
        result = importer.import_shadowsaas_output(args.input_file)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    print(f"[+] Imported {len(result.assets)} assets from {args.input_file}")
    print(f"    {result.summary()}")
    if result.skipped:
        print(f"[!] {len(result.skipped)} record(s) skipped for failing schema validation:")
        for s in result.skipped:
            print(f"    - {s['subdomain']}: {s['errors']}")

    active_analyzer_kwargs = None
    if args.allow_active_probes:
        js_output_dir = args.js_output_dir or _default_js_output_dir(args.input_file)
        print(f"[*] JS evidence will be saved to {js_output_dir}")
        oidc_output_dir = args.oidc_output_dir or _default_oidc_output_dir(args.input_file)
        print(f"[*] OIDC evidence will be saved to {oidc_output_dir}")
        active_analyzer_kwargs = {
            "js_content": {"output_dir": js_output_dir},
            "oauth_discovery": {"output_dir": oidc_output_dir},
        }

    findings = correlate.correlate_all(
        result,
        allow_active=args.allow_active_probes,
        active_analyzer_kwargs=active_analyzer_kwargs,
    )

    if args.state:
        persisted = state_module.load_state(args.state)
        findings = state_module.assign_stable_ids(findings, persisted)
        state_module.save_state(args.state, persisted)
        print(f"[+] Finding IDs persisted in {args.state}")

    impact_summary = _summarize_findings(findings)
    explanation = correlate.explain_empty(result, findings)

    # The raw JSON dump below can be hundreds of lines long — long enough
    # on a real scan to push anything printed before it off the top of a
    # terminal's visible scrollback. It's printed here, BEFORE the
    # human-readable summary, so that summary is the last thing on
    # screen once the command finishes, not buried above a wall of JSON.
    output = {"findings": findings}
    print(json.dumps(output, indent=2 if args.pretty else None))

    print(f"\n[+] {len(findings)} finding(s)")
    if impact_summary:
        print(f"    {impact_summary}")
    if explanation:
        print(f"[*] {explanation}")

    if args.html:
        html = report.render_html_report(result, findings)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] HTML report saved to {args.html}")


if __name__ == "__main__":
    main()