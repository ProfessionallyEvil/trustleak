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


class _SavedSummary:
    """
    Minimal stand-in for importer.ImportResult, used only when
    --render-from loads a file this script previously wrote with
    -o/--output. render_html_report() only ever calls .summary() on
    whatever "import_result" it's given — this provides exactly that,
    from the small summary dict saved alongside the findings themselves,
    without needing the original ShadowSaaS scan file (or the asset list
    importer.import_shadowsaas_output() would otherwise reconstruct) to
    still be around or re-parsed.
    """
    def __init__(self, summary_dict):
        self._summary_dict = summary_dict or {}

    def summary(self):
        return self._summary_dict


def _default_evidence_dir(source_name, prefix):
    """
    Auto-generated default for where an active analyzer saves its
    evidence, so the person running this never HAS to think of a
    directory name themselves — the matching --*-output-dir flag
    overrides it, for whoever wants to pick their own.

    Placed next to the scan file itself (source_name's own directory),
    not wherever the current working directory happens to be when the
    command is run — otherwise the same scan produces evidence in a
    different physical location depending on which folder you were
    standing in when you ran run_trustleak.py vs. shadow_saas_surface.py,
    which is confusing when managing an engagement's evidence across
    both entry points. Named after the scan file (so evidence from
    different engagements doesn't land in the same place by accident)
    plus a timestamp (so re-running against the same file twice doesn't
    silently overwrite the previous run's evidence).
    """
    if source_name:
        base_dir = os.path.dirname(os.path.abspath(source_name))
        slug = os.path.splitext(os.path.basename(source_name))[0]
    else:
        base_dir = os.getcwd()
        slug = "scan"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"trustleak_{prefix}_{slug}_{timestamp}")


def _default_js_output_dir(source_name):
    return _default_evidence_dir(source_name, "js")


def _default_oidc_output_dir(source_name):
    return _default_evidence_dir(source_name, "oidc")


def _default_cors_output_dir(source_name):
    return _default_evidence_dir(source_name, "cors")


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
            for a suspicious target's hostname.
  OIDC    — fetches every active application's own
            /.well-known/openid-configuration.
  CORS    — sends a forged Origin header per (active, suspicious) pair
            and checks whether it's reflected back.
  Each has its own confirmation prompt past a request-volume threshold;
  see NOTES.md.

The passive analyzers only correlate data ShadowSaaS already collected
during its own scan — no new network request. The three active ones do
send new requests (only within their own scope checks) and only run
when --allow-active-probes is passed explicitly.

Output options:
  --pretty               — Pretty-print JSON output
  --html FILE            — Generate a self-contained HTML report
  --state FILE           — Persist findings across runs with stable finding_ids
  -o, --output FILE      — Save findings (+ enough summary info to
                           --render-from later) to FILE as JSON
  --render-from FILE     — Skip import/correlate entirely; regenerate
                           output from a FILE previously written with
                           -o/--output (no active probes re-run, no
                           --allow-active-probes needed)
  --allow-active-probes  — Allow active-probe analyzers (JS, OIDC, CORS) to run
  --js-output-dir DIR    — Save every fetched .js file's content (plus a
                           manifest.json) to DIR. Requires --allow-active-probes.
  --oidc-output-dir DIR  — Save every valid OIDC discovery document found
                           to DIR. Requires --allow-active-probes.
  --cors-output-dir DIR  — Save evidence for every CONFIRMED CORS
                           reflection to DIR. Requires --allow-active-probes.

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

  # Allow all three active-probe analyzers to run, saving each one's
  # own evidence, and save the resulting findings for later reuse
  python run_trustleak.py shadowsaas_output.json --allow-active-probes -o findings.json --html report.html

  # Later: regenerate the HTML report (e.g. after an Attack Path tweak)
  # from that saved findings file, with NO active probing at all --
  # no network request, no --allow-active-probes needed
  python run_trustleak.py --render-from findings.json --html report.html
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
        "-o", "--output",
        metavar="FILE",
        help=(
            "Save findings to FILE as JSON, alongside the small summary "
            "info (asset/suspicious counts) needed to --render-from this "
            "file later without the original ShadowSaaS scan. Written in "
            "addition to the normal stdout JSON dump, not instead of it."
        ),
    )
    parser.add_argument(
        "--render-from",
        metavar="FILE",
        help=(
            "Skip importing a ShadowSaaS scan and correlating entirely -- "
            "load findings (and their saved summary) from FILE, a file "
            "previously written with -o/--output, and jump straight to "
            "producing output (JSON and/or --html) from them. Useful for "
            "regenerating an --html report without re-running active-probe "
            "analyzers against the real target again. input_file, "
            "--allow-active-probes, and --state are all ignored when this "
            "is given, since no new correlation happens."
        ),
    )
    parser.add_argument(
        "--allow-active-probes",
        action="store_true",
        help=(
            "Allow active-probe analyzers to send new requests against "
            "scoped targets, beyond what ShadowSaaS already collected. "
            "Enables the JS, OAuth/OIDC discovery, and CORS reflection "
            "analyzers."
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
    parser.add_argument(
        "--cors-output-dir",
        metavar="DIR",
        help=(
            "Override where the CORS reflection analyzer saves evidence "
            "for every CONFIRMED reflection (plus a manifest.json) -- a "
            "pair that didn't reflect produces nothing to save. Optional "
            "— same auto-naming default as --js-output-dir."
        ),
    )

    args = parser.parse_args()

    if not args.render_from and not args.input_file:
        parser.print_help()
        sys.exit(0)

    print(_BANNER + "\n")

    explanation = None

    if args.render_from:
        # --render-from bypasses import_shadowsaas_output()/correlate_all()
        # entirely -- the whole point is to reuse already-computed
        # findings without a new scan file, a new correlation pass, or any
        # risk of re-triggering active probes against a real target.
        try:
            with open(args.render_from, "r", encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] Could not read --render-from file: {exc}")
            sys.exit(1)

        # Fail loudly and specifically here, before anything downstream
        # (like report.py's summary["total_assets"]) hits a bare KeyError
        # on a file that was never meant for this flag -- most commonly a
        # raw ShadowSaaS scan file (which has "results"/"total_subdomains",
        # not "findings"/"total_assets") passed to --render-from by
        # mistake instead of to the plain input_file argument.
        saved_summary = saved.get("summary") or {}
        looks_like_shadowsaas_scan = "results" in saved and "findings" not in saved
        missing_summary_keys = [k for k in ("total_assets", "suspicious") if k not in saved_summary]
        if "findings" not in saved or not isinstance(saved["findings"], list) or missing_summary_keys:
            if looks_like_shadowsaas_scan:
                print(
                    f"[!] {args.render_from} looks like a raw ShadowSaaS scan "
                    f"file (it has \"results\", not \"findings\"), not a file "
                    f"previously saved with -o/--output. Run it as the plain "
                    f"input file instead, without --render-from:\n"
                    f"    python run_trustleak.py {args.render_from} --html <FILE>"
                )
            else:
                print(
                    f"[!] {args.render_from} doesn't look like a file "
                    f"previously saved with -o/--output -- missing or "
                    f"malformed \"findings\" and/or \"summary\" "
                    f"({', '.join(missing_summary_keys) or 'findings'})."
                )
            sys.exit(1)

        findings = saved["findings"]
        result = _SavedSummary(saved_summary)
        print(f"[+] Loaded {len(findings)} finding(s) from {args.render_from}")
        if args.allow_active_probes:
            print("[*] --allow-active-probes has no effect with --render-from (no new correlation runs).")
        if args.state:
            print("[*] --state has no effect with --render-from (finding_ids were already assigned when this file was saved).")
    else:
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
            cors_output_dir = args.cors_output_dir or _default_cors_output_dir(args.input_file)
            print(f"[*] CORS reflection evidence will be saved to {cors_output_dir}")
            active_analyzer_kwargs = {
                "js_content": {"output_dir": js_output_dir},
                "oauth_discovery": {"output_dir": oidc_output_dir},
                "cors_reflection": {"output_dir": cors_output_dir},
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

        explanation = correlate.explain_empty(result, findings)

    impact_summary = _summarize_findings(findings)

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

    if args.output:
        saved_payload = {"findings": findings, "summary": result.summary()}
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(saved_payload, fh, indent=2 if args.pretty else None)
        print(f"[+] Findings saved to {args.output} (reusable later with --render-from)")

    if args.html:
        html = report.render_html_report(result, findings)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] HTML report saved to {args.html}")


if __name__ == "__main__":
    main()