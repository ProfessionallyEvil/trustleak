"""
TrustLeak — ShadowSaaS output importer (M1: Data Integration).

Reads a ShadowSaaS scan output (JSON), validates each result record against
shadowsaas-output-v1.schema.json, and classifies assets into the buckets
TrustLeak's analyzers consume: suspicious (target candidates), active
(source candidates), and inconclusive (neither, for now).

Design decision: a single malformed record must never abort an import of
36 good ones. Per-record validation failures are collected in
ImportResult.skipped and the record is excluded from .assets — the rest of
the import proceeds. Only a document-level problem (not a ShadowSaaS
output file at all) is a hard failure.
"""
import json

import jsonschema

from trustleak._paths import find_schema

SCHEMA_VERSION = "1.0"

_OUTPUT_SCHEMA_PATH = find_schema("shadowsaas-output-v1.schema.json")

with open(_OUTPUT_SCHEMA_PATH, encoding="utf-8") as _fh:
    _OUTPUT_SCHEMA = json.load(_fh)

_DOC_VALIDATOR = jsonschema.Draft7Validator(_OUTPUT_SCHEMA)
_RESULT_VALIDATOR = jsonschema.Draft7Validator(_OUTPUT_SCHEMA["definitions"]["result"])


def classify_asset(result):
    """
    Return 'suspicious', 'active', or 'inconclusive' for one ShadowSaaS
    result record.

    - 'suspicious': ShadowSaaS flagged takeover_possible=True AND
      confidence is not 'speculative'. These are TARGET candidates — the
      hostname a CSP/CORS/cookie reference from some other, active
      application might point at. A 'speculative' hit comes from the
      --speculative wordlist guessing a name, not from confirming it via
      CT logs or direct input — ShadowSaaS itself marks that confidence
      tier below 'low' for a reason, and TrustLeak shouldn't build a
      trust-relationship correlation on top of a guess ShadowSaaS hasn't
      vouched for. These demote to 'inconclusive', not get dropped
      silently — they're still visible in the import, just not treated
      as a target worth correlating against yet.
    - 'active': DNS resolves and a real HTTP response came back. These
      are SOURCE candidates — a live application whose headers/body get
      inspected for a reference to a 'suspicious' hostname.
    - 'inconclusive': everything else (DNS inactive, DNS active with no
      HTTP response and not already flagged suspicious, or a speculative
      takeover candidate as described above). Not useful as a source or
      a target until there's more signal.
    """
    if result.get("takeover_possible") and result.get("confidence") != "speculative":
        return "suspicious"
    if result.get("dns_active") and result.get("http_status") is not None:
        return "active"
    return "inconclusive"


def _format_errors(errors):
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in errors
    ]


class ImportResult:
    """
    Outcome of importing one ShadowSaaS output file: classified assets,
    any records skipped for failing schema validation, and the summary
    block ShadowSaaS itself reported (including its own warnings, if the
    scan was aborted for a target — see shadowsaas-output-v1.schema.json).
    """

    def __init__(self, source_summary, assets, skipped):
        self.source_summary = source_summary
        self.assets = assets
        self.skipped = skipped

    def by_classification(self, classification):
        return [a for a in self.assets if a["classification"] == classification]

    @property
    def suspicious(self):
        return self.by_classification("suspicious")

    @property
    def active(self):
        return self.by_classification("active")

    @property
    def inconclusive(self):
        return self.by_classification("inconclusive")

    @property
    def source_had_warnings(self):
        """True if ShadowSaaS itself reported an aborted-scan warning for this file."""
        return bool(self.source_summary.get("warnings"))

    def summary(self):
        return {
            "total_assets": len(self.assets),
            "suspicious": len(self.suspicious),
            "active": len(self.active),
            "inconclusive": len(self.inconclusive),
            "skipped_invalid_records": len(self.skipped),
            "source_scan_had_warnings": self.source_had_warnings,
        }


def import_shadowsaas_output(path):
    """
    Load and classify a ShadowSaaS output JSON file. Raises ValueError if
    the file isn't a ShadowSaaS output document at all (wrong top-level
    shape). Individual malformed result records are skipped, not fatal —
    see ImportResult.skipped.
    """
    with open(path, encoding="utf-8") as fh:
        document = json.load(fh)

    doc_errors = sorted(_DOC_VALIDATOR.iter_errors(document), key=lambda e: list(e.path))
    # Per-record errors inside "results" are handled individually below;
    # only a document-level problem (missing "summary", wrong top-level
    # type) is treated as the file not being a ShadowSaaS output at all.
    top_level_errors = [e for e in doc_errors if not (e.path and e.path[0] == "results")]
    if top_level_errors:
        raise ValueError(
            "Not a valid ShadowSaaS output file:\n  " + "\n  ".join(_format_errors(top_level_errors))
        )

    assets = []
    skipped = []

    for i, result in enumerate(document.get("results", [])):
        errors = list(_RESULT_VALIDATOR.iter_errors(result))
        if errors:
            skipped.append({
                "index": i,
                "subdomain": result.get("subdomain", "<unknown>"),
                "errors": _format_errors(sorted(errors, key=lambda e: list(e.path))),
            })
            continue

        assets.append({
            "hostname": result["subdomain"],
            "classification": classify_asset(result),
            "dns_active": result["dns_active"],
            "dns_target": result.get("dns_target"),
            "http_status": result.get("http_status"),
            "takeover_possible": result["takeover_possible"],
            "confidence": result["confidence"],
            "relevant_headers": result.get("relevant_headers", {}),
            "relevant_body_refs": result.get("relevant_body_refs", {}),
            "raw": result,
        })

    return ImportResult(
        source_summary=document.get("summary", {}),
        assets=assets,
        skipped=skipped,
    )
