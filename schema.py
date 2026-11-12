"""
TrustLeak finding schema validation (v2).

The JSON Schema file (trustleak-finding-v2.schema.json) is the actual
contract — language-agnostic, and what the Graph Analyzer (or any other
consumer, in any language) validates against. This module is the
Python-side enforcement of that same document, plus one check the JSON
Schema itself doesn't do: that relationship.category actually matches the
category registered for relationship.type in categories.py (see the
schema v2 design doc, open question 4, Option C — a dict is easier to
keep in sync than parallel if/then blocks in the .json file).

v1 is a breaking change here, not an additive one: SCHEMA_VERSION moved
from "1.0" to "2.0", the old flat "confidence" field is gone, and no
compatibility shim is provided on purpose. A v1 finding read by this
module fails validation loudly (wrong schema_version) rather than being
silently misread.
"""
import datetime
import json

import jsonschema

from trustleak import categories
from trustleak._paths import find_schema

SCHEMA_VERSION = "2.0"

_SCHEMA_PATH = find_schema("trustleak-finding-v2.schema.json")

with open(_SCHEMA_PATH, encoding="utf-8") as _fh:
    _SCHEMA = json.load(_fh)

_VALIDATOR = jsonschema.Draft7Validator(_SCHEMA)


class FindingSchemaError(Exception):
    """
    Raised when a finding does not conform to trustleak-finding-v2.schema.json,
    or when relationship.category disagrees with the category registered
    for relationship.type in categories.py. Carries every violation found
    (not just the first), so a caller fixing a malformed finding doesn't
    have to re-run validation once per field.
    """

    def __init__(self, messages):
        self.messages = messages
        super().__init__("Invalid TrustLeak finding:\n  " + "\n  ".join(messages))


def validate_finding(record):
    """
    Validate a finding dict against the schema, then cross-check that
    relationship.category matches the category registered for
    relationship.type. Returns the record unchanged on success, so this
    can be used inline: finding = validate_finding(build_finding(...))
    """
    errors = sorted(_VALIDATOR.iter_errors(record), key=lambda e: list(e.path))
    messages = [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]

    relationship = record.get("relationship", {})
    rel_type = relationship.get("type")
    rel_category = relationship.get("category")
    if rel_type in categories.TYPE_TO_CATEGORY and rel_category is not None:
        expected = categories.TYPE_TO_CATEGORY[rel_type]
        if rel_category != expected:
            messages.append(
                f"relationship/category: {rel_category!r} does not match the "
                f"registered category {expected!r} for relationship.type {rel_type!r}"
            )

    if messages:
        raise FindingSchemaError(messages)
    return record


def build_finding(
    finding_id,
    source_hostname,
    target_hostname,
    target_asset_status,
    relationship_type,
    relationship_status,
    evidence_source_url,
    evidence_collected_via,
    evidence_confidence,
    potential_impact,
    validation_status="not_validated",
    target_shadowsaas_confidence=None,
    evidence_header=None,
    evidence_directive=None,
    evidence_matched_value=None,
):
    """
    Construct a finding dict in the documented v2 shape and validate it
    before returning. Prefer this over hand-building the dict literal at
    call sites — it keeps every finding's shape centralized in one place,
    derives relationship.category from relationship_type automatically
    (via categories.category_for(), so callers can never pass a
    mismatched pair), and a future schema field only needs updating here.
    """
    category = categories.category_for(relationship_type)

    finding = {
        "schema_version": SCHEMA_VERSION,
        "finding_id": finding_id,
        "source": {
            "hostname": source_hostname,
            "type": "active_application",
        },
        "target": {
            "hostname": target_hostname,
            "asset_status": target_asset_status,
        },
        "relationship": {
            "type": relationship_type,
            "category": category,
            "status": relationship_status,
        },
        "assessment": {
            "evidence_confidence": evidence_confidence,
            "potential_impact": potential_impact,
            "validation_status": validation_status,
        },
        "evidence": {
            "source_url": evidence_source_url,
            "collected_via": evidence_collected_via,
        },
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }

    if target_shadowsaas_confidence is not None:
        finding["target"]["shadowsaas_confidence"] = target_shadowsaas_confidence
    if evidence_header is not None:
        finding["evidence"]["header"] = evidence_header
    if evidence_directive is not None:
        finding["evidence"]["directive"] = evidence_directive
    if evidence_matched_value is not None:
        finding["evidence"]["matched_value"] = evidence_matched_value

    return validate_finding(finding)
