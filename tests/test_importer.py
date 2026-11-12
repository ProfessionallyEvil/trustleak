"""
Integration tests for trustleak.importer, using real ShadowSaaS output
captured during the proxy-hardening session (sunresorts direct-subdomain scan
with a confirmed Vercel takeover, and the secureideas.com enumeration with
37 hosts, four of them sharing a cookie domain scope).
"""
import os

import pytest

from trustleak import importer

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name):
    return os.path.join(FIXTURES, name)


# ---------------------------------------------------------------------------
# sunresorts_direct.json — single confirmed takeover
# ---------------------------------------------------------------------------

def test_sunresorts_imports_one_asset():
    result = importer.import_shadowsaas_output(fixture_path("sunresorts_direct.json"))
    assert len(result.assets) == 1
    assert result.skipped == []


def test_sunresorts_classified_as_suspicious():
    result = importer.import_shadowsaas_output(fixture_path("sunresorts_direct.json"))
    asset = result.assets[0]
    assert asset["hostname"] == "preview.tickets.sunresorts.example"
    assert asset["classification"] == "suspicious"
    assert asset["takeover_possible"] is True
    assert asset["confidence"] == "high"


def test_sunresorts_empty_relevant_headers_preserved():
    result = importer.import_shadowsaas_output(fixture_path("sunresorts_direct.json"))
    # The Vercel "deployment could not be found" error page doesn't set CSP/
    # CORS/cookies — confirmed manually during the session. The importer
    # must preserve that as {}, not drop the key or treat it as missing.
    assert result.assets[0]["relevant_headers"] == {}


def test_sunresorts_relevant_body_refs_defaults_to_empty_dict():
    # This fixture predates ShadowSaaS's relevant_body_refs patch — the
    # key is entirely absent from the source JSON. The importer must
    # default it to {}, the same tolerant behavior as relevant_headers,
    # not raise a KeyError when a downstream analyzer reads it.
    result = importer.import_shadowsaas_output(fixture_path("sunresorts_direct.json"))
    assert result.assets[0]["relevant_body_refs"] == {}


# ---------------------------------------------------------------------------
# secureideas_enum.json — 37 hosts, real CSP/cookie data, no takeovers
# ---------------------------------------------------------------------------

def test_secureideas_imports_all_records():
    result = importer.import_shadowsaas_output(fixture_path("secureideas_enum.json"))
    assert len(result.assets) == 37
    assert result.skipped == []


def test_secureideas_no_suspicious_assets():
    # potential_takeovers: 0 in the source summary — every asset should
    # classify as active or inconclusive, never suspicious.
    result = importer.import_shadowsaas_output(fixture_path("secureideas_enum.json"))
    assert result.suspicious == []


def test_secureideas_classification_counts():
    result = importer.import_shadowsaas_output(fixture_path("secureideas_enum.json"))
    s = result.summary()
    assert s["total_assets"] == 37
    assert s["suspicious"] == 0
    # 16 hosts have dns_active=True and a non-null http_status in the fixture.
    assert s["active"] == 16
    assert s["inconclusive"] == 21
    assert s["skipped_invalid_records"] == 0


def test_secureideas_cookie_domain_scope_is_visible_for_correlation():
    # The real finding that motivated writing the cookie_domain_scope
    # relationship type in the schema: four independently-hosted apps
    # (two behind HubSpot, one behind Elementor Cloud, one the Cloudflare
    # apex) all share Domain=secureideas.com on their session cookie.
    result = importer.import_shadowsaas_output(fixture_path("secureideas_enum.json"))
    hosts_sharing_cookie_domain = [
        a["hostname"] for a in result.active
        if "domain=secureideas.com" in a["relevant_headers"].get("set-cookie", "").lower()
    ]
    assert set(hosts_sharing_cookie_domain) == {
        "www.secureideas.com",
        "quotes.secureideas.com",
        "stage.secureideas.com",
        "secureideas.com",
    }


def test_secureideas_csp_only_present_on_hubspot_hosts():
    result = importer.import_shadowsaas_output(fixture_path("secureideas_enum.json"))
    hosts_with_csp = {
        a["hostname"] for a in result.assets if "content-security-policy" in a["relevant_headers"]
    }
    assert hosts_with_csp == {"hsemail.secureideas.com", "helpdesk.secureideas.com"}


def test_secureideas_source_summary_preserved():
    result = importer.import_shadowsaas_output(fixture_path("secureideas_enum.json"))
    assert result.source_summary["total_subdomains"] == 37
    assert result.source_summary["potential_takeovers"] == 0
    assert result.source_had_warnings is False


# ---------------------------------------------------------------------------
# Robustness: one malformed record must not abort the whole import
# ---------------------------------------------------------------------------

def test_one_malformed_record_is_skipped_not_fatal(tmp_path):
    import json

    with open(fixture_path("secureideas_enum.json"), encoding="utf-8") as fh:
        doc = json.load(fh)

    # Corrupt a single record: confidence outside the enum the schema allows.
    doc["results"][0]["confidence"] = "extremely_confident"  # not a valid enum value

    broken_path = tmp_path / "broken.json"
    broken_path.write_text(json.dumps(doc), encoding="utf-8")

    result = importer.import_shadowsaas_output(str(broken_path))

    assert len(result.skipped) == 1
    assert result.skipped[0]["subdomain"] == "siamdepot.secureideas.com"
    assert "confidence" in result.skipped[0]["errors"][0]
    # The other 36 good records still imported.
    assert len(result.assets) == 36


def test_not_a_shadowsaas_file_raises_clear_error(tmp_path):
    import json

    not_shadowsaas = tmp_path / "not_shadowsaas.json"
    not_shadowsaas.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    with pytest.raises(ValueError, match="Not a valid ShadowSaaS output file"):
        importer.import_shadowsaas_output(str(not_shadowsaas))


# ---------------------------------------------------------------------------
# Speculative confidence must never be treated as a trustworthy target
# ---------------------------------------------------------------------------

def test_speculative_takeover_is_not_suspicious():
    # Neither real fixture contains a --speculative (wordlist) hit, so this
    # exercises the rule directly against a record shaped the way ShadowSaaS
    # actually produces one: _source="wordlist" forces confidence to
    # "speculative" regardless of takeover_possible (see
    # calculate_confidence() in shadow_saas_surface.py).
    speculative_hit = {
        "subdomain": "admin.secureideas.com",
        "_source": "wordlist",
        "dns_active": False,
        "dns_target": None,
        "saas": None,
        "http_status": None,
        "risk_score": 25,
        "takeover_possible": True,
        "confidence": "speculative",
        "analysis": ["Speculative subdomain (not present in DNS)"],
        "relevant_headers": {},
    }
    assert importer.classify_asset(speculative_hit) == "inconclusive"


def test_non_speculative_takeover_is_still_suspicious():
    # Guard against the fix above accidentally over-excluding: a genuine
    # high-confidence takeover candidate must still classify as suspicious.
    confirmed_hit = {
        "subdomain": "preview.tickets.sunresorts.example",
        "takeover_possible": True,
        "confidence": "high",
        "dns_active": True,
        "http_status": 404,
    }
    assert importer.classify_asset(confirmed_hit) == "suspicious"
