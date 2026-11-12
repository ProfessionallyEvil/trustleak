"""
TrustLeak — relationship type -> category mapping, and category -> default
potential_impact lookup.

Centralized here as a single dict, rather than enforced via parallel
if/then blocks in the JSON Schema, because a dict is the easier thing to
keep correct as new relationship types are added — see the schema v2
design doc, open question 4 (Option C). schema.py uses this same mapping
to reject a finding whose relationship.type and relationship.category
disagree, so this is the one place both finding construction and finding
validation read from.
"""

TYPE_TO_CATEGORY = {
    "csp_script_src": "execution_dependency",
    "csp_worker_src": "execution_dependency",
    "csp_default_src": "fallback_dependency",  # provisional — see design doc §9.3
    "csp_connect_src": "data_exfiltration_dependency",
    "csp_frame_src": "framing_dependency",
    "csp_img_src": "resource_dependency",
    "csp_other_directive": "resource_dependency",
    "cors_allowed_origin": "cross_origin_trust",
    "cookie_domain_scope": "shared_scope",
    # HTML relationship types deliberately reuse the SAME category as
    # their CSP counterpart where the underlying risk mechanism is
    # identical — html_script_reference and csp_script_src both mean
    # "an attacker-controlled host's JS would execute here" (HTML is
    # actually the stronger evidence: the page already loads it, vs. CSP
    # only permitting it); html_iframe_embed and csp_frame_src both mean
    # "an attacker-controlled host would be embedded here". Only the form
    # case needs a genuinely new category — submitting a form to a
    # taken-over host is a phishing/credential-harvesting risk, not
    # execution or framing.
    "html_script_reference": "execution_dependency",
    "html_iframe_embed": "framing_dependency",
    "html_form_action": "navigation_dependency",
    # Passive references to an OAuth redirect_uri or SAML ACS endpoint
    # that already appear somewhere in the page text (a login link's
    # query string, a redirect URL) — not an active discovery request
    # (fetching /.well-known/openid-configuration or SAML metadata XML
    # remains unbuilt, see NOTES.md). If the dangling subdomain is
    # whitelisted as where an identity provider sends an authorization
    # code or SAML assertion, taking it over could let an attacker
    # intercept a login flow — a genuinely new risk mechanism, hence a
    # new category rather than reusing an existing one.
    "html_oauth_redirect_uri_reference": "authentication_dependency",
    "html_saml_acs_reference": "authentication_dependency",
    # The first ACTIVE-probe relationship type (see js_analyzer.py and
    # NOTES.md) — a suspicious target's hostname found inside a
    # downloaded .js file's own content. Deliberately its own category:
    # without actually executing the script, there's no way to tell
    # whether the reference is an execution-style dependency (the script
    # dynamically loads more code from that host) or a data-exfiltration
    # one (it's just an API endpoint URL) — js_content_dependency assumes
    # the worse case (see CATEGORY_DEFAULT_IMPACT below) rather than
    # guessing which.
    "js_content_reference": "js_content_dependency",
}

# Baseline potential_impact per category. Two categories have a
# per-finding override an analyzer can supply on top of this default:
# cross_origin_trust escalates to "high" when Access-Control-Allow-
# Credentials is true; shared_scope escalates to "high" for a
# session/auth-like cookie name. See cors_analyzer.py and
# cookie_analyzer.py for where that override is applied.
CATEGORY_DEFAULT_IMPACT = {
    "execution_dependency": "high",
    "data_exfiltration_dependency": "high",
    "cross_origin_trust": "medium",
    "shared_scope": "low",
    "framing_dependency": "medium",
    "resource_dependency": "low",
    "fallback_dependency": "medium",
    "navigation_dependency": "medium",
    "authentication_dependency": "high",
    "js_content_dependency": "high",
}


def category_for(relationship_type):
    """Return the category for a relationship type, or raise with a clear message."""
    try:
        return TYPE_TO_CATEGORY[relationship_type]
    except KeyError as exc:
        raise KeyError(
            f"No category registered for relationship type {relationship_type!r}. "
            f"Add it to TYPE_TO_CATEGORY in categories.py."
        ) from exc


def default_impact_for(category):
    """Return the baseline potential_impact for a category."""
    try:
        return CATEGORY_DEFAULT_IMPACT[category]
    except KeyError as exc:
        raise KeyError(
            f"No default potential_impact registered for category {category!r}. "
            f"Add it to CATEGORY_DEFAULT_IMPACT in categories.py."
        ) from exc
