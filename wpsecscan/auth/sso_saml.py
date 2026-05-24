"""SAML SSO scaffold for the daemon.

Round-64 #115 — wraps python3-saml. Most enterprise IdPs (Okta, Azure
AD, ADFS) support both OIDC + SAML — prefer OIDC. This scaffold is for
the small set of customers who require SAML.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SAMLConfig:
    sp_entity_id: str
    sp_acs_url: str  # assertion consumer service URL
    idp_entity_id: str
    idp_sso_url: str
    idp_x509_cert_path: str


def build_saml_settings(config: SAMLConfig) -> dict:
    """Returns the python3-saml settings dict.

    Caller passes this to OneLogin_Saml2_Auth(req, settings).
    """
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": config.sp_entity_id,
            "assertionConsumerService": {
                "url": config.sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": config.idp_entity_id,
            "singleSignOnService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert_file": config.idp_x509_cert_path,
        },
    }


def parse_saml_response(saml_response_b64: str, config: SAMLConfig) -> dict:
    """Verify the SAML response, return {nameid, attributes}.

    Raises ImportError if python3-saml isn't installed.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore
    except ImportError as e:
        raise ImportError("pip install python3-saml required for SAML verification") from e

    # Construct a minimal req-shaped dict
    req = {
        "https": "on",
        "http_host": "_unused",
        "script_name": config.sp_acs_url,
        "get_data": {},
        "post_data": {"SAMLResponse": saml_response_b64},
    }
    auth = OneLogin_Saml2_Auth(req, build_saml_settings(config))
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        raise ValueError(f"SAML errors: {errors}; reason: {auth.get_last_error_reason()}")
    return {
        "nameid": auth.get_nameid(),
        "attributes": auth.get_attributes(),
    }
