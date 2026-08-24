"""Legacy SAML settings sourced from the environment, never from source secrets."""

import os

from core.config import parse_bool, read_optional_file_from_env


SAML_SETTINGS = {
    'strict': parse_bool(os.environ.get('SAML_STRICT'), default=True, name='SAML_STRICT'),
    'debug': parse_bool(os.environ.get('SAML_DEBUG'), default=False, name='SAML_DEBUG'),
    'sp': {
        'entityId': os.environ.get('SAML_SP_ENTITY_ID', ''),
        'assertionConsumerService': {
            'url': os.environ.get('SAML_SP_ACS_URL', ''),
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        },
        'singleLogoutService': {
            'url': os.environ.get('SAML_SP_SLO_URL', ''),
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        },
        'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'x509cert': read_optional_file_from_env('SAML_SP_CERT_PATH'),
        'privateKey': read_optional_file_from_env('SAML_SP_PRIVATE_KEY_PATH'),
    },
    'idp': {
        'entityId': os.environ.get('SAML_IDP_ENTITY_ID', ''),
        'singleSignOnService': {
            'url': os.environ.get('SAML_IDP_SSO_URL', ''),
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        },
        'singleLogoutService': {
            'url': os.environ.get('SAML_IDP_SLO_URL', ''),
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        },
        'x509cert': read_optional_file_from_env('SAML_IDP_CERT_PATH'),
    },
    'security': {
        'authnRequestsSigned': True,
        'logoutRequestSigned': True,
        'logoutResponseSigned': True,
        'wantMessagesSigned': True,
        'wantAssertionsSigned': False,
        'wantNameId': True,
        'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
        'debug': parse_bool(os.environ.get('SAML_DEBUG'), default=False, name='SAML_DEBUG'),
    },
}
