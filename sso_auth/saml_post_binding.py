"""Browser HTTP-POST AuthnRequest construction for IdPs that only expose a
SingleSignOnService POST binding.

`OneLogin_Saml2_Auth.login()` is hardcoded to the HTTP-Redirect binding (it always
deflates the request and calls `redirect_to`). This module builds the same
`OneLogin_Saml2_Authn_Request` the toolkit uses internally, but encodes and (optionally)
signs it the way the SAML HTTP-POST binding requires: plain base64 of the XML, with an
enveloped XML signature via the toolkit's own `OneLogin_Saml2_Utils.add_sign` when the
provider requires signed AuthnRequests. No custom XML signing is implemented here.
"""

from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class SAMLPostBindingError(ValueError):
    """Raised when a POST-binding AuthnRequest cannot be safely constructed."""


def build_post_authn_request(provider, saml_settings, return_to):
    """Build a POST-binding AuthnRequest for the given provider settings.

    :param provider: The SSOProvider the request is being built for.
    :param saml_settings: The dict returned by SSOProvider.get_saml_settings().
    :param return_to: The RelayState target URL.
    :returns: dict with sso_url, saml_request (base64 str), relay_state, request_id.
    :raises SAMLPostBindingError: if signing is required but SP key/cert are missing.
    """
    sso_url = saml_settings['idp']['singleSignOnService']['url']
    sp_key = saml_settings['sp']['privateKey']
    sp_cert = saml_settings['sp']['x509cert']

    # python3-saml's own settings validation also requires an SP certificate/key
    # whenever any signing flag is set (AuthnRequest or logout), regardless of
    # binding. Checking first keeps the failure message specific to this call site.
    if provider.saml_authn_requests_signed and not (sp_key and sp_cert):
        raise SAMLPostBindingError(
            'Signed POST AuthnRequest requires an SP certificate and private key.'
        )

    settings_obj = OneLogin_Saml2_Settings(settings=saml_settings)
    authn_request = OneLogin_Saml2_Authn_Request(settings_obj)
    request_id = authn_request.get_id()

    if provider.saml_authn_requests_signed:
        signed_xml = OneLogin_Saml2_Utils.add_sign(
            authn_request.get_xml(),
            sp_key,
            sp_cert,
            sign_algorithm=provider.saml_signature_algorithm,
            digest_algorithm=provider.saml_digest_algorithm,
        )
        saml_request = OneLogin_Saml2_Utils.b64encode(signed_xml)
    else:
        saml_request = authn_request.get_request(deflate=False)

    return {
        'sso_url': sso_url,
        'saml_request': saml_request,
        'relay_state': return_to,
        'request_id': request_id,
    }
