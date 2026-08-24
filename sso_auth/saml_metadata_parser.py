"""Secure parsing of pasted IdP metadata XML for provider onboarding.

Untrusted input never reaches an unguarded XML parser: `OneLogin_Saml2_XML.to_etree`
is python3-saml's own defusedxml-derived lxml parser (`onelogin.saml2.xmlparser`),
which already disables DTDs, external entities, and network entity resolution, and
bounds tree size (`huge_tree=False`). This module adds an explicit byte-size cap the
toolkit does not enforce, then extracts onboarding fields via namespace-aware XPath on
the already-hardened tree. It does not implement SAML protocol logic.
"""

from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from onelogin.saml2.xmlparser import DTDForbidden, EntitiesForbidden

from lxml.etree import XMLSyntaxError


MAX_METADATA_BYTES = 1 * 1024 * 1024


class SAMLMetadataError(ValueError):
    """Raised when pasted IdP metadata cannot be safely or usefully parsed."""


def parse_idp_metadata_xml(xml_text):
    """Parse pasted IdP metadata XML and return discovered onboarding fields.

    :param xml_text: Raw metadata XML as submitted by an administrator.
    :type xml_text: str
    :returns: dict with entity_id, sso_endpoints, slo_endpoints, certs, nameid_formats.
    :rtype: dict
    :raises SAMLMetadataError: for missing/oversized/malformed/unsafe/unusable input.
    """
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise SAMLMetadataError('IdP metadata XML is required.')

    encoded = xml_text.encode('utf-8', errors='strict') if isinstance(xml_text, str) else xml_text
    if len(encoded) > MAX_METADATA_BYTES:
        raise SAMLMetadataError('IdP metadata XML exceeds the maximum accepted size.')

    try:
        dom = OneLogin_Saml2_XML.to_etree(xml_text)
    except (DTDForbidden, EntitiesForbidden):
        raise SAMLMetadataError('IdP metadata XML contains a forbidden DTD or external entity.')
    except (XMLSyntaxError, ValueError):
        raise SAMLMetadataError('IdP metadata XML is malformed.')

    idp_descriptor_nodes = OneLogin_Saml2_XML.query(dom, '//md:EntityDescriptor/md:IDPSSODescriptor')
    if not idp_descriptor_nodes:
        raise SAMLMetadataError('IdP metadata does not contain an IDPSSODescriptor.')
    idp_descriptor = idp_descriptor_nodes[0]
    entity_descriptor = idp_descriptor.getparent()

    entity_id = entity_descriptor.get('entityID') or ''
    if not entity_id:
        raise SAMLMetadataError('IdP metadata is missing an EntityDescriptor entityID.')

    sso_endpoints = [
        {'url': node.get('Location'), 'binding': node.get('Binding')}
        for node in OneLogin_Saml2_XML.query(idp_descriptor, './md:SingleSignOnService')
        if node.get('Location') and node.get('Binding')
    ]
    if not sso_endpoints:
        raise SAMLMetadataError('IdP metadata does not advertise a usable SingleSignOnService endpoint.')

    slo_endpoints = [
        {'url': node.get('Location'), 'binding': node.get('Binding')}
        for node in OneLogin_Saml2_XML.query(idp_descriptor, './md:SingleLogoutService')
        if node.get('Location') and node.get('Binding')
    ]

    signing_cert_nodes = OneLogin_Saml2_XML.query(
        idp_descriptor,
        "./md:KeyDescriptor[not(contains(@use, 'encryption'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
    )
    certs = [
        ''.join(OneLogin_Saml2_XML.element_text(node).split())
        for node in signing_cert_nodes
        if OneLogin_Saml2_XML.element_text(node)
    ]

    nameid_formats = [
        OneLogin_Saml2_XML.element_text(node)
        for node in OneLogin_Saml2_XML.query(idp_descriptor, './md:NameIDFormat')
        if OneLogin_Saml2_XML.element_text(node)
    ]

    return {
        'entity_id': entity_id,
        'sso_endpoints': sso_endpoints,
        'slo_endpoints': slo_endpoints,
        'certs': certs,
        'nameid_formats': nameid_formats,
    }
