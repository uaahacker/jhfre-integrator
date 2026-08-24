"""Database-free native runtime smoke tests for the SAML XML stack."""

import unittest

from lxml import etree
import xmlsec
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings


class SamlRuntimeTests(unittest.TestCase):
    def test_xmlsec_and_python3_saml_import_and_initialize(self):
        self.assertIsNotNone(OneLogin_Saml2_Auth)
        self.assertIsNotNone(OneLogin_Saml2_Settings)

        xmlsec.init()
        try:
            document = etree.fromstring(b"<root/>")
            signature = xmlsec.template.create(
                document,
                xmlsec.Transform.EXCL_C14N,
                xmlsec.Transform.RSA_SHA256,
            )
            self.assertEqual(signature.tag, "{http://www.w3.org/2000/09/xmldsig#}Signature")
        finally:
            xmlsec.shutdown()
