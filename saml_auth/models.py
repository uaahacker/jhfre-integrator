from django.db import models

class SamlConfiguration(models.Model):
    """
    Stores dynamic SAML configuration for Keycloak (or any SAML IdP).
    An admin can update these values in the Django Admin.
    """

    # IDP Settings
    idp_entity_id = models.URLField("IdP Entity ID", max_length=500, blank=False)
    idp_sso_url = models.URLField("IdP Single Sign-On URL", max_length=500, blank=False)
    idp_slo_url = models.URLField("IdP Single Logout URL", max_length=500, blank=True, null=True)
    idp_x509cert = models.TextField("IdP x509 Certificate", blank=True, null=True)

    # SP (Service Provider) Settings
    sp_entity_id = models.URLField("SP Entity ID", max_length=500, blank=False)
    sp_acs_url = models.URLField("SP Assertion Consumer Service (ACS) URL", max_length=500, blank=False)
    sp_slo_url = models.URLField("SP Single Logout URL", max_length=500, blank=True, null=True)
    sp_x509cert = models.TextField("SP x509 Certificate", blank=True, null=True)
    sp_private_key = models.TextField("SP Private Key", blank=True, null=True)
    name_id_format = models.CharField(
        "NameID Format",
        max_length=255,
        default='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        blank=True
    )

    # Security Options
    want_messages_signed = models.BooleanField(default=True)
    want_assertions_signed = models.BooleanField(default=False)
    authn_requests_signed = models.BooleanField(default=True)
    logout_requests_signed = models.BooleanField(default=True)
    logout_responses_signed = models.BooleanField(default=True)
    signature_algorithm = models.CharField(
        max_length=255,
        default='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    )
    digest_algorithm = models.CharField(
        max_length=255,
        default='http://www.w3.org/2001/04/xmlenc#sha256'
    )

    # Misc
    strict = models.BooleanField(default=True)
    debug = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    enabled = models.BooleanField(default=False, help_text="Toggle to enable/disable SAML login.")

    def __str__(self):
        return f"SAML Config (IdP: {self.idp_entity_id})"

    def to_saml_settings(self):
        """
        Returns a dictionary of SAML settings compatible with OneLogin_Saml2_Auth.
        """
        return {
            'strict': self.strict,
            'debug': self.debug,
            'sp': {
                'entityId': self.sp_entity_id,
                'assertionConsumerService': {
                    'url': self.sp_acs_url,
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                },
                'singleLogoutService': {
                    'url': self.sp_slo_url,
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'NameIDFormat': self.name_id_format,
                'x509cert': self.sp_x509cert or '',
                'privateKey': self.sp_private_key or '',
            },
            'idp': {
                'entityId': self.idp_entity_id,
                'singleSignOnService': {
                    'url': self.idp_sso_url,
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'singleLogoutService': {
                    'url': self.idp_slo_url or '',
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                },
                'x509cert': self.idp_x509cert or '',
            },
            'security': {
                'authnRequestsSigned': self.authn_requests_signed,
                'logoutRequestSigned': self.logout_requests_signed,
                'logoutResponseSigned': self.logout_responses_signed,
                'wantMessagesSigned': self.want_messages_signed,
                'wantAssertionsSigned': self.want_assertions_signed,
                'wantNameId': True,  # Usually set True if you want the NameID
                'signatureAlgorithm': self.signature_algorithm,
                'digestAlgorithm': self.digest_algorithm,
                'debug': self.debug,
            },
        }
