# from core.saml.settings import SAML_SETTINGS
# # from saml_auth.models import SAMLProvider


# def get_saml_settings(provider_name):
#     """
#     Get SAML settings dynamically based on the provider.
#     """
#     try:
#         provider = SAMLProvider.objects.get(name=provider_name, is_active=True)
#         return {
#             'strict': SAML_SETTINGS['strict'],
#             'debug': SAML_SETTINGS['debug'],
#             'sp': SAML_SETTINGS['sp'],
#             'idp': {
#                 'entityId': provider.entity_id,
#                 'singleSignOnService': {
#                     'url': provider.sso_url,
#                     'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
#                 },
#                 'singleLogoutService': {
#                     'url': provider.slo_url,
#                     'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
#                 },
#                 'x509cert': provider.x509cert,
#             },
#             'security': SAML_SETTINGS['security'],
#         }
#     except SAMLProvider.DoesNotExist:
#         raise ValueError(f"SAML Provider '{provider_name}' not found or inactive.")
