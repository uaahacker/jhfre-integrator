from django.contrib import admin
from .models import SamlConfiguration


@admin.register(SamlConfiguration)
class SamlConfigurationAdmin(admin.ModelAdmin):
    list_display = (
        'idp_entity_id', 
        'sp_entity_id',  
        'updated_at',
        'enabled')
    # Optional: define fields or fieldsets for clarity
    # fieldsets = (
    #     ('IdP Settings', {
    #         'fields': ('idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_x509cert')
    #     }),
    #     ('SP Settings', {
    #         'fields': ('sp_entity_id', 'sp_acs_url', 'sp_slo_url', 'sp_x509cert', 'sp_private_key')
    #     }),
    #     ('Security', {
    #         'fields': ('want_messages_signed', 'want_assertions_signed', 'authn_requests_signed',
    #                    'logout_requests_signed', 'logout_responses_signed',
    #                    'signature_algorithm', 'digest_algorithm', 'strict', 'debug')
    #     }),
    # )