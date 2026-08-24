from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import SSOProvider, SSOAuditLog, SSOUserProfile


# SSOProvider is intentionally not registered: the dedicated superuser-only
# management UI is the supported configuration surface and avoids raw secrets
# being rendered by Django admin.
class SSOProviderAdmin(admin.ModelAdmin):
    list_display = ['name', 'protocol', 'status', 'enabled', 'last_tested_display', 'test_status']
    list_filter = ['protocol', 'status', 'enabled', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at', 'last_tested', 'test_results_display']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'protocol', 'status', 'description', 'enabled', 'allow_registration', 'debug_mode')
        }),
        ('SAML Identity Provider Settings', {
            'fields': (
                'saml_idp_entity_id', 'saml_idp_sso_url', 'saml_idp_sso_binding', 'saml_idp_slo_url',
                'saml_idp_x509cert', 'saml_idp_x509cert_additional',
            ),
            'classes': ['collapse'],
        }),
        ('SAML Service Provider Settings', {
            'fields': (
                'saml_sp_entity_id', 'saml_sp_acs_url', 'saml_sp_slo_url', 
                'saml_sp_x509cert', 'saml_sp_private_key'
            ),
            'classes': ['collapse'],
        }),
        ('SAML Security Settings', {
            'fields': (
                'saml_name_id_format', 'saml_identity_policy', 'saml_immutable_attribute_name',
                'saml_want_messages_signed', 'saml_want_assertions_signed',
                'saml_authn_requests_signed', 'saml_logout_requests_signed', 'saml_logout_responses_signed',
                'saml_signature_algorithm', 'saml_digest_algorithm', 'saml_strict_mode'
            ),
            'classes': ['collapse'],
        }),
        ('OIDC Settings', {
            'fields': (
                'oidc_client_id', 'oidc_client_secret', 'oidc_discovery_url',
                'oidc_authorization_endpoint', 'oidc_token_endpoint', 'oidc_userinfo_endpoint',
                'oidc_jwks_uri', 'oidc_issuer', 'oidc_scopes'
            ),
            'classes': ['collapse'],
        }),
        ('Attribute Mapping', {
            'fields': ('attr_email', 'attr_first_name', 'attr_last_name', 'attr_username'),
            'classes': ['collapse'],
        }),
        ('Testing & Metadata', {
            'fields': ('created_at', 'updated_at', 'last_tested', 'test_results_display'),
            'classes': ['collapse'],
        }),
    )

    def last_tested_display(self, obj):
        if obj.last_tested:
            return obj.last_tested.strftime('%Y-%m-%d %H:%M:%S')
        return 'Never'
    last_tested_display.short_description = 'Last Tested'

    def test_status(self, obj):
        if not obj.test_results:
            return format_html('<span style="color: gray;">Not tested</span>')
        
        if obj.test_results.get('success'):
            return format_html('<span style="color: green;">✓ Passed</span>')
        else:
            return format_html('<span style="color: red;">✗ Failed</span>')
    test_status.short_description = 'Test Status'

    def test_results_display(self, obj):
        if not obj.test_results:
            return 'No test results available'
        
        html = f"<strong>Success:</strong> {obj.test_results.get('success', False)}<br>"
        
        if obj.test_results.get('message'):
            html += f"<strong>Message:</strong> {obj.test_results['message']}<br>"
        
        if obj.test_results.get('errors'):
            html += "<strong>Errors:</strong><br>"
            for error in obj.test_results['errors']:
                html += f"• {error}<br>"
        
        if obj.test_results.get('warnings'):
            html += "<strong>Warnings:</strong><br>"
            for warning in obj.test_results['warnings']:
                html += f"• {warning}<br>"
        
        return format_html(html)
    test_results_display.short_description = 'Test Results'

    actions = ['test_connection', 'enable_provider', 'disable_provider']

    def test_connection(self, request, queryset):
        count = 0
        for provider in queryset:
            provider.test_connection()
            count += 1
        self.message_user(request, f'Tested {count} provider(s)')
    test_connection.short_description = 'Test connection'

    def enable_provider(self, request, queryset):
        count = queryset.update(enabled=True)
        self.message_user(request, f'Enabled {count} provider(s)')
    enable_provider.short_description = 'Enable selected providers'

    def disable_provider(self, request, queryset):
        count = queryset.update(enabled=False)
        self.message_user(request, f'Disabled {count} provider(s)')
    disable_provider.short_description = 'Disable selected providers'


@admin.register(SSOAuditLog)
class SSOAuditLogAdmin(admin.ModelAdmin):
    list_display = ['provider', 'event_type', 'user_identifier', 'ip_address', 'timestamp']
    list_filter = ['event_type', 'provider', 'timestamp']
    search_fields = ['user_identifier', 'ip_address']
    fields = ['provider', 'event_type', 'user_identifier', 'ip_address', 'timestamp']
    readonly_fields = fields
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SSOUserProfile)
class SSOUserProfileAdmin(admin.ModelAdmin):
    list_display = [
        'user_display', 'provider', 'sso_id', 'sso_login_count', 
        'last_login_from_sso', 'is_sso_user'
    ]
    list_filter = ['provider', 'is_sso_user', 'last_login_from_sso', 'created_at']
    search_fields = ['user__username', 'user__email', 'sso_id']
    readonly_fields = [
        'user', 'provider', 'sso_id', 'sso_login_count', 
        'last_login_from_sso', 'created_at', 'updated_at',
        'raw_attributes_display', 'mapped_attributes_display'
    ]
    
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'provider', 'sso_id', 'is_sso_user')
        }),
        ('SSO Attributes', {
            'fields': ('mapped_attributes_display', 'raw_attributes_display'),
            'classes': ['collapse'],
        }),
        ('Login Tracking', {
            'fields': ('sso_login_count', 'last_login_from_sso'),
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ['collapse'],
        }),
    )
    
    def user_display(self, obj):
        return f"{obj.user.get_full_name() or obj.user.username} ({obj.user.email})"
    user_display.short_description = "User"
    user_display.admin_order_field = "user__username"
    
    def raw_attributes_display(self, obj):
        if not obj.raw_attributes:
            return "No raw attributes"
        
        html_content = "<div style='max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 5px;'>"
        for key, value in obj.raw_attributes.items():
            if isinstance(value, (list, dict)):
                html_content += f"<strong>{key}:</strong> {str(value)}<br>"
            else:
                html_content += f"<strong>{key}:</strong> {value}<br>"
        html_content += "</div>"
        return format_html(html_content)
    raw_attributes_display.short_description = "Raw SSO Attributes"
    
    def mapped_attributes_display(self, obj):
        if not obj.mapped_attributes:
            return "No mapped attributes"
        
        html_content = "<div style='max-height: 200px; overflow-y: auto; background: #e8f4f8; padding: 10px; border-radius: 5px;'>"
        for key, value in obj.mapped_attributes.items():
            if isinstance(value, (list, dict)):
                html_content += f"<strong>{key}:</strong> {str(value)}<br>"
            else:
                html_content += f"<strong>{key}:</strong> {value}<br>"
        html_content += "</div>"
        return format_html(html_content)
    mapped_attributes_display.short_description = "Mapped Attributes"
    
    def has_add_permission(self, request):
        return False  # SSO profiles are created automatically
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser  # Only superusers can delete
