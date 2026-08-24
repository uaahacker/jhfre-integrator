from django.contrib import admin
from django import forms
from .models import *
from django.utils.timezone import localtime, get_current_timezone_name
from .webhook_responses import safe_webhook_response_metadata
from core.image_upload_validation import validate_branding_image


class CompanyAdminForm(forms.ModelForm):
    class Meta:
        model = Company
        fields = '__all__'

    def clean_logo(self):
        return validate_branding_image(self.cleaned_data.get('logo'))

    def clean_favicon(self):
        return validate_branding_image(self.cleaned_data.get('favicon'), favicon=True)


class DynamicFormAdminForm(forms.ModelForm):
    class Meta:
        model = DynamicForm
        fields = '__all__'

    def clean_custom_logo(self):
        return validate_branding_image(self.cleaned_data.get('custom_logo'))


class IntegrationAdminForm(forms.ModelForm):
    class Meta:
        model = Integration
        fields = '__all__'

    def clean_icon(self):
        return validate_branding_image(self.cleaned_data.get('icon'))


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    form = CompanyAdminForm
    list_display = ('name', 'language', 'timezone', 'show_logo_as_text')
    search_fields = ('name', 'email')
    readonly_fields = ('created_at', 'updated_at')
    def created_at_display(self, obj):
        return localtime(obj.created_at).strftime('%m-%d-%Y %H:%M %Z')
    created_at_display.short_description = 'Created At (Local Time)'

    def updated_at_display(self, obj):
        return localtime(obj.updated_at).strftime('%m-%d-%Y %H:%M %Z')
    updated_at_display.short_description = 'Updated At (Local Time)'
    
@admin.register(DynamicForm)
class DynamicFormAdmin(admin.ModelAdmin):
    form = DynamicFormAdminForm
    list_display = ('formname', 'template_type', 'access_level', 'login_required', 'created_at')
    list_filter = ('template_type', 'access_level', 'login_required', 'created_at')
    search_fields = ('formname', 'form_description')
    readonly_fields = ('uuid', 'created_at')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('uuid', 'formname', 'form_description', 'access_level', 'login_required')
        }),
        ('Template & Styling', {
            'fields': ('template_type', 'custom_logo', 'custom_colors', 'header_text', 'footer_text')
        }),
        ('Sidebar Content (Branded Template)', {
            'fields': (
                ('sidebar_section1_title', 'sidebar_section1_content'),
                ('sidebar_section2_title', 'sidebar_section2_content'),
                ('sidebar_section3_title', 'sidebar_section3_content'),
            ),
            'description': 'These fields are used for the sidebar in the branded template.'
        }),
        ('Integration', {
            'fields': ('webhook_url',)
        }),
        ('Advanced', {
            'fields': ('config', 'created_at'),
            'classes': ('collapse',)
        })
    )
    
admin.site.register(FormPermission)
@admin.register(FormSubmission)
class FormSubmissionAdmin(admin.ModelAdmin):
    """Keep raw historical webhook response JSON out of the admin UI."""

    exclude = ('response',)
    list_display = (
        'submissionID', 'form', 'submitted_at', 'delivery_status',
        'delivery_status_code', 'delivery_truncated',
    )
    readonly_fields = ('delivery_status', 'delivery_status_code', 'delivery_truncated')

    @admin.display(description='Delivery status')
    def delivery_status(self, obj):
        return safe_webhook_response_metadata(obj.response).get('status', '')

    @admin.display(description='HTTP status')
    def delivery_status_code(self, obj):
        return safe_webhook_response_metadata(obj.response).get('status_code', '')

    @admin.display(description='Response truncated')
    def delivery_truncated(self, obj):
        return safe_webhook_response_metadata(obj.response).get('truncated', '')
admin.site.register(FileUpload)
admin.site.register(DataRecord)
admin.site.register(Client)
@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    form = IntegrationAdminForm
