from django.contrib.auth.models import Group, Permission
from django.utils import timezone
from django.db import models
from django.contrib.postgres.fields import JSONField
import os
from os.path import join
from django.conf import settings
from django.templatetags.static import static
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from timezone_field import TimeZoneField 
from django.contrib.auth import get_user_model
import uuid # Add this import


    
class Company(models.Model):
    name = models.CharField(max_length=255, unique=True)
    logo = models.FileField(upload_to='company_logos/', blank=True, null=True)
    favicon = models.FileField(upload_to='company_favicons/', blank=True, null=True)
    show_logo_as_text = models.BooleanField(default=True)
    email = models.EmailField(max_length=255, unique=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    language = models.CharField(
        max_length=10,
        choices=[('en', 'English'), ('es', 'Spanish'), ('fr', 'French')],
        default='en'
    )
    
    timezone = TimeZoneField(default='UTC')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f'{self.name} ({self.language} - {self.timezone})'
    
    def get_logo_display(self):
        """
        Return either the logo image or the company name based on the toggle.
        """
        if self.show_logo_as_text or not self.logo:
            return self.name
        return self.logo.url
    
    
    def get_favicon_url(self):
        """
        Returns the URL of the favicon if available.
        """
        return self.favicon.url if self.favicon else None

    class Meta:
        db_table = "company"





class DynamicForm(models.Model):
    PERMISSION_CHOICES = [
        ('public', 'Public'),
        ('authenticated', 'Authenticated Users'),
        ('selected_users', 'Specific Users'),
    ]
    
    TEMPLATE_CHOICES = [
        ('default', 'Default Template'),
        ('corporate', 'Corporate Template'),
        ('minimal', 'Minimal Template'),
        ('modern', 'Modern Template'),
        ('classic', 'Classic Template'),
        ('branded', 'Branded Template'),
    ]
    
    uuid = models.CharField(
        max_length=36,
        unique=True,
        default=uuid.uuid4  # Ensure new forms get a UUID by default
    )  # Unique identifier for the form
    formname = models.CharField(max_length=255,null=True,blank=True)  # Name of the form
    form_description = models.CharField(max_length=255,null=True,blank=True)  # Name of the for the front side
    config = models.TextField(default='{}')  # JSON configuration for fields
    webhook_url = models.URLField(blank=True, null=True)  # Webhook URL for data submission
    headers = models.JSONField(default=dict, blank=True)  # Headers to be sent with webhook
    success_message = models.TextField(blank=True, null=True)  # Custom success message
    enable_redirect = models.BooleanField(default=False)  # Enable redirect after submission
    redirect_url = models.URLField(blank=True, null=True)  # URL to redirect to after submission
    access_level = models.CharField(
        max_length=20,
        choices=PERMISSION_CHOICES,
        default='public',  # IMPORTANT: Default to 'public'
    )
    login_required = models.BooleanField(default=True)  # Added field for login requirement
    template_type = models.CharField(
        max_length=20,
        choices=TEMPLATE_CHOICES,
        default='default'
    )
    custom_logo = models.ImageField(upload_to='form_logos/', blank=True, null=True)
    custom_colors = models.JSONField(default=dict, blank=True)  # Store custom color scheme
    footer_text = models.TextField(blank=True, null=True)
    header_text = models.TextField(blank=True, null=True)
    
    # Sidebar content for branded template
    sidebar_section1_title = models.CharField(max_length=100, default='Information', blank=True)
    sidebar_section1_content = models.TextField(default='Please fill out all required fields marked with an asterisk (*) to complete your submission.', blank=True)
    sidebar_section2_title = models.CharField(max_length=100, default='Contact', blank=True)
    sidebar_section2_content = models.TextField(default='If you need assistance completing this form, please contact our support team.', blank=True)
    sidebar_section3_title = models.CharField(max_length=100, default='Privacy', blank=True)
    sidebar_section3_content = models.TextField(default='Your information is secure and will only be used for the purposes stated in our privacy policy.', blank=True)
    
    # SSO Integration Settings
    enable_sso_prepopulate = models.BooleanField(default=False, help_text="Enable SSO field prepopulation")
    sso_prepopulate_fields = models.JSONField(default=dict, blank=True, help_text="JSON mapping of form fields to SSO attributes")
    sso_disabled_fields = models.JSONField(default=list, blank=True, help_text="List of field names that should be disabled for SSO users")
    auto_redirect_to_sso = models.BooleanField(default=True, help_text="Automatically redirect to SSO login instead of showing login page")
    
    # Dynamic Options Configuration
    dynamic_options_config = models.JSONField(default=dict, blank=True, help_text="Configuration for dynamic dropdown/radio/checkbox options")
    
    created_at = models.DateTimeField(default=timezone.now)  # Set a default value


    def __str__(self):
        return self.formname if self.formname else f"Form {self.uuid}"

    class Meta:
        db_table = "dynamicform"

class FormSubmission(models.Model):
    submissionID = models.CharField(max_length=36, unique=True,null=True,blank=True)
    form = models.ForeignKey(DynamicForm, on_delete=models.SET_NULL, null=True, blank=True)
    submission_data = models.JSONField()  # Store submitted form data as JSON
    response = models.JSONField(default=dict, blank=True)  # Store response from webhook
    form_uuid = models.CharField(max_length=36, null=True, blank=True)
    submitted_at = models.DateTimeField(default=timezone.now)
    
    def save(self, *args, **kwargs):
        # Save form UUID for reference before form deletion
        if self.form and not self.form_uuid:
            self.form_uuid = self.form.uuid
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Submission for {self.form.formname} at {self.submitted_at}"

    class Meta:
        db_table = "formsubmission"

class FileUpload(models.Model):
    submission = models.ForeignKey(FormSubmission, on_delete=models.CASCADE, related_name='files')
    field_name = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/')

    def __str__(self):
        return f"File for {self.field_name} in submission {self.submission.id}" 
    def filename(self):
        return os.path.basename(self.file.name)

    class Meta:
        db_table = "fileupload"

class DataRecord(models.Model):
    # Identifies the client or tenant
    client = models.ForeignKey('Client', on_delete=models.CASCADE)
    # Identifies the source system (e.g., PMWeb, SystemX)
    source_system = models.CharField(max_length=100)
    # Timestamp when the data was created in the source system
    source_timestamp = models.DateTimeField()
    # The data payload from the source system
    data = models.JSONField()
    # Timestamp when the record was created in our system
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.client.name} - {self.source_system} - {self.source_timestamp}"
    
    class Meta:
        db_table = "datarecord"
    
    
class FormPermission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='form_permissions')
    form = models.ForeignKey(DynamicForm, on_delete=models.CASCADE, related_name='permissions')
    assigned_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} -> {self.form.formname}"
    
    class Meta:
        db_table = "formpermission"
    

        
class Client(models.Model):
    name = models.CharField(max_length=255)
    # Additional client-specific fields
    
    def __str__(self):
        return self.name 
    
    class Meta:
        db_table = "client"
    
  
    
# -------------integrations

class Integration(models.Model):
    """Model to manage API integrations."""
    name = models.CharField(max_length=255, unique=True)
    icon = models.FileField(upload_to='integration_icons/', null=True, blank=True)
    description = models.TextField()
    fields = models.JSONField(default=dict)  # Dynamic field definitions, e.g., {"api_key": "API Key", "api_secret": "API Secret"}
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = "integration"


class IntegrationCredential(models.Model):
    """Model to store API credentials for a user and integration."""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    credentials = models.JSONField(null=True,blank=True)  # Dynamic key-value pairs for API credentials
    enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "integrationcredential"
        unique_together = ('user', 'integration')  # Ensures one user-integration pair

    def __str__(self):
        return f"{self.user.username} - {self.integration.name}"

class DatabaseConnection(models.Model):
    """
    Model to store database connection information.
    """
    CONNECTION_TYPES = (
        ('mssql', 'Microsoft SQL Server'),
        ('mysql', 'MySQL'),
        ('postgresql', 'PostgreSQL'),
        ('oracle', 'Oracle'),
    )
    
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='database_connections')
    name = models.CharField(max_length=100)
    connection_type = models.CharField(max_length=20, choices=CONNECTION_TYPES)
    server = models.CharField(max_length=255)
    port = models.CharField(max_length=10)
    database_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=255)  # Will be encrypted
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.name} ({self.connection_type})"
    
    def set_password(self, password):
        """Encrypt and store the password"""
        from django.conf import settings
        from cryptography.fernet import Fernet
        
        key = settings.ENCRYPTION_KEY.encode()
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        self.password = encrypted_password.decode()
    
    def get_password(self):
        """Decrypt and return the password"""
        from django.conf import settings
        from cryptography.fernet import Fernet
        
        key = settings.ENCRYPTION_KEY.encode()
        cipher_suite = Fernet(key)
        decrypted_password = cipher_suite.decrypt(self.password.encode())
        return decrypted_password.decode()
    
    class Meta:
        db_table = "databaseconnection"
        ordering = ['-is_default', 'name']
        unique_together = ['user', 'name']


class SavedQuery(models.Model):
    """
    Model to store saved SQL queries.
    """
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='saved_queries')
    connection = models.ForeignKey(DatabaseConnection, on_delete=models.CASCADE, related_name='queries')
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    query_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_run = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "savedquery"
        ordering = ['name']
        unique_together = ['user', 'name']


class SavedProcedureExecution(models.Model):
    """
    Model to store saved stored procedure executions with parameters.
    """
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='saved_procedure_executions')
    connection = models.ForeignKey(DatabaseConnection, on_delete=models.CASCADE, related_name='procedure_executions')
    name = models.CharField(max_length=100)
    procedure_name = models.CharField(max_length=100)
    procedure_schema = models.CharField(max_length=100, blank=True, null=True)
    parameters = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_run = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "savedprocedureexecution"
        ordering = ['name']
        unique_together = ['user', 'name']


class ApprovedProcedure(models.Model):
    """An explicitly reviewed stored procedure that may be considered for execution."""

    READ_EXPECTED = 'READ_EXPECTED'
    MUTATING = 'MUTATING'
    BEHAVIOR_CHOICES = (
        (READ_EXPECTED, 'Read expected'),
        (MUTATING, 'Mutating'),
    )

    connection = models.ForeignKey(
        DatabaseConnection,
        on_delete=models.CASCADE,
        related_name='approved_procedures',
    )
    engine = models.CharField(max_length=20, choices=DatabaseConnection.CONNECTION_TYPES)
    database_name = models.CharField(max_length=100)
    schema = models.CharField(max_length=100)
    procedure_name = models.CharField(max_length=100)
    # PostgreSQL overloads are not supported until a reliable signature can be approved.
    signature = models.CharField(max_length=255, blank=True, default='')
    behavior = models.CharField(max_length=20, choices=BEHAVIOR_CHOICES)
    enabled = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        get_user_model(),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='approved_procedures',
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'approvedprocedure'
        constraints = [
            models.UniqueConstraint(
                fields=['connection', 'schema', 'procedure_name', 'signature'],
                name='unique_approved_procedure_identity',
            ),
        ]

    def __str__(self):
        return f'{self.connection_id}:{self.schema}.{self.procedure_name}'


class ApprovedProcedureParameter(models.Model):
    """The server-side parameter contract for an approved procedure."""

    INPUT = 'IN'
    OUTPUT = 'OUT'
    INPUT_OUTPUT = 'INOUT'
    DIRECTION_CHOICES = (
        (INPUT, 'Input'),
        (OUTPUT, 'Output'),
        (INPUT_OUTPUT, 'Input/output'),
    )

    approved_procedure = models.ForeignKey(
        ApprovedProcedure,
        on_delete=models.CASCADE,
        related_name='parameters',
    )
    ordinal = models.PositiveIntegerField()
    name = models.CharField(max_length=128)
    direction = models.CharField(max_length=5, choices=DIRECTION_CHOICES, default=INPUT)
    database_type = models.CharField(max_length=100)
    required = models.BooleanField(default=True)
    nullable = models.BooleanField(default=False)
    max_length = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        db_table = 'approvedprocedureparameter'
        ordering = ['ordinal']
        constraints = [
            models.UniqueConstraint(
                fields=['approved_procedure', 'ordinal'],
                name='unique_approved_procedure_parameter_ordinal',
            ),
            models.UniqueConstraint(
                fields=['approved_procedure', 'name'],
                name='unique_approved_procedure_parameter_name',
            ),
        ]

    def __str__(self):
        return f'{self.approved_procedure_id}:{self.ordinal}:{self.name}'


class ProcedureExecutionAudit(models.Model):
    """Sanitized, persistent security history for authorized procedure attempts."""

    SUCCESS = 'SUCCESS'
    VALIDATION_FAILED = 'VALIDATION_FAILED'
    APPROVAL_DISABLED = 'APPROVAL_DISABLED'
    MUTATING_DENIED = 'MUTATING_DENIED'
    IDENTITY_MISMATCH = 'IDENTITY_MISMATCH'
    READONLY_SETUP_FAILED = 'READONLY_SETUP_FAILED'
    CONNECTION_FAILED = 'CONNECTION_FAILED'
    TIMEOUT = 'TIMEOUT'
    EXECUTION_FAILED = 'EXECUTION_FAILED'
    RESULT_PROCESSING_FAILED = 'RESULT_PROCESSING_FAILED'
    FAILURE_CATEGORY_CHOICES = (
        (SUCCESS, 'Success'),
        (VALIDATION_FAILED, 'Validation failed'),
        (APPROVAL_DISABLED, 'Approval disabled'),
        (MUTATING_DENIED, 'Mutating procedure denied'),
        (IDENTITY_MISMATCH, 'Approval identity mismatch'),
        (READONLY_SETUP_FAILED, 'Read-only setup failed'),
        (CONNECTION_FAILED, 'Connection failed'),
        (TIMEOUT, 'Timeout'),
        (EXECUTION_FAILED, 'Execution failed'),
        (RESULT_PROCESSING_FAILED, 'Result processing failed'),
    )

    user = models.ForeignKey(
        get_user_model(),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='procedure_execution_audits',
    )
    approved_procedure = models.ForeignKey(
        ApprovedProcedure,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='execution_audits',
    )
    started_at = models.DateTimeField(default=timezone.now)
    duration_ms = models.PositiveIntegerField(default=0)
    success = models.BooleanField(default=False)
    failure_category = models.CharField(max_length=32, choices=FAILURE_CATEGORY_CHOICES)
    row_count = models.PositiveIntegerField(default=0)
    result_set_count = models.PositiveIntegerField(default=0)
    truncated = models.BooleanField(default=False)
    engine_snapshot = models.CharField(max_length=20)
    database_name_snapshot = models.CharField(max_length=100)
    schema_snapshot = models.CharField(max_length=100)
    procedure_name_snapshot = models.CharField(max_length=100)

    class Meta:
        db_table = 'procedureexecutionaudit'
        ordering = ['-started_at', '-id']
        indexes = [
            models.Index(fields=['user', 'started_at']),
            models.Index(fields=['approved_procedure', 'started_at']),
        ]

    def __str__(self):
        return f'{self.started_at.isoformat()}:{self.failure_category}:{self.procedure_name_snapshot}'
