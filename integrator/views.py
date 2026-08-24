# views.py

# ============================================================================
#                       IMPORT STATEMENT DESCRIPTIONS
# ============================================================================
# This block describes the imported modules and their primary uses.
# These libraries are essential for building the user interface, handling authentication,
# responding to web requests, creating dynamic forms, interacting with databases, 
# handling authentication with SAML, logging errors, using REST APIs, and securing the site.

# ============================================================================
#                         DJANGO CORE IMPORTS
# ============================================================================
import json  # To handle JSON data (parsing, serializing)
import time
import uuid as uuid_lib  # To generate UUIDs for unique identifiers
from functools import wraps

from django.shortcuts import render, get_object_or_404, redirect, resolve_url  # For handling shortcuts for views
from django.contrib.auth.views import redirect_to_login  # For redirecting unauthorized users to the login page
from django.urls import reverse_lazy, reverse  # For handling url reversals
from django.http import FileResponse, Http404, HttpResponseForbidden, HttpResponseRedirect, JsonResponse  # For creating HTTP responses (including JSON)
from django.views import View  # Base class for generic views
from django.views.generic import TemplateView  # For rendering templates
from django.contrib.auth import login, logout, get_user_model, authenticate # For handling authentication related tasks

from django.conf import settings # To access the application settings
from django.contrib.auth.decorators import login_required # for views that need authentication
from django.views.decorators.http import require_POST # decorator that checks for POST requests in the views
from django.contrib import messages  # For displaying success and error messages in templates
from django.template import loader
# ============================================================================
#                    ONE LOGIN SAML IMPORTS
# ============================================================================
from onelogin.saml2.auth import OneLogin_Saml2_Auth # SAML Authentication
from onelogin.saml2.settings import OneLogin_Saml2_Settings  # SAML Settings
from django.utils.http import url_has_allowed_host_and_scheme # to validate if the urls are allowed

# ============================================================================
#                         LOGGING AND DATABASE IMPORTS
# ============================================================================
import logging # To log errors
from django.db import IntegrityError, transaction  # Handles database integrity errors
import os # To work with the OS like getting environment variables
from django.contrib.auth.forms import AuthenticationForm # To handle authentication form
# models
from .models import * # Import from all files inside models folder
from django.db.models import Count # used for counting number of related records

# ============================================================================
#                 AUTH/USER HANDLING AND PERMISSION IMPORTS
# ============================================================================
from django.contrib.auth.models import User # User model
from django.contrib.auth.hashers import make_password # Hash the password
from django.db.models import Q # Complex queries using Q
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin # For view access checks

# ============================================================================
#                       DYNAMIC FORM IMPORTS
# ============================================================================
from .utils import create_form_class # for creating a dynamic form class
from .upload_validation import UploadValidationError, validate_dynamic_uploads
from .webhook_security import (
    WebhookDeliveryError,
    WebhookSecurityError,
    deliver_webhook,
    validate_webhook_headers,
    validate_webhook_url,
)
from .webhook_headers import (
    DuplicateWebhookHeaderError,
    WebhookHeaderError,
    WebhookHeaderSecretError,
    browser_safe_webhook_headers,
    parse_webhook_configuration_json,
    parse_webhook_headers_json,
    prepare_webhook_headers_for_storage,
)
from .webhook_responses import build_webhook_response_metadata, safe_webhook_response_metadata
from django.forms import Form, CharField, IntegerField, EmailField # base form handling
from django.utils import timezone
import requests #used to make HTTP requests

# ============================================================================
#                        REST API IMPORTS
# ============================================================================
from rest_framework.decorators import api_view  # For API view decorators
from rest_framework.response import Response   # To create responses for REST API calls

logger = logging.getLogger(__name__) # Logger object

# ============================================================================
#                    CUSTOM DECORATORS IMPORTS
# ============================================================================
# decorator
from django.utils.decorators import method_decorator # For decorating class-based view methods
from .decorators import user_has_permission # For user access controls


# ============================================================================
#                 DATABASE CONNECTION IMPORTS
# ============================================================================
# ----connection to mssql
from django.db import connections, OperationalError # Database connection related imports
from django.shortcuts import render # For rendering templates
from .db_config import * # Configuration for MSSQL
from .db_utils import fetch_data_from_connection, fetch_data_from_integration
from .db_config import fetch_mssql_data
from .query_execution import (
    ExternalQueryTimeoutError,
    ReadOnlyEnforcementError,
    configure_postgresql_statement_timeout,
    establish_mysql_read_only_transaction,
    establish_postgresql_read_only_transaction,
    fetch_limited_rows,
    get_external_query_limits,
    get_procedure_execution_limits,
    is_timeout_error,
)
from .procedure_execution import (
    ProcedureExecutionValidationError,
    build_procedure_call,
    fetch_bounded_procedure_result_sets,
    parameter_type_category,
    require_safe_identifier,
    validate_approved_procedure,
    validate_parameter_values,
)
from .sql_policy import SqlPolicyViolation, USER_FACING_ERROR, validate_read_only_query
from .integration_credentials import (
    browser_credential_state, encrypt_credentials_for_storage, merge_submitted_credentials,
)


class SuperuserRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Restrict administrative browser views to Django superusers."""

    def test_func(self):
        return self.request.user.is_superuser


class JsonSuperuserRequiredView(View):
    """Return JSON authentication errors for administrative API views."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication required.'}, status=401)
        if not request.user.is_superuser:
            return JsonResponse({'detail': 'Administrative access required.'}, status=403)
        return super().dispatch(request, *args, **kwargs)


class DebugSuperuserRequiredMixin(SuperuserRequiredMixin):
    """Expose diagnostic browser views only to superusers in debug mode."""

    def dispatch(self, request, *args, **kwargs):
        if not settings.DEBUG:
            raise Http404
        return super().dispatch(request, *args, **kwargs)


def debug_superuser_required_json(view_func):
    """Expose diagnostic JSON endpoints only to superusers in debug mode."""

    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not settings.DEBUG:
            return JsonResponse({'detail': 'Not found.'}, status=404)
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication required.'}, status=401)
        if not request.user.is_superuser:
            return JsonResponse({'detail': 'Administrative access required.'}, status=403)
        return view_func(request, *args, **kwargs)

    return wrapped_view


def form_delivery_access_denial(request, dynamic_form, anonymous_response=None):
    """Return a denial response unless the request can use the delivered form."""
    access_level = dynamic_form.access_level
    if access_level == 'public':
        return None

    if not request.user.is_authenticated:
        if anonymous_response is not None:
            return anonymous_response()
        return redirect_to_login(request.get_full_path(), login_url=reverse('login'))

    if access_level == 'authenticated':
        return None

    if access_level == 'selected_users' and FormPermission.objects.filter(
        form=dynamic_form,
        user=request.user,
    ).exists():
        return None

    return HttpResponseForbidden(
        loader.render_to_string('pages/forms/access_denied.html', request=request)
    )

class LoginView(TemplateView):
    """
    View for handling user login.
    """
    template_name = 'authentication/layouts/corporate/sign-in.html'

    def get(self, request, *args, **kwargs):
        # If the user is already logged in, redirect to the next page or dashboard
        if request.user.is_authenticated:
            next_url = request.GET.get('next') or reverse('home')
            if not url_has_allowed_host_and_scheme(
                url=next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
            ):
                next_url = reverse('home')
            return redirect(next_url)
        
        # Pass the 'next' parameter to the template if it exists
        next_url = request.GET.get('next')
        context = {}
        if next_url:
            context['next'] = next_url
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        # Handle POST request to authenticate user
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            # Redirect to 'next' URL if provided in POST or GET, otherwise to 'home'
            next_url = request.POST.get('next') or request.GET.get('next') or reverse('home')
            
            # Ensure the next_url is safe to redirect to
            if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
                next_url = reverse('home')

            return redirect(next_url)
        else:
            # Render the template with an error message
            # Pass the 'next' parameter back to the template if it exists, to repopulate the form
            next_url = request.POST.get('next') 
            context = {'error': 'Invalid username or password'}
            if next_url:
                context['next'] = next_url
            return render(request, self.template_name, context)


class LogoutView(View):
    """
    View for logging out a user.
    """
    def post(self, request, *args, **kwargs):
        logout(request)
        return HttpResponseRedirect('/login/')

class publicHomeView(TemplateView):
    """
    View for the public home page.
    """
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(reverse('home'))
        else:
            return redirect(reverse('login'))

# Existing class-based view
class HomePageView(LoginRequiredMixin, TemplateView):
    """
    View for rendering the main dashboard page.
    """
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Dashboard" # set the title here
        return context

    def get(self, request):
      
        return render(request, "dashboard.html")

# Converted class-based views
class InitiativesView(SuperuserRequiredMixin, TemplateView):
    """
    View to display Initiatives and Data from MSSQL.
    """
    template_name = 'pages/dbview/dbview.html'
    login_url = '/login/'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Initiatives" # set the title here
        return context

    def get(self, request):
        # Fetch initial data from default table
        query = "SELECT TOP 10 Name, Email, Phone, CountryId, HomeStateId FROM Application_ExternalUsers"
        data = fetch_mssql_data(request.user, query)

        # Fetch list of all tables
        table_query = """
            SELECT TABLE_NAME
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME ASC
        """
        tables = fetch_mssql_data(request.user, table_query)
        table_list = [row['TABLE_NAME'] for row in tables]
        

        return render(request, self.template_name, {
            'data': data,
            'tables': table_list
        })



class FetchTableDataView(JsonSuperuserRequiredView):
    """
    View to fetch table data from a dynamically selected MSSQL table.
    """
    def get(self, request):
        table_name = request.GET.get('table')
        if not table_name:
            return JsonResponse({'error': 'Table name is required'}, status=400)

        query = f"SELECT TOP 10 * FROM {table_name}"
        data = fetch_mssql_data(request.user, query)

        return JsonResponse({'data': data})

class AdminView(LoginRequiredMixin, TemplateView):
    """
    View for displaying the admin page.
    """
    template_name = 'admin.html'
    login_url = '/login/'
    def get_context_data(self, **kwargs):
      context = super().get_context_data(**kwargs)
      context['title'] = "Admin" # set the title here
      return context

class SettingsView(LoginRequiredMixin, TemplateView):
    """
    View for rendering the settings page.
    """
    template_name = 'settings.html'
    login_url = '/login/'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Settings" # set the title here
        return context


class ManageFormsView(SuperuserRequiredMixin, TemplateView):
    """
    View for managing dynamic forms.
    """
    template_name = 'pages/forms/manage-forms.html'
    login_url = '/login/'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Manage Forms" # set the title here
        context['forms'] = DynamicForm.objects.all().order_by('-created_at')
        return context

class CreateFormsView(SuperuserRequiredMixin, TemplateView):
    """
    View for creating new dynamic forms.
    """
    template_name = 'pages/forms/create-forms.html'
    login_url = '/login/'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Create Form" # set the title here
        context['forms'] = DynamicForm.objects.all().order_by('-created_at')
        
        # Get DatabaseConnection objects
        if self.request.user.is_superuser or self.request.user.is_staff:
            # Admin/superuser can see all connections
            db_connections = DatabaseConnection.objects.filter(is_active=True)
        else:
            # Regular users see only their own connections
            db_connections = DatabaseConnection.objects.filter(user=self.request.user, is_active=True)
        
        # Get enabled database integrations (identified by having database connection fields)
        if self.request.user.is_superuser or self.request.user.is_staff:
            # Admin/superuser can see all integrations
            db_integrations = IntegrationCredential.objects.filter(
                enabled=True
            ).select_related('integration')
        else:
            # Regular users see only their own integrations
            db_integrations = IntegrationCredential.objects.filter(
                user=self.request.user,
                enabled=True
            ).select_related('integration')
        
        # Filter integrations that have database fields (host, database, password, username)
        db_integrations = [
            cred for cred in db_integrations 
            if all(field in cred.integration.fields for field in ['host', 'database', 'password', 'username'])
        ]
        
        # Combine both types into a single list with a unified format
        all_connections = []
        
        # Add DatabaseConnection objects
        for conn in db_connections:
            all_connections.append({
                'id': f"db_{conn.id}",  # Prefix with 'db_' to distinguish from integrations
                'name': conn.name,
                'type': 'database_connection',
                'connection_type': conn.connection_type
            })
        
        # Add database integrations
        for cred in db_integrations:
            all_connections.append({
                'id': f"int_{cred.integration.id}",  # Prefix with 'int_' to distinguish from database connections
                'name': cred.integration.name,
                'type': 'integration',
                'connection_type': 'integration'
            })
        
        context['database_connections'] = all_connections
        return context



class CreateFrom(JsonSuperuserRequiredView):
    """
    View to handle creation of Dynamic Form data
    """
    login_url = '/login/'
    def post(self, request, *args, **kwargs):
        if request.method == "POST":
            # Parse JSON input
            form_data = parse_webhook_configuration_json(request.body)
            formname = form_data.get("formname", "")
            form_description = form_data.get("form_description", "")
            fields = form_data.get("fields", {})
            webhookurl = form_data.get("webhookurl", "")
            headers = form_data.get("headers", {})
            success_message = form_data.get("success_message", "")
            enable_redirect = form_data.get("enable_redirect", False)
            redirect_url = form_data.get("redirect_url", "")
            
            # Template-related fields
            template_type = form_data.get("template_type", "default")
            custom_colors = form_data.get("custom_colors", "{}")
            header_text = form_data.get("header_text", "")
            footer_text = form_data.get("footer_text", "")

            try:
                webhookurl = validate_webhook_url(webhookurl)
                headers = prepare_webhook_headers_for_storage(headers)
                headers = validate_webhook_headers(headers)
            except DuplicateWebhookHeaderError:
                return JsonResponse({'error': 'Duplicate webhook header name.'}, status=400)
            except WebhookHeaderSecretError:
                return JsonResponse({'error': 'Secret value configuration is invalid.'}, status=400)
            except WebhookHeaderError:
                return JsonResponse({'error': 'Invalid webhook header configuration.'}, status=400)
            except WebhookSecurityError:
                return JsonResponse({'error': 'Webhook configuration is not allowed.'}, status=400)
            

            # Generate a unique form link
            form_uuid = str(uuid_lib.uuid4())
            User = get_user_model()
            user = User.objects.get(username=request.user)

            # Save form configuration in the database, including webhook, headers, and template data
            dynamic_form = DynamicForm(
                uuid=form_uuid,
                formname=formname,
               form_description = form_description,
                config=json.dumps(fields),
                webhook_url=webhookurl,
                headers=headers,
                success_message=success_message,
                enable_redirect=enable_redirect,
                redirect_url=redirect_url if enable_redirect else "",
                template_type=template_type,
                custom_colors=custom_colors,
                header_text=header_text,
                footer_text=footer_text
            )
            dynamic_form.save()

            # Return the link to the generated form
            form_link = request.build_absolute_uri(reverse("fill_form", args=[form_uuid]))
            return JsonResponse({"form_link": form_link})

        return JsonResponse({"error": "Only POST requests are allowed"}, status=400)


class FetchDatabaseDataView(JsonSuperuserRequiredView):
    """Execute form-builder preview queries for superusers only."""

    def post(self, request):
        try:
            data = json.loads(request.body)
            query = data.get('query')
            connection_id = data.get('connection_id')

            if not query:
                return JsonResponse({'error': 'Query not provided'}, status=400)
            if not connection_id:
                return JsonResponse({'error': 'Database connection not selected'}, status=400)

            limits = get_external_query_limits()

            policy_result = validate_read_only_query(query)
            if not policy_result.allowed:
                logger.warning('Blocked form-builder preview query by SQL policy (%s).', policy_result.code)
                return JsonResponse({'error': USER_FACING_ERROR}, status=400)

            if connection_id.startswith('db_'):
                result = fetch_data_from_connection(
                    request.user,
                    connection_id.replace('db_', ''),
                    query,
                    max_rows=limits.admin_max_rows,
                    execution_context='form-builder database preview',
                )
            elif connection_id.startswith('int_'):
                result = fetch_data_from_integration(
                    request.user,
                    connection_id.replace('int_', ''),
                    query,
                    max_rows=limits.admin_max_rows,
                    execution_context='form-builder database preview',
                )
            else:
                result = fetch_data_from_connection(
                    request.user,
                    connection_id,
                    query,
                    max_rows=limits.admin_max_rows,
                    execution_context='form-builder database preview',
                )

            return JsonResponse(result, safe=False)
        except ExternalQueryTimeoutError:
            logger.warning('Form-builder database preview timed out.')
            return JsonResponse({'error': 'Database query timed out.'}, status=504)
        except ReadOnlyEnforcementError:
            logger.warning('Form-builder database read-only protection could not be established.')
            return JsonResponse({'error': 'Database preview failed.'}, status=500)
        except Exception:
            logger.warning('Form-builder database preview failed.')
            return JsonResponse({'error': 'Database preview failed.'}, status=500)



class EditFormView(SuperuserRequiredMixin, View):
    """
    View to handle editing a dynamic form.
    """
    login_url = '/login/'
    
    def get(self, request, uuid, *args, **kwargs):
        dynamic_form = get_object_or_404(DynamicForm, uuid=uuid)
        
        # Get DatabaseConnection objects
        if request.user.is_superuser or request.user.is_staff:
            # Admin/superuser can see all connections
            db_connections = DatabaseConnection.objects.filter(is_active=True)
        else:
            # Regular users see only their own connections
            db_connections = DatabaseConnection.objects.filter(user=request.user, is_active=True)
        
        # Get enabled database integrations (identified by having database connection fields)
        if request.user.is_superuser or request.user.is_staff:
            # Admin/superuser can see all integrations
            db_integrations = IntegrationCredential.objects.filter(
                enabled=True
            ).select_related('integration')
        else:
            # Regular users see only their own integrations
            db_integrations = IntegrationCredential.objects.filter(
                user=request.user,
                enabled=True
            ).select_related('integration')
        
        # Filter integrations that have database fields (host, database, password, username)
        db_integrations = [
            cred for cred in db_integrations 
            if all(field in cred.integration.fields for field in ['host', 'database', 'password', 'username'])
        ]
        
        # Combine both types into a single list with a unified format
        all_connections = []
        
        # Add DatabaseConnection objects
        for conn in db_connections:
            all_connections.append({
                'id': f"db_{conn.id}",  # Prefix with 'db_' to distinguish from integrations
                'name': conn.name,
                'type': 'database_connection',
                'connection_type': conn.connection_type
            })
        
        # Add database integrations
        for cred in db_integrations:
            all_connections.append({
                'id': f"int_{cred.integration.id}",  # Prefix with 'int_' to distinguish from database connections
                'name': cred.integration.name,
                'type': 'integration',
                'connection_type': 'integration'
            })
        
        return render(request, "pages/forms/edit-form.html", {
            "form": dynamic_form,
            "browser_headers_json": json.dumps(browser_safe_webhook_headers(dynamic_form.headers)),
            "database_connections": all_connections,
            "sso_prepopulate_fields_json": json.dumps(dynamic_form.sso_prepopulate_fields) if dynamic_form.sso_prepopulate_fields else '{}',
            "sso_disabled_fields_json": json.dumps(dynamic_form.sso_disabled_fields) if dynamic_form.sso_disabled_fields else '[]',
        })

    def post(self, request, uuid, *args, **kwargs): # 'uuid' here is the original UUID from the URL path
        logger.info('Form update requested for form_uuid=%s.', uuid)

        dynamic_form = get_object_or_404(DynamicForm, uuid=uuid)

        try:
            form_data = json.loads(request.body)

            proposed_webhook_url = form_data.get("webhook_url", dynamic_form.webhook_url)
            try:
                proposed_webhook_url = validate_webhook_url(proposed_webhook_url)
            except WebhookSecurityError:
                return JsonResponse({'error': 'Webhook configuration is not allowed.'}, status=400)

            # Update formname
            new_formname = form_data.get("formname", dynamic_form.formname)
            if dynamic_form.formname != new_formname:
                dynamic_form.formname = new_formname

            # Update form_description
            new_form_description = form_data.get("form_description", dynamic_form.form_description)
            if dynamic_form.form_description != new_form_description:
                dynamic_form.form_description = new_form_description
            
            # Update UUID if provided and changed
            new_uuid_from_payload = form_data.get("uuid", str(dynamic_form.uuid)).strip() # Get new UUID from payload, strip whitespace
            original_uuid_on_instance = str(dynamic_form.uuid) # Current UUID on model instance (same as from DB at this point)

            if original_uuid_on_instance != new_uuid_from_payload:
                # Validate new UUID format
                try:
                    uuid_lib.UUID(new_uuid_from_payload)
                except ValueError:
                    error_msg = f"Invalid UUID format: '{new_uuid_from_payload}'. Please provide a valid UUID."
                    logger.warning(f"Invalid UUID format provided: {new_uuid_from_payload} for form PK {dynamic_form.pk}")
                    return JsonResponse({"error": error_msg}, status=400)

                # Check if the new UUID already exists for another form (excluding the current one by its PK)
                if DynamicForm.objects.filter(uuid=new_uuid_from_payload).exclude(pk=dynamic_form.pk).exists():
                    error_msg = f"UUID '{new_uuid_from_payload}' already exists. Please choose a unique UUID."
                    logger.warning(f"Attempt to change UUID to an existing UUID: {new_uuid_from_payload} for form PK {dynamic_form.pk}")
                    return JsonResponse({"error": error_msg}, status=400)
                
                dynamic_form.uuid = new_uuid_from_payload # Update the UUID on the model instance

            # Update config (fields)
            if "fields" in form_data:
                fields_data = form_data.get("fields")
                
                # ENHANCED FIX: Restore missing dynamic configurations and fix field types
                if isinstance(fields_data, list):
                    # Get original form configuration for comparison
                    original_config = {}
                    try:
                        if dynamic_form.config:
                            original_config_data = json.loads(dynamic_form.config)
                            if isinstance(original_config_data, dict) and 'fields' in original_config_data:
                                original_fields = original_config_data['fields']
                            elif isinstance(original_config_data, list):
                                original_fields = original_config_data
                            else:
                                original_fields = []
                                
                            # Create lookup for original field configs
                            for orig_field in original_fields:
                                if isinstance(orig_field, dict) and 'name' in orig_field:
                                    original_config[orig_field['name']] = orig_field
                    except (json.JSONDecodeError, KeyError, TypeError):
                        logger.warning('Could not parse original form config for dynamic field restoration.')
                        original_fields = []
                    
                    # Process each field in the new data
                    for field in fields_data:
                        if isinstance(field, dict):
                            field_name = field.get('name', '')
                            field_type = field.get('type', '')
                            dynamic_config = field.get('dynamicOptionsConfig')
                            
                            # Check if original field had dynamic configuration
                            original_field = original_config.get(field_name, {})
                            original_dynamic_config = original_field.get('dynamicOptionsConfig')
                            
                            # RESTORE MISSING DYNAMIC CONFIG
                            if original_dynamic_config and not dynamic_config:
                                logger.warning(f"Restoring missing dynamicOptionsConfig for field '{field_name}'")
                                field['dynamicOptionsConfig'] = original_dynamic_config
                                dynamic_config = original_dynamic_config
                            
                            # FIX FIELD TYPE FOR DYNAMIC FIELDS
                            if dynamic_config and (not field_type or field_type.strip() == '' or field_type != 'select'):
                                old_type = field_type
                                field['type'] = 'select'
                                logger.warning(f"Field '{field_name}' has dynamic config but wrong type '{old_type}', setting to 'select'")
                
                new_config_json = json.dumps(fields_data)
                if dynamic_form.config != new_config_json:
                    dynamic_form.config = new_config_json
            
            # Update login_required
            if "login_required" in form_data: # Check presence of key
                login_required_data = form_data.get("login_required") # This will be True/False from JS
                if dynamic_form.login_required != login_required_data:
                    dynamic_form.login_required = login_required_data

            # Update access_level
            if "access_level" in form_data: # Check presence of key
                access_level_data = form_data.get("access_level") # This will be 'public', 'authenticated', or 'selected_users' from JS
                if dynamic_form.access_level != access_level_data:
                    dynamic_form.access_level = access_level_data


            # Update webhook_url
            new_webhook_url = proposed_webhook_url
            if dynamic_form.webhook_url != new_webhook_url:
                logger.info('Webhook URL updated for form_uuid=%s.', uuid)
                dynamic_form.webhook_url = new_webhook_url
            else:
                logger.info('Webhook URL unchanged for form_uuid=%s.', uuid)
            
            # Missing header data leaves storage untouched; within a submitted
            # object, omitted keys are explicit removal and masks preserve a
            # matching encrypted sensitive value.
            if 'headers' in form_data:
                headers_data_raw = form_data['headers']
                try:
                    if isinstance(headers_data_raw, str):
                        parsed_headers_data = parse_webhook_headers_json(headers_data_raw) if headers_data_raw.strip() else {}
                    else:
                        parsed_headers_data = headers_data_raw
                    stored_headers = prepare_webhook_headers_for_storage(
                        parsed_headers_data,
                        existing_headers=dynamic_form.headers,
                    )
                    stored_headers = validate_webhook_headers(stored_headers)
                except DuplicateWebhookHeaderError:
                    return JsonResponse({'error': 'Duplicate webhook header name.'}, status=400)
                except WebhookHeaderSecretError:
                    return JsonResponse({'error': 'Secret value configuration is invalid.'}, status=400)
                except (WebhookHeaderError, TypeError, ValueError):
                    return JsonResponse({'error': 'Invalid webhook header configuration.'}, status=400)

                if dynamic_form.headers != stored_headers:
                    logger.info('Form headers updated for form_uuid=%s.', uuid)
                    dynamic_form.headers = stored_headers
            
            # Update template-related fields
            template_type = form_data.get("template_type", dynamic_form.template_type)
            if hasattr(dynamic_form, 'template_type') and dynamic_form.template_type != template_type:
                dynamic_form.template_type = template_type
            elif not hasattr(dynamic_form, 'template_type'):
                dynamic_form.template_type = template_type
            
            custom_colors = form_data.get("custom_colors", getattr(dynamic_form, 'custom_colors', '{}'))
            if hasattr(dynamic_form, 'custom_colors') and dynamic_form.custom_colors != custom_colors:
                dynamic_form.custom_colors = custom_colors
            elif not hasattr(dynamic_form, 'custom_colors'):
                dynamic_form.custom_colors = custom_colors
                
            header_text = form_data.get("header_text", getattr(dynamic_form, 'header_text', ''))
            if hasattr(dynamic_form, 'header_text') and dynamic_form.header_text != header_text:
                dynamic_form.header_text = header_text
            elif not hasattr(dynamic_form, 'header_text'):
                dynamic_form.header_text = header_text
                
            footer_text = form_data.get("footer_text", getattr(dynamic_form, 'footer_text', ''))
            if hasattr(dynamic_form, 'footer_text') and dynamic_form.footer_text != footer_text:
                dynamic_form.footer_text = footer_text
            elif not hasattr(dynamic_form, 'footer_text'):
                dynamic_form.footer_text = footer_text
            
            # Update success_message
            success_message = form_data.get("success_message", getattr(dynamic_form, 'success_message', ''))
            if hasattr(dynamic_form, 'success_message') and dynamic_form.success_message != success_message:
                dynamic_form.success_message = success_message
            elif not hasattr(dynamic_form, 'success_message'):
                dynamic_form.success_message = success_message
            
            # Update enable_redirect
            enable_redirect = form_data.get("enable_redirect", getattr(dynamic_form, 'enable_redirect', False))
            if hasattr(dynamic_form, 'enable_redirect') and dynamic_form.enable_redirect != enable_redirect:
                dynamic_form.enable_redirect = enable_redirect
            elif not hasattr(dynamic_form, 'enable_redirect'):
                dynamic_form.enable_redirect = enable_redirect
                
            # Update redirect_url (only if enable_redirect is True)
            redirect_url = form_data.get("redirect_url", getattr(dynamic_form, 'redirect_url', ''))
            if enable_redirect:  # Only update redirect_url if redirect is enabled
                if hasattr(dynamic_form, 'redirect_url') and dynamic_form.redirect_url != redirect_url:
                    logger.info('Redirect URL updated for form_uuid=%s.', uuid)
                    dynamic_form.redirect_url = redirect_url
                elif not hasattr(dynamic_form, 'redirect_url'):
                    dynamic_form.redirect_url = redirect_url
                else:
                    logger.info('Redirect URL unchanged for form_uuid=%s.', uuid)
            else:
                # Clear redirect_url if redirect is disabled
                if hasattr(dynamic_form, 'redirect_url'):
                    dynamic_form.redirect_url = ''
            
            # Update SSO Integration settings
            enable_sso_prepopulate = form_data.get("enable_sso_prepopulate", getattr(dynamic_form, 'enable_sso_prepopulate', False))
            if hasattr(dynamic_form, 'enable_sso_prepopulate') and dynamic_form.enable_sso_prepopulate != enable_sso_prepopulate:
                dynamic_form.enable_sso_prepopulate = enable_sso_prepopulate
            elif not hasattr(dynamic_form, 'enable_sso_prepopulate'):
                dynamic_form.enable_sso_prepopulate = enable_sso_prepopulate
            
            # Update SSO prepopulate fields mapping
            sso_prepopulate_fields = form_data.get("sso_prepopulate_fields", getattr(dynamic_form, 'sso_prepopulate_fields', {}))
            if hasattr(dynamic_form, 'sso_prepopulate_fields') and dynamic_form.sso_prepopulate_fields != sso_prepopulate_fields:
                dynamic_form.sso_prepopulate_fields = sso_prepopulate_fields
            elif not hasattr(dynamic_form, 'sso_prepopulate_fields'):
                dynamic_form.sso_prepopulate_fields = sso_prepopulate_fields
            
            # Update SSO disabled fields
            sso_disabled_fields = form_data.get("sso_disabled_fields", getattr(dynamic_form, 'sso_disabled_fields', []))
            if hasattr(dynamic_form, 'sso_disabled_fields') and dynamic_form.sso_disabled_fields != sso_disabled_fields:
                dynamic_form.sso_disabled_fields = sso_disabled_fields
            elif not hasattr(dynamic_form, 'sso_disabled_fields'):
                dynamic_form.sso_disabled_fields = sso_disabled_fields
            
            # Update SSO auto redirect setting
            auto_redirect_to_sso = form_data.get("auto_redirect_to_sso", getattr(dynamic_form, 'auto_redirect_to_sso', True))
            if hasattr(dynamic_form, 'auto_redirect_to_sso') and dynamic_form.auto_redirect_to_sso != auto_redirect_to_sso:
                dynamic_form.auto_redirect_to_sso = auto_redirect_to_sso
            elif not hasattr(dynamic_form, 'auto_redirect_to_sso'):
                dynamic_form.auto_redirect_to_sso = auto_redirect_to_sso
            
            # Update Dynamic Options Configuration
            # Extract dynamic options configurations from field configurations
            dynamic_options_config = {}
            if "fields" in form_data:
                fields_data = form_data.get("fields", [])
                for field in fields_data:
                    if field.get("dynamicOptionsConfig"):
                        field_name = field.get("name")
                        field_type = field.get("type")
                        if field_name:
                            dynamic_options_config[field_name] = field.get("dynamicOptionsConfig")
                            
                            # Ensure the field type is correct for dynamic fields
                            if not field_type or field_type.strip() == '':
                                logger.warning(f"Dynamic field '{field_name}' has empty type, this should have been fixed earlier")
            
            # Save dynamic options configuration
            if dynamic_options_config != dynamic_form.dynamic_options_config:
                dynamic_form.dynamic_options_config = dynamic_options_config
            
            try:
                dynamic_form.save()
            except IntegrityError:
                logger.warning('Form update hit a database constraint for form_id=%s.', dynamic_form.pk)
                # This might happen if UUID became non-unique due to a race condition despite prior checks, though unlikely with .exclude(pk=...).
                return JsonResponse({"error": "Form update could not be saved due to a configuration constraint."}, status=400)

            return JsonResponse({"success": "Form updated successfully.", "new_uuid": str(dynamic_form.uuid)})

        except json.JSONDecodeError:
            logger.warning('Invalid form update JSON for form_uuid=%s.', uuid)
            return JsonResponse({"error": "Invalid JSON format. Please correct it and try again."}, status=400)
        except Exception:
            logger.warning('Unexpected form update failure for form_uuid=%s.', uuid)
            return JsonResponse({"error": "Form update failed."}, status=500)
        

# class FillFormView(LoginRequiredMixin, TemplateView): # LoginRequiredMixin removed for this view only
class FillFormView(TemplateView):
    """
    View to handle display of a form for submission by user.
    """
    
    def get_template_names(self):
        """
        Return the appropriate template based on the form's template_type
        """
        uuid = self.kwargs['uuid']
        dynamic_form = get_object_or_404(DynamicForm, uuid=uuid)
        template_type = getattr(dynamic_form, 'template_type', 'default')
        
        # Map template types to template files
        template_map = {
            'corporate': 'form_templates/corporate.html',
            'minimal': 'form_templates/minimal.html',
            'modern': 'form_templates/modern.html',
            'classic': 'form_templates/classic.html',
            'branded': 'form_templates/branded.html',
            'default': 'pages/forms/fill_form.html',
        }
        
        return [template_map.get(template_type, 'pages/forms/fill_form.html')]

    def dispatch(self, request, *args, **kwargs):
        uuid = self.kwargs['uuid']
        self.dynamic_form = get_object_or_404(DynamicForm, uuid=uuid)
        denial = form_delivery_access_denial(
            request,
            self.dynamic_form,
            anonymous_response=lambda: self._anonymous_delivery_redirect(request),
        )
        if denial is not None:
            return denial

        return super().dispatch(request, *args, **kwargs)

    def _anonymous_delivery_redirect(self, request):
        """Preserve the existing SSO-aware redirect for protected form displays."""
        if getattr(self.dynamic_form, 'auto_redirect_to_sso', True):
            try:
                from sso_auth.models import SSOProvider

                sso_provider = SSOProvider.objects.filter(enabled=True).first()
                if sso_provider:
                    if sso_provider.protocol == 'saml':
                        sso_login_url = reverse(
                            'sso:saml_login_named',
                            kwargs={'provider_name': sso_provider.name},
                        )
                    elif sso_provider.protocol == 'oidc':
                        sso_login_url = reverse(
                            'sso:oidc_login_named',
                            kwargs={'provider_name': sso_provider.name},
                        )
                    else:
                        sso_login_url = None
                    if sso_login_url:
                        return redirect(f'{sso_login_url}?next={request.get_full_path()}')
            except ImportError:
                pass
            except Exception as exc:
                logger.warning('Could not determine an SSO redirect for form delivery: %s', exc)

        return redirect_to_login(request.get_full_path(), login_url=reverse('login'))

    def populate_dynamic_dropdown_choices(self, form_config, dynamic_form, user):
        """
        Populate choices for dynamic dropdown fields by executing database queries.
        This is critical for form templates to display dropdown options.
        """
        if not dynamic_form.dynamic_options_config:
            return form_config
            
        logger.info(f"Populating dynamic dropdowns for form: {dynamic_form.formname}")
        
        for field in form_config:
            field_name = field.get('name')
            field_type = field.get('type')
            
            # Only process select/dropdown fields
            if field_type != 'select':
                continue
                
            # Check if this field has dynamic configuration
            dynamic_config = dynamic_form.dynamic_options_config.get(field_name)
            if not dynamic_config:
                continue
                
            logger.info(f"Processing dynamic dropdown for field: {field_name}")
            
            try:
                choices = self.load_dynamic_choices(dynamic_config, user)
                if choices:
                    field['choices'] = choices
                    field['options'] = choices  # Backward compatibility
                    logger.info(f"Loaded {len(choices)} choices for field: {field_name}")
                else:
                    logger.warning(f"No choices loaded for dynamic field: {field_name}")
                    field['choices'] = []
                    field['options'] = []
                    
            except Exception:
                logger.warning('Dynamic dropdown choices could not be loaded for field=%s.', field_name)
                # Set empty choices on error to prevent template crashes
                field['choices'] = []
                field['options'] = []
                
        return form_config
    
    def load_dynamic_choices(self, config, user):
        """
        Load choices from database based on dynamic configuration.
        """
        if not config.get('connection_id'):
            return []
            
        # Build query
        query = self.build_dynamic_query(config)
        if not query:
            return []
            
        logger.info('Loading configured dynamic dropdown choices.')
        
        try:
            limits = get_external_query_limits()
            # Use existing fetch functions
            if config['connection_id'].startswith('db_'):
                db_connection_id = config['connection_id'].replace('db_', '')
                from .db_utils import fetch_data_from_connection
                result = fetch_data_from_connection(
                    user,
                    db_connection_id,
                    query,
                    max_rows=limits.dynamic_dropdown_max_rows,
                    execution_context='dynamic dropdown',
                )
            elif config['connection_id'].startswith('int_'):
                integration_id = config['connection_id'].replace('int_', '')
                from .db_utils import fetch_data_from_integration
                result = fetch_data_from_integration(
                    user,
                    integration_id,
                    query,
                    max_rows=limits.dynamic_dropdown_max_rows,
                    execution_context='dynamic dropdown',
                )
            else:
                # For backward compatibility, assume it's a database connection ID
                from .db_utils import fetch_data_from_connection
                result = fetch_data_from_connection(
                    user,
                    config['connection_id'],
                    query,
                    max_rows=limits.dynamic_dropdown_max_rows,
                    execution_context='dynamic dropdown',
                )
            
            # Convert result to choices format
            choices = []
            if isinstance(result, list) and result:
                for row in result:
                    if isinstance(row, dict):
                        # Try to get value and label from row
                        value = row.get('value') or row.get(list(row.keys())[0]) if row.keys() else ''
                        label = row.get('label') or row.get(list(row.keys())[1]) if len(row.keys()) > 1 else value
                        
                        choices.append({
                            'value': str(value) if value is not None else '',
                            'label': str(label) if label is not None else str(value) if value is not None else ''
                        })
                    else:
                        # Handle tuple/list rows
                        value = str(row[0]) if len(row) > 0 else ''
                        label = str(row[1]) if len(row) > 1 else value
                        choices.append({'value': value, 'label': label})
                        
            return choices
            
        except SqlPolicyViolation as exc:
            logger.warning('Blocked dynamic dropdown query by SQL policy (%s).', exc.code)
            return []
        except ExternalQueryTimeoutError:
            logger.warning('Dynamic dropdown query timed out.')
            return []
        except ReadOnlyEnforcementError:
            logger.warning('Dynamic dropdown read-only protection could not be established.')
            return []
        except Exception:
            logger.warning('Dynamic dropdown query failed.')
            return []
    
    def build_dynamic_query(self, config):
        """
        Build SQL query from dynamic configuration.
        """
        if config.get('query_mode') == 'custom' and config.get('custom_query'):
            return config['custom_query']
            
        if config.get('query_mode') == 'guided' and config.get('table') and config.get('value_column'):
            query = f"SELECT DISTINCT {config['value_column']} as value"
            
            if config.get('label_column') and config['label_column'] != config['value_column']:
                query += f", {config['label_column']} as label"
                
            query += f" FROM {config['table']}"
            
            # Add WHERE conditions if any
            where_clauses = []
            
            # Basic WHERE conditions
            if config.get('where_conditions'):
                for condition in config['where_conditions']:
                    if condition.get('column') and condition.get('operator'):
                        clause = f"{condition['column']} {condition['operator']}"
                        if not condition['operator'].upper().endswith('NULL'):
                            if condition['operator'].upper() == 'IN':
                                clause += f" ({condition.get('value', '')})"
                            else:
                                clause += f" '{condition.get('value', '')}'"
                        where_clauses.append(clause)
            
            # Add exclusions
            if config.get('exclusions'):
                for exclusion in config['exclusions']:
                    if exclusion.get('column') and exclusion.get('condition'):
                        clause = f"NOT ({exclusion['column']} {exclusion['condition']}"
                        if not exclusion['condition'].upper().endswith('NULL'):
                            if exclusion['condition'].upper() == 'IN':
                                clause += f" ({exclusion.get('value', '')}))"
                            else:
                                clause += f" '{exclusion.get('value', '')}')"
                        else:
                            clause += ")"
                        where_clauses.append(clause)
            
            # Add inclusions
            if config.get('inclusions'):
                inclusion_clauses = []
                for inclusion in config['inclusions']:
                    if inclusion.get('column') and inclusion.get('condition'):
                        clause = f"{inclusion['column']} {inclusion['condition']}"
                        if not inclusion['condition'].upper().endswith('NULL'):
                            if inclusion['condition'].upper() == 'IN':
                                clause += f" ({inclusion.get('value', '')})"
                            else:
                                clause += f" '{inclusion.get('value', '')}'"
                        inclusion_clauses.append(clause)
                if inclusion_clauses:
                    where_clauses.append(f"({' OR '.join(inclusion_clauses)})")
            
            if where_clauses:
                query += f" WHERE {' AND '.join(where_clauses)}"
            
            # Add sorting
            if config.get('sort_column'):
                sort_order = config.get('sort_order', 'ASC')
                query += f" ORDER BY {config['sort_column']} {sort_order}"
            
            # Add limit
            if config.get('result_limit'):
                try:
                    limit = int(config['result_limit'])
                    # Use database-appropriate limit syntax
                    query += f" LIMIT {limit}"
                except (ValueError, TypeError):
                    pass
                    
            return query
            
        return None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        formuuid = self.kwargs['uuid']
        dynamic_form = get_object_or_404(DynamicForm, uuid=formuuid)
        form_config = json.loads(dynamic_form.config)
        
        # Convert form_config from object to array format expected by JavaScript
        if isinstance(form_config, dict):
            # Convert from {field_name: {type, label, ...}} to [{name: field_name, type, label, ...}]
            form_config_array = []
            for field_name, field_data in form_config.items():
                field_item = {
                    'name': field_name,
                    **field_data  # Spread the field data (type, label, required, etc.)
                }
                form_config_array.append(field_item)
            form_config = form_config_array
        
        # CRITICAL FIX: Populate dynamic dropdown choices before rendering
        form_config = self.populate_dynamic_dropdown_choices(form_config, dynamic_form, self.request.user)
        
        context['formname'] = dynamic_form.formname
        context['title'] = dynamic_form.formname # set the title here
        context['form_config'] = json.dumps(form_config)
        context['form_uuid'] = formuuid
        # Template-specific context
        context['template_type'] = getattr(dynamic_form, 'template_type', 'default')
        context['custom_colors'] = getattr(dynamic_form, 'custom_colors', '{}')
        context['custom_logo'] = getattr(dynamic_form, 'custom_logo', None)
        context['header_text'] = getattr(dynamic_form, 'header_text', '')
        context['footer_text'] = getattr(dynamic_form, 'footer_text', '')
        
        # Sidebar content for branded template
        context['sidebar_section1_title'] = getattr(dynamic_form, 'sidebar_section1_title', 'Information')
        context['sidebar_section1_content'] = getattr(dynamic_form, 'sidebar_section1_content', 'Please fill out all required fields marked with an asterisk (*) to complete your submission.')
        context['sidebar_section2_title'] = getattr(dynamic_form, 'sidebar_section2_title', 'Contact')
        context['sidebar_section2_content'] = getattr(dynamic_form, 'sidebar_section2_content', 'If you need assistance completing this form, please contact our support team.')
        context['sidebar_section3_title'] = getattr(dynamic_form, 'sidebar_section3_title', 'Privacy')
        context['sidebar_section3_content'] = getattr(dynamic_form, 'sidebar_section3_content', 'Your information is secure and will only be used for the purposes stated in our privacy policy.')
        
        # Add SSO user data for form prepopulation
        logger.debug('Preparing form-delivery SSO prepopulation context.')
        if dynamic_form.enable_sso_prepopulate and self.request.user.is_authenticated:
            try:
                from sso_auth.utils import SSOUtils
                sso_user_data = SSOUtils.get_sso_user_data(self.request)
                context['sso_user_data'] = json.dumps(sso_user_data)
                context['sso_prepopulate_fields'] = dynamic_form.sso_prepopulate_fields
                context['sso_disabled_fields'] = dynamic_form.sso_disabled_fields
            except ImportError:
                # SSO module not available, continue without SSO features
                logger.debug('SSO module is unavailable for form prepopulation.')
                context['sso_user_data'] = '{}'
                context['sso_prepopulate_fields'] = {}
                context['sso_disabled_fields'] = []
        else:
            logger.debug('Form delivery does not use SSO prepopulation.')
            context['sso_user_data'] = '{}'
            context['sso_prepopulate_fields'] = {}
            context['sso_disabled_fields'] = []
        
        context['dynamic_form'] = dynamic_form
        return context

class PreviewTemplateView(SuperuserRequiredMixin, TemplateView):
    """
    View to preview different templates for form building
    """
    
    def get_template_names(self):
        """
        Return the appropriate template based on the template parameter
        """
        template_type = self.request.GET.get('template', 'default')
        
        # Map template types to template files
        template_map = {
            'corporate': 'form_templates/corporate.html',
            'minimal': 'form_templates/minimal.html',
            'modern': 'form_templates/modern.html',
            'classic': 'form_templates/classic.html',
            'branded': 'form_templates/branded.html',
            'default': 'pages/forms/fill_form.html',
        }
        
        return [template_map.get(template_type, 'pages/forms/fill_form.html')]
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        form_name = kwargs.get('form_name', 'Sample Form')
        template_type = self.request.GET.get('template', 'default')
        
        # Create sample form data for preview - make it more realistic
        sample_config = [
            {
                'name': 'full_name',
                'type': 'text',
                'label': 'Full Name',
                'required': True,
                'placeholder': 'Enter your full name'
            },
            {
                'name': 'email_address',
                'type': 'email',
                'label': 'Email Address',
                'required': True,
                'placeholder': 'Enter your email'
            },
            {
                'name': 'phone_number',
                'type': 'text',
                'label': 'Phone Number',
                'required': False,
                'placeholder': '(555) 123-4567'
            },
            {
                'name': 'budget_amount',
                'type': 'currency',
                'label': 'Budget Amount',
                'required': False,
                'placeholder': '$0.00',
                'currencySymbol': '$'
            },
            {
                'name': 'project_description',
                'type': 'textarea',
                'label': 'Project Description',
                'required': False,
                'placeholder': 'Describe your project...'
            },
            {
                'name': 'priority_level',
                'type': 'select',
                'label': 'Priority Level',
                'required': True,
                'choices': [
                    {'value': 'high', 'label': 'High'},
                    {'value': 'medium', 'label': 'Medium'},
                    {'value': 'low', 'label': 'Low'}
                ]
            },
            {
                'name': 'project_type',
                'type': 'radio',
                'label': 'Project Type',
                'required': True,
                'choices': [
                    {'value': 'new', 'label': 'New Project'},
                    {'value': 'renovation', 'label': 'Renovation'},
                    {'value': 'maintenance', 'label': 'Maintenance'}
                ]
            },
            {
                'name': 'start_date',
                'type': 'date',
                'label': 'Preferred Start Date',
                'required': False
            },
            {
                'name': 'additional_services',
                'type': 'checkbox',
                'label': 'Additional Services',
                'required': False,
                'choices': [
                    {'value': 'design', 'label': 'Design Consultation'},
                    {'value': 'permits', 'label': 'Permit Assistance'},
                    {'value': 'management', 'label': 'Project Management'}
                ]
            }
        ]
        
        # Generate HTML for preview form fields
        form_html = self._generate_preview_form_html(sample_config)
        
        # Create a mock dynamic form object for preview
        class MockDynamicForm:
            def __init__(self, request):
                self.formname = form_name
                self.form_description = 'This is a preview of how your form will look'
                self.template_type = template_type
                self.custom_colors = request.GET.get('colors', '{"primary": "#007bff", "secondary": "#6c757d"}')
                self.header_text = request.GET.get('header', 'Welcome to Our Form')
                self.footer_text = request.GET.get('footer', '© 2025 Your Organization')
                self.custom_logo = None
        
        mock_form = MockDynamicForm(self.request)
        
        context.update({
            'formname': form_name,
            'title': f'{form_name} - Template Preview',
            'form_config': json.dumps(sample_config),  # Convert to JSON string like FillFormView
            'form_uuid': 'preview-mode',
            'template_type': template_type,
            'custom_colors': self.request.GET.get('colors', '{"primary": "#007bff", "secondary": "#6c757d"}'),
            'custom_logo': None,
            'header_text': self.request.GET.get('header', 'Welcome to Our Form'),
            'footer_text': self.request.GET.get('footer', '© 2025 Your Organization'),
            
            # Sidebar content for branded template (preview mode)
            'sidebar_section1_title': 'Information',
            'sidebar_section1_content': 'Please fill out all required fields marked with an asterisk (*) to complete your submission.',
            'sidebar_section2_title': 'Contact',
            'sidebar_section2_content': 'If you need assistance completing this form, please contact our support team.',
            'sidebar_section3_title': 'Privacy',
            'sidebar_section3_content': 'Your information is secure and will only be used for the purposes stated in our privacy policy.',
            
            'dynamic_form': mock_form,
            'preview_mode': True,
            # Generate actual form HTML for preview
            'form_html': form_html,
            # Mock form object for templates that expect it
            'form': mock_form  # Use the mock_form instead of creating a new object
        })
        return context
    
    def _generate_preview_form_html(self, form_config):
        """Generate HTML for preview form fields"""
        html_parts = []
        
        # form_config is now a list of field objects, not a dictionary
        for field_data in form_config:
            field_name = field_data.get('name')
            field_type = field_data.get('type', 'text')
            label = field_data.get('label', field_name)
            required = field_data.get('required', False)
            placeholder = field_data.get('placeholder', '')
            
            # Create field HTML based on type
            if field_type == 'text':
                field_html = f'''
                <div class="form-group mb-3">
                    <label for="{field_name}" class="form-label">{label}{"*" if required else ""}</label>
                    <input type="text" class="form-control" id="{field_name}" name="{field_name}" 
                           placeholder="{placeholder}" {"required" if required else ""}>
                </div>'''
            
            elif field_type == 'email':
                field_html = f'''
                <div class="form-group mb-3">
                    <label for="{field_name}" class="form-label">{label}{"*" if required else ""}</label>
                    <input type="email" class="form-control" id="{field_name}" name="{field_name}" 
                           placeholder="{placeholder}" {"required" if required else ""}>
                </div>'''
            
            elif field_type == 'currency':
                field_html = f'''
                <div class="form-group mb-3">
                    <label for="{field_name}" class="form-label">{label}{"*" if required else ""}</label>
                    <div class="input-group">
                        <span class="input-group-text">$</span>
                        <input type="text" class="form-control currency-field" id="{field_name}" name="{field_name}" 
                               placeholder="0.00" data-currency="USD" {"required" if required else ""}>
                    </div>
                </div>'''
            
            elif field_type == 'textarea':
                field_html = f'''
                <div class="form-group mb-3">
                    <label for="{field_name}" class="form-label">{label}{"*" if required else ""}</label>
                    <textarea class="form-control" id="{field_name}" name="{field_name}" rows="4"
                              placeholder="{placeholder}" {"required" if required else ""}></textarea>
                </div>'''
            
            elif field_type == 'select':
                options = field_data.get('options', [])
                # Handle both string and list formats
                if isinstance(options, str):
                    options = options.split(',')
                elif not isinstance(options, list):
                    options = []
                
                options_html = ''.join([f'<option value="{opt.strip()}">{opt.strip()}</option>' for opt in options if str(opt).strip()])
                field_html = f'''
                <div class="form-group mb-3">
                    <label for="{field_name}" class="form-label">{label}{"*" if required else ""}</label>
                    <select class="form-control" id="{field_name}" name="{field_name}" {"required" if required else ""}>
                        <option value="">Choose...</option>
                        {options_html}
                    </select>
                </div>'''
            
            else:
                # Default to text input
                field_html = f'''
                <div class="form-group mb-3">
                    <label for="{field_name}" class="form-label">{label}{"*" if required else ""}</label>
                    <input type="text" class="form-control" id="{field_name}" name="{field_name}" 
                           placeholder="{placeholder}" {"required" if required else ""}>
                </div>'''
            
            html_parts.append(field_html)
        
        return ''.join(html_parts)

class SubmitFormView(View):
    """
    View to handle submission of Dynamic Forms.
    """
    def dispatch(self, request, *args, **kwargs):
         uuid = self.kwargs['uuid']
         self.dynamic_form = get_object_or_404(DynamicForm, uuid=uuid)
         denial = form_delivery_access_denial(request, self.dynamic_form)
         if denial is not None:
             return denial

         return super().dispatch(request, *args, **kwargs)

    def post(self, request, uuid, *args, **kwargs):
        dynamic_form = get_object_or_404(DynamicForm, uuid=uuid)

        # Resolve all multipart fields against the trusted saved form schema
        # before creating database records or writing anything to storage.
        try:
            validated_uploads = validate_dynamic_uploads(dynamic_form.config, request.FILES)
        except UploadValidationError as exc:
            return JsonResponse({'error': str(exc)}, status=400)

        # Collect submitted data
        submission_data = {}
        for key in request.POST:
            values = request.POST.getlist(key)
            if len(values) > 1:
                submission_data[key] = values
            else:
                submission_data[key] = request.POST[key]

        # Save the submission and validated files together.  File storage is
        # not transactional, so clean up any stored files if persistence fails.
        stored_file_uploads = []
        try:
            with transaction.atomic():
                submissionid = str(uuid_lib.uuid4())
                form_submission = FormSubmission.objects.create(
                    form=dynamic_form,
                    submissionID=submissionid,
                    submission_data=submission_data
                )
                for field_name, file_obj in validated_uploads:
                    file_upload = FileUpload(
                        submission=form_submission,
                        field_name=field_name,
                        file=file_obj,
                    )
                    # Track before save so a storage write followed by a
                    # database error is still removed by the exception path.
                    stored_file_uploads.append(file_upload)
                    file_upload.save()
        except Exception:
            for file_upload in stored_file_uploads:
                file_upload.file.delete(save=False)
            logger.warning('Form submission persistence failed for form_uuid=%s.', uuid)
            return JsonResponse({"error": "Submission could not be saved."}, status=500)

        # Rewind files for the existing webhook delivery path.
        file_uploads = []
        for field_name, file_obj in validated_uploads:
            file_obj.seek(0)
            file_uploads.append((field_name, file_obj))

        # Deliver through the contained webhook transport.
        if dynamic_form.webhook_url:
            try:
                # Prepare the data and files for the request
                data = {}
                files = []

                # Ensure submission_data is a dictionary
                if isinstance(submission_data, str):
                    submission_data = json.loads(submission_data)
                # Add submission data to the data dictionary
                for key, value in submission_data.items():
                    if isinstance(value, list):
                        data[key] = json.dumps(value)
                    else:
                        data[key] = value

                # Add files to the files list
                for field_name, file_obj in file_uploads:
                    files.append(
                        (field_name, (file_obj.name, file_obj, file_obj.content_type))
                    )
                # Preserve existing payload and header semantics; the delivery
                # helper removes unsafe transport-control headers from legacy rows.
                headers = dynamic_form.headers or {}
                if isinstance(headers, str):
                    try:
                        headers = json.loads(headers)
                    except (TypeError, ValueError):
                        headers = {}

                form_submission.response = deliver_webhook(
                    dynamic_form.webhook_url,
                    data=data,
                    files=files,
                    headers=headers,
                )
                form_submission.save()
                logger.info(
                    'Form webhook delivery completed with status=%s.',
                    form_submission.response['status_code'],
                )

            except WebhookSecurityError as exc:
                form_submission.response = build_webhook_response_metadata(status=exc.code)
                form_submission.save(update_fields=['response'])
                logger.warning('Form webhook delivery blocked category=%s.', exc.code)
            except WebhookDeliveryError as exc:
                form_submission.response = build_webhook_response_metadata(status=exc.code)
                form_submission.save(update_fields=['response'])
                logger.warning('Form webhook delivery failed category=%s.', exc.code)
            except Exception:
                form_submission.response = build_webhook_response_metadata(status='WEBHOOK_DELIVERY_FAILED')
                form_submission.save(update_fields=['response'])
                logger.warning('Form webhook delivery failed category=WEBHOOK_DELIVERY_FAILED.')

        # Get custom success message or use default
        success_message = dynamic_form.success_message or "Thank you! Your form has been submitted successfully."
        
        response_data = {
            "success": True,
            "message": success_message
        }
        
        # Add redirect information if enabled
        if dynamic_form.enable_redirect and dynamic_form.redirect_url:
            response_data["redirect_url"] = dynamic_form.redirect_url
            response_data["enable_redirect"] = True
        else:
            response_data["enable_redirect"] = False

        return JsonResponse(response_data)

    def get(self, request, uuid, *args, **kwargs):
        return JsonResponse({"error": "Only POST requests are allowed."}, status=405)
    
    
class DeleteFormView(SuperuserRequiredMixin, View):
    """
    View to delete a Dynamic Form
    """
    def post(self, request, uuid, *args, **kwargs):
        form = get_object_or_404(DynamicForm, uuid=uuid)
        form.delete()
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({"message": "Form successfully deleted."}, status=200)
        messages.success(request, "Form successfully deleted.")
        return redirect('manage_forms')
    
    
class ViewFormSubmissionsView(SuperuserRequiredMixin, TemplateView):
    """
    View to display Form Submissions in admin side
    """
    template_name = 'pages/forms/view-form-submissions.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Form Submissions" # set the title here
        context['forms'] =  DynamicForm.objects.annotate(total_submissions=Count('formsubmission')).order_by('-created_at')

        
        return context

class OpenFormSubmissionsView(SuperuserRequiredMixin, TemplateView):
    """
    View to display submissions of a single form in admin side
    """
    template_name = 'pages/forms/open-form-submissions.html'
    login_url = '/login/'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        uuid = self.kwargs['uuid']
        form = get_object_or_404(DynamicForm, uuid=uuid)
        submissions = FormSubmission.objects.filter(form=form).order_by('-submitted_at')
        for submission in submissions:
            submission.delivery_metadata = safe_webhook_response_metadata(submission.response)
        context['title'] =  f"{form.formname} - Submissions" # set the title here
        context['form'] = form
        context['submissions'] = submissions
        return context
    
class submissionDetails(SuperuserRequiredMixin, TemplateView):
    """
    View to display single submission's details in admin side
    """
    template_name='pages/forms/submission_details.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        submissionid = self.kwargs['uuid']
        submission = get_object_or_404(FormSubmission, submissionID=submissionid)
        files = submission.files.all()  # Access related FileUpload objects
        context['title'] =  f"{submission.form.formname} - Submission Details" # set the title here
        context['submission'] = submission
        context['delivery_metadata'] = safe_webhook_response_metadata(submission.response)
        context['files'] = files
        context['form_uuid'] = submission.form.uuid
        return context


class FileUploadDownloadView(SuperuserRequiredMixin, View):
    """Stream a submitted file only after superuser authorization succeeds."""

    def get(self, request, file_id, *args, **kwargs):
        file_upload = get_object_or_404(FileUpload, pk=file_id)
        try:
            if not file_upload.file or not file_upload.file.storage.exists(file_upload.file.name):
                raise Http404
            safe_filename = os.path.basename(file_upload.file.name).replace('\r', '').replace('\n', '')
            return FileResponse(
                file_upload.file.open('rb'),
                as_attachment=True,
                filename=safe_filename,
            )
        except Http404:
            raise
        except (OSError, ValueError):
            logger.warning('Protected submission file was unavailable for file_id=%s.', file_id)
            raise Http404


# user side

class user_submissionDetails(LoginRequiredMixin,TemplateView):
    """
    View to display single submission's details for a form in the user side.
    """
    template_name='pages/userside/user-submission_details.html'
    login_url = '/login/'
    
    def dispatch(self, request, *args, **kwargs):
        # FormSubmission has no trusted owner/reader relationship. A form UUID or
        # delivery permission cannot establish authority to read submitted data.
        raise Http404
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        submissionid = self.kwargs['uuid']
        submissions = FormSubmission.objects.get(submissionID=submissionid)
        context['title'] = f"{submissions.form.formname} - Submission Details" # set the title here
        context['submissions'] = submissions
        context['delivery_metadata'] = safe_webhook_response_metadata(submissions.response)
        context['form_uuid'] = submissions.form.uuid
        return context

class user_OpenFormSubmissionsView(LoginRequiredMixin,TemplateView):
    """
    View to display all the submissions of a particular form
    """
    template_name = 'pages/userside/user-open-form-submissions.html'
    login_url = '/login/'
    
    def dispatch(self, request, *args, **kwargs):
        # Fail closed until a deliberate submission ownership model exists.
        raise Http404

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        uuid = self.kwargs['uuid']
        form = get_object_or_404(DynamicForm, uuid=uuid)
        formname = form.formname
        submissions = FormSubmission.objects.filter(form=form).order_by('-submitted_at')
        for submission in submissions:
            submission.delivery_metadata = safe_webhook_response_metadata(submission.response)
        context['title'] = f"{formname} - Submissions" # set the title here
        context['formname'] = formname
        context['submissions'] = submissions
        return context
    
    

    
    
class IntegrationsView(SuperuserRequiredMixin, TemplateView):
    """
    View for integrations page.
    """
    template_name = 'pages/integrations/integrations.html'
    login_url = '/login/'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Integrations" # set the title here
        integrations = Integration.objects.all()
        user_credentials = {
            cred.integration_id: cred for cred in IntegrationCredential.objects.filter(user=self.request.user)
        }

        # Add credentials data to each integration
        for integration in integrations:
            integration.credential = user_credentials.get(integration.id, None)

        context['integrations'] = integrations
        return context

# API View to fetch dynamic fields for a specific integration
class FetchIntegrationFieldsView(JsonSuperuserRequiredView):
    """
    API view for fetching fields based on integration
    """
    def get(self, request, integration_id):
        integration = get_object_or_404(Integration, pk=integration_id)
        credential = IntegrationCredential.objects.filter(
            user=request.user, integration=integration
        ).first()
        
        fields, saved_credentials, secret_fields = browser_credential_state(
            integration.fields, credential.credentials if credential else {}
        )
        return JsonResponse({
            'fields': fields,
            'saved_credentials': saved_credentials,
            'secret_fields': secret_fields,
        })

 
class SaveIntegrationCredentialView(JsonSuperuserRequiredView):
    """
    API view to save user credentials for integration
    """
    def post(self, request):
        try:
            data = json.loads(request.body)
            if not isinstance(data, dict):
                raise ValueError('Credential update must be an object.')
            integration_id = data.get('integration_id')
            credentials = data.get('credentials', {})
            enabled = data.get('enabled', False)
            if not isinstance(enabled, bool):
                raise ValueError('Invalid enabled value.')

            integration = get_object_or_404(Integration, pk=integration_id)
            existing = IntegrationCredential.objects.filter(user=request.user, integration=integration).first()
            merged_credentials = merge_submitted_credentials(
                integration.fields, existing.credentials if existing else {}, credentials
            )
            encrypted_credentials = encrypt_credentials_for_storage(integration.fields, merged_credentials)
            if not encrypted_credentials and enabled:
                return JsonResponse({'status': 'error', 'message': 'Credentials required to enable integration.'}, status=400)
            if existing:
                existing.credentials = encrypted_credentials
                existing.enabled = enabled
                existing.save(update_fields=['credentials', 'enabled', 'updated_at'])
            else:
                IntegrationCredential.objects.create(
                    user=request.user, integration=integration, credentials=encrypted_credentials, enabled=enabled
                )

            return JsonResponse({'status': 'success', 'message': f'{integration.name} updated successfully!'})

        except (TypeError, ValueError, json.JSONDecodeError):
            return JsonResponse({'status': 'error', 'message': 'Credential update is invalid.'}, status=400)
        except Exception:
            logger.warning('Integration credential update failed.')
            return JsonResponse({'status': 'error', 'message': 'Credential update failed.'}, status=500)

class ToggleIntegrationView(JsonSuperuserRequiredView):
    """Handles enabling/disabling of an integration toggle switch."""

    def post(self, request):
        data = {}
        try:
            data = json.loads(request.body)
            integration_id = data.get('integration_id')
            enabled = data.get('enabled')

            # Validate the integration ID
            integration = get_object_or_404(Integration, pk=integration_id)

            # Check if credentials exist
            credential = IntegrationCredential.objects.filter(
                user=request.user, integration=integration
            ).first()

            if not credential or not credential.credentials:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Credentials required to enable integration.'
                }, status=400)

            # Update the enabled state
            credential.enabled = enabled
            credential.save()

            return JsonResponse({'status': 'success', 'message': 'Integration status updated successfully!'})

        except Exception:
            logger.warning('Integration status update failed for integration_id=%s.', data.get('integration_id'))
            return JsonResponse({'status': 'error', 'message': 'Integration operation failed.'}, status=500)
    
    
    
    
    
# ----------add users 



class UserListView(SuperuserRequiredMixin, View):
    """
    View for displaying the user list page.
    """
    def get(self, request):
        
        context = {
        }
        
        return render(request, "pages/Users/add_users.html")


class UserDetailView(JsonSuperuserRequiredView):
    """
    API view to fetch detail of user
    """
    def get(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        return JsonResponse({
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "role": "Administrator" if user.is_superuser else "Staff" if user.is_staff else "User"
        })


class AddOrUpdateUserView(JsonSuperuserRequiredView):
    """
    API view to add or update user details.
    """
    def post(self, request, user_id=None):
        try:
            data = json.loads(request.body)
            if user_id:
                user = get_object_or_404(User, id=user_id)
            else:
                if User.objects.filter(username=data['username']).exists():
                    return JsonResponse({'status': 'error', 'message': 'Username already exists!'})
                user = User()

            # Update fields
            user.username = data['username']
            user.email = data['email']
            user.is_active = data.get('is_active', False)
            user.is_staff = data['role'] == 'Staff'
            user.is_superuser = data['role'] == 'Administrator'

            if data.get('password'):
                user.password = make_password(data['password'])
            user.save()

            return JsonResponse({'status': 'success', 'message': 'User saved successfully.'})
        except Exception:
            logger.warning('User management update failed.')
            return JsonResponse({'status': 'error', 'message': 'User update failed.'}, status=500)


class DeleteUserView(JsonSuperuserRequiredView):
    """
    API View to delete user
    """
    def delete(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return JsonResponse({'status': 'success', 'message': 'User deleted successfully.'})


class SearchUserView(JsonSuperuserRequiredView):
    """
    API view to get list of users for table display
    """
    def get(self, request):
        users = User.objects.all()
        user_list = [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': 'Administrator' if user.is_superuser else 'Staff' if user.is_staff else 'User',
                'status': 'Active' if user.is_active else 'Inactive',
                'joined_date': user.date_joined.strftime('%d %b %Y, %I:%M %p'),
            } for user in users
        ]
        return JsonResponse({'data': user_list})
    
    
class PermissionsView(SuperuserRequiredMixin, TemplateView):
    """
    View to handle and display form permissions page
    """
    template_name = "pages/permissions/permissionpage.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Permissions"
        context['forms'] = DynamicForm.objects.all()
        context['users'] = User.objects.all()
        context['permissions'] = FormPermission.objects.select_related('user', 'form')
        return context


class PermissionsDataView(JsonSuperuserRequiredView):
    """
    View to return JSON data for Permissions DataTable
    """
    def get(self, request):
        # Get all forms with their permission information
        data = []
        
        for form in DynamicForm.objects.all():
            if form.access_level == 'selected_users':
                # For forms with selected_users, show each user permission as a separate row
                permissions = FormPermission.objects.filter(form=form).select_related('user')
                if permissions.exists():
                    for permission in permissions:
                        data.append({
                            'form_name': form.formname,
                            'access_level': form.get_access_level_display(),
                            'users': permission.user.username,
                            'assigned_at': permission.assigned_at.strftime('%Y-%m-%d %H:%M:%S'),
                            'actions': f'''
                                <div class="d-flex justify-content-end align-items-center">
                                    <button class="btn btn-icon btn-active-light-primary edit-form-btn me-2" data-form-id="{form.id}" title="Edit Form Access">
                                        <i class="ki-duotone ki-pencil fs-3">
                                            <span class="path1"></span>
                                            <span class="path2"></span>
                                        </i>
                                    </button>
                                    <button class="btn btn-icon btn-active-light-primary text-danger delete-permission-btn" data-id="{permission.id}" title="Remove User Permission">
                                        <i class="ki-duotone ki-trash-square fs-3">
                                            <span class="path1"></span>
                                            <span class="path2"></span>
                                            <span class="path3"></span>
                                            <span class="path4"></span>
                                        </i>
                                    </button>
                                </div>
                            '''
                        })
                else:
                    # Form has selected_users but no users assigned yet
                    data.append({
                        'form_name': form.formname,
                        'access_level': form.get_access_level_display(),
                        'users': '<em>No users assigned</em>',
                        'assigned_at': '',
                        'actions': f'''
                            <div class="d-flex justify-content-end align-items-center">
                                <button class="btn btn-icon btn-active-light-primary edit-form-btn" data-form-id="{form.id}" title="Edit Form Access">
                                    <i class="ki-duotone ki-pencil fs-3">
                                        <span class="path1"></span>
                                        <span class="path2"></span>
                                    </i>
                                </button>
                            </div>
                        '''
                    })
            else:
                # For public and authenticated forms, show one row per form
                data.append({
                    'form_name': form.formname,
                    'access_level': form.get_access_level_display(),
                    'users': 'All users' if form.access_level == 'public' else 'All authenticated users',
                    'assigned_at': '',
                    'actions': f'''
                        <div class="d-flex justify-content-end align-items-center">
                            <button class="btn btn-icon btn-active-light-primary edit-form-btn" data-form-id="{form.id}" title="Edit Form Access">
                                <i class="ki-duotone ki-pencil fs-3">
                                    <span class="path1"></span>
                                    <span class="path2"></span>
                                </i>
                            </button>
                        </div>
                    '''
                })
                
        return JsonResponse({'data': data})


class EditPermissionView(JsonSuperuserRequiredView):
    """
    View to handle fetching data for editing a specific FormPermission.
    """
    login_url = '/login/'

    def get(self, request, permission_id):
        try:
            permission = get_object_or_404(FormPermission, id=permission_id)

            # Prepare data for the response. Include IDs, not full objects.
            data = {
                'id': permission.id,
                'form_id': permission.form.id,  # Send form_id
                'access_level': permission.form.access_level,
                # Fetch user IDs directly related to this permission's form and access level 'selected_users'
                'user_ids': list(FormPermission.objects.filter(form=permission.form).values_list('user_id', flat=True)) if permission.form.access_level == 'selected_users' else [], # Corrected logic to get user_ids
            }
            return JsonResponse(data)

        except FormPermission.DoesNotExist:
            return JsonResponse({'error': 'Permission not found.'}, status=404)
        except Exception:
            logger.warning('Permission detail retrieval failed.')
            return JsonResponse({'error': 'Permission operation failed.'}, status=500)


class DeletePermissionView(JsonSuperuserRequiredView):
     def delete(self, request, permission_id):
         try:
             permission = get_object_or_404(FormPermission, id=permission_id)
             permission.delete()
             return JsonResponse({'success': True, 'message': 'Permission deleted successfully!'})
         except FormPermission.DoesNotExist:
             return JsonResponse({'success': False, 'message': 'Permission not found'}, status=404)
         except Exception:
             logger.warning('Permission deletion failed.')
             return JsonResponse({'success': False, 'message': 'Permission operation failed.'}, status=400)

class PermissionsSaveView(JsonSuperuserRequiredView):
    def post(self, request):
        try:
            from .cache_utils import CacheInvalidationManager
            
            data = json.loads(request.body)
            form_id = data.get('form_id')
            access_level = data.get('access_level')
            user_ids = data.get('user_ids', [])

            form = get_object_or_404(DynamicForm, id=form_id)
            form.access_level = access_level
            form.save()

            # Track users whose permissions are being changed for cache invalidation
            affected_user_ids = set()

            # Handle user-specific permissions
            if access_level == 'selected_users':
                existing_user_ids = set(FormPermission.objects.filter(form=form).values_list('user_id', flat=True))
                new_user_ids = set(user_ids)

                users_to_add = User.objects.filter(id__in=new_user_ids - existing_user_ids)
                users_to_remove = User.objects.filter(id__in=existing_user_ids - new_user_ids)

                # Track all affected users
                affected_user_ids.update(existing_user_ids)
                affected_user_ids.update(new_user_ids)

                FormPermission.objects.filter(form=form, user__in=users_to_remove).delete()

                for user in users_to_add:
                    FormPermission.objects.create(
                        user=user,
                        form=form
                    )
            else:
                # Get existing users before clearing permissions
                existing_user_ids = set(FormPermission.objects.filter(form=form).values_list('user_id', flat=True))
                affected_user_ids.update(existing_user_ids)
                
                FormPermission.objects.filter(form=form).delete()

            # Invalidate caches for affected users
            if affected_user_ids:
                CacheInvalidationManager.invalidate_user_caches(list(affected_user_ids))

            return JsonResponse({
                'success': True, 
                'message': 'Permissions updated successfully!',
                'affected_users': list(affected_user_ids),
                'refresh_required': True  # Signal that UI should refresh
            })

        except Exception:
            logger.warning('Permission update failed.')
            return JsonResponse({'success': False, 'message': 'Permission update failed.'}, status=400)


class RefreshCacheView(JsonSuperuserRequiredView):
    """View to manually refresh user caches"""
    
    def post(self, request):
        try:
            from .cache_utils import CacheInvalidationManager
            
            # Get user IDs from request or refresh current user's cache
            data = json.loads(request.body) if request.body else {}
            user_ids = data.get('user_ids', [request.user.id])
            
            # Invalidate caches for specified users
            CacheInvalidationManager.invalidate_user_caches(user_ids)
            
            return JsonResponse({
                'success': True, 
                'message': f'Cache refreshed for {len(user_ids)} user(s)'
            })
            
        except Exception:
            return JsonResponse({
                'success': False, 
                'message': 'Cache refresh failed.'
            }, status=400)
    
@debug_superuser_required_json
@api_view(['POST'])
def testapi(request):
    """
    API View to test django rest framework.
    """
    return Response({'status':200, 'message':'Hellow from django rest framework'} )

class ConfigurationsView(SuperuserRequiredMixin, TemplateView):
    template_name = 'pages/configurations/configurations.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get the tab from the request, if it exists
        tab = self.request.GET.get('tab', 'security')
        
        # Valid tabs
        valid_tabs = ['security', 'integrations', 'settings', 'permissions', 'users', 'database-connections', 'approved-procedures']
        
        # Validate tab
        if tab not in valid_tabs:
            tab = 'security'
            
        context['active_tab'] = tab
        return context


# Database Connections Views
class DatabaseConnectionsView(JsonSuperuserRequiredView):
    """View to list all database connections for the current user"""
    def get(self, request):
        try:
            connections = DatabaseConnection.objects.filter(user=request.user)
            return JsonResponse({
                'success': True,
                'connections': [
                    {
                        'id': conn.id,
                        'name': conn.name,
                        'type': conn.connection_type,
                        'server': conn.server,
                        'database': conn.database_name,
                        'status': 'active' if conn.is_active else 'inactive',
                        'last_used': conn.last_used.strftime('%Y-%m-%d %H:%M:%S') if conn.last_used else None,
                        'is_default': conn.is_default
                    }
                    for conn in connections
                ]
            })
        except Exception:
            logger.warning('Database connection listing failed.')
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class DatabaseConnectionDetailView(JsonSuperuserRequiredView):
    """View to get, update or delete a specific database connection"""
    def get(self, request, connection_id):
        try:
            connection = get_object_or_404(DatabaseConnection, id=connection_id, user=request.user)
            return JsonResponse({
                'success': True,
                'connection': {
                    'id': connection.id,
                    'name': connection.name,
                    'type': connection.connection_type,
                    'server': connection.server,
                    'port': connection.port,
                    'database': connection.database_name,
                    'username': connection.username,
                    # Password is not returned for security reasons
                    'is_default': connection.is_default,
                    'is_active': connection.is_active
                }
            })
        except Exception:
            logger.warning('Database connection retrieval failed for connection_id=%s.', connection_id)
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)
            
    def delete(self, request, connection_id):
        try:
            connection = get_object_or_404(DatabaseConnection, id=connection_id, user=request.user)
            connection.delete()
            return JsonResponse({'success': True})
        except Exception:
            logger.warning('Database connection deletion failed for connection_id=%s.', connection_id)
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class TestDatabaseConnectionView(JsonSuperuserRequiredView):
    """View to test a database connection"""
    def post(self, request):
        try:
            data = json.loads(request.body)
            limits = get_external_query_limits()
            # Test connection logic based on the connection type
            connection_type = data.get('type')
            
            # Use existing function from InitiativesView to test MSSQL connections
            if connection_type == 'mssql':
                # Create a temporary connection and test it
                try:
                    # Import improved driver detection
                    from .db_config import get_available_odbc_driver
                    
                    # Get the best available driver
                    driver = get_available_odbc_driver()
                    if not driver:
                        return JsonResponse({'success': False, 'error': 'No compatible ODBC driver found'})
                    
                    # Create a temporary connection string
                    conn_string = (
                        f"DRIVER={{{driver}}};SERVER={data.get('server')},{data.get('port')};"
                        f"DATABASE={data.get('database')};UID={data.get('username')};"
                        f"PWD={data.get('password')};TrustServerCertificate=yes;"
                        f"Connection Timeout={limits.connect_timeout};"
                    )
                    
                    # Try to connect
                    conn = pyodbc.connect(conn_string)
                    cursor = conn.cursor()
                    cursor.timeout = limits.query_timeout
                    cursor.execute("SELECT 1")  # Simple test query
                    cursor.close()
                    conn.close()
                    
                    return JsonResponse({'success': True})
                except Exception:
                    logger.warning('MSSQL connection test failed.')
                    return JsonResponse({'success': False, 'error': 'Database connection test failed.'}, status=500)
            elif connection_type == 'mysql':
                # Add logic for MySQL connection test
                try:
                    import pymysql
                    connection = pymysql.connect(
                        host=data.get('server'),
                        port=int(data.get('port')),
                        user=data.get('username'),
                        password=data.get('password'),
                        database=data.get('database'),
                        connect_timeout=limits.connect_timeout,
                        read_timeout=limits.query_timeout,
                        write_timeout=limits.query_timeout,
                    )
                    connection.close()
                    return JsonResponse({'success': True})
                except Exception:
                    logger.warning('MySQL connection test failed.')
                    return JsonResponse({'success': False, 'error': 'Database connection test failed.'}, status=500)
            elif connection_type == 'postgresql':
                # Add logic for PostgreSQL connection test
                try:
                    import psycopg2
                    connection = psycopg2.connect(
                        host=data.get('server'),
                        port=data.get('port'),
                        user=data.get('username'),
                        password=data.get('password'),
                        dbname=data.get('database'),
                        connect_timeout=limits.connect_timeout,
                        options=f'-c statement_timeout={limits.query_timeout * 1000}',
                    )
                    connection.close()
                    return JsonResponse({'success': True})
                except Exception:
                    logger.warning('PostgreSQL connection test failed.')
                    return JsonResponse({'success': False, 'error': 'Database connection test failed.'}, status=500)
            elif connection_type == 'oracle':
                # Add logic for Oracle connection test
                try:
                    import cx_Oracle
                    dsn = cx_Oracle.makedsn(
                        host=data.get('server'),
                        port=data.get('port'),
                        service_name=data.get('database')
                    )
                    connection = cx_Oracle.connect(
                        user=data.get('username'),
                        password=data.get('password'),
                        dsn=dsn
                    )
                    connection.close()
                    return JsonResponse({'success': True})
                except Exception:
                    logger.warning('Oracle connection test failed.')
                    return JsonResponse({'success': False, 'error': 'Database connection test failed.'}, status=500)
            else:
                return JsonResponse({'success': False, 'error': 'Unsupported database type'})
                
        except Exception:
            logger.warning('Database connection test request failed.')
            return JsonResponse({'success': False, 'error': 'Database connection test failed.'}, status=500)


class SaveDatabaseConnectionView(JsonSuperuserRequiredView):
    """View to save a database connection"""
    def post(self, request):
        try:
            data = json.loads(request.body)
            
            # If this connection is set as default, unset any existing default
            if data.get('is_default'):
                DatabaseConnection.objects.filter(user=request.user, is_default=True).update(is_default=False)
            
            if data.get('id'):
                # Update existing connection
                connection = get_object_or_404(DatabaseConnection, id=data.get('id'), user=request.user)
                connection.name = data.get('name')
                connection.connection_type = data.get('type')
                connection.server = data.get('server')
                connection.port = data.get('port')
                connection.database_name = data.get('database')
                connection.username = data.get('username')
                if data.get('password'):  # Only update if provided
                    connection.set_password(data.get('password'))
                connection.is_default = data.get('is_default', False)
                connection.save()
            else:
                # Create new connection
                connection = DatabaseConnection(
                    user=request.user,
                    name=data.get('name'),
                    connection_type=data.get('type'),
                    server=data.get('server'),
                    port=data.get('port'),
                    database_name=data.get('database'),
                    username=data.get('username'),
                    is_default=data.get('is_default', False)
                )
                connection.set_password(data.get('password'))
                connection.save()
                
            return JsonResponse({'success': True, 'connection_id': connection.id})
        except Exception:
            logger.warning('Database connection save failed.')
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class SavedQueriesView(JsonSuperuserRequiredView):
    """View to list all saved queries for the current user"""
    def get(self, request):
        try:
            queries = SavedQuery.objects.filter(user=request.user).select_related('connection')
            return JsonResponse({
                'success': True,
                'queries': [
                    {
                        'id': query.id,
                        'name': query.name,
                        'connection_id': query.connection.id,
                        'connection_name': query.connection.name,
                        'description': query.description,
                        'created_at': query.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                        'last_run': query.last_run.strftime('%Y-%m-%d %H:%M:%S') if query.last_run else None
                    }
                    for query in queries
                ]
            })
        except Exception:
            logger.warning('Saved query listing failed.')
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class SavedQueryDetailView(JsonSuperuserRequiredView):
    """View to get, update or delete a specific saved query"""
    def get(self, request, query_id):
        try:
            query = get_object_or_404(SavedQuery, id=query_id, user=request.user)
            return JsonResponse({
                'success': True,
                'query': {
                    'id': query.id,
                    'name': query.name,
                    'connection_id': query.connection.id,
                    'description': query.description,
                    'query': query.query_text
                }
            })
        except Exception:
            logger.warning('Saved query retrieval failed for query_id=%s.', query_id)
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)
            
    def delete(self, request, query_id):
        try:
            query = get_object_or_404(SavedQuery, id=query_id, user=request.user)
            query.delete()
            return JsonResponse({'success': True})
        except Exception:
            logger.warning('Saved query deletion failed for query_id=%s.', query_id)
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class RunQueryView(JsonSuperuserRequiredView):
    """View to run a SQL query against a database connection"""
    def post(self, request):
        conn = cursor = None
        read_only_transaction = False
        try:
            data = json.loads(request.body)
            connection_id = data.get('connection_id')
            query_text = data.get('query')

            policy_result = validate_read_only_query(query_text)
            if not policy_result.allowed:
                logger.warning('Blocked administrative query by SQL policy (%s).', policy_result.code)
                return JsonResponse({'success': False, 'error': USER_FACING_ERROR}, status=400)

            limits = get_external_query_limits()
            connection = get_object_or_404(DatabaseConnection, id=connection_id, user=request.user)
            results = []
            columns = []
            truncated = False

            if connection.connection_type == 'mssql':
                from .db_config import get_available_odbc_driver
                driver = get_available_odbc_driver()
                if not driver:
                    return JsonResponse({'error': 'No compatible ODBC driver found'}, status=500)

                conn_string = (
                    f'DRIVER={{{driver}}};SERVER={connection.server},{connection.port};'
                    f'DATABASE={connection.database_name};UID={connection.username};'
                    f'PWD={connection.get_password()};TrustServerCertificate=yes;'
                    f'Connection Timeout={limits.connect_timeout};'
                )
                conn = pyodbc.connect(conn_string)
                cursor = conn.cursor()
                cursor.timeout = limits.query_timeout
                cursor.execute(query_text)
                columns = [column[0] for column in cursor.description]
                rows, truncated = fetch_limited_rows(cursor, limits.admin_max_rows)
                results = [dict(zip(columns, row)) for row in rows]
            elif connection.connection_type == 'mysql':
                import pymysql
                conn = pymysql.connect(
                    host=connection.server,
                    port=int(connection.port),
                    user=connection.username,
                    password=connection.get_password(),
                    database=connection.database_name,
                    cursorclass=pymysql.cursors.DictCursor,
                    connect_timeout=limits.connect_timeout,
                    read_timeout=limits.query_timeout,
                    write_timeout=limits.query_timeout,
                    autocommit=False,
                )
                cursor = conn.cursor()
                establish_mysql_read_only_transaction(cursor)
                read_only_transaction = True
                cursor.execute(query_text)
                results, truncated = fetch_limited_rows(cursor, limits.admin_max_rows)
                if results:
                    columns = list(results[0].keys())
            elif connection.connection_type == 'postgresql':
                import psycopg2
                import psycopg2.extras
                conn = psycopg2.connect(
                    host=connection.server,
                    port=connection.port,
                    user=connection.username,
                    password=connection.get_password(),
                    dbname=connection.database_name,
                    connect_timeout=limits.connect_timeout,
                )
                establish_postgresql_read_only_transaction(conn)
                read_only_transaction = True
                cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                configure_postgresql_statement_timeout(cursor, limits.query_timeout)
                cursor.execute(query_text)
                columns = [desc[0] for desc in cursor.description]
                result_tuples, truncated = fetch_limited_rows(cursor, limits.admin_max_rows)
                results = [dict(row) for row in result_tuples]
            elif connection.connection_type == 'oracle':
                import cx_Oracle
                dsn = cx_Oracle.makedsn(
                    host=connection.server,
                    port=connection.port,
                    service_name=connection.database_name
                )
                conn = cx_Oracle.connect(
                    user=connection.username,
                    password=connection.get_password(),
                    dsn=dsn
                )
                cursor = conn.cursor()
                cursor.execute(query_text)
                columns = [d[0] for d in cursor.description]
                rows, truncated = fetch_limited_rows(cursor, limits.admin_max_rows)
                results = [dict(zip(columns, row)) for row in rows]

            connection.last_used = timezone.now()
            connection.save()
            if truncated:
                logger.warning(
                    'Administrative query results were truncated at %s rows.',
                    limits.admin_max_rows,
                )
            return JsonResponse({
                'success': True,
                'columns': columns,
                'results': results,
                'truncated': truncated,
            })
        except Exception as exc:
            if isinstance(exc, ReadOnlyEnforcementError):
                logger.warning('Database read-only protection could not be established.')
                return JsonResponse(
                    {'success': False, 'error': 'Query execution failed.'}, status=500
                )
            if isinstance(exc, ExternalQueryTimeoutError) or is_timeout_error(exc):
                logger.warning('Administrative query timed out.')
                return JsonResponse(
                    {'success': False, 'error': 'Database query timed out.'}, status=504
                )
            logger.warning('Administrative query execution failed.')
            return JsonResponse(
                {'success': False, 'error': 'Query execution failed.'}, status=500
            )
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    logger.debug('Administrative query cursor did not close cleanly.')
            if read_only_transaction and conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    logger.debug('Administrative query transaction did not roll back cleanly.')
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    logger.debug('Administrative query connection did not close cleanly.')


class SaveQueryView(JsonSuperuserRequiredView):
    """View to save a query"""
    def post(self, request):
        try:
            data = json.loads(request.body)
            
            connection = get_object_or_404(DatabaseConnection, id=data.get('connection_id'), user=request.user)
            
            if data.get('id'):
                # Update existing query
                query = get_object_or_404(SavedQuery, id=data.get('id'), user=request.user)
                query.name = data.get('name')
                query.connection = connection
                query.description = data.get('description', '')
                query.query_text = data.get('query')
                query.save()
            else:
                # Create new query
                query = SavedQuery(
                    user=request.user,
                    name=data.get('name'),
                    connection=connection,
                    description=data.get('description', ''),
                    query_text=data.get('query')
                )
                query.save()
                
            return JsonResponse({'success': True, 'query_id': query.id})
        except Exception:
            logger.warning('Saved query save failed.')
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class RunSavedQueryView(SuperuserRequiredMixin, View):
    """View to run a saved query and display results"""
    def get(self, request, query_id):
        try:
            query = get_object_or_404(SavedQuery, id=query_id, user=request.user)
            connection = query.connection
            
            # Run query and get results
            # This code would be similar to RunQueryView but adapted for display in a template
            
            # Update last_run timestamp
            query.last_run = timezone.now()
            query.save()
            
            # Return results in template
            return render(request, 'pages/configurations/query-results.html', {
                'query': query,
                'connection': connection,
                # Add results data here
            })
        except Exception:
            logger.warning('Saved query execution failed.')
            messages.error(request, 'Query execution failed.')
            return redirect('configurations')


# Stored Procedures Views
class StoredProceduresView(JsonSuperuserRequiredView):
    """View to list all stored procedures for a database connection"""
    def get(self, request, connection_id):
        try:
            connection = get_object_or_404(DatabaseConnection, id=connection_id, user=request.user)
            
            # Get stored procedures based on the connection type
            procedures = []
            
            if connection.connection_type == 'mssql':
                # Use improved driver detection logic
                from .db_config import get_available_odbc_driver
                
                driver = get_available_odbc_driver()
                if not driver:
                    return JsonResponse({'error': 'No compatible ODBC driver found'}, status=500)
                
                conn_string = f"DRIVER={{{driver}}};SERVER={connection.server},{connection.port};DATABASE={connection.database_name};UID={connection.username};PWD={connection.get_password()};TrustServerCertificate=yes;Connection Timeout=30;"
                conn = pyodbc.connect(conn_string)
                cursor = conn.cursor()
                
                # Query to get stored procedures
                query = """
                    SELECT 
                        p.name,
                        SCHEMA_NAME(p.schema_id) as schema_name,
                        o.type_desc
                    FROM 
                        sys.procedures p
                    INNER JOIN 
                        sys.objects o ON p.object_id = o.object_id
                    WHERE 
                        o.type_desc = 'SQL_STORED_PROCEDURE'
                    ORDER BY 
                        SCHEMA_NAME(p.schema_id), p.name
                """
                cursor.execute(query)
                
                for row in cursor.fetchall():
                    procedures.append({
                        'id': f"{row.schema_name}.{row.name}",
                        'name': row.name,
                        'schema': row.schema_name,
                        'type': row.type_desc
                    })
                
                cursor.close()
                conn.close()
                
            elif connection.connection_type == 'mysql':
                import pymysql
                conn = pymysql.connect(
                    host=connection.server,
                    port=int(connection.port),
                    user=connection.username,
                    password=connection.get_password(),
                    database=connection.database_name,
                    cursorclass=pymysql.cursors.DictCursor
                )
                
                with conn.cursor() as cursor:
                    # Query to get stored procedures
                    query = """
                        SELECT 
                            ROUTINE_NAME as name,
                            ROUTINE_SCHEMA as schema_name,
                            ROUTINE_TYPE as type
                        FROM 
                            INFORMATION_SCHEMA.ROUTINES
                        WHERE 
                            ROUTINE_TYPE = 'PROCEDURE'
                        ORDER BY 
                            ROUTINE_SCHEMA, ROUTINE_NAME
                    """
                    cursor.execute(query)
                    
                    for row in cursor.fetchall():
                        procedures.append({
                            'id': f"{row['schema_name']}.{row['name']}",
                            'name': row['name'],
                            'schema': row['schema_name'],
                            'type': row['type']
                        })
                
                conn.close()
                
            elif connection.connection_type == 'postgresql':
                import psycopg2
                import psycopg2.extras
                
                conn = psycopg2.connect(
                    host=connection.server,
                    port=connection.port,
                    user=connection.username,
                    password=connection.get_password(),
                    dbname=connection.database_name
                )
                
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                    # Query to get stored procedures
                    query = """
                        SELECT 
                            p.proname as name,
                            n.nspname as schema_name,
                            pg_catalog.pg_get_function_result(p.oid) as return_type
                        FROM 
                            pg_catalog.pg_proc p
                        LEFT JOIN 
                            pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                        WHERE 
                            n.nspname NOT IN ('pg_catalog', 'information_schema')
                        ORDER BY 
                            n.nspname, p.proname
                    """
                    cursor.execute(query)
                    
                    for row in cursor.fetchall():
                        procedures.append({
                            'id': f"{row['schema_name']}.{row['name']}",
                            'name': row['name'],
                            'schema': row['schema_name'],
                            'return_type': row['return_type']
                        })
                
                conn.close()
                
            elif connection.connection_type == 'oracle':
                import cx_Oracle
                
                dsn = cx_Oracle.makedsn(
                    host=connection.server,
                    port=connection.port,
                    service_name=connection.database_name
                )
                
                conn = cx_Oracle.connect(
                    user=connection.username,
                    password=connection.get_password(),
                    dsn=dsn
                )
                
                cursor = conn.cursor()
                
                # Query to get stored procedures
                query = """
                    SELECT 
                        OBJECT_NAME as name,
                        OWNER as schema_name,
                        OBJECT_TYPE as type
                    FROM 
                        ALL_OBJECTS
                    WHERE 
                        OBJECT_TYPE = 'PROCEDURE'
                        AND OWNER NOT IN ('SYS', 'SYSTEM')
                    ORDER BY 
                        OWNER, OBJECT_NAME
                """
                cursor.execute(query)
                
                for row in cursor:
                    procedures.append({
                        'id': f"{row[1]}.{row[0]}",
                        'name': row[0],
                        'schema': row[1],
                        'type': row[2]
                    })
                
                cursor.close()
                conn.close()
            
            # Update last_used timestamp for the connection
            connection.last_used = timezone.now()
            connection.save()
            
            return JsonResponse({
                'success': True,
                'procedures': procedures
            })
        except Exception:
            logger.warning('Stored procedure discovery failed for connection_id=%s.', connection_id)
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class ProcedureParametersView(JsonSuperuserRequiredView):
    """View to get parameters for a stored procedure"""
    def get(self, request, connection_id, procedure_id):
        try:
            connection = get_object_or_404(DatabaseConnection, id=connection_id, user=request.user)
            
            # Parse procedure ID
            parts = procedure_id.split('.')
            schema_name = parts[0] if len(parts) > 1 else None
            procedure_name = parts[-1]
            
            # Get procedure parameters based on the connection type
            parameters = []
            
            if connection.connection_type == 'mssql':
                # Use improved driver detection logic
                from .db_config import get_available_odbc_driver
                
                driver = get_available_odbc_driver()
                if not driver:
                    return JsonResponse({'error': 'No compatible ODBC driver found'}, status=500)
                
                conn_string = f"DRIVER={{{driver}}};SERVER={connection.server},{connection.port};DATABASE={connection.database_name};UID={connection.username};PWD={connection.get_password()};TrustServerCertificate=yes;Connection Timeout=30;"
                conn = pyodbc.connect(conn_string)
                cursor = conn.cursor()
                
                # Query to get procedure parameters
                query = """
                    SELECT 
                        p.name as procedure_name,
                        params.name as parameter_name,
                        t.name as data_type,
                        params.is_output
                    FROM 
                        sys.procedures p
                    INNER JOIN 
                        sys.parameters params ON p.object_id = params.object_id
                    INNER JOIN 
                        sys.types t ON params.user_type_id = t.user_type_id
                    WHERE 
                        p.name = ?
                        AND SCHEMA_NAME(p.schema_id) = ?
                    ORDER BY 
                        params.parameter_id
                """
                cursor.execute(query, (procedure_name, schema_name))
                
                for row in cursor.fetchall():
                    direction = 'OUT' if row.is_output else 'IN'
                    parameters.append({
                        'name': row.parameter_name,
                        'data_type': row.data_type,
                        'direction': direction
                    })
                
                cursor.close()
                conn.close()
                
            elif connection.connection_type == 'mysql':
                import pymysql
                conn = pymysql.connect(
                    host=connection.server,
                    port=int(connection.port),
                    user=connection.username,
                    password=connection.get_password(),
                    database=connection.database_name,
                    cursorclass=pymysql.cursors.DictCursor
                )
                
                with conn.cursor() as cursor:
                    # Query to get procedure parameters
                    query = """
                        SELECT 
                            PARAMETER_NAME as name,
                            DATA_TYPE as data_type,
                            PARAMETER_MODE as direction
                        FROM 
                            INFORMATION_SCHEMA.PARAMETERS
                        WHERE 
                            SPECIFIC_NAME = %s
                            AND SPECIFIC_SCHEMA = %s
                        ORDER BY 
                            ORDINAL_POSITION
                    """
                    cursor.execute(query, (procedure_name, schema_name))
                    
                    for row in cursor.fetchall():
                        parameters.append({
                            'name': row['name'],
                            'data_type': row['data_type'],
                            'direction': row['direction']
                        })
                
                conn.close()
                
            elif connection.connection_type == 'postgresql':
                import psycopg2
                import psycopg2.extras
                
                conn = psycopg2.connect(
                    host=connection.server,
                    port=connection.port,
                    user=connection.username,
                    password=connection.get_password(),
                    dbname=connection.database_name
                )
                
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                    # Query to get procedure parameters
                    query = """
                        SELECT 
                            p.proname as procedure_name,
                            pg_catalog.pg_get_function_arguments(p.oid) as arguments
                        FROM 
                            pg_catalog.pg_proc p
                        LEFT JOIN 
                            pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                        WHERE 
                            p.proname = %s
                            AND n.nspname = %s
                    """
                    cursor.execute(query, (procedure_name, schema_name))
                    
                    row = cursor.fetchone()
                    if row and row['arguments']:
                        args = row['arguments'].split(',')
                        for arg in args:
                            arg = arg.strip()
                            parts = arg.split(' ')
                            if len(parts) >= 2:
                                name = parts[0]
                                data_type = ' '.join(parts[1:])
                                direction = 'IN'  # PostgreSQL doesn't easily expose parameter direction
                                parameters.append({
                                    'name': name,
                                    'data_type': data_type,
                                    'direction': direction
                                })
                
                conn.close()
                
            elif connection.connection_type == 'oracle':
                import cx_Oracle
                
                dsn = cx_Oracle.makedsn(
                    host=connection.server,
                    port=connection.port,
                    service_name=connection.database_name
                )
                
                conn = cx_Oracle.connect(
                    user=connection.username,
                    password=connection.get_password(),
                    dsn=dsn
                )
                
                cursor = conn.cursor()
                
                # Query to get procedure parameters
                query = """
                    SELECT 
                        ARGUMENT_NAME as name,
                        DATA_TYPE as data_type,
                        IN_OUT as direction
                    FROM 
                        ALL_ARGUMENTS
                    WHERE 
                        OBJECT_NAME = :proc_name
                        AND OWNER = :owner
                    ORDER BY 
                        POSITION
                """
                cursor.execute(query, proc_name=procedure_name, owner=schema_name)
                
                for row in cursor:
                    if row[0]:  # Skip return type which has no name
                        parameters.append({
                            'name': row[0],
                            'data_type': row[1],
                            'direction': row[2]
                        })
                
                cursor.close()
                conn.close()
            
            return JsonResponse({
                'success': True,
                'parameters': parameters
            })
        except Exception:
            logger.warning('Stored procedure parameter discovery failed for connection_id=%s.', connection_id)
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class ExecuteProcedureView(JsonSuperuserRequiredView):
    """Execute an explicitly approved READ_EXPECTED stored procedure only."""
    def post(self, request):
        conn = cursor = None
        approved_procedure = None
        started_at = timezone.now()
        started_at_monotonic = time.monotonic()
        audit_success = False
        audit_failure_category = ProcedureExecutionAudit.VALIDATION_FAILED
        row_count = 0
        result_set_count = 0
        truncated = False
        execution_stage = 'validation'
        try:
            data = json.loads(request.body)
            if not isinstance(data, dict) or set(data) != {'approved_procedure_id', 'parameters'}:
                raise ProcedureExecutionValidationError('Invalid procedure execution request.')
            approved_procedure_id = data.get('approved_procedure_id')
            if isinstance(approved_procedure_id, bool) or not isinstance(approved_procedure_id, int):
                raise ProcedureExecutionValidationError('Invalid procedure execution request.')

            try:
                approved_procedure = ApprovedProcedure.objects.select_related('connection').prefetch_related(
                    'parameters'
                ).get(
                    id=approved_procedure_id,
                    connection__user=request.user,
                )
            except ApprovedProcedure.DoesNotExist:
                raise ProcedureExecutionValidationError('Procedure execution is not approved.') from None

            if not approved_procedure.enabled:
                audit_failure_category = ProcedureExecutionAudit.APPROVAL_DISABLED
                raise ProcedureExecutionValidationError('Procedure execution is not approved.')
            if approved_procedure.behavior != ApprovedProcedure.READ_EXPECTED:
                audit_failure_category = ProcedureExecutionAudit.MUTATING_DENIED
                raise ProcedureExecutionValidationError('Procedure execution is not approved.')

            audit_failure_category = ProcedureExecutionAudit.IDENTITY_MISMATCH
            validate_approved_procedure(approved_procedure)
            audit_failure_category = ProcedureExecutionAudit.VALIDATION_FAILED
            approved_parameters = list(approved_procedure.parameters.all())
            bound_values = validate_parameter_values(approved_parameters, data['parameters'])
            procedure_call = build_procedure_call(approved_procedure, approved_parameters)
            connection = approved_procedure.connection
            limits = get_procedure_execution_limits()

            result_sets = []
            output_parameters = []
            if approved_procedure.engine == 'mssql':
                from .db_config import get_available_odbc_driver
                driver = get_available_odbc_driver()
                if not driver:
                    raise ProcedureExecutionValidationError('Procedure execution is unavailable.')

                conn_string = (
                    f"DRIVER={{{driver}}};SERVER={connection.server},{connection.port};"
                    f"DATABASE={connection.database_name};UID={connection.username};"
                    f"PWD={connection.get_password()};TrustServerCertificate=yes;"
                    f"Connection Timeout={limits.connect_timeout};"
                )
                execution_stage = 'connection'
                conn = pyodbc.connect(conn_string, autocommit=False)
                cursor = conn.cursor()
                cursor.timeout = limits.procedure_timeout
                execution_stage = 'execution'
                cursor.execute(procedure_call, *bound_values)
                execution_stage = 'result_processing'
                result_sets, truncated, result_set_count, row_count = fetch_bounded_procedure_result_sets(
                    cursor, limits, supports_multiple_result_sets=True
                )

            elif approved_procedure.engine == 'mysql':
                import pymysql
                execution_stage = 'connection'
                conn = pymysql.connect(
                    host=connection.server,
                    port=int(connection.port),
                    user=connection.username,
                    password=connection.get_password(),
                    database=connection.database_name,
                    cursorclass=pymysql.cursors.DictCursor,
                    connect_timeout=limits.connect_timeout,
                    read_timeout=limits.procedure_timeout,
                    write_timeout=limits.procedure_timeout,
                    autocommit=False,
                )
                cursor = conn.cursor()
                establish_mysql_read_only_transaction(cursor)
                execution_stage = 'execution'
                cursor.execute(procedure_call, tuple(bound_values))
                execution_stage = 'result_processing'
                result_sets, truncated, result_set_count, row_count = fetch_bounded_procedure_result_sets(
                    cursor, limits, supports_multiple_result_sets=True
                )

            elif approved_procedure.engine == 'postgresql':
                import psycopg2
                import psycopg2.extras
                execution_stage = 'connection'
                conn = psycopg2.connect(
                    host=connection.server,
                    port=connection.port,
                    user=connection.username,
                    password=connection.get_password(),
                    dbname=connection.database_name,
                    connect_timeout=limits.connect_timeout,
                )
                establish_postgresql_read_only_transaction(conn)
                cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                configure_postgresql_statement_timeout(cursor, limits.procedure_timeout)
                execution_stage = 'execution'
                cursor.execute(procedure_call, tuple(bound_values))
                execution_stage = 'result_processing'
                result_sets, truncated, result_set_count, row_count = fetch_bounded_procedure_result_sets(
                    cursor, limits, supports_multiple_result_sets=False
                )

            audit_success = True
            audit_failure_category = ProcedureExecutionAudit.SUCCESS
            return JsonResponse({
                'success': True,
                'result_sets': result_sets,
                'output_parameters': output_parameters,
                'truncated': truncated,
                'result_set_count': result_set_count,
                'row_count': row_count,
            })

        except ProcedureExecutionValidationError:
            return JsonResponse(
                {'success': False, 'error': 'Procedure execution is not available.'}, status=400
            )
        except ReadOnlyEnforcementError:
            audit_failure_category = ProcedureExecutionAudit.READONLY_SETUP_FAILED
            logger.warning('Approved procedure read-only setup failed.')
            return JsonResponse(
                {'success': False, 'error': 'Procedure execution failed.'}, status=500
            )
        except Exception as exc:
            if is_timeout_error(exc):
                audit_failure_category = ProcedureExecutionAudit.TIMEOUT
                logger.warning('Approved procedure execution timed out.')
                return JsonResponse({'success': False, 'error': 'Procedure execution timed out.'}, status=504)
            if execution_stage == 'connection':
                audit_failure_category = ProcedureExecutionAudit.CONNECTION_FAILED
            elif execution_stage == 'result_processing':
                audit_failure_category = ProcedureExecutionAudit.RESULT_PROCESSING_FAILED
            else:
                audit_failure_category = ProcedureExecutionAudit.EXECUTION_FAILED
            logger.warning('Approved procedure execution failed.')
            return JsonResponse(
                {'success': False, 'error': 'Procedure execution failed.'}, status=500
            )
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    logger.debug('Approved procedure cursor did not close cleanly.')
            if conn is not None:
                # READ_EXPECTED execution never commits application-managed transaction state.
                try:
                    conn.rollback()
                except Exception:
                    logger.debug('Approved procedure transaction did not roll back cleanly.')
                try:
                    conn.close()
                except Exception:
                    logger.debug('Approved procedure connection did not close cleanly.')
            if approved_procedure is not None:
                try:
                    ProcedureExecutionAudit.objects.create(
                        user=request.user,
                        approved_procedure=approved_procedure,
                        started_at=started_at,
                        duration_ms=max(0, int((time.monotonic() - started_at_monotonic) * 1000)),
                        success=audit_success,
                        failure_category=audit_failure_category,
                        row_count=row_count,
                        result_set_count=result_set_count,
                        truncated=truncated,
                        engine_snapshot=approved_procedure.engine,
                        database_name_snapshot=approved_procedure.database_name,
                        schema_snapshot=approved_procedure.schema,
                        procedure_name_snapshot=approved_procedure.procedure_name,
                    )
                except Exception:
                    logger.warning('Approved procedure audit persistence failed.')


def _approved_procedure_payload(approval):
    """Return only the non-secret fields needed by the approval-management UI."""
    return {
        'id': approval.id,
        'connection_id': approval.connection_id,
        'connection_name': approval.connection.name,
        'engine': approval.engine,
        'database_name': approval.database_name,
        'schema': approval.schema,
        'procedure_name': approval.procedure_name,
        'signature': approval.signature,
        'behavior': approval.behavior,
        'enabled': approval.enabled,
        'approved_by': approval.approved_by.username if approval.approved_by else None,
        'approved_at': approval.approved_at.isoformat() if approval.approved_at else None,
        'created_at': approval.created_at.isoformat(),
        'updated_at': approval.updated_at.isoformat(),
    }


def _procedure_management_error():
    return JsonResponse({'success': False, 'error': 'Procedure approval data is invalid.'}, status=400)


def _load_json_object(request):
    try:
        data = json.loads(request.body)
    except (TypeError, ValueError):
        raise ProcedureExecutionValidationError('Invalid approval request.') from None
    if not isinstance(data, dict):
        raise ProcedureExecutionValidationError('Invalid approval request.')
    return data


class ApprovedProcedureManagementView(SuperuserRequiredMixin, TemplateView):
    """Small Configurations-linked page for reviewing procedure approvals."""
    template_name = 'pages/configurations/approved_procedures.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['approvals'] = ApprovedProcedure.objects.select_related('connection', 'approved_by').all()
        context['connections'] = DatabaseConnection.objects.filter(is_active=True).only(
            'id', 'name', 'connection_type', 'database_name'
        )
        return context


class ApprovedProcedureManagementDetailView(SuperuserRequiredMixin, TemplateView):
    template_name = 'pages/configurations/approved_procedure_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        approval = get_object_or_404(
            ApprovedProcedure.objects.select_related('connection', 'approved_by'), id=self.kwargs['approval_id']
        )
        context['approval'] = approval
        context['parameters'] = approval.parameters.all()
        context['audits'] = approval.execution_audits.select_related('user').all()[:50]
        return context


class ApprovedProcedureCollectionView(JsonSuperuserRequiredView):
    """List existing approvals or create one explicit, disabled READ_EXPECTED approval."""
    def get(self, request):
        approvals = ApprovedProcedure.objects.select_related('connection', 'approved_by').all()
        return JsonResponse({'success': True, 'approvals': [_approved_procedure_payload(item) for item in approvals]})

    def post(self, request):
        try:
            data = _load_json_object(request)
            if set(data) - {'connection_id', 'schema', 'procedure_name', 'signature'}:
                raise ProcedureExecutionValidationError('Unexpected approval fields.')
            connection_id = data.get('connection_id')
            if isinstance(connection_id, bool) or not isinstance(connection_id, int):
                raise ProcedureExecutionValidationError('Invalid connection.')
            connection = DatabaseConnection.objects.get(id=connection_id, is_active=True)
            if connection.connection_type not in {'mssql', 'mysql', 'postgresql'}:
                raise ProcedureExecutionValidationError('Unsupported connection type.')
            schema = require_safe_identifier(data.get('schema'))
            procedure_name = require_safe_identifier(data.get('procedure_name'))
            signature = data.get('signature', '')
            if not isinstance(signature, str) or len(signature) > 255:
                raise ProcedureExecutionValidationError('Invalid approval signature.')
            approval = ApprovedProcedure.objects.create(
                connection=connection,
                engine=connection.connection_type,
                database_name=connection.database_name,
                schema=schema,
                procedure_name=procedure_name,
                signature=signature,
                behavior=ApprovedProcedure.READ_EXPECTED,
                enabled=False,
                approved_by=request.user,
            )
        except (ApprovedProcedure.DoesNotExist, DatabaseConnection.DoesNotExist, IntegrityError, ProcedureExecutionValidationError):
            return _procedure_management_error()
        return JsonResponse({'success': True, 'approval': _approved_procedure_payload(approval)}, status=201)


class ApprovedProcedureDetailView(JsonSuperuserRequiredView):
    """Inspect or update non-execution approval metadata only."""
    def get(self, request, approval_id):
        approval = get_object_or_404(
            ApprovedProcedure.objects.select_related('connection', 'approved_by'), id=approval_id
        )
        return JsonResponse({'success': True, 'approval': _approved_procedure_payload(approval)})

    def post(self, request, approval_id):
        approval = get_object_or_404(ApprovedProcedure, id=approval_id)
        try:
            data = _load_json_object(request)
            if set(data) - {'schema', 'procedure_name', 'signature'}:
                raise ProcedureExecutionValidationError('Unexpected approval fields.')
            approval.schema = require_safe_identifier(data.get('schema'))
            approval.procedure_name = require_safe_identifier(data.get('procedure_name'))
            signature = data.get('signature', '')
            if not isinstance(signature, str) or len(signature) > 255:
                raise ProcedureExecutionValidationError('Invalid approval signature.')
            approval.signature = signature
            approval.full_clean()
            approval.save(update_fields=['schema', 'procedure_name', 'signature', 'updated_at'])
        except (IntegrityError, ProcedureExecutionValidationError):
            return _procedure_management_error()
        return JsonResponse({'success': True, 'approval': _approved_procedure_payload(approval)})


class ApprovedProcedureToggleView(JsonSuperuserRequiredView):
    def post(self, request, approval_id):
        approval = get_object_or_404(ApprovedProcedure, id=approval_id)
        try:
            data = _load_json_object(request)
            if set(data) != {'enabled'} or not isinstance(data['enabled'], bool):
                raise ProcedureExecutionValidationError('Invalid enabled value.')
            if data['enabled'] and approval.behavior != ApprovedProcedure.READ_EXPECTED:
                raise ProcedureExecutionValidationError('Mutating procedures cannot be enabled.')
            approval.enabled = data['enabled']
            approval.save(update_fields=['enabled', 'updated_at'])
        except ProcedureExecutionValidationError:
            return _procedure_management_error()
        return JsonResponse({'success': True, 'enabled': approval.enabled})


class ApprovedProcedureParametersView(JsonSuperuserRequiredView):
    def get(self, request, approval_id):
        approval = get_object_or_404(ApprovedProcedure, id=approval_id)
        return JsonResponse({'success': True, 'parameters': [
            {
                'ordinal': parameter.ordinal, 'name': parameter.name, 'direction': parameter.direction,
                'database_type': parameter.database_type, 'required': parameter.required,
                'nullable': parameter.nullable, 'max_length': parameter.max_length,
            }
            for parameter in approval.parameters.all()
        ]})

    def post(self, request, approval_id):
        approval = get_object_or_404(ApprovedProcedure, id=approval_id)
        try:
            data = _load_json_object(request)
            parameters = data.get('parameters')
            if set(data) != {'parameters'} or not isinstance(parameters, list):
                raise ProcedureExecutionValidationError('Invalid parameter contract.')
            normalized = []
            ordinals = set()
            names = set()
            for item in parameters:
                required_fields = {'ordinal', 'name', 'direction', 'database_type', 'required', 'nullable'}
                if not isinstance(item, dict) or not required_fields <= set(item) or set(item) - (required_fields | {'max_length'}):
                    raise ProcedureExecutionValidationError('Invalid parameter contract.')
                ordinal = item['ordinal']
                if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1 or ordinal in ordinals:
                    raise ProcedureExecutionValidationError('Invalid parameter ordinal.')
                name = require_safe_identifier(item['name'])
                if name in names or item['direction'] not in {
                    ApprovedProcedureParameter.INPUT, ApprovedProcedureParameter.OUTPUT,
                    ApprovedProcedureParameter.INPUT_OUTPUT,
                }:
                    raise ProcedureExecutionValidationError('Invalid parameter contract.')
                if not isinstance(item['required'], bool) or not isinstance(item['nullable'], bool):
                    raise ProcedureExecutionValidationError('Invalid parameter contract.')
                category = parameter_type_category(item['database_type'])
                max_length = item.get('max_length')
                if max_length is not None and (isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 1):
                    raise ProcedureExecutionValidationError('Invalid parameter length.')
                if max_length is not None and category != 'string':
                    raise ProcedureExecutionValidationError('Invalid parameter length.')
                ordinals.add(ordinal)
                names.add(name)
                normalized.append(ApprovedProcedureParameter(
                    approved_procedure=approval, ordinal=ordinal, name=name, direction=item['direction'],
                    database_type=item['database_type'].strip(), required=item['required'],
                    nullable=item['nullable'], max_length=max_length,
                ))
            with transaction.atomic():
                approval.parameters.all().delete()
                ApprovedProcedureParameter.objects.bulk_create(normalized)
        except (IntegrityError, ProcedureExecutionValidationError, TypeError, AttributeError):
            return _procedure_management_error()
        return JsonResponse({'success': True, 'parameter_count': len(normalized)})


class ApprovedProcedureAuditHistoryView(JsonSuperuserRequiredView):
    def get(self, request, approval_id):
        approval = get_object_or_404(ApprovedProcedure, id=approval_id)
        return JsonResponse({'success': True, 'audits': [
            {
                'started_at': audit.started_at.isoformat(),
                'user': audit.user.username if audit.user else 'Deleted user',
                'success': audit.success,
                'failure_category': audit.failure_category,
                'duration_ms': audit.duration_ms,
                'row_count': audit.row_count,
                'result_set_count': audit.result_set_count,
                'truncated': audit.truncated,
            }
            for audit in approval.execution_audits.select_related('user').all()[:50]
        ]})


class SaveProcedureExecutionView(JsonSuperuserRequiredView):
    """View to save a procedure execution for later use"""
    def post(self, request):
        try:
            data = json.loads(request.body)
            
            connection = get_object_or_404(DatabaseConnection, id=data.get('connection_id'), user=request.user)
            
            # Create or update procedure execution
            saved_execution = SavedProcedureExecution(
                user=request.user,
                connection=connection,
                name=data.get('name'),
                procedure_name=data.get('procedure_name'),
                procedure_schema=data.get('schema'),
                parameters=data.get('parameters', [])
            )
            saved_execution.save()
            
            return JsonResponse({'success': True, 'id': saved_execution.id})
        except Exception:
            logger.warning('Saved procedure execution save failed.')
            return JsonResponse({'success': False, 'error': 'Database operation failed.'}, status=500)


class SavedProcedureExecutionsView(JsonSuperuserRequiredView):
    """List the current superuser's saved procedure convenience records."""

    def get(self, request):
        executions = SavedProcedureExecution.objects.filter(user=request.user).select_related('connection')
        return JsonResponse({
            'success': True,
            'executions': [
                {
                    'id': execution.id,
                    'name': execution.name,
                    'connection_id': execution.connection_id,
                    'connection_name': execution.connection.name,
                    'procedure_name': execution.procedure_name,
                    'procedure_schema': execution.procedure_schema,
                    'parameters': execution.parameters,
                    'created_at': execution.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_run': execution.last_run.strftime('%Y-%m-%d %H:%M:%S') if execution.last_run else None,
                }
                for execution in executions
            ],
        })


class SSOTestView(DebugSuperuserRequiredMixin, TemplateView):
    """
    Test view to demonstrate SSO field prepopulation and disabling
    """
    template_name = 'pages/forms/sso_test.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Simulate SSO user data
        context['sso_user_data'] = {
            'email': 'user@example.com',
            'username': 'testuser',
            'first_name': 'John',
            'last_name': 'Doe',
            'full_name': 'John Doe'
        }
        
        # Sample form configuration with SSO settings
        context['form_config'] = [
            {
                'name': 'user_email',
                'type': 'email',
                'label': 'Email Address',
                'required': True
            },
            {
                'name': 'user_name',
                'type': 'text',
                'label': 'Full Name',
                'required': True
            },
            {
                'name': 'user_username',
                'type': 'text',
                'label': 'Username',
                'required': False
            }
        ]
        
        # SSO field mappings
        context['sso_prepopulate_fields'] = {
            'user_email': 'email',
            'user_name': 'full_name',
            'user_username': 'username'
        }
        
        # SSO disabled fields
        context['sso_disabled_fields'] = ['user_email', 'user_username']
        
        return context


class IntegrationsView(SuperuserRequiredMixin, TemplateView):
    """
    View for integrations page.
    """
    template_name = 'pages/integrations/integrations.html'
    login_url = '/login/'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Integrations" # set the title here
        integrations = Integration.objects.all()
        user_credentials = {
            cred.integration_id: cred for cred in IntegrationCredential.objects.filter(user=self.request.user)
        }

        # Add credentials data to each integration
        for integration in integrations:
            integration.credential = user_credentials.get(integration.id, None)

        context['integrations'] = integrations
        return context

class SSOProviderInfoView(View):
    """API endpoint to provide information about available SSO providers"""
    
    def get(self, request, *args, **kwargs):
        from sso_auth.models import SSOProvider
        
        enabled_provider = SSOProvider.objects.filter(enabled=True).first()
        
        if enabled_provider:
            return JsonResponse({
                'available': True,
                'provider_name': enabled_provider.name,
                'protocol': enabled_provider.protocol.lower(),
                'redirect_url': enabled_provider.get_login_url() if hasattr(enabled_provider, 'get_login_url') else '#'
            })
        else:
            return JsonResponse({
                'available': False,
                'provider_name': None,
                'protocol': None,
                'redirect_url': None
            })


@debug_superuser_required_json
def debug_auth(request):
    """Debug endpoint to check authentication status and integrations"""
    from .models import IntegrationCredential, DatabaseConnection
    
    if request.user.is_authenticated:
        if request.user.is_superuser or request.user.is_staff:
            # Admin/superuser can see all integrations and connections
            db_integrations = IntegrationCredential.objects.filter(
                enabled=True
            ).select_related('integration')
            
            db_connections = DatabaseConnection.objects.filter(
                is_active=True
            )
        else:
            # Regular users see only their own
            db_integrations = IntegrationCredential.objects.filter(
                user=request.user,
                enabled=True
            ).select_related('integration')
            
            db_connections = DatabaseConnection.objects.filter(
                user=request.user, 
                is_active=True
            )
        
        integration_data = []
        for cred in db_integrations:
            integration_data.append({
                'name': cred.integration.name,
                'id': cred.integration.id,
                'fields': cred.integration.fields,
                'has_db_fields': all(field in cred.integration.fields for field in ['host', 'database', 'password', 'username'])
            })
        
        connection_data = []
        for conn in db_connections:
            connection_data.append({
                'name': conn.name,
                'id': conn.id,
                'type': conn.connection_type
            })
        
        return JsonResponse({
            'authenticated': True,
            'user': {
                'username': request.user.username,
                'id': request.user.id,
                'is_staff': request.user.is_staff,
                'is_superuser': request.user.is_superuser
            },
            'integrations': integration_data,
            'database_connections': connection_data,
            'total_available': len(integration_data) + len(connection_data)
        }, json_dumps_params={'indent': 2})
    else:
        return JsonResponse({
            'authenticated': False,
            'message': 'User not authenticated. Please log in.',
            'login_url': '/login/'
        }, json_dumps_params={'indent': 2})
