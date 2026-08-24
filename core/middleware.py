# core/middleware.py
from django.shortcuts import redirect
from integrator.models import Company # Changed from sysbrix.models
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse
from urllib.parse import urlencode
from django.db import connection

class SAMLRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        excluded_paths = [
            '/admin/',
            '/login/',  # Exclude the login page itself
            '/saml/',   # Exclude all SAML paths as well - let saml_auth handle it
        ]

        if request.path.startswith('/saml/'):
            return self.get_response(request) # Let SAML URLs be handled by saml_auth views

        if isinstance(request.user, AnonymousUser):
            if request.path not in ['/login/', reverse('login')]: # If not already on login page
                return redirect('/login/')  # Redirect to the standard login page

        if request.path in excluded_paths:
            return self.get_response(request) # Allow access to excluded paths
        return self.get_response(request) # Proceed for authenticated users or non-protected paths


class CompanyTimezoneMiddleware(MiddlewareMixin):
    """
    Middleware to set timezone dynamically based on company settings.
    """
    def process_request(self, request):
       if hasattr(request, 'company_data') and request.company_data.get('company'):
          company = request.company_data.get('company')
          if company and company.timezone:
            timezone.activate(company.timezone)
          else:
            timezone.deactivate()
       else:
            timezone.deactivate()


class CompanySettingsMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Determine the table name for the Company model
        table_name = Company._meta.db_table
        # If the table does not exist, set default company_data and exit
        if table_name not in connection.introspection.table_names():
            request.company_data = {
                'company': None,
                'company_favicon_url': None,
                'company_logo_display': settings.DEFAULT_LOGO_TEXT
            }
            return

        # Table exists; attempt to fetch the company safely
        try:
            company = Company.objects.first()
        except Exception:
            company = None

        if company:  # If a company exists, load or cache its settings
            cache_key = f'current_company_settings_{company.id}'
            company_data = cache.get(cache_key)
            if company_data is None:
                company_data = {
                    'company': company,
                    'company_favicon_url': company.get_favicon_url() if company else None,
                    'company_logo_display': company.get_logo_display() if company else settings.DEFAULT_LOGO_TEXT,
                }
                cache.set(cache_key, company_data, settings.COMPANY_CACHE_TIMEOUT)
            request.company_data = company_data
        else:
            request.company_data = {
                'company': None,
                'company_favicon_url': None,
                'company_logo_display': settings.DEFAULT_LOGO_TEXT
            }