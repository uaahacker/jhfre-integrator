import re

from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.http import Http404, HttpResponse
from django.urls import path, include, re_path
from django.views.static import serve as static_serve


def healthz(request):
    """Unauthenticated liveness check for the container platform.

    Deliberately does not touch the database: it only proves Gunicorn/Django
    is up and routing requests, so a transient DB hiccup doesn't get the
    container killed by the platform's health check. Database reachability
    is verified separately at boot (entrypoint.sh) and by migrations.
    """
    return HttpResponse("ok", content_type="text/plain")


urlpatterns = [
    path('healthz/', healthz, name='healthz'),
    path('admin/', admin.site.urls),
    path('',include('accounts.urls')),
    path('',include('integrator.urls')), # Changed from 'sysbrix.urls'
    # path('saml/',include('saml_auth.urls')),  # Commented out old SAML - using unified SSO
    path('sso/',include('sso_auth.urls')),  # New unified SSO URLs
]

if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT
    )
else:
    # django.conf.urls.static.static() is itself a DEBUG-only no-op, so it
    # cannot be reused outside DEBUG. Public branding media (company logos/
    # favicons, form logos, integration icons) still needs to be reachable at
    # MEDIA_URL in production. media/uploads/ stays blocked here -- those
    # files are only ever served through the authorization-aware
    # FileUploadDownloadView (integrator/views.py), never by path.
    def _serve_public_media(request, path, document_root=None):
        if path.startswith('uploads/'):
            raise Http404
        return static_serve(request, path, document_root=document_root)

    urlpatterns += [
        re_path(
            r'^%s(?P<path>.*)$' % re.escape(settings.MEDIA_URL.lstrip('/')),
            _serve_public_media,
            kwargs={'document_root': settings.MEDIA_ROOT},
        ),
    ]
