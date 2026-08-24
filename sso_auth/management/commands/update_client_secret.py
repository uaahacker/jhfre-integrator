"""
Management command to update SSO provider credentials securely
"""
from django.core.management.base import BaseCommand, CommandError
from sso_auth.models import SSOProvider
import getpass


class Command(BaseCommand):
    help = 'Update SSO provider client secret securely'

    def add_arguments(self, parser):
        parser.add_argument(
            'provider_name',
            type=str,
            help='Name of the provider to update'
        )
        parser.add_argument(
            '--client-secret',
            type=str,
            help='Client secret (will prompt securely if not provided)'
        )

    def handle(self, *args, **options):
        provider_name = options['provider_name']
        client_secret = options.get('client_secret')
        
        try:
            provider = SSOProvider.objects.get(name=provider_name)
        except SSOProvider.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'Provider "{provider_name}" not found.')
            )
            return

        if provider.protocol != 'oidc':
            self.stdout.write(
                self.style.ERROR(f'Provider "{provider_name}" is not an OIDC provider.')
            )
            return

        # Get client secret securely
        if not client_secret:
            client_secret = getpass.getpass(f'Enter client secret for "{provider_name}": ')
        
        if not client_secret:
            self.stdout.write(
                self.style.ERROR('Client secret is required.')
            )
            return

        # Update the provider
        provider.oidc_client_secret = client_secret
        provider.save()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'✓ Updated client secret for "{provider.name}"'
            )
        )
        
        # Show current configuration (without secret)
        self.stdout.write('\nCurrent OIDC configuration:')
        self.stdout.write(f'  Client ID: {provider.oidc_client_id}')
        self.stdout.write(f'  Discovery URL: {provider.oidc_discovery_url}')
        self.stdout.write(f'  Scopes: {provider.oidc_scopes}')
        self.stdout.write(f'  Enabled: {provider.enabled}')
        
        if provider.enabled:
            self.stdout.write(
                self.style.SUCCESS('\nProvider is active and ready to use!')
            )
        else:
            self.stdout.write(
                self.style.WARNING('\nProvider is disabled. Enable it to use for SSO.')
            )
