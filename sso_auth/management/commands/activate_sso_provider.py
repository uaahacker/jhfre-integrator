"""
Management command to activate a specific SSO provider
"""
from django.core.management.base import BaseCommand, CommandError
from sso_auth.models import SSOProvider


class Command(BaseCommand):
    help = 'Activate a specific SSO provider (disables all others)'

    def add_arguments(self, parser):
        parser.add_argument(
            'provider_name',
            type=str,
            help='Name of the provider to activate'
        )

    def handle(self, *args, **options):
        provider_name = options['provider_name']
        
        try:
            provider = SSOProvider.objects.get(name=provider_name)
        except SSOProvider.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'Provider "{provider_name}" not found.')
            )
            
            # Show available providers
            available = SSOProvider.objects.all()
            if available.exists():
                self.stdout.write('\nAvailable providers:')
                for p in available:
                    status = '✓ ACTIVE' if p.enabled else '○ inactive'
                    self.stdout.write(f'  {status} {p.name} ({p.protocol})')
            else:
                self.stdout.write('No providers configured.')
            return

        # Enable the provider (this will automatically disable others)
        provider.enabled = True
        provider.save()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'✓ Activated "{provider.name}" ({provider.protocol})'
            )
        )
        
        # Show status of all providers
        self.stdout.write('\nProvider status:')
        for p in SSOProvider.objects.all().order_by('name'):
            status = '✓ ACTIVE' if p.enabled else '○ inactive'
            self.stdout.write(f'  {status} {p.name} ({p.protocol})')
