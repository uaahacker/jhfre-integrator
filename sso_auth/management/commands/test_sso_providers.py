from django.core.management.base import BaseCommand, CommandError
from sso_auth.models import SSOProvider


class Command(BaseCommand):
    help = 'Test SSO provider connections'

    def add_arguments(self, parser):
        parser.add_argument(
            '--provider',
            type=str,
            help='Name of the provider to test (optional, tests all if not specified)',
        )
        parser.add_argument(
            '--protocol',
            type=str,
            choices=['saml', 'oidc'],
            help='Test providers of specific protocol only',
        )

    def handle(self, *args, **options):
        provider_name = options.get('provider')
        protocol = options.get('protocol')

        if provider_name:
            # Test specific provider
            try:
                provider = SSOProvider.objects.get(name=provider_name)
                self.test_provider(provider)
            except SSOProvider.DoesNotExist:
                raise CommandError(f'Provider "{provider_name}" does not exist.')
        else:
            # Test all providers or filtered by protocol
            queryset = SSOProvider.objects.filter(enabled=True)
            if protocol:
                queryset = queryset.filter(protocol=protocol)
            
            providers = queryset.all()
            
            if not providers:
                self.stdout.write(
                    self.style.WARNING('No enabled providers found to test.')
                )
                return

            self.stdout.write(f'Testing {len(providers)} provider(s)...\n')
            
            for provider in providers:
                self.test_provider(provider)

    def test_provider(self, provider):
        self.stdout.write(f'Testing {provider.name} ({provider.get_protocol_display()})...')
        
        try:
            results = provider.test_connection()
            
            if results['success']:
                self.stdout.write(
                    self.style.SUCCESS(f'✓ {provider.name}: {results.get("message", "Test passed")}')
                )
            else:
                errors = '; '.join(results.get('errors', ['Unknown error']))
                self.stdout.write(
                    self.style.ERROR(f'✗ {provider.name}: {errors}')
                )
                
                # Show warnings if any
                if results.get('warnings'):
                    warnings = '; '.join(results['warnings'])
                    self.stdout.write(
                        self.style.WARNING(f'  Warnings: {warnings}')
                    )
                    
        except Exception:
            e = 'details suppressed'
            self.stdout.write(
                self.style.ERROR(f'✗ {provider.name}: Test failed with exception: {str(e)}')
            )
