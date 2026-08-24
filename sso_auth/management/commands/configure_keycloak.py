"""
Management command to easily configure Keycloak SSO providers
"""
from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from sso_auth.models import SSOProvider


class Command(BaseCommand):
    help = 'Configure Keycloak SSO provider with production settings'

    def add_arguments(self, parser):
        parser.add_argument(
            '--keycloak-url', 
            type=str, 
            required=True,
            help='Keycloak server URL (e.g., https://auth.example.com)'
        )
        parser.add_argument(
            '--realm', 
            type=str, 
            required=True,
            help='Keycloak realm name'
        )
        parser.add_argument(
            '--client-id', 
            type=str,
            help='OIDC Client ID (for OIDC provider)'
        )
        parser.add_argument(
            '--client-secret', 
            type=str,
            help='OIDC Client Secret (for OIDC provider)'
        )
        parser.add_argument(
            '--production-url', 
            type=str,
            required=True,
            help='Your production application URL (e.g., https://myapp.example.com)'
        )
        parser.add_argument(
            '--protocol', 
            type=str, 
            choices=['saml', 'oidc', 'both'],
            default='both',
            help='Which protocol to configure (default: both)'
        )
        parser.add_argument(
            '--update-existing', 
            action='store_true',
            help='Update existing providers instead of creating new ones'
        )

    def handle(self, *args, **options):
        keycloak_url = options['keycloak_url'].rstrip('/')
        realm = options['realm']
        production_url = options['production_url'].rstrip('/')
        protocol = options['protocol']
        update_existing = options['update_existing']

        self.stdout.write(
            self.style.SUCCESS(
                f"Configuring Keycloak SSO for realm '{realm}' at '{keycloak_url}'"
            )
        )

        if protocol in ['saml', 'both']:
            self.configure_saml_provider(
                keycloak_url, realm, production_url, update_existing
            )

        if protocol in ['oidc', 'both']:
            client_id = options.get('client_id')
            client_secret = options.get('client_secret')
            
            if not client_id or not client_secret:
                self.stdout.write(
                    self.style.WARNING(
                        "Client ID and client secret are required; skipping OIDC configuration. "
                        "Use --client-id and --client-secret to configure OIDC."
                    )
                )
            else:
                self.configure_oidc_provider(
                    keycloak_url, realm, production_url, 
                    client_id, client_secret, update_existing
                )

        self.stdout.write(
            self.style.SUCCESS("Keycloak configuration completed!")
        )

    def configure_saml_provider(self, keycloak_url, realm, production_url, update_existing):
        """Configure SAML provider"""
        provider_name = f"{realm.title()} SAML"
        
        # SAML configuration
        saml_config = {
            'name': provider_name,
            'protocol': 'saml',
            'enabled': True,
            'saml_idp_entity_id': f"{keycloak_url}/realms/{realm}",
            'saml_idp_sso_url': f"{keycloak_url}/realms/{realm}/protocol/saml",
            'saml_idp_slo_url': f"{keycloak_url}/realms/{realm}/protocol/saml",
            'saml_sp_entity_id': f"{production_url}/sso/saml/metadata/",
            'saml_sp_acs_url': f"{production_url}/sso/saml/acs/",
            'debug_mode': False,
        }

        if update_existing:
            try:
                provider = SSOProvider.objects.get(name=provider_name)
                for key, value in saml_config.items():
                    setattr(provider, key, value)
                provider.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Updated existing SAML provider: {provider_name}")
                )
            except SSOProvider.DoesNotExist:
                provider = SSOProvider.objects.create(**saml_config)
                self.stdout.write(
                    self.style.SUCCESS(f"Created new SAML provider: {provider_name}")
                )
        else:
            # Delete test providers first
            SSOProvider.objects.filter(
                name__icontains="test", protocol='saml'
            ).delete()
            SSOProvider.objects.filter(
                saml_idp_entity_id__icontains="example.com"
            ).delete()
            
            provider, created = SSOProvider.objects.get_or_create(
                name=provider_name,
                defaults=saml_config
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f"Created new SAML provider: {provider_name}")
                )
            else:
                for key, value in saml_config.items():
                    setattr(provider, key, value)
                provider.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Updated SAML provider: {provider_name}")
                )

        # Display configuration info
        self.stdout.write("\nSAML Configuration Details:")
        self.stdout.write(f"  IdP Entity ID: {saml_config['saml_idp_entity_id']}")
        self.stdout.write(f"  IdP SSO URL: {saml_config['saml_idp_sso_url']}")
        self.stdout.write(f"  SP Entity ID: {saml_config['saml_sp_entity_id']}")
        self.stdout.write(f"  SP ACS URL: {saml_config['saml_sp_acs_url']}")
        self.stdout.write(f"  Metadata URL: {production_url}/sso/saml/metadata/")

    def configure_oidc_provider(self, keycloak_url, realm, production_url, 
                              client_id, client_secret, update_existing):
        """Configure OIDC provider"""
        provider_name = f"{realm.title()} OIDC"
        
        # OIDC configuration
        oidc_config = {
            'name': provider_name,
            'protocol': 'oidc',
            'enabled': True,
            'oidc_client_id': client_id,
            'oidc_client_secret': client_secret,
            'oidc_discovery_url': f"{keycloak_url}/realms/{realm}/.well-known/openid_configuration",
            'oidc_scopes': 'openid email profile',
            'debug_mode': False,
        }

        if update_existing:
            try:
                provider = SSOProvider.objects.get(name=provider_name)
                for key, value in oidc_config.items():
                    setattr(provider, key, value)
                provider.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Updated existing OIDC provider: {provider_name}")
                )
            except SSOProvider.DoesNotExist:
                provider = SSOProvider.objects.create(**oidc_config)
                self.stdout.write(
                    self.style.SUCCESS(f"Created new OIDC provider: {provider_name}")
                )
        else:
            # Delete test providers first
            SSOProvider.objects.filter(
                name__icontains="test", protocol='oidc'
            ).delete()
            SSOProvider.objects.filter(
                oidc_discovery_url__icontains="example.com"
            ).delete()
            
            provider, created = SSOProvider.objects.get_or_create(
                name=provider_name,
                defaults=oidc_config
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f"Created new OIDC provider: {provider_name}")
                )
            else:
                for key, value in oidc_config.items():
                    setattr(provider, key, value)
                provider.save()
                self.stdout.write(
                    self.style.SUCCESS(f"Updated OIDC provider: {provider_name}")
                )

        # Display configuration info
        self.stdout.write("\nOIDC Configuration Details:")
        self.stdout.write(f"  Client ID: {client_id}")
        self.stdout.write(f"  Discovery URL: {oidc_config['oidc_discovery_url']}")
        self.stdout.write(f"  Redirect URI: {production_url}/sso/oidc/callback/{provider_name.lower().replace(' ', '-')}/")
        self.stdout.write(f"  Scopes: {oidc_config['oidc_scopes']}")
