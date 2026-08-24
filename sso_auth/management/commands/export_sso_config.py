from django.core.management.base import BaseCommand, CommandError
from django.core import serializers
from sso_auth.models import SSOProvider
import json
import os


class Command(BaseCommand):
    help = 'Export SSO provider configurations to JSON file'

    def add_arguments(self, parser):
        parser.add_argument(
            'output_file',
            type=str,
            help='Output file path for exported configurations',
        )
        parser.add_argument(
            '--provider',
            type=str,
            help='Name of specific provider to export (optional)',
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['json', 'yaml'],
            default='json',
            help='Export format (default: json)',
        )

    def handle(self, *args, **options):
        output_file = options['output_file']
        provider_name = options.get('provider')
        export_format = options['format']

        # Get providers to export
        if provider_name:
            try:
                providers = [SSOProvider.objects.get(name=provider_name)]
            except SSOProvider.DoesNotExist:
                raise CommandError(f'Provider "{provider_name}" does not exist.')
        else:
            providers = SSOProvider.objects.all()

        if not providers:
            self.stdout.write(self.style.WARNING('No providers found to export.'))
            return

        # Prepare data for export
        export_data = []
        
        for provider in providers:
            data = {
                'name': provider.name,
                'protocol': provider.protocol,
                'status': provider.status,
                'description': provider.description,
                'enabled': provider.enabled,
                'allow_registration': provider.allow_registration,
                'debug_mode': provider.debug_mode,
                
                # Attribute mapping
                'attr_email': provider.attr_email,
                'attr_first_name': provider.attr_first_name,
                'attr_last_name': provider.attr_last_name,
                'attr_username': provider.attr_username,
            }
            
            if provider.protocol == 'saml':
                data.update({
                    'saml_idp_entity_id': provider.saml_idp_entity_id,
                    'saml_idp_sso_url': provider.saml_idp_sso_url,
                    'saml_idp_slo_url': provider.saml_idp_slo_url,
                    'saml_idp_x509cert': provider.saml_idp_x509cert,
                    'saml_sp_entity_id': provider.saml_sp_entity_id,
                    'saml_sp_acs_url': provider.saml_sp_acs_url,
                    'saml_sp_slo_url': provider.saml_sp_slo_url,
                    'saml_name_id_format': provider.saml_name_id_format,
                    'saml_want_messages_signed': provider.saml_want_messages_signed,
                    'saml_want_assertions_signed': provider.saml_want_assertions_signed,
                    'saml_authn_requests_signed': provider.saml_authn_requests_signed,
                    'saml_logout_requests_signed': provider.saml_logout_requests_signed,
                    'saml_logout_responses_signed': provider.saml_logout_responses_signed,
                    'saml_signature_algorithm': provider.saml_signature_algorithm,
                    'saml_digest_algorithm': provider.saml_digest_algorithm,
                    'saml_strict_mode': provider.saml_strict_mode,
                })
                
            
            elif provider.protocol == 'oidc':
                data.update({
                    'oidc_client_id': provider.oidc_client_id,
                    'oidc_discovery_url': provider.oidc_discovery_url,
                    'oidc_authorization_endpoint': provider.oidc_authorization_endpoint,
                    'oidc_token_endpoint': provider.oidc_token_endpoint,
                    'oidc_userinfo_endpoint': provider.oidc_userinfo_endpoint,
                    'oidc_jwks_uri': provider.oidc_jwks_uri,
                    'oidc_issuer': provider.oidc_issuer,
                    'oidc_scopes': provider.oidc_scopes,
                })
                
            
            export_data.append(data)

        # Write to file
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w') as f:
                if export_format == 'yaml':
                    try:
                        import yaml
                        yaml.dump(export_data, f, default_flow_style=False)
                    except ImportError:
                        raise CommandError('PyYAML is required for YAML export. Install with: pip install PyYAML')
                else:
                    json.dump(export_data, f, indent=2)
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully exported {len(export_data)} provider(s) to {output_file}')
            )
            
            self.stdout.write(self.style.WARNING('Sensitive fields were excluded from export.'))
                
        except Exception as e:
            raise CommandError(f'Failed to write export file: {str(e)}')
