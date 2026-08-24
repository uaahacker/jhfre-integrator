from django.db import migrations
from django.apps import apps


def migrate_saml_config(apps, schema_editor):
    """Migrate existing SAML configuration to the new SSO system."""
    # Get models
    SSOProvider = apps.get_model('sso_auth', 'SSOProvider')
    
    try:
        # Try to get the old SAML configuration model
        SamlConfiguration = apps.get_model('saml_auth', 'SamlConfiguration')
        
        # Get existing SAML configurations
        old_configs = SamlConfiguration.objects.all()
        
        for old_config in old_configs:
            # Create new SSO provider from old config
            sso_provider, created = SSOProvider.objects.get_or_create(
                name=f"SAML Provider {old_config.id}",
                defaults={
                    'protocol': 'saml',
                    'status': 'active' if old_config.enabled else 'inactive',
                    'enabled': old_config.enabled,
                    'debug_mode': old_config.debug,
                    
                    # SAML IdP Settings
                    'saml_idp_entity_id': old_config.idp_entity_id,
                    'saml_idp_sso_url': old_config.idp_sso_url,
                    'saml_idp_slo_url': old_config.idp_slo_url,
                    'saml_idp_x509cert': old_config.idp_x509cert,
                    
                    # SAML SP Settings
                    'saml_sp_entity_id': old_config.sp_entity_id,
                    'saml_sp_acs_url': old_config.sp_acs_url,
                    'saml_sp_slo_url': old_config.sp_slo_url,
                    'saml_sp_x509cert': old_config.sp_x509cert,
                    'saml_sp_private_key': old_config.sp_private_key,
                    'saml_name_id_format': old_config.name_id_format,
                    
                    # SAML Security Settings
                    'saml_want_messages_signed': old_config.want_messages_signed,
                    'saml_want_assertions_signed': old_config.want_assertions_signed,
                    'saml_authn_requests_signed': old_config.authn_requests_signed,
                    'saml_logout_requests_signed': old_config.logout_requests_signed,
                    'saml_logout_responses_signed': old_config.logout_responses_signed,
                    'saml_signature_algorithm': old_config.signature_algorithm,
                    'saml_digest_algorithm': old_config.digest_algorithm,
                    'saml_strict_mode': old_config.strict,
                    
                    'created_at': old_config.created_at,
                    'updated_at': old_config.updated_at,
                }
            )
            if created:
                print(f"Migrated SAML configuration to SSO provider: {sso_provider.name}")
    
    except LookupError:
        # Old saml_auth app or SamlConfiguration model doesn't exist
        print("No existing SAML configuration found to migrate")
        pass


def reverse_migrate_saml_config(apps, schema_editor):
    """Reverse migration - remove migrated SSO providers."""
    SSOProvider = apps.get_model('sso_auth', 'SSOProvider')
    
    # Delete all SAML providers created by migration
    migrated_providers = SSOProvider.objects.filter(
        protocol='saml',
        name__startswith='SAML Provider '
    )
    count = migrated_providers.count()
    migrated_providers.delete()
    print(f"Removed {count} migrated SAML providers")


class Migration(migrations.Migration):
    dependencies = [
        ('sso_auth', '0001_initial'),
        ('saml_auth', '__latest__'),  # Depend on the latest migration from saml_auth
    ]

    operations = [
        migrations.RunPython(
            code=migrate_saml_config,
            reverse_code=reverse_migrate_saml_config,
        ),
    ]
