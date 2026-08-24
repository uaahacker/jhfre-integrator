# Generated migration for SSO User Profile

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('sso_auth', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='SSOUserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sso_id', models.CharField(max_length=255, help_text='SSO unique identifier (NameID for SAML, sub for OIDC)')),
                ('raw_attributes', models.JSONField(default=dict, help_text='All raw SSO attributes received')),
                ('mapped_attributes', models.JSONField(default=dict, help_text='Processed/mapped attributes for easy access')),
                ('last_login_from_sso', models.DateTimeField(auto_now=True, help_text='Last time user logged in via SSO')),
                ('sso_login_count', models.PositiveIntegerField(default=0, help_text='Number of SSO logins')),
                ('is_sso_user', models.BooleanField(default=True, help_text='Whether this user came from SSO')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='sso_profile', to='auth.user')),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_profiles', to='sso_auth.ssoprovider')),
            ],
            options={
                'verbose_name': 'SSO User Profile',
                'verbose_name_plural': 'SSO User Profiles',
                'ordering': ['-last_login_from_sso'],
            },
        ),
        migrations.AddIndex(
            model_name='ssouserprofile',
            index=models.Index(fields=['sso_id'], name='sso_auth_ss_sso_id_idx'),
        ),
        migrations.AddIndex(
            model_name='ssouserprofile',
            index=models.Index(fields=['user', 'provider'], name='sso_auth_ss_user_pr_idx'),
        ),
    ]
