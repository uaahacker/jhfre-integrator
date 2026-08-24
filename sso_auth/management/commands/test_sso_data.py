from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from sso_auth.utils import SSOUtils
from sso_auth.models import SSOProvider, SSOUserProfile
import json

User = get_user_model()


class Command(BaseCommand):
    help = 'Test SSO user data functionality for both SSO and regular users'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--create-test-data', 
            action='store_true',
            help='Create test SSO provider and users',
        )
        parser.add_argument(
            '--test-user',
            type=str,
            help='Test specific user by username or email',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🔍 Testing SSO User Data Functionality')
        )
        
        if options['create_test_data']:
            self.create_test_data()
        
        if options['test_user']:
            self.test_specific_user(options['test_user'])
        else:
            self.test_all_users()
    
    def create_test_data(self):
        """Create test SSO provider and test users."""
        self.stdout.write('📝 Creating test data...')
        
        # Create test SSO provider
        provider, created = SSOProvider.objects.get_or_create(
            name='Test SAML Provider',
            defaults={
                'protocol': 'saml',
                'status': 'active',
                'enabled': True,
                'allow_registration': True,
                'attr_email': 'email',
                'attr_first_name': 'first_name',
                'attr_last_name': 'last_name',
                'attr_username': 'username',
            }
        )
        
        if created:
            self.stdout.write('  ✅ Created test SSO provider')
        else:
            self.stdout.write('  ℹ️  Test SSO provider already exists')
        
        # Create test regular user
        regular_user, created = User.objects.get_or_create(
            username='regular_user',
            defaults={
                'email': 'regular@example.com',
                'first_name': 'Regular',
                'last_name': 'User',
            }
        )
        
        if created:
            self.stdout.write('  ✅ Created regular user')
        else:
            self.stdout.write('  ℹ️  Regular user already exists')
        
        # Create test SSO user with profile
        sso_user, created = User.objects.get_or_create(
            username='sso_user',
            defaults={
                'email': 'sso@example.com',
                'first_name': 'SSO',
                'last_name': 'User',
            }
        )
        
        if created:
            self.stdout.write('  ✅ Created SSO user')
        else:
            self.stdout.write('  ℹ️  SSO user already exists')
        
        # Create SSO profile for the test user
        sso_profile, created = SSOUserProfile.objects.get_or_create(
            user=sso_user,
            provider=provider,
            defaults={
                'sso_id': 'sso@example.com',
                'raw_attributes': {
                    'email': 'sso@example.com',
                    'first_name': 'SSO',
                    'last_name': 'User',
                    'department': 'IT Department',
                    'job_title': 'Software Developer',
                    'phone': '+1-555-0123',
                    'organization': 'Test Company',
                    'manager': 'John Manager',
                    'employee_id': 'EMP001',
                    'office_location': 'New York',
                    'groups': ['developers', 'employees']
                },
                'mapped_attributes': {
                    'email': 'sso@example.com',
                    'first_name': 'SSO',
                    'last_name': 'User',
                    'department': 'IT Department',
                    'job_title': 'Software Developer',
                    'phone': '+1-555-0123',
                    'organization': 'Test Company',
                    'manager': 'John Manager',
                    'employee_id': 'EMP001',
                    'office_location': 'New York',
                    'groups': ['developers', 'employees']
                },
                'sso_login_count': 5,
            }
        )
        
        if created:
            self.stdout.write('  ✅ Created SSO user profile')
        else:
            self.stdout.write('  ℹ️  SSO user profile already exists')
        
        self.stdout.write(
            self.style.SUCCESS('✅ Test data creation completed')
        )
    
    def test_specific_user(self, identifier):
        """Test specific user data extraction."""
        try:
            if '@' in identifier:
                user = User.objects.get(email=identifier)
            else:
                user = User.objects.get(username=identifier)
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f'❌ User not found: {identifier}')
            )
            return
        
        self.stdout.write(f'🔍 Testing user: {user.username} ({user.email})')
        self.display_user_data(user)
    
    def test_all_users(self):
        """Test data extraction for all users."""
        users = User.objects.all()
        
        if not users:
            self.stdout.write(
                self.style.WARNING('⚠️  No users found in database')
            )
            return
        
        self.stdout.write(f'🔍 Testing {users.count()} users...\n')
        
        for user in users:
            self.display_user_data(user)
            self.stdout.write('-' * 50)
    
    def display_user_data(self, user):
        """Display user data and SSO information."""
        self.stdout.write(f'👤 User: {user.username} ({user.email})')
        
        # Check if user has SSO profile
        try:
            sso_profile = user.sso_profile
            self.stdout.write('🔐 SSO User: YES')
            self.stdout.write(f'  Provider: {sso_profile.provider.name} ({sso_profile.provider.protocol})')
            self.stdout.write(f'  SSO ID: {sso_profile.sso_id}')
            self.stdout.write(f'  Login Count: {sso_profile.sso_login_count}')
            self.stdout.write(f'  Last Login: {sso_profile.last_login_from_sso}')
            
            if sso_profile.mapped_attributes:
                self.stdout.write('  📋 Mapped Attributes:')
                for key, value in sso_profile.mapped_attributes.items():
                    self.stdout.write(f'    {key}: {value}')
        except SSOUserProfile.DoesNotExist:
            self.stdout.write('🔐 SSO User: NO (Regular user)')
        
        # Test SSOUtils.get_user_sso_attributes
        sso_attrs = SSOUtils.get_user_sso_attributes(user)
        if sso_attrs:
            self.stdout.write('📊 SSO Attributes Retrieved:')
            self.stdout.write(f'  Provider: {sso_attrs.get("provider", "N/A")}')
            self.stdout.write(f'  Protocol: {sso_attrs.get("protocol", "N/A")}')
            self.stdout.write(f'  Login Count: {sso_attrs.get("login_count", "N/A")}')
        else:
            self.stdout.write('📊 No SSO attributes available')
        
        # Basic user info
        self.stdout.write('ℹ️  Basic Info:')
        self.stdout.write(f'  Full Name: {user.get_full_name() or "Not set"}')
        self.stdout.write(f'  Email: {user.email or "Not set"}')
        self.stdout.write(f'  Date Joined: {user.date_joined}')
        self.stdout.write(f'  Last Login: {user.last_login or "Never"}')
        self.stdout.write('')
