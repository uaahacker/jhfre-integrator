import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from integrator.db_config import test_mssql_connection


class Command(BaseCommand):
    help = 'Test MSSQL ODBC connection across environments'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user',
            type=str,
            help='Username to test connection with (defaults to first user)',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('=== MSSQL ODBC Connection Test ===\n')
        )
        
        # Get user
        User = get_user_model()
        
        if options['user']:
            try:
                user = User.objects.get(username=options['user'])
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'User "{options["user"]}" not found')
                )
                return
        else:
            user = User.objects.first()
            if not user:
                self.stdout.write(
                    self.style.ERROR('No users found in database')
                )
                return

        self.stdout.write(f'Testing with user: {user.username}')
        
        # Run diagnostics
        diagnostics = test_mssql_connection(user)
        
        # Display results
        self.stdout.write(f'\n📊 Diagnostics:')
        self.stdout.write(f'  Environment: {diagnostics["environment"]}')
        self.stdout.write(f'  Should use MSSQL: {diagnostics["should_use_mssql"]}')
        self.stdout.write(f'  Available drivers: {len(diagnostics["available_drivers"])}')
        
        if options['verbose']:
            for i, driver in enumerate(diagnostics['available_drivers'], 1):
                self.stdout.write(f'    {i}. {driver}')
        
        self.stdout.write(f'  Selected driver: {diagnostics["selected_driver"]}')
        
        # Connection result
        if diagnostics['connection_successful']:
            self.stdout.write(
                self.style.SUCCESS('\n✅ Connection test: PASSED')
            )
        else:
            self.stdout.write(
                self.style.ERROR('\n❌ Connection test: FAILED')
            )
            if diagnostics['error_message']:
                self.stdout.write(f'   Error: {diagnostics["error_message"]}')
        
        # Environment-specific guidance
        app_env = diagnostics['environment']
        self.stdout.write(f'\n🔧 Environment-specific notes:')
        
        if app_env == 'local':
            if not diagnostics['should_use_mssql']:
                self.stdout.write('  • MSSQL disabled for local SQLite development')
                self.stdout.write('  • This is expected behavior')
            else:
                self.stdout.write('  • MSSQL enabled in local environment')
                self.stdout.write('  • Make sure credentials are configured')
                
        elif app_env in ['development', 'production']:
            if diagnostics['selected_driver']:
                self.stdout.write(f'  • Using ODBC driver: {diagnostics["selected_driver"]}')
                if not diagnostics['connection_successful']:
                    self.stdout.write('  • Check database credentials and network connectivity')
            else:
                self.stdout.write('  • No ODBC drivers found!')
                self.stdout.write('  • This should not happen in containerized environments')
        
        self.stdout.write(f'\n📝 Quick fixes:')
        self.stdout.write('  • For local dev: Use SQLite (default behavior)')
        self.stdout.write('  • For containers: ODBC drivers should be pre-installed')
        self.stdout.write('  • For connection issues: Check IntegrationCredential table')
