from django.core.management.base import BaseCommand
from django.db import connection
from django.db.utils import OperationalError
from django.apps import apps


class Command(BaseCommand):
    help = 'Check cloud database connectivity and migration status'

    def handle(self, *args, **options):
        self.stdout.write('🔍 Checking cloud database status...')
        
        # Check database connectivity
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version();")
                version = cursor.fetchone()
                self.stdout.write(f'✅ Database connected: {version[0]}')
        except OperationalError as e:
            self.stdout.write(self.style.ERROR(f'❌ Database connection failed: {e}'))
            return
        
        # Check current migration status
        try:
            from django.db.migrations.executor import MigrationExecutor
            executor = MigrationExecutor(connection)
            
            # Get all migrations
            all_migrations = executor.loader.graph.nodes.keys()
            applied_migrations = executor.loader.applied_migrations
            
            self.stdout.write(f'📊 Total migrations available: {len(all_migrations)}')
            self.stdout.write(f'📊 Applied migrations: {len(applied_migrations)}')
            
            # Check specific migrations
            integrator_migrations = [m for m in all_migrations if m[0] == 'integrator']
            integrator_applied = [m for m in applied_migrations if m[0] == 'integrator']
            
            self.stdout.write(f'🔧 Integrator migrations available: {len(integrator_migrations)}')
            self.stdout.write(f'🔧 Integrator migrations applied: {len(integrator_applied)}')
            
            # Check for our SSO migration
            sso_migration = None
            for migration in integrator_migrations:
                if '0007_dynamicform_enable_sso_prepopulate_and_more' in str(migration):
                    sso_migration = migration
                    break
            
            if sso_migration:
                if sso_migration in integrator_applied:
                    self.stdout.write(self.style.SUCCESS('✅ SSO migration is applied'))
                else:
                    self.stdout.write(self.style.WARNING('⚠️  SSO migration exists but NOT applied'))
                    
                    # Check what's blocking it
                    plan = executor.migration_plan([sso_migration])
                    if plan:
                        self.stdout.write(f'📋 Migration plan: {len(plan)} migrations to apply')
                        for migration, backwards in plan:
                            self.stdout.write(f'   - {migration}')
                    else:
                        self.stdout.write('✅ Migration can be applied immediately')
            else:
                self.stdout.write(self.style.ERROR('❌ SSO migration not found'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Migration check failed: {e}'))
            import traceback
            self.stdout.write(traceback.format_exc())
