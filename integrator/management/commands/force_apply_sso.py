from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.state import ProjectState


class Command(BaseCommand):
    help = 'Force apply the SSO migration if it exists but is not applied'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually doing it',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        
        self.stdout.write('🔧 Force applying SSO migration...')
        
        try:
            executor = MigrationExecutor(connection)
            
            # Find the SSO migration
            sso_migration = None
            for migration in executor.loader.graph.nodes.keys():
                if migration[0] == 'integrator' and '0007_dynamicform_enable_sso_prepopulate_and_more' in str(migration):
                    sso_migration = migration
                    break
            
            if not sso_migration:
                self.stdout.write(self.style.ERROR('❌ SSO migration not found'))
                return
            
            self.stdout.write(f'📋 Found SSO migration: {sso_migration}')
            
            # Check if it's already applied
            if sso_migration in executor.loader.applied_migrations:
                self.stdout.write(self.style.SUCCESS('✅ SSO migration is already applied'))
                return
            
            # Check what's blocking it
            plan = executor.migration_plan([sso_migration])
            if plan:
                self.stdout.write(f'📋 Dependencies to apply first: {len(plan)} migrations')
                for migration, backwards in plan:
                    self.stdout.write(f'   - {migration}')
                
                if not dry_run:
                    self.stdout.write('🚀 Applying dependencies...')
                    for migration, backwards in plan:
                        self.stdout.write(f'   Applying {migration}...')
                        executor.apply_migration(migration, 'integrator')
                        self.stdout.write(f'   ✅ {migration} applied')
            
            # Now apply the SSO migration
            if not dry_run:
                self.stdout.write('🚀 Applying SSO migration...')
                executor.apply_migration(sso_migration, 'integrator')
                self.stdout.write(self.style.SUCCESS('✅ SSO migration applied successfully!'))
                
                # Verify it's applied
                executor = MigrationExecutor(connection)  # Refresh
                if sso_migration in executor.loader.applied_migrations:
                    self.stdout.write('✅ Verification: SSO migration is now applied')
                else:
                    self.stdout.write(self.style.ERROR('❌ Verification failed: SSO migration still not applied'))
            else:
                self.stdout.write('🔍 Dry run - would apply SSO migration')
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Force apply failed: {e}'))
            import traceback
            self.stdout.write(traceback.format_exc())
