from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.state import ProjectState
from django.apps import apps


class Command(BaseCommand):
    help = 'Test if the SSO migration can run successfully'

    def handle(self, *args, **options):
        self.stdout.write('Testing SSO migration...')
        
        try:
            # Check current migration status
            executor = MigrationExecutor(connection)
            plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
            
            self.stdout.write(f'Current migration plan: {len(plan)} migrations to apply')
            
            # Check if our migration is in the plan
            sso_migration = None
            for migration, backwards in plan:
                if '0007_dynamicform_enable_sso_prepopulate_and_more' in str(migration):
                    sso_migration = migration
                    break
            
            if sso_migration:
                self.stdout.write(f'SSO migration found in plan: {sso_migration}')
                
                # Try to apply just this migration
                self.stdout.write('Attempting to apply SSO migration...')
                executor.apply_migration(sso_migration, 'integrator')
                self.stdout.write(self.style.SUCCESS('SSO migration applied successfully!'))
                
            else:
                self.stdout.write('SSO migration not found in plan - may already be applied')
                
                # Check current migration status
                current = executor.loader.graph.leaf_nodes()
                self.stdout.write(f'Current migrations: {current}')
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Migration test failed: {e}'))
            import traceback
            self.stdout.write(traceback.format_exc())
