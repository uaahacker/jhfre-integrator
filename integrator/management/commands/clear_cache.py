from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management.base import BaseCommand

from integrator.cache_utils import CacheInvalidationManager, PermissionCacheManager


class Command(BaseCommand):
    help = 'Clear Django permission caches'

    def add_arguments(self, parser):
        parser.add_argument(
            '--type',
            choices=['permission', 'all'],
            default='all',
            help='Type of permission cache to clear',
        )
        parser.add_argument(
            '--user-ids',
            nargs='+',
            type=int,
            help='Specific user IDs whose permission caches should be cleared',
        )
        parser.add_argument(
            '--flush-all',
            action='store_true',
            help='Flush the configured cache backend (use with caution)',
        )

    def handle(self, *args, **options):
        if options['flush_all']:
            cache.clear()
            self.stdout.write(self.style.SUCCESS('Flushed the configured cache backend'))
            return

        user_ids = options.get('user_ids')
        if user_ids:
            CacheInvalidationManager.invalidate_user_caches(user_ids)
            self.stdout.write(self.style.SUCCESS(f'Cleared permission caches for users: {user_ids}'))
            return

        if options['type'] == 'permission':
            PermissionCacheManager.clear_users_permission_cache(User.objects.all())
            self.stdout.write(self.style.SUCCESS('Cleared permission caches for all users'))
            return

        CacheInvalidationManager.invalidate_all_caches()
        self.stdout.write(self.style.SUCCESS('Cleared all permission caches'))
