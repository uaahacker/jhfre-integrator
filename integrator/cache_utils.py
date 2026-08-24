"""Permission-cache invalidation utilities."""
from django.contrib.auth.models import User
import logging

logger = logging.getLogger(__name__)


class PermissionCacheManager:
    """Manages Django's built-in permission caching"""
    
    @staticmethod
    def clear_user_permission_cache(user):
        """Clear Django's built-in permission cache for a user"""
        if hasattr(user, '_perm_cache'):
            delattr(user, '_perm_cache')
        if hasattr(user, '_user_perm_cache'):
            delattr(user, '_user_perm_cache')
        if hasattr(user, '_group_perm_cache'):
            delattr(user, '_group_perm_cache')
        logger.info(f"Cleared permission cache for user {user.username}")
    
    @staticmethod
    def clear_users_permission_cache(users):
        """Clear permission cache for multiple users"""
        for user in users:
            PermissionCacheManager.clear_user_permission_cache(user)
        logger.info(f"Cleared permission cache for {len(users)} users")


class CacheInvalidationManager:
    """Main cache invalidation manager for Django permission caches."""
    
    @staticmethod
    def invalidate_user_caches(user_ids):
        """Invalidate permission caches for specific users."""
        users = User.objects.filter(id__in=user_ids)
        PermissionCacheManager.clear_users_permission_cache(users)
        
        logger.info(f"Invalidated permission caches for users: {user_ids}")
    
    @staticmethod
    def invalidate_all_caches():
        """Invalidate permission caches for all users."""
        all_users = User.objects.all()
        PermissionCacheManager.clear_users_permission_cache(all_users)
        
        logger.info("Invalidated all user permission caches")
