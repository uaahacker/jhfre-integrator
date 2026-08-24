"""Django signals for permission-cache invalidation."""
from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.contrib.auth.models import User, Group
from .models import FormPermission
from .cache_utils import CacheInvalidationManager
import logging

logger = logging.getLogger(__name__)


@receiver([post_save, post_delete], sender=FormPermission)
def invalidate_user_cache_on_form_permission_change(sender, instance, **kwargs):
    """
    Invalidate specific user's cache when FormPermission is created or deleted
    """
    user_id = instance.user.id
    logger.info(f"FormPermission for user {instance.user.username} changed - invalidating user cache")
    CacheInvalidationManager.invalidate_user_caches([user_id])


@receiver(m2m_changed, sender=User.groups.through)
def invalidate_user_cache_on_group_change(sender, instance, action, pk_set, **kwargs):
    """
    Invalidate user's cache when user is added/removed from groups
    """
    if action in ['post_add', 'post_remove', 'post_clear']:
        logger.info(f"User {instance.username} group membership changed - invalidating user cache")
        CacheInvalidationManager.invalidate_user_caches([instance.id])


@receiver([post_save, post_delete], sender=Group)
def invalidate_cache_on_group_change(sender, instance, **kwargs):
    """
    Invalidate cache for all users in a group when group permissions change
    """
    user_ids = list(instance.user_set.values_list('id', flat=True))
    if user_ids:
        logger.info(f"Group {instance.name} changed - invalidating cache for {len(user_ids)} users")
        CacheInvalidationManager.invalidate_user_caches(user_ids)
