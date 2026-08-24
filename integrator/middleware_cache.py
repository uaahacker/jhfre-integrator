"""
Middleware to handle permission cache invalidation and session updates
"""
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user
import logging

logger = logging.getLogger(__name__)


class PermissionCacheMiddleware(MiddlewareMixin):
    """
    Middleware to ensure permission changes take effect immediately
    """
    
    def process_request(self, request):
        """
        Clear permission cache if we detect the user's permissions have changed
        """
        if request.user.is_authenticated:
            # Check if we have a flag indicating permissions changed
            if request.session.get('_permissions_changed', False):
                # Clear Django's built-in permission cache
                if hasattr(request.user, '_perm_cache'):
                    delattr(request.user, '_perm_cache')
                if hasattr(request.user, '_user_perm_cache'):
                    delattr(request.user, '_user_perm_cache')
                if hasattr(request.user, '_group_perm_cache'):
                    delattr(request.user, '_group_perm_cache')
                
                # Remove the flag
                del request.session['_permissions_changed']
                logger.debug(f"Cleared permission cache for user {request.user.username}")
        
        return None
    
    def process_response(self, request, response):
        """
        Set flag if permissions might have been changed in this request
        """
        if (request.user.is_authenticated and 
            request.path.startswith('/permissions/') and 
            request.method == 'POST'):
            # Mark that permissions might have changed
            request.session['_permissions_changed'] = True
            logger.debug(f"Marked permissions as changed for user {request.user.username}")
        
        return response
