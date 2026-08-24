from functools import wraps
from django.http import HttpResponseForbidden

def user_has_permission(permission_name):
    def decorator(func):
        @wraps(func)
        def wrapper(self, request, *args, **kwargs):
            if request.user.is_authenticated and request.user.has_perm(permission_name):
                return func(self, request, *args, **kwargs)
            return HttpResponseForbidden("You do not have permission to view this page.")
        return wrapper
    return decorator
