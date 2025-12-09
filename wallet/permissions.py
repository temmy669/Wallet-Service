from rest_framework.permissions import BasePermission

class HasAPIKeyPermission(BasePermission):
    def has_permission(self, request, view):
        # If authenticated via JWT, allow all actions
        if not hasattr(request, 'api_key'):
            return True
        
        # Check API key permissions
        required_permission = getattr(view, 'required_api_permission', None)
        
        if not required_permission:
            return True
        
        api_key = request.api_key
        return required_permission in api_key.permissions