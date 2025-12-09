from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from .models import APIKey
from datetime import datetime

class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get('x-api-key')
        
        if not api_key:
            return None
        
        try:
            key_obj = APIKey.objects.select_related('user').get(key=api_key)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')
        
        if not key_obj.is_active:
            raise AuthenticationFailed('API key is revoked')
        
        if key_obj.is_expired:
            raise AuthenticationFailed('API key has expired')
        
        # Store API key object in request for permission checking
        request.api_key = key_obj
        
        return (key_obj.user, None)
