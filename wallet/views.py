from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import User
from django.db import transaction as db_transaction
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
from decimal import Decimal
import json
import secrets
from django.utils import timezone as dj_timezone
from datetime import datetime, timezone

from .models import Wallet, Transaction, APIKey
from .serializers import (
    WalletSerializer, TransactionSerializer,
    APIKeyCreateSerializer, APIKeyRolloverSerializer
)
from .authentication import APIKeyAuthentication
from .permissions import HasAPIKeyPermission
from .utils import (
    parse_expiry, verify_paystack_signature,
    initialize_paystack_payment, verify_paystack_transaction, format_utc
)
from urllib.parse import urlencode
from django.contrib.auth.hashers import make_password, check_password

# Google Authentication Views
class GoogleAuthView(APIView):
    def get(self, request):

        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/userinfo.email "
                    "https://www.googleapis.com/auth/userinfo.profile openid",
            "access_type": "offline",
            "prompt": "consent",
        }

        auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

        return Response({"auth_url": auth_url})

class GoogleCallbackView(APIView):
    def get(self, request):
        code = request.GET.get('code')
        
        if not code:
            return Response(
                {"error": "Authorization code not provided"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Exchange code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        
        import requests
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'error' in token_json:
            return Response(
                {"error": token_json['error']},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get user info from Google
        try:
            access_token = token_json.get('access_token')
            userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            userinfo_response = requests.get(userinfo_url, headers=headers)
            userinfo = userinfo_response.json()
            
            email = userinfo.get('email')
            google_id = userinfo.get('id')
            name = userinfo.get('name', '')
            print(name)
            
            first_name = name.split(' ')[0] if name else ''
            last_name = ' '.join(name.split(' ')[1:]) if len(name.split(' ')) > 1 else ''
            
            if not email:
                return Response(
                    {"error": "Email not provided by Google"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get or create user
            try:
                user = User.objects.get(email=email)
                created = False
            except User.DoesNotExist:
                # username = generate_unique_username(email)
                user = User.objects.create(
                    email=email,
                    # username=username,
                    first_name=first_name,
                    last_name=last_name
                )
                created = True
            user = User.objects.get(email=email)        
            # Create wallet if user is new
            if created:
                Wallet.objects.create(
                    user=user,
                    wallet_number=Wallet.generate_wallet_number()
                )
            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            
            return Response({
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "user": {
                    "email": user.email,
                    "name": name
                }
            })
            
        except Exception as e:
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

class DummyLogin(APIView):
    """
    Dummy login view for testing purposes.
    """
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response(
                {"error": "Email is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user, created = User.objects.get_or_create(
            email=email,
            defaults={'username': email}
        )
        
        if created:
            Wallet.objects.create(
                user=user,
                wallet_number=Wallet.generate_wallet_number()
            )
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "user": {
                "email": user.email
            }
        })
        


# API Key Management Views
class CreateAPIKeyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        
        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        active_keys = APIKey.objects.filter(
        user=request.user,
        is_active=True,     
        expires_at__gt=dj_timezone.now()
         ).count()

        if active_keys >= 5:
            return Response(
                {"error": "Maximum of 5 active API keys allowed"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate and hash key
        raw_key=APIKey.generate_key()
        
        # Store API key in db
        expires_at = parse_expiry(serializer.validated_data['expiry'])
        api_key = APIKey.objects.create(
            user=request.user,
            name=serializer.validated_data['name'],
            key=raw_key,
            permissions=serializer.validated_data['permissions'],
            expires_at=expires_at
        )
        print(api_key.expires_at)
        
        return Response({
            "api_key": raw_key,
            "expires_at": format_utc(api_key.expires_at)
        }, status=status.HTTP_201_CREATED)

# List API Keys
class ListAPIKeysView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        api_keys = APIKey.objects.filter(user=request.user).order_by('-created_at')
        
        keys_data = []
        for key in api_keys:
            keys_data.append({
                "id": key.key_id,
                "name": key.name,
                "permissions": key.permissions,
                "is_active": key.is_active,
                "is_expired": key.is_expired,
                "expires_at": key.expires_at,
                "created_at": key.created_at,
                "revoked_at": key.revoked_at if key.revoked_at else None,
                # Only show last 8 characters for security
                "key_preview": f"...{key.key[-8:]}"
            })
        
        return Response(keys_data)


# Revoke API Key
class RevokeAPIKeyView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        key_id = request.data.get('key_id')
        api_key = APIKey.objects.get(key_id=key_id, user=request.user)
        if not key_id:
            return Response(
                {"error": "key_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if api_key.is_active == False:
            return Response(
                {"error": "API key is already revoked"},
                status=status.HTTP_400_BAD_REQUEST)
            
        try:
            api_key.is_active = False
            api_key.revoked_at = datetime.now()
            api_key.save()
            
            return Response({
                "message": "API key revoked successfully",
                "key_id": api_key.key_id
            })
        except APIKey.DoesNotExist:
            return Response(
                {"error": "API key not found"},
                status=status.HTTP_404_NOT_FOUND
            )

class RolloverAPIKeyView(APIView):
    authentication_classes = []
    permission_classes = []
    
    def post(self, request):
        serializer = APIKeyRolloverSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            old_key = APIKey.objects.get(
                key_id=serializer.validated_data['expired_key_id'],
            )
        except APIKey.DoesNotExist:
            return Response(
                {"error": "API key not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if revoked    
        if revoked := not old_key.is_active:
            return Response(
                {"error": "Cannot rollover a revoked key"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if expired
        if not old_key.is_expired:
            return Response(
                {"error": "Key must be expired to rollover"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        
        # Check active keys limit
        active_keys = APIKey.objects.filter(
            user=request.user,
            is_active=True,
            expires_at__gt=datetime.now()
        ).count()
        
        if active_keys == 5:
            return Response(
                {"error": "Maximum of 5 active API keys allowed"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create new key with same permissions
        expires_at = parse_expiry(serializer.validated_data['expiry'])
        new_key = APIKey.objects.create(
            user=request.user,
            name=old_key.name,
            key=APIKey.generate_key(),
            permissions=old_key.permissions,
            expires_at=expires_at
        )
        
        return Response({
            "api_key": new_key.key,
            "expires_at": new_key.expires_at.isoformat().replace("+00:00", "Z")
        }, status=status.HTTP_201_CREATED)


# Wallet Views
class DepositView(APIView):
    authentication_classes = [JWTAuthentication, APIKeyAuthentication]
    permission_classes = [IsAuthenticated, HasAPIKeyPermission]
    required_api_permission = 'deposit'
    
    def post(self, request):
        amount = request.data.get('amount')
        
        if not amount or Decimal(amount) <= 0:
            return Response(
                {"error": "Valid amount is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        wallet = Wallet.objects.get(user=request.user)
        reference = f"TXN_{datetime.now().timestamp()}_{secrets.token_hex(4)}"
        
        # Create pending transaction
        transaction = Transaction.objects.create(
            wallet=wallet,
            type='deposit',
            amount=Decimal(amount),
            status='pending',
            reference=reference
        )
        
        # Initialize Paystack payment
        try:
            response = initialize_paystack_payment(
                request.user.email,
                Decimal(amount),
                reference
            )
            
            if response.get('status'):
                return Response({
                    "reference": reference,
                    "authorization_url": response['data']['authorization_url']
                })
            else:
                transaction.status = 'failed'
                transaction.save()
                return Response(
                    {"error": "Failed to initialize payment"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            transaction.status = 'failed'
            transaction.save()
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class PaystackWebhookView(APIView):
    authentication_classes = []
    permission_classes = []
    
    def post(self, request):
        signature = request.headers.get('x-paystack-signature')
        
        if not signature:
            return Response(
                {"error": "No signature provided"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify signature
        if not verify_paystack_signature(request.body, signature):
            return Response(
                {"error": "Invalid signature"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        payload = request.data
        event = payload.get('event')
        
        if event == 'charge.success':
            data = payload.get('data', {})
            reference = data.get('reference')
            amount = Decimal(data.get('amount', 0)) / 100  # Convert from kobo
            
            try:
                with db_transaction.atomic():
                    txn = Transaction.objects.select_for_update().get(reference=reference)
                    
                    # Idempotency check
                    if txn.status == 'success':
                        return Response({"status": True})
                    
                    # Update transaction
                    txn.status = 'success'
                    txn.save()
                    
                    # Credit wallet
                    wallet = txn.wallet
                    wallet.balance += amount
                    wallet.save()
                    
                return Response({"status": True})
                
            except Transaction.DoesNotExist:
                return Response(
                    {"error": "Transaction not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        return Response({"status": True})


class DepositStatusView(APIView):
    authentication_classes = [JWTAuthentication, APIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, reference):
        try:
            transaction = Transaction.objects.get(
                reference=reference,
                wallet__user=request.user
            )
            
            return Response({
                "reference": transaction.reference,
                "status": transaction.status,
                "amount": float(transaction.amount)
            })
        except Transaction.DoesNotExist:
            return Response(
                {"error": "Transaction not found"},
                status=status.HTTP_404_NOT_FOUND
            )


class WalletBalanceView(APIView):
    authentication_classes = [JWTAuthentication, APIKeyAuthentication]
    permission_classes = [IsAuthenticated, HasAPIKeyPermission]
    required_api_permission = 'read'
    
    def get(self, request):
        wallet = Wallet.objects.get(user=request.user)
        return Response({"balance": float(wallet.balance)})


class TransferView(APIView):
    authentication_classes = [JWTAuthentication, APIKeyAuthentication]
    permission_classes = [IsAuthenticated, HasAPIKeyPermission]
    required_api_permission = 'transfer'
    
    def post(self, request):
        wallet_number = request.data.get('wallet_number')
        amount = request.data.get('amount')
        
        #validate wallet number 
        if wallet_number == Wallet.objects.get(user=request.user).wallet_number:
            return Response(
                {"error": "Cannot transfer to the same wallet"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not wallet_number or not amount:
            return Response(
                {"error": "wallet_number and amount are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        amount = Decimal(amount)
        
        if amount <= 0:
            return Response(
                {"error": "Amount must be positive"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with db_transaction.atomic():
                sender_wallet = Wallet.objects.select_for_update().get(user=request.user)
                recipient_wallet = Wallet.objects.select_for_update().get(wallet_number=wallet_number)
                
                if sender_wallet.balance < amount:
                    return Response(
                        {"error": "Insufficient balance"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Deduct from sender
                sender_wallet.balance -= amount
                sender_wallet.save()
                
                # Add to recipient
                recipient_wallet.balance += amount
                recipient_wallet.save()
                
                # Create transactions
                reference = f"TXF_{datetime.now().timestamp()}_{secrets.token_hex(4)}"
                
                Transaction.objects.create(
                    wallet=sender_wallet,
                    type='transfer',
                    amount=amount,
                    status='success',
                    reference=reference,
                    recipient_wallet=recipient_wallet
                )
                
                return Response({
                    "status": "success",
                    "message": "Transfer completed"
                })
                
        except Wallet.DoesNotExist:
            return Response(
                {"error": "Recipient wallet not found"},
                status=status.HTTP_404_NOT_FOUND
            )


class TransactionHistoryView(APIView):
    authentication_classes = [JWTAuthentication, APIKeyAuthentication]
    permission_classes = [IsAuthenticated, HasAPIKeyPermission]
    required_api_permission = 'read'
    
    def get(self, request):
        wallet = Wallet.objects.get(user=request.user)
        transactions = Transaction.objects.filter(wallet=wallet).order_by('-created_at')
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)

