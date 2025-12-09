from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
import secrets
from datetime import datetime, timedelta
from .utils import generate_api_key_id
import uuid

class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    wallet_number = models.CharField(max_length=20, unique=True, db_index=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0, validators=[MinValueValidator(0)])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} - {self.wallet_number}"

    @classmethod
    def generate_wallet_number(cls):
        while True:
            wallet_number = str(secrets.randbelow(9000000000000) + 1000000000000)
            if not cls.objects.filter(wallet_number=wallet_number).exists():
                return wallet_number

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('transfer', 'Transfer'),
    ]
    
    TRANSACTION_STATUS = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(0)])
    status = models.CharField(max_length=10, choices=TRANSACTION_STATUS, default='pending')
    reference = models.CharField(max_length=100, unique=True, db_index=True)
    recipient_wallet = models.ForeignKey(Wallet, on_delete=models.SET_NULL, null=True, blank=True, related_name='received_transfers')
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.type} - {self.reference}"

class APIKey(models.Model):
    PERMISSION_CHOICES = [
        ('deposit', 'Deposit'),
        ('transfer', 'Transfer'),
        ('read', 'Read'),
    ]
    key_id = models.CharField(max_length=20, unique=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=100, unique=True, db_index=True)
    permissions = models.JSONField(default=list)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} - {self.user.email}"
    
    def save(self, *args, **kwargs):
        if not self.key_id:
            # Generate a unique key
            while True:
                key_id = generate_api_key_id()
                if not APIKey.objects.filter(key_id=key_id).exists():
                    self.key_id = key_id
                    break
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return datetime.now(self.expires_at.tzinfo) > self.expires_at

    @property
    def is_valid(self):
        return self.is_active and not self.is_expired and self.revoked_at is None

    @classmethod
    def generate_key(cls):
        return f"sk_live_{secrets.token_hex(32)}"
