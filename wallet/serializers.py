from rest_framework import serializers
from .models import Wallet, Transaction, APIKey
from django.contrib.auth.models import User

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['wallet_number', 'balance', 'created_at']

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['type', 'amount', 'status']

class APIKeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    permissions = serializers.ListField(
        child=serializers.ChoiceField(choices=['deposit', 'transfer', 'read'],
                                      error_messages={
            "invalid_choice": "Invalid permission. Valid values are: deposit, transfer, read."}
        )
    )
    expiry = serializers.ChoiceField(choices=['1H', '1D', '1M', '1Y'],
                                     error_messages={
            "invalid_choice": "Invalid expiry option. Valid values are: 1H, 1D, 1M, 1Y."
        }
)
    
    def validate_permissions(self, value):
        if not value:
            raise serializers.ValidationError("At least one permission is required")
        return value

class APIKeyRolloverSerializer(serializers.Serializer):
    expired_key_id = serializers.CharField()
    expiry = serializers.ChoiceField(choices=['1H', '1D', '1M', '1Y'])
