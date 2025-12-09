from django.urls import path
from .views import (
    GoogleAuthView, GoogleCallbackView, DummyLogin,
    CreateAPIKeyView, RolloverAPIKeyView,
    DepositView, PaystackWebhookView, DepositStatusView,
    WalletBalanceView, TransferView, TransactionHistoryView, RevokeAPIKeyView, ListAPIKeysView
)

urlpatterns = [
    # Authentication
    path('auth/google', GoogleAuthView.as_view()),
    path('auth/google/callback', GoogleCallbackView.as_view()),
    path('auth/dummy-login', DummyLogin.as_view()),
    
    # API Keys
    path('keys/create', CreateAPIKeyView.as_view()),
    path('keys/rollover', RolloverAPIKeyView.as_view()),
    path('keys/revoke', RevokeAPIKeyView.as_view()),
    path('keys/list', ListAPIKeysView.as_view()),
    
    # Wallet Operations
    path('wallet/deposit', DepositView.as_view()),
    path('wallet/paystack/webhook', PaystackWebhookView.as_view()),
    path('wallet/deposit/<str:reference>/status', DepositStatusView.as_view()),
    path('wallet/balance', WalletBalanceView.as_view()),
    path('wallet/transfer', TransferView.as_view()),
    path('wallet/transactions', TransactionHistoryView.as_view()),
]