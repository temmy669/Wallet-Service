import hmac
import hashlib
import requests
from django.conf import settings
from datetime import datetime, timedelta, timezone
import random
import string

def parse_expiry(expiry_str):
    """Convert expiry string to datetime"""
    now = datetime.now(timezone.utc)
    expiry_map = {
        '1H': timedelta(hours=1),
        '1D': timedelta(days=1),
        '1M': timedelta(days=30),
        '1Y': timedelta(days=365),
    }
    return now + expiry_map[expiry_str]

def verify_paystack_signature(request_body, signature):
    """Verify Paystack webhook signature"""
    computed_signature = hmac.new(
        settings.PAYSTACK_SECRET_KEY.encode('utf-8'),
        request_body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed_signature, signature)

def initialize_paystack_payment(email, amount, reference):
    """Initialize Paystack payment"""
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "email": email,
        "amount": int(amount * 100),  # Convert to kobo
        "reference": reference,
        "callback_url": f"{settings.FRONTEND_URL}/wallet/deposit"
    }
    
    response = requests.post(url, json=data, headers=headers)
    print(response)
    return response.json()

def verify_paystack_transaction(reference):
    """Verify Paystack transaction"""
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"
    }
    
    response = requests.get(url, headers=headers)
    return response.json()

def format_utc(dt):
    if not dt:
        return None
    #Ensure datetime is not a string
    dt = dt if isinstance(dt, datetime) else datetime.fromisoformat(dt)
    #Remove microseconds and convert to ISO 8601 format with 'Z' suffix
    dt = dt.replace(microsecond=0, tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")

def generate_api_key_id(length=20):
    """Generate a random key ID consisting of uppercase letters and digits."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=length))