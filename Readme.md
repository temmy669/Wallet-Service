# Wallet Service API (Django + Paystack + JWT)

A scalable **wallet service** built with:

* **Django REST Framework** (API backend)
* **Paystack** (payment processing)
* **Google OAuth** (authentication)
* **JWT** (user sessions)
* **API Keys** (service-to-service access)

This API allows users to:

* **Authenticate** via Google OAuth
* **Deposit money** using Paystack
* **Transfer funds** between wallets
* **Track transactions** with full history
* **Generate API keys** for automated services

All transactions are atomic, secure, and support both user authentication (JWT) and service authentication (API keys).

---

## Features

### Google OAuth Authentication

Users sign in with Google → receive JWT access and refresh tokens → wallet created automatically.

### Paystack Deposits

Users deposit money via Paystack → webhook verifies payment → wallet credited automatically. Supports idempotent webhook handling (no double-credits).

### Wallet-to-Wallet Transfers

Users can transfer funds between wallets using unique wallet numbers. Transfers are atomic (no partial deductions).

### API Key Management

Users can generate up to 5 active API keys with granular permissions:

* `deposit` - Initialize deposits
* `transfer` - Transfer funds
* `read` - View balance and transactions

Keys support:

* Expiration (1H, 1D, 1M, 1Y)
* Rollover for expired keys
* Revocation

### Transaction History

Track all deposits and transfers with status tracking (`pending`, `success`, `failed`).

---

## Project Structure

```
project/
│── core/
│   └── settings.py
│
│── wallet/
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   ├── authentication.py
│   ├── permissions.py
│   └── utils.py
│
│── requirements.txt
│── README.md
```

---

## How It Works

### 1️ Authentication

User signs in with Google → backend exchanges code for user info → JWT tokens generated → wallet created if new user.

**Example Response**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

---

### 2️ Deposit Flow

Client hits `/wallet/deposit` → Paystack payment initialized → user redirected to Paystack → payment completed → Paystack webhook credits wallet.

**Example Response**

```json
{
  "reference": "TXN_1733750400_a1b2c3d4",
  "authorization_url": "https://checkout.paystack.com/..."
}
```

---

### 3️ Transfer Flow

Client hits `/wallet/transfer` with recipient wallet number → balance checked → atomic transfer executed → both wallets updated → transaction recorded.

**Example Response**

```json
{
  "status": "success",
  "message": "Transfer completed"
}
```

---

## Key Components

### Django Models

* **Wallet** - Stores user balance and unique wallet number
* **Transaction** - Records all deposits and transfers
* **APIKey** - Manages service API keys with permissions

### Custom Authentication

* **JWTAuthentication** - Validates JWT tokens from Google OAuth
* **APIKeyAuthentication** - Validates service API keys

### Paystack Integration

* **Webhook Handler** - Verifies signatures and credits wallets
* **Payment Initializer** - Creates Paystack payment links

---

## Installation

### Prerequisites

* Python 3.8+
* Django 4.0+
* PostgreSQL (recommended)

### Setup

1. **Clone and create virtual environment**

```bash
git clone <repository-url>
cd wallet-service
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. **Install dependencies**

```bash
pip install django djangorestframework djangorestframework-simplejwt google-auth requests
```

3. **Configure environment variables**

Create `.env` file:

```env
SECRET_KEY=your-django-secret-key
DEBUG=True

PAYSTACK_SECRET_KEY=sk_test_your_paystack_secret_key
PAYSTACK_PUBLIC_KEY=pk_test_your_paystack_public_key

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback

FRONTEND_URL=http://localhost:3000
```

4. **Run migrations**

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
```

---

## API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/auth/google` | Get Google OAuth URL | None |
| GET | `/auth/google/callback` | Google OAuth callback | None |
| POST | `/keys/create` | Create API key | JWT |
| GET | `/keys/list` | List all API keys | JWT |
| POST | `/keys/rollover` | Rollover expired key | JWT |
| POST | `/keys/revoke` | Revoke API key | JWT |
| POST | `/wallet/deposit` | Initialize deposit | JWT/API Key |
| POST | `/wallet/paystack/webhook` | Paystack webhook | Signature |
| GET | `/wallet/deposit/<ref>/status` | Check deposit status | JWT/API Key |
| GET | `/wallet/balance` | Get wallet balance | JWT/API Key |
| POST | `/wallet/transfer` | Transfer funds | JWT/API Key |
| GET | `/wallet/transactions` | Get transaction history | JWT/API Key |

---

## Testing the API

### Using cURL

**1. Start Google Sign-In**

```bash
curl http://localhost:8000/auth/google
```

Visit the returned `auth_url` in your browser → complete Google sign-in → copy the `access_token`.

**2. Check Wallet Balance**

```bash
curl http://localhost:8000/wallet/balance \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**3. Create API Key**

```bash
curl -X POST http://localhost:8000/keys/create \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mobile-app",
    "permissions": ["deposit", "transfer", "read"],
    "expiry": "1M"
  }'
```

**4. Deposit Money**

```bash
curl -X POST http://localhost:8000/wallet/deposit \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 5000}'
```

Visit the returned `authorization_url` to complete payment.

**5. Transfer Money**

```bash
curl -X POST http://localhost:8000/wallet/transfer \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_number": "1234567890123",
    "amount": 3000
  }'
```

**6. View Transactions**

```bash
curl http://localhost:8000/wallet/transactions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Testing via Postman

**Test Authentication**

* New Request → GET → `http://localhost:8000/auth/google`
* Visit `auth_url` in browser
* Copy `access_token` from callback response

**Test Deposit**

* New Request → POST → `http://localhost:8000/wallet/deposit`
* Headers: `Authorization: Bearer YOUR_ACCESS_TOKEN`
* Body (JSON):
  ```json
  {
    "amount": 5000
  }
  ```

**Test Transfer**

* New Request → POST → `http://localhost:8000/wallet/transfer`
* Headers: `Authorization: Bearer YOUR_ACCESS_TOKEN`
* Body (JSON):
  ```json
  {
    "wallet_number": "1234567890123",
    "amount": 3000
  }
  ```

---

## Setting up Paystack Webhook

### Local Testing with ngrok

1. Install ngrok: `npm install -g ngrok`
2. Start ngrok: `ngrok http 8000`
3. Copy the HTTPS URL (e.g., `https://abc123.ngrok.io`)
4. Go to [Paystack Dashboard → Settings → Webhooks](https://dashboard.paystack.com/#/settings/developer)
5. Add webhook URL: `https://abc123.ngrok.io/wallet/paystack/webhook`
6. Test deposits → Paystack will send events to your local server

### Production Setup

Update webhook URL to your production domain:
```
https://yourdomain.com/wallet/paystack/webhook
```

---

## Technologies Used

| Component | Tool |
|-----------|------|
| Backend | Django REST Framework |
| Authentication | Google OAuth + JWT |
| Payments | Paystack |
| API Keys | Custom authentication |
| Database | PostgreSQL / SQLite |

---

## Known Challenges Solved

✔ **Issue:** JWT tokens not recognized
→ **Fix:** Added `JWTAuthentication` to authentication classes

✔ **Issue:** Paystack webhook signature verification failed
→ **Fix:** Used raw request body for HMAC verification

✔ **Issue:** Race condition in concurrent transfers
→ **Fix:** Used `select_for_update()` for atomic transactions

✔ **Issue:** Webhooks crediting wallet multiple times
→ **Fix:** Added idempotency check on transaction status

---

## Security Features

* ✅ Paystack webhook signature verification
* ✅ Atomic database transactions
* ✅ Idempotent webhook handling
* ✅ Permission-based API key access
* ✅ API key expiration and limits (max 5 active)
* ✅ JWT token authentication
* ✅ Balance validation before transfers

---

## Future Improvements

* Withdrawal support
* Multi-currency wallets
* Transaction notifications (email/SMS)
* Rate limiting on transfers
* Admin dashboard
* Scheduled payments

---

## Author

**Favour Adebose**
Backend Developer — Django • REST APIs • Payment Integration
GitHub: [https://github.com/temmy669](https://github.com/temmy669)