# Midtrans Webhooker

A webhook relay service for Midtrans notifications. It receives webhook notifications from Midtrans, verifies cryptographic signatures, and dispatches rich interactive embeds/cards to Discord and Lark (Feishu).

Supports Midtrans Core API (Snap/Payment), Recurring Subscriptions, Account Binding, IRIS Disbursements, and Bank Indonesia (BI) SNAP Open API.

---

## Features

- **Lightweight & Efficient**: Minimal resource footprint and fast response times.
- **Dual Notification Relay**: Forwards beautifully formatted cards/embeds to Discord and Lark (Feishu).
- **Interactive "View Raw JSON"**: Built-in raw payload inspector with syntax highlighting and direct JSON export.
- **Cryptographic Signature Verification**:
  - Legacy Pay-in (SHA-512 constant-time verification)
  - IRIS Disbursement (SHA-512 with `IRIS_MERCHANT_KEY`)
  - BI SNAP / Open API (RSA-SHA256 PKCS#1 v1.5 verification with Midtrans Public Key)
  - Lark Webhook Signing (HMAC-SHA256)
- **Container Ready**: Multi-stage minimal Alpine Docker build published to GitHub Container Registry (`linux/amd64`).

---

## Supported Endpoints

| Endpoint | Event Type | Verification Scheme | Key Configuration |
| :--- | :--- | :--- | :--- |
| `POST /payment-legacy`<br/>`POST /webhook/midtrans`<br/>`POST /webhook` | Core API / Snap transactions | SHA-512 (`signature_key`) | `MIDTRANS_SERVER_KEY` |
| `POST /recurring-legacy` | Subscription lifecycle events | SHA-512 (`signature_key`) | `MIDTRANS_SERVER_KEY` |
| `POST /binding-legacy` | Account linking events | SHA-512 (`signature_key`) | `MIDTRANS_SERVER_KEY` |
| `POST /iris`<br/>`POST /disbursement` | IRIS payouts / disbursements | SHA-512 (`Iris-Signature` header) | `IRIS_MERCHANT_KEY` |
| `POST /bi-snap/*` | BI SNAP / Open API | RSA-SHA256 (`X-SIGNATURE` header) | `MIDTRANS_PUBLIC_KEY` or `MIDTRANS_PUBLIC_KEY_PATH` |
| `GET /raw/:id` | Raw webhook payload viewer | In-memory ring buffer (LRU) | `ENABLE_RAW_VIEW=true` |
| `GET /health` | Service health check & metrics | None | N/A |

---

## Installation & Setup

### 1. Clone and Configure

```bash
git clone https://github.com/hdhr/midtrans-webhooker.git
cd midtrans-webhooker
cp .env.example .env
```

Edit `.env` with your credentials:

```ini
PORT=3000

# Discord Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

# Lark / Feishu Notifications
LARK_WEBHOOK_URL=https://open.larksuite.com/open-apis/bot/v2/hook/YOUR_BOT_TOKEN
# LARK_WEBHOOK_SECRET=your_lark_bot_secret

# Midtrans Pay-in Server Key (Dashboard > Settings > Access Keys > Payment > Server Key)
MIDTRANS_SERVER_KEY=your_midtrans_server_key

# Midtrans IRIS Merchant Key (Dashboard > Settings > Access Keys > Transfer > Merchant Key)
IRIS_MERCHANT_KEY=your_iris_merchant_key
```

If you use BI SNAP verification, place your Midtrans public key at `keys/midtrans-public.pem`.

---

### 2. Run with Docker Compose (Recommended)

Prebuilt Docker images (`linux/amd64`) are automatically published to GitHub Container Registry (`ghcr.io/hdhr/midtrans-webhooker:latest`):

```bash
# Pull and start container
docker compose pull
docker compose up -d

# View live logs
docker compose logs -f
```

To build locally from source with Docker:

```bash
docker compose up -d --build
```

---

### 3. Run Locally (from source)

```bash
cargo run --release
```

---

## Configuration Reference

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `PORT` | Number | `3000` | Port for the HTTP server. |
| `APP_URL` | String | Auto-detected | Base public URL used for the "View Raw JSON" button link. |
| `DISCORD_WEBHOOK_URL` | String | `""` | Target Discord webhook URL. |
| `DISCORD_MENTION` | String | `""` | Optional role or user mention for Discord (e.g. `<@&ROLE_ID>`). |
| `LARK_WEBHOOK_URL` | String | `""` | Target Lark / Feishu custom bot webhook URL. |
| `LARK_WEBHOOK_SECRET` | String | `""` | Secret for Lark bot HMAC-SHA256 signature verification. |
| `LARK_MENTION` | String | `""` | Optional user mention for Lark (e.g. `<at user_id="all">Everyone</at>`). |
| `MIDTRANS_SERVER_KEY` | String | `""` | Midtrans Pay-in Server Key. |
| `VERIFY_LEGACY_SIGNATURE` | Boolean | `true` | Enforces SHA-512 signature validation on pay-in routes. |
| `IRIS_MERCHANT_KEY` | String | `""` | IRIS Merchant Key for payout notifications. |
| `VERIFY_IRIS_SIGNATURE` | Boolean | `true` | Enforces `Iris-Signature` header validation on `/iris`. |
| `MIDTRANS_PUBLIC_KEY` | String | `""` | Midtrans RSA Public Key string in PEM format. |
| `MIDTRANS_PUBLIC_KEY_PATH` | String | `./keys/midtrans-public.pem` | File path to Midtrans RSA public key file. |
| `VERIFY_BI_SNAP_SIGNATURE`| Boolean | `true` | Enforces asymmetric RSA signature checking on `/bi-snap/*`. |
| `NOTIFY_ON_PENDING` | Boolean | `true` | When `false`, suppresses pending transaction notifications. |
| `ENABLE_RAW_VIEW` | Boolean | `true` | Enables in-memory raw payload caching and `/raw/:id` viewer. |
| `MAX_RAW_ENTRIES` | Number | `500` | Maximum number of raw payloads retained in memory. |

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
