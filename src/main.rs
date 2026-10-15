pub mod midtrans;
pub mod discord;
pub mod lark;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Clone, Serialize, Deserialize)]
pub struct RawEntry {
    pub id: String,
    pub timestamp: String,
    pub endpoint: String,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
}

#[derive(Clone)]
pub struct AppConfig {
    pub discord_webhook_url: String,
    pub discord_mention: String,
    pub lark_webhook_url: String,
    pub lark_webhook_secret: String,
    pub lark_mention: String,
    pub payin_keys: Vec<String>,
    pub verify_legacy_signature: bool,
    pub iris_merchant_key: String,
    pub verify_iris_signature: bool,
    pub midtrans_public_key: Option<String>,
    pub verify_bi_snap: bool,
    pub notify_on_pending: bool,
    pub enable_raw_view: bool,
    pub max_raw_entries: usize,
    pub app_url: Option<String>,
}

pub struct AppState {
    pub config: AppConfig,
    pub client: reqwest::Client,
    pub start_time: Instant,
    pub raw_cache: RwLock<RawCache>,
}

pub struct RawCache {
    pub map: HashMap<String, RawEntry>,
    pub queue: VecDeque<String>,
    pub max_size: usize,
}

impl RawCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            map: HashMap::new(),
            queue: VecDeque::new(),
            max_size,
        }
    }

    pub fn insert(&mut self, entry: RawEntry) {
        if self.map.len() >= self.max_size {
            if let Some(oldest) = self.queue.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.queue.push_back(entry.id.clone());
        self.map.insert(entry.id.clone(), entry);
    }

    pub fn get(&self, id: &str) -> Option<RawEntry> {
        self.map.get(id).cloned()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

fn generate_random_id() -> String {
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    hex::encode(bytes)
}

fn extract_relevant_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let relevant_keys = [
        "content-type",
        "user-agent",
        "x-signature",
        "x-timestamp",
        "x-partner-id",
        "x-external-id",
        "iris-signature",
    ];

    for key in relevant_keys {
        if let Some(val) = headers.get(key) {
            if let Ok(val_str) = val.to_str() {
                map.insert(key.to_string(), val_str.to_string());
            }
        }
    }
    map
}

fn headers_to_tuple_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, val)| {
            val.to_str().ok().map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

fn get_base_url(headers: &HeaderMap, app_url_env: Option<&str>) -> String {
    if let Some(url) = app_url_env {
        let trimmed = url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:3000");

    format!("{}://{}", proto, host)
}

async fn store_raw(
    state: &AppState,
    endpoint: &str,
    headers: &HeaderMap,
    body: &serde_json::Value,
) -> Option<String> {
    if !state.config.enable_raw_view {
        return None;
    }
    let id = generate_random_id();
    let entry = RawEntry {
        id: id.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        endpoint: endpoint.to_string(),
        headers: extract_relevant_headers(headers),
        body: body.clone(),
    };

    let mut cache = state.raw_cache.write().await;
    cache.insert(entry);
    Some(id)
}

async fn dispatch_notifications(
    state: &AppState,
    discord_payload: &serde_json::Value,
    lark_card: &serde_json::Value,
    identifier: &str,
) {
    if !state.config.discord_webhook_url.is_empty() {
        if let Err(e) = discord::send_discord_webhook(&state.client, &state.config.discord_webhook_url, discord_payload).await {
            error!("{} Failed to forward to Discord: {}", identifier, e);
        } else {
            info!("{} Successfully forwarded to Discord.", identifier);
        }
    }

    if !state.config.lark_webhook_url.is_empty() {
        let secret = if state.config.lark_webhook_secret.is_empty() { None } else { Some(state.config.lark_webhook_secret.as_str()) };
        if let Err(e) = lark::send_lark_webhook(&state.client, &state.config.lark_webhook_url, lark_card, secret).await {
            error!("{} Failed to forward to Lark: {}", identifier, e);
        } else {
            info!("{} Successfully forwarded to Lark.", identifier);
        }
    }
}

// -----------------------------------------------------------------------------
// Health Check Route
// -----------------------------------------------------------------------------
async fn health_check(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let raw_count = state.raw_cache.read().await.len();
    Json(json!({
        "status": "healthy",
        "service": "midtrans-webhooker",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptimeSeconds": state.start_time.elapsed().as_secs(),
        "channels": {
            "discord": !state.config.discord_webhook_url.is_empty(),
            "lark": !state.config.lark_webhook_url.is_empty(),
            "larkSigned": !state.config.lark_webhook_secret.is_empty()
        },
        "features": {
            "rawViewEnabled": state.config.enable_raw_view,
            "cachedRawPayloads": raw_count,
            "maxRawCapacity": state.config.max_raw_entries
        },
        "endpoints": {
            "paymentLegacy": "/payment-legacy",
            "recurringLegacy": "/recurring-legacy",
            "bindingLegacy": "/binding-legacy",
            "biSnap": "/bi-snap/*",
            "iris": "/iris",
            "rawPayloadViewer": "/raw/:id"
        },
        "security": {
            "payinKeyConfigured": !state.config.payin_keys.is_empty(),
            "payinKeyCount": state.config.payin_keys.len(),
            "payinSignatureCheck": state.config.verify_legacy_signature,
            "irisMerchantKeyConfigured": !state.config.iris_merchant_key.is_empty(),
            "irisSignatureCheck": state.config.verify_iris_signature,
            "biSnapPublicKeyConfigured": state.config.midtrans_public_key.is_some(),
            "biSnapSignatureCheck": state.config.verify_bi_snap
        }
    }))
}

// -----------------------------------------------------------------------------
// Raw Payload Viewer Route (/raw/:id)
// -----------------------------------------------------------------------------
async fn get_raw_payload(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let entry = {
        let cache = state.raw_cache.read().await;
        cache.get(&id)
    };

    let entry = match entry {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "status": "error", "message": "Payload not found or expired from cache." })),
            ).into_response();
        }
    };

    let accepts_html = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    if accepts_html {
        let json_pretty = serde_json::to_string_pretty(&entry).unwrap_or_default();
        let body_pretty = serde_json::to_string_pretty(&entry.body).unwrap_or_default();
        let headers_pretty = serde_json::to_string_pretty(&entry.headers).unwrap_or_default();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Midtrans Webhook Raw Payload - {id}</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
  <style>
    :root {{ --bg: #0f172a; --panel: #1e293b; --text: #f8fafc; --muted: #94a3b8; --border: #334155; --primary: #38bdf8; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; line-height: 1.5; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }}
    .badge {{ background: #0284c7; color: white; padding: 4px 10px; border-radius: 9999px; font-size: 13px; font-weight: 600; }}
    .btn {{ background: var(--panel); color: var(--text); border: 1px solid var(--border); padding: 8px 16px; border-radius: 6px; cursor: pointer; text-decoration: none; font-size: 14px; font-weight: 500; }}
    .btn:hover {{ border-color: var(--primary); color: var(--primary); }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; overflow: hidden; }}
    .card-header {{ padding: 12px 16px; background: rgba(0,0,0,0.2); font-weight: 600; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--muted); }}
    pre {{ margin: 0 !important; padding: 16px !important; border-radius: 0 !important; max-height: 500px; overflow: auto; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin: 0 0 6px 0; font-size: 22px;">Midtrans Webhook Payload</h1>
        <span style="color: var(--muted); font-size: 14px;">ID: <code>{id}</code> &bull; {timestamp}</span>
      </div>
      <div>
        <span class="badge">{endpoint}</span>
        <button class="btn" onclick="navigator.clipboard.writeText(JSON.stringify(rawBody, null, 2)); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy JSON', 2000)">Copy JSON</button>
        <a class="btn" href="/raw/{id}?format=json" target="_blank">Direct JSON</a>
      </div>
    </div>

    <div class="card">
      <div class="card-header">PAYLOAD BODY (JSON)</div>
      <pre><code class="language-json">{body_pretty}</code></pre>
    </div>

    <div class="card">
      <div class="card-header">SIGNIFICANT HEADERS</div>
      <pre><code class="language-json">{headers_pretty}</code></pre>
    </div>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
  <script>
    const rawBody = {json_pretty};
  </script>
</body>
</html>"#,
            id = entry.id,
            timestamp = entry.timestamp,
            endpoint = entry.endpoint,
            body_pretty = body_pretty,
            headers_pretty = headers_pretty,
            json_pretty = json_pretty,
        );
        Html(html).into_response()
    } else {
        Json(entry).into_response()
    }
}

// -----------------------------------------------------------------------------
// 1. Payment Legacy Route (/payment-legacy)
// -----------------------------------------------------------------------------
async fn handle_payment_legacy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let notification: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Malformed JSON payload" })),
        )
    })?;

    let order_id = notification.get("order_id").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
    let status = notification.get("transaction_status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
    let gross_amt = notification.get("gross_amount").and_then(|v| v.as_str()).unwrap_or("N/A");

    info!("[PAYMENT-LEGACY] order_id={}, status={}, amount={}", order_id, status, gross_amt);

    if state.config.verify_legacy_signature {
        if state.config.payin_keys.is_empty() {
            error!("[PAYMENT-LEGACY] Error: VERIFY_LEGACY_SIGNATURE is enabled but no Server Key is configured!");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Pay-in signature verification enabled but no Server Key configured." })),
            ));
        }

        if let Err(err) = midtrans::verify_midtrans_signature(&notification, &state.config.payin_keys) {
            error!("[PAYMENT-LEGACY] Signature verification failed for {}: {}", order_id, err);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "status": "unauthorized", "message": err })),
            ));
        }
    }

    if !state.config.notify_on_pending && status == "pending" {
        return Ok(Json(json!({ "status": "skipped", "message": "Pending notification skipped" })));
    }

    let raw_id = store_raw(&state, "/payment-legacy", &headers, &notification).await;
    let base_url = get_base_url(&headers, state.config.app_url.as_deref());
    let raw_url = raw_id.map(|id| format!("{}/raw/{}", base_url, id));

    let discord_build = discord::build_legacy_payment_embed(
        &notification,
        Some(&state.config.discord_mention),
        raw_url.as_deref(),
    );
    let lark_build = lark::build_lark_payment_card(
        &notification,
        Some(&state.config.lark_mention),
        raw_url.as_deref(),
    );

    let identifier = format!("[Legacy Payment: {}]", order_id);
    dispatch_notifications(&state, &discord_build.payload, &lark_build.card, &identifier).await;

    Ok(Json(json!({ "status": "ok" })))
}

// -----------------------------------------------------------------------------
// 2. Recurring Legacy Route (/recurring-legacy)
// -----------------------------------------------------------------------------
async fn handle_recurring_legacy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let notification: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Malformed JSON payload" })),
        )
    })?;

    let sub_id = notification.get("subscription_id")
        .or_else(|| notification.get("id"))
        .or_else(|| notification.get("order_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");

    info!("[RECURRING-LEGACY] subscription_id={}", sub_id);

    if state.config.verify_legacy_signature {
        if state.config.payin_keys.is_empty() {
            error!("[RECURRING-LEGACY] Error: VERIFY_LEGACY_SIGNATURE is enabled but no Server Key is configured!");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Subscription signature verification enabled but no Server Key configured." })),
            ));
        }

        if let Err(err) = midtrans::verify_midtrans_signature(&notification, &state.config.payin_keys) {
            error!("[RECURRING-LEGACY] Signature verification failed for {}: {}", sub_id, err);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "status": "unauthorized", "message": err })),
            ));
        }
    }

    let raw_id = store_raw(&state, "/recurring-legacy", &headers, &notification).await;
    let base_url = get_base_url(&headers, state.config.app_url.as_deref());
    let raw_url = raw_id.map(|id| format!("{}/raw/{}", base_url, id));

    let discord_build = discord::build_recurring_embed(
        &notification,
        Some(&state.config.discord_mention),
        raw_url.as_deref(),
    );
    let lark_build = lark::build_lark_recurring_card(
        &notification,
        Some(&state.config.lark_mention),
        raw_url.as_deref(),
    );

    let identifier = format!("[Recurring: {}]", sub_id);
    dispatch_notifications(&state, &discord_build.payload, &lark_build.card, &identifier).await;

    Ok(Json(json!({ "status": "ok" })))
}

// -----------------------------------------------------------------------------
// 3. Binding Legacy Route (/binding-legacy)
// -----------------------------------------------------------------------------
async fn handle_binding_legacy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let notification: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Malformed JSON payload" })),
        )
    })?;

    let account_id = notification.get("account_id")
        .or_else(|| notification.get("payment_account_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let status = notification.get("account_status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");

    info!("[BINDING-LEGACY] account_id={}, status={}", account_id, status);

    if state.config.verify_legacy_signature {
        if state.config.payin_keys.is_empty() {
            error!("[BINDING-LEGACY] Error: VERIFY_LEGACY_SIGNATURE is enabled but no Server Key is configured!");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Binding signature verification enabled but no Server Key configured." })),
            ));
        }

        if let Err(err) = midtrans::verify_midtrans_signature(&notification, &state.config.payin_keys) {
            error!("[BINDING-LEGACY] Signature verification failed for {}: {}", account_id, err);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "status": "unauthorized", "message": err })),
            ));
        }
    }

    let raw_id = store_raw(&state, "/binding-legacy", &headers, &notification).await;
    let base_url = get_base_url(&headers, state.config.app_url.as_deref());
    let raw_url = raw_id.map(|id| format!("{}/raw/{}", base_url, id));

    let discord_build = discord::build_binding_embed(
        &notification,
        Some(&state.config.discord_mention),
        raw_url.as_deref(),
    );
    let lark_build = lark::build_lark_binding_card(
        &notification,
        Some(&state.config.lark_mention),
        raw_url.as_deref(),
    );

    let identifier = format!("[Binding: {}]", account_id);
    dispatch_notifications(&state, &discord_build.payload, &lark_build.card, &identifier).await;

    Ok(Json(json!({ "status": "ok" })))
}

// -----------------------------------------------------------------------------
// 4. BI SNAP Route (/bi-snap/*)
// -----------------------------------------------------------------------------
async fn handle_bi_snap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    method: axum::http::Method,
    body_bytes: Bytes,
) -> Response {
    let path = uri.path();
    let original_url = uri.to_string();

    let mut response_code = "2005600"; // default debit notify
    if path.contains("/qr/") {
        response_code = "2005200"; // QRIS
    } else if path.contains("/transfer-va/") {
        response_code = "2002700"; // VA
    }

    let snap_success_json = json!({
        "responseCode": response_code,
        "responseMessage": "Request has been processed successfully"
    });

    let current_iso_time = chrono::Utc::now().to_rfc3339();

    let notification: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("X-TIMESTAMP", current_iso_time), ("Content-Type", "application/json".to_string())],
                Json(json!({
                    "responseCode": "4000000",
                    "responseMessage": "Invalid or empty request body"
                })),
            ).into_response();
        }
    };

    let order_ref = notification.get("originalPartnerReferenceNo")
        .or_else(|| notification.get("originalReferenceNo"))
        .or_else(|| notification.get("virtualAccountNo"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");

    let status = notification.get("latestTransactionStatus")
        .or_else(|| notification.get("transactionStatus"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");

    info!("[BI-SNAP] url={}, orderRef={}, status={}", path, order_ref, status);

    if state.config.verify_bi_snap {
        let public_key = match &state.config.midtrans_public_key {
            Some(pk) => pk,
            None => {
                error!("[BI-SNAP] Error: VERIFY_BI_SNAP_SIGNATURE is enabled but MIDTRANS_PUBLIC_KEY is missing!");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("X-TIMESTAMP", current_iso_time), ("Content-Type", "application/json".to_string())],
                    Json(json!({
                        "responseCode": "5000000",
                        "responseMessage": "BI SNAP signature verification enabled but MIDTRANS_PUBLIC_KEY is not configured."
                    })),
                ).into_response();
            }
        };

        let x_sig = headers.get("x-signature").and_then(|v| v.to_str().ok());
        let x_ts = headers.get("x-timestamp").and_then(|v| v.to_str().ok());

        if let Err(err) = midtrans::verify_bi_snap_signature(
            method.as_str(),
            path,
            &body_bytes,
            Some(&notification),
            x_sig,
            x_ts,
            public_key,
        ) {
            error!("[BI-SNAP] RSA signature verification failed: {}", err);
            return (
                StatusCode::UNAUTHORIZED,
                [("X-TIMESTAMP", current_iso_time), ("Content-Type", "application/json".to_string())],
                Json(json!({
                    "responseCode": "4010000",
                    "responseMessage": "Unauthorized. Signature verification failed."
                })),
            ).into_response();
        }
    }

    if !state.config.notify_on_pending && status == "03" {
        info!("[BI-SNAP] Muting pending (03) notification for {}", order_ref);
        return (
            StatusCode::OK,
            [("X-TIMESTAMP", current_iso_time), ("Content-Type", "application/json".to_string())],
            Json(snap_success_json),
        ).into_response();
    }

    let raw_id = store_raw(&state, &original_url, &headers, &notification).await;
    let base_url = get_base_url(&headers, state.config.app_url.as_deref());
    let raw_url = raw_id.map(|id| format!("{}/raw/{}", base_url, id));

    let header_vec = headers_to_tuple_vec(&headers);
    let discord_build = discord::build_bi_snap_embed(
        &notification,
        &header_vec,
        Some(&state.config.discord_mention),
        raw_url.as_deref(),
    );
    let lark_build = lark::build_lark_bi_snap_card(
        &notification,
        &header_vec,
        Some(&state.config.lark_mention),
        raw_url.as_deref(),
    );

    let identifier = format!("[BI SNAP: {}]", order_ref);
    dispatch_notifications(&state, &discord_build.payload, &lark_build.card, &identifier).await;

    (
        StatusCode::OK,
        [("X-TIMESTAMP", current_iso_time), ("Content-Type", "application/json".to_string())],
        Json(snap_success_json),
    ).into_response()
}

// -----------------------------------------------------------------------------
// 5. IRIS Route (/iris)
// -----------------------------------------------------------------------------
async fn handle_iris_payout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let notification: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Payload is empty or malformed" })),
        )
    })?;

    let ref_no = notification.get("reference_no")
        .or_else(|| notification.get("payout_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let status = notification.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
    let amount = notification.get("amount").and_then(|v| v.as_str()).unwrap_or("0");

    info!("[IRIS-PAYOUT] ref_no={}, status={}, amount={}", ref_no, status, amount);

    let header_sig = headers.get("iris-signature").and_then(|v| v.to_str().ok());

    if state.config.verify_iris_signature {
        if state.config.iris_merchant_key.is_empty() {
            error!("[IRIS-PAYOUT] Error: VERIFY_IRIS_SIGNATURE is enabled but IRIS_MERCHANT_KEY is missing!");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "IRIS signature verification enabled but IRIS_MERCHANT_KEY is not configured." })),
            ));
        }

        if let Err(err) = midtrans::verify_iris_signature(
            &body_bytes,
            Some(&notification),
            header_sig,
            &state.config.iris_merchant_key,
        ) {
            error!("[IRIS-PAYOUT] Signature verification failed for {}: {}", ref_no, err);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "status": "unauthorized", "message": err })),
            ));
        }
    }

    let status_lower = status.to_lowercase();
    if !state.config.notify_on_pending && (status_lower == "queued" || status_lower == "pending") {
        info!("[IRIS-PAYOUT] Skipping queued/pending notification for {}", ref_no);
        return Ok(Json(json!({ "status": "skipped", "message": "Queued notification skipped" })));
    }

    let raw_id = store_raw(&state, "/iris", &headers, &notification).await;
    let base_url = get_base_url(&headers, state.config.app_url.as_deref());
    let raw_url = raw_id.map(|id| format!("{}/raw/{}", base_url, id));

    let header_vec = headers_to_tuple_vec(&headers);
    let discord_build = discord::build_iris_embed(
        &notification,
        &header_vec,
        Some(&state.config.discord_mention),
        raw_url.as_deref(),
    );
    let lark_build = lark::build_lark_iris_card(
        &notification,
        &header_vec,
        Some(&state.config.lark_mention),
        raw_url.as_deref(),
    );

    let identifier = format!("[IRIS Disbursement: {}]", ref_no);
    dispatch_notifications(&state, &discord_build.payload, &lark_build.card, &identifier).await;

    Ok(Json(json!({ "status": "ok" })))
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let discord_webhook_url = std::env::var("DISCORD_WEBHOOK_URL").unwrap_or_default();
    let discord_mention = std::env::var("DISCORD_MENTION").unwrap_or_default();

    let lark_webhook_url = std::env::var("LARK_WEBHOOK_URL").unwrap_or_default();
    let lark_webhook_secret = std::env::var("LARK_WEBHOOK_SECRET").unwrap_or_default();
    let lark_mention = std::env::var("LARK_MENTION").unwrap_or_default();

    let mut payin_keys = Vec::new();
    for key_env in ["MIDTRANS_SERVER_KEY", "MIDTRANS_CLIENT_KEY", "MIDTRANS_MERCHANT_KEY"] {
        if let Ok(val) = std::env::var(key_env) {
            for k in val.split(',') {
                let trimmed = k.trim().to_string();
                if !trimmed.is_empty() && !payin_keys.contains(&trimmed) {
                    payin_keys.push(trimmed);
                }
            }
        }
    }

    let verify_legacy_signature = std::env::var("VERIFY_LEGACY_SIGNATURE")
        .or_else(|_| std::env::var("VERIFY_SIGNATURE"))
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let iris_merchant_key = std::env::var("IRIS_MERCHANT_KEY")
        .or_else(|_| std::env::var("MIDTRANS_IRIS_MERCHANT_KEY"))
        .unwrap_or_default();

    let verify_iris_signature = std::env::var("VERIFY_IRIS_SIGNATURE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let bi_snap_raw = std::env::var("MIDTRANS_PUBLIC_KEY")
        .or_else(|_| std::env::var("MIDTRANS_PUBLIC_KEY_PATH"))
        .unwrap_or_default();
    let midtrans_public_key = midtrans::load_public_key(&bi_snap_raw);

    let verify_bi_snap = std::env::var("VERIFY_BI_SNAP_SIGNATURE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let notify_on_pending = std::env::var("NOTIFY_ON_PENDING")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let enable_raw_view = std::env::var("ENABLE_RAW_VIEW")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let max_raw_entries = std::env::var("MAX_RAW_ENTRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);

    let app_url = std::env::var("APP_URL")
        .or_else(|_| std::env::var("BASE_URL"))
        .ok();

    let config = AppConfig {
        discord_webhook_url,
        discord_mention,
        lark_webhook_url,
        lark_webhook_secret,
        lark_mention,
        payin_keys,
        verify_legacy_signature,
        iris_merchant_key,
        verify_iris_signature,
        midtrans_public_key,
        verify_bi_snap,
        notify_on_pending,
        enable_raw_view,
        max_raw_entries,
        app_url,
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let state = Arc::new(AppState {
        raw_cache: RwLock::new(RawCache::new(config.max_raw_entries)),
        config,
        client,
        start_time: Instant::now(),
    });

    let app = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/raw/{id}", get(get_raw_payload))
        .route("/payment-legacy", post(handle_payment_legacy))
        .route("/webhook/midtrans", post(handle_payment_legacy))
        .route("/webhook", post(handle_payment_legacy))
        .route("/recurring-legacy", post(handle_recurring_legacy))
        .route("/binding-legacy", post(handle_binding_legacy))
        .route("/bi-snap", post(handle_bi_snap))
        .route("/bi-snap/{*rest}", post(handle_bi_snap))
        .route("/iris", post(handle_iris_payout))
        .route("/disbursement", post(handle_iris_payout))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("====================================================");
    info!(" Midtrans Webhooker is starting on port {}", port);
    info!(" Endpoints registered:");
    info!("  1. POST /payment-legacy (/webhook/midtrans, /webhook)");
    info!("  2. POST /recurring-legacy");
    info!("  3. POST /binding-legacy");
    info!("  4. POST /bi-snap/*");
    info!("  5. POST /iris (/disbursement)");
    info!("  6. GET  /raw/:id");
    info!("  7. GET  /health");
    info!("====================================================");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind TCP listener");

    axum::serve(listener, app)
        .await
        .expect("Axum server error");
}
