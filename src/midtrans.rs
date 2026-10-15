use subtle::ConstantTimeEq;
use sha2::{Sha256, Sha512, Digest};
use rsa::pkcs8::DecodePublicKey;
use rsa::{RsaPublicKey, Pkcs1v15Sign};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Constant-time string comparison to prevent timing attacks
pub fn safe_compare(a: &str, b: &str) -> bool {
    let a_lower = a.to_ascii_lowercase();
    let b_lower = b.to_ascii_lowercase();
    let buf_a = a_lower.as_bytes();
    let buf_b = b_lower.as_bytes();
    if buf_a.len() != buf_b.len() {
        return false;
    }
    buf_a.ct_eq(buf_b).into()
}

/// Normalize and clean RSA Public Key from env string or file path into standard PEM
pub fn load_public_key(key_or_path: &str) -> Option<String> {
    let trimmed = key_or_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let raw_key = if Path::new(trimmed).exists() {
        match fs::read_to_string(trimmed) {
            Ok(content) => content,
            Err(e) => {
                tracing::error!("Failed to read public key file at {}: {}", trimmed, e);
                return None;
            }
        }
    } else {
        trimmed.to_string()
    };

    // Handle escaped newlines (e.g. from .env file "line1\nline2")
    let unescaped = raw_key.replace("\\n", "\n");

    // Strip existing PEM header/footer and any whitespace
    let mut clean_body = String::new();
    let mut in_body = true;
    for line in unescaped.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if l.starts_with("-----END") {
            break;
        }
        if in_body {
            clean_body.extend(l.chars().filter(|c| !c.is_whitespace()));
        }
    }

    if clean_body.is_empty() {
        return None;
    }

    // Format into standard 64-character PEM lines
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in clean_body.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            pem.push_str(s);
            pem.push('\n');
        }
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Some(pem)
}

/// Visual status details for notifications
#[derive(Debug, Clone)]
pub struct StatusDetails {
    pub title: &'static str,
    pub badge: String,
    pub color: u32,
    pub is_success: bool,
    pub is_pending: bool,
    pub is_failed: bool,
}

/// Format gross amount into Indonesian Rupiah (or raw currency)
pub fn format_currency(amount: Option<&str>, currency: Option<&str>) -> String {
    let curr = currency.unwrap_or("IDR");
    let amt_str = match amount {
        Some(a) if !a.is_empty() => a,
        _ => return "N/A".to_string(),
    };

    let Ok(num) = amt_str.parse::<f64>() else {
        return format!("{} {}", curr, amt_str);
    };

    let int_part = num.trunc().abs() as u64;
    let frac_part = (num.fract().abs() * 100.0).round() as u64;

    // Indonesian thousand separator uses '.'
    let int_str = int_part.to_string();
    let mut formatted_int = String::new();
    for (i, c) in int_str.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            formatted_int.push('.');
        }
        formatted_int.push(c);
    }
    let formatted_int: String = formatted_int.chars().rev().collect();

    if curr.eq_ignore_ascii_case("IDR") {
        if frac_part == 0 {
            format!("Rp {}", formatted_int)
        } else {
            format!("Rp {},{:02}", formatted_int, frac_part)
        }
    } else if frac_part == 0 {
        format!("{} {}", curr, formatted_int)
    } else {
        format!("{} {}.{:02}", curr, formatted_int, frac_part)
    }
}

/// Payment method details
#[derive(Debug, Clone)]
pub struct PaymentMethodInfo {
    pub name: String,
    pub detail: Option<String>,
}

/// Parse Legacy Payment Method
pub fn parse_payment_method(notification: &serde_json::Value) -> PaymentMethodInfo {
    let payment_type = notification.get("payment_type").and_then(|v| v.as_str()).unwrap_or("");

    match payment_type {
        "bank_transfer" => {
            if let Some(va_numbers) = notification.get("va_numbers").and_then(|v| v.as_array()) {
                if let Some(first_va) = va_numbers.first() {
                    let bank = first_va.get("bank").and_then(|v| v.as_str()).unwrap_or("Bank").to_uppercase();
                    let va = first_va.get("va_number").and_then(|v| v.as_str());
                    return PaymentMethodInfo {
                        name: format!("Virtual Account ({})", bank),
                        detail: va.map(|v| format!("VA: `{}`", v)),
                    };
                }
            }
            if let Some(permata_va) = notification.get("permata_va_number").and_then(|v| v.as_str()) {
                return PaymentMethodInfo {
                    name: "Virtual Account (PERMATA)".to_string(),
                    detail: Some(format!("VA: `{}`", permata_va)),
                };
            }
            PaymentMethodInfo {
                name: "Bank Transfer (VA)".to_string(),
                detail: None,
            }
        }
        "echannel" => {
            let bill_key = notification.get("bill_key").and_then(|v| v.as_str());
            let biller_code = notification.get("biller_code").and_then(|v| v.as_str()).unwrap_or("70012");
            PaymentMethodInfo {
                name: "Mandiri Bill Payment".to_string(),
                detail: bill_key.map(|bk| format!("Biller: `{}` | Bill Key: `{}`", biller_code, bk)),
            }
        }
        "qris" => {
            let issuer = notification.get("issuer").and_then(|v| v.as_str())
                .map(|i| format!(" ({})", i.to_uppercase()))
                .unwrap_or_default();
            let acquirer = notification.get("acquirer").and_then(|v| v.as_str())
                .map(|a| format!("Acquirer: {}", a));
            PaymentMethodInfo {
                name: format!("QRIS{}", issuer),
                detail: acquirer,
            }
        }
        "gopay" => PaymentMethodInfo {
            name: "GoPay".to_string(),
            detail: None,
        },
        "shopeepay" => PaymentMethodInfo {
            name: "ShopeePay".to_string(),
            detail: None,
        },
        "credit_card" => {
            let card = notification.get("masked_card").and_then(|v| v.as_str())
                .map(|c| {
                    let last4 = if c.len() >= 4 { &c[c.len() - 4..] } else { c };
                    format!(" •••• {}", last4)
                })
                .unwrap_or_default();
            let bank = notification.get("bank").and_then(|v| v.as_str())
                .map(|b| format!(" ({})", b.to_uppercase()))
                .unwrap_or_default();
            let detail = notification.get("channel_response_message").and_then(|v| v.as_str()).map(|s| s.to_string());
            PaymentMethodInfo {
                name: format!("Credit Card{}{}", bank, card),
                detail,
            }
        }
        "cstore" => {
            let store = notification.get("store").and_then(|v| v.as_str())
                .map(|s| s.to_uppercase())
                .unwrap_or_else(|| "Convenience Store".to_string());
            let code = notification.get("payment_code").and_then(|v| v.as_str())
                .map(|c| format!("Payment Code: `{}`", c));
            PaymentMethodInfo {
                name: store,
                detail: code,
            }
        }
        "akulaku" => PaymentMethodInfo {
            name: "Akulaku PayLater".to_string(),
            detail: None,
        },
        "kredivo" => PaymentMethodInfo {
            name: "Kredivo".to_string(),
            detail: None,
        },
        other => PaymentMethodInfo {
            name: if other.is_empty() { "Unknown Payment".to_string() } else { other.to_string() },
            detail: None,
        },
    }
}

/// Map Midtrans legacy transaction status to visual status details
pub fn get_status_details(notification: &serde_json::Value) -> StatusDetails {
    let trx_status = notification.get("transaction_status").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    let fraud_status = notification.get("fraud_status").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();

    match trx_status.as_str() {
        "authorize" => StatusDetails {
            title: "📋 Payment Authorized (Pre-Auth)",
            badge: "🟡 Authorize (Must be Captured)".to_string(),
            color: 0xF39C12,
            is_success: false,
            is_pending: true,
            is_failed: false,
        },
        "capture" => {
            if fraud_status == "challenge" {
                StatusDetails {
                    title: "⚠️ Payment Challenged",
                    badge: "🟡 Challenge (Fraud Review Required)".to_string(),
                    color: 0xF1C40F,
                    is_success: false,
                    is_pending: false,
                    is_failed: false,
                }
            } else {
                StatusDetails {
                    title: "✅ Payment Captured",
                    badge: "🟢 Capture / Success".to_string(),
                    color: 0x2ECC71,
                    is_success: true,
                    is_pending: false,
                    is_failed: false,
                }
            }
        }
        "settlement" => StatusDetails {
            title: "✅ Payment Received",
            badge: "🟢 Settlement (Paid)".to_string(),
            color: 0x2ECC71,
            is_success: true,
            is_pending: false,
            is_failed: false,
        },
        "pending" => StatusDetails {
            title: "⏳ Payment Pending",
            badge: "🟡 Waiting for Customer Payment".to_string(),
            color: 0xF39C12,
            is_success: false,
            is_pending: true,
            is_failed: false,
        },
        "deny" => StatusDetails {
            title: "❌ Payment Denied",
            badge: "🔴 Denied by Bank/Fraud Control".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "cancel" => StatusDetails {
            title: "🚫 Payment Canceled",
            badge: "⚪ Canceled".to_string(),
            color: 0x95A5A6,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "expire" => StatusDetails {
            title: "⏰ Payment Expired",
            badge: "🔴 Expired (Unpaid)".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "failure" => StatusDetails {
            title: "💥 Payment Failed",
            badge: "🔴 Processing Failure".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "refund" | "partial_refund" => StatusDetails {
            title: "🔄 Payment Refunded",
            badge: if trx_status == "partial_refund" { "🔵 Partial Refund".to_string() } else { "🔵 Refund".to_string() },
            color: 0x3498DB,
            is_success: false,
            is_pending: false,
            is_failed: false,
        },
        "chargeback" | "partial_chargeback" => StatusDetails {
            title: "⚠️ Payment Chargeback Dispute",
            badge: if trx_status == "partial_chargeback" { "🔴 Partial Chargeback".to_string() } else { "🔴 Chargeback".to_string() },
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        other => StatusDetails {
            title: "ℹ️ Payment Update",
            badge: if other.is_empty() { "Unknown Status".to_string() } else { other.to_string() },
            color: 0x7F8C8D,
            is_success: false,
            is_pending: false,
            is_failed: false,
        },
    }
}

/// Map BI SNAP / Open API latestTransactionStatus code to details
pub fn get_bi_snap_status_details(status_code: &str, status_desc: Option<&str>) -> StatusDetails {
    match status_code {
        "00" => StatusDetails {
            title: "✅ BI SNAP Payment Successful",
            badge: "🟢 Success (00)".to_string(),
            color: 0x2ECC71,
            is_success: true,
            is_pending: false,
            is_failed: false,
        },
        "03" => StatusDetails {
            title: "⏳ BI SNAP Payment Pending",
            badge: "🟡 Pending (03)".to_string(),
            color: 0xF39C12,
            is_success: false,
            is_pending: true,
            is_failed: false,
        },
        "04" => StatusDetails {
            title: "🔄 BI SNAP Payment Refunded",
            badge: "🔵 Refunded (04)".to_string(),
            color: 0x3498DB,
            is_success: false,
            is_pending: false,
            is_failed: false,
        },
        "05" => StatusDetails {
            title: "🚫 BI SNAP Payment Canceled",
            badge: "⚪ Canceled (05)".to_string(),
            color: 0x95A5A6,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "06" => StatusDetails {
            title: "💥 BI SNAP Payment Failed",
            badge: "🔴 Failure (06)".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "08" => StatusDetails {
            title: "⏰ BI SNAP Payment Expired",
            badge: "🔴 Expired (08)".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "09" => StatusDetails {
            title: "❌ BI SNAP Payment Rejected",
            badge: "🔴 Rejected (09)".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        other => {
            let desc = status_desc.filter(|d| !d.is_empty()).unwrap_or(other);
            StatusDetails {
                title: "ℹ️ BI SNAP Notification",
                badge: format!("{} ({})", desc, if other.is_empty() { "N/A" } else { other }),
                color: 0x7F8C8D,
                is_success: false,
                is_pending: false,
                is_failed: false,
            }
        }
    }
}

/// Map Midtrans IRIS payout status to visual status details
pub fn get_iris_status_details(status: &str) -> StatusDetails {
    let normalized = status.to_lowercase().trim().to_string();

    match normalized.as_str() {
        "completed" => StatusDetails {
            title: "💸 Payout Disbursed Successfully",
            badge: "🟢 Completed (Disbursed)".to_string(),
            color: 0x2ECC71,
            is_success: true,
            is_pending: false,
            is_failed: false,
        },
        "processed" => StatusDetails {
            title: "🔄 Payout Processing at Bank",
            badge: "🔵 Processed (Processing at Bank)".to_string(),
            color: 0x3498DB,
            is_success: false,
            is_pending: true,
            is_failed: false,
        },
        "approved" => StatusDetails {
            title: "📋 Payout Approved (Awaiting Bank Processing)",
            badge: "🟡 Approved (Pending Processing)".to_string(),
            color: 0xF39C12,
            is_success: false,
            is_pending: true,
            is_failed: false,
        },
        "queued" | "pending" => StatusDetails {
            title: "⏳ Payout Queued / In Progress",
            badge: "🟡 Queued".to_string(),
            color: 0xF39C12,
            is_success: false,
            is_pending: true,
            is_failed: false,
        },
        "rejected" => StatusDetails {
            title: "❌ Payout Rejected",
            badge: "🔴 Rejected".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        "failed" => StatusDetails {
            title: "💥 Payout Failed",
            badge: "🔴 Failed".to_string(),
            color: 0xE74C3C,
            is_success: false,
            is_pending: false,
            is_failed: true,
        },
        other => StatusDetails {
            title: "ℹ️ IRIS Payout Notification",
            badge: if other.is_empty() { "Unknown Status".to_string() } else { format!("Status: {}", other) },
            color: 0x7F8C8D,
            is_success: false,
            is_pending: false,
            is_failed: false,
        },
    }
}

/// Verify Legacy Midtrans Pay-in signature key (Payment, Recurring, Account Binding)
pub fn verify_midtrans_signature(
    notification: &serde_json::Value,
    secret_keys: &[String],
) -> Result<(), String> {
    if secret_keys.is_empty() {
        return Err("Server key not provided; signature check cannot be performed.".to_string());
    }

    let status_code = notification.get("status_code").and_then(|v| v.as_str());
    let signature_key = notification.get("signature_key").and_then(|v| v.as_str());

    let (status_code, signature_key) = match (status_code, signature_key) {
        (Some(sc), Some(sk)) => (sc, sk),
        _ => return Err("Missing status_code or signature_key in payload.".to_string()),
    };

    let order_id = notification.get("order_id").and_then(|v| v.as_str());
    let account_id = notification.get("account_id").and_then(|v| v.as_str());
    let sub_id = notification.get("subscription_id").and_then(|v| v.as_str());

    let id = order_id.or(account_id).or(sub_id);
    let id = match id {
        Some(i) => i,
        None => return Err("Missing identifier (order_id or account_id) in payload.".to_string()),
    };

    let gross_amt_val = notification.get("gross_amount");
    let gross_amt_str = gross_amt_val.and_then(|v| {
        if v.is_string() {
            v.as_str()
        } else {
            None
        }
    }).map(|s| s.to_string())
      .or_else(|| gross_amt_val.and_then(|v| v.as_f64()).map(|f| format!("{:.2}", f)))
      .unwrap_or_default();

    for secret_key in secret_keys {
        let mut candidates = Vec::new();

        // 1. Pay Account notification
        if let Some(acc_id) = account_id {
            if let Some(acc_status) = notification.get("account_status").and_then(|v| v.as_str()) {
                candidates.push(format!("{}{}{}{}", acc_id, acc_status, status_code, secret_key));
            }
            candidates.push(format!("{}{}{}", acc_id, status_code, secret_key));
        }

        // 2. Transaction notification (order_id or subscription_id)
        if order_id.is_some() || sub_id.is_some() {
            let trx_id = order_id.or(sub_id).unwrap();
            candidates.push(format!("{}{}{}{}", trx_id, status_code, gross_amt_str, secret_key));

            if let Ok(num) = gross_amt_str.parse::<f64>() {
                candidates.push(format!("{}{}{:.2}{}", trx_id, status_code, num, secret_key));
                candidates.push(format!("{}{}{}{}", trx_id, status_code, num.round() as i64, secret_key));
            }
        }

        // Fallback candidate
        candidates.push(format!("{}{}{}", id, status_code, secret_key));

        for raw_str in candidates {
            let mut hasher = Sha512::new();
            hasher.update(raw_str.as_bytes());
            let calculated = hex::encode(hasher.finalize());
            if safe_compare(&calculated, signature_key) {
                return Ok(());
            }
        }
    }

    Err("Signature mismatch: notification may be unauthorized or tampered with.".to_string())
}

/// Verify Midtrans IRIS Disbursement Signature
/// Header: Iris-Signature
/// Formula: SHA512( rawBody + IRIS_MERCHANT_KEY )
pub fn verify_iris_signature(
    raw_body: &[u8],
    body_json: Option<&serde_json::Value>,
    header_signature: Option<&str>,
    iris_key: &str,
) -> Result<(), String> {
    if iris_key.is_empty() {
        return Err("IRIS_MERCHANT_KEY not configured; IRIS signature check cannot be performed.".to_string());
    }

    let header_sig = match header_signature {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return Err("Missing Iris-Signature HTTP header.".to_string()),
    };

    let mut candidates = Vec::new();
    if !raw_body.is_empty() {
        if let Ok(s) = std::str::from_utf8(raw_body) {
            candidates.push(s.to_string());
        }
    }

    if let Some(json_val) = body_json {
        if let Ok(serialized) = serde_json::to_string(json_val) {
            if !candidates.contains(&serialized) {
                candidates.push(serialized);
            }
        }
    }

    for body_str in candidates {
        let string_to_sign = format!("{}{}", body_str, iris_key);
        let mut hasher = Sha512::new();
        hasher.update(string_to_sign.as_bytes());
        let calculated = hex::encode(hasher.finalize());
        if safe_compare(&calculated, header_sig) {
            return Ok(());
        }
    }

    Err("Iris-Signature mismatch: notification body or IRIS Merchant Key does not match.".to_string())
}

/// Verify Bank Indonesia SNAP / Open API Asymmetric Signature
/// Formula: SHA256withRSA (privateKey, stringToSign)
/// stringToSign = HTTPMethod + ":" + EndpointUrl + ":" + Lowercase(HexEncode(SHA-256(minify(RequestBody)))) + ":" + TimeStamp
pub fn verify_bi_snap_signature(
    method: &str,
    uri_path: &str,
    raw_body: &[u8],
    body_json: Option<&serde_json::Value>,
    x_signature: Option<&str>,
    x_timestamp: Option<&str>,
    public_key_pem: &str,
) -> Result<String, String> {
    let sig_b64 = match x_signature {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return Err("Missing X-SIGNATURE header in BI SNAP request.".to_string()),
    };

    let timestamp = match x_timestamp {
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => return Err("Missing X-TIMESTAMP header in BI SNAP request.".to_string()),
    };

    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("Failed to parse public key PEM: {}", e))?;

    let signature_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
        .map_err(|e| format!("Invalid base64 in X-SIGNATURE: {}", e))?;

    // Minified body candidates
    let mut minified_body_variants = Vec::new();
    if let Some(json_val) = body_json {
        if let Ok(s) = serde_json::to_string(json_val) {
            minified_body_variants.push(s);
        }
    }
    if !raw_body.is_empty() {
        if let Ok(json_parsed) = serde_json::from_slice::<serde_json::Value>(raw_body) {
            if let Ok(s) = serde_json::to_string(&json_parsed) {
                if !minified_body_variants.contains(&s) {
                    minified_body_variants.push(s);
                }
            }
        }
        if let Ok(s) = std::str::from_utf8(raw_body) {
            let trimmed = s.trim().to_string();
            if !minified_body_variants.contains(&trimmed) {
                minified_body_variants.push(trimmed);
            }
        }
    }

    let clean_path = uri_path.split('?').next().unwrap_or(uri_path);
    let mut url_variants = HashSet::new();
    url_variants.insert(clean_path.to_string());
    url_variants.insert(clean_path.trim_end_matches('/').to_string());

    if let Some(stripped) = clean_path.strip_prefix("/bi-snap") {
        url_variants.insert(if stripped.is_empty() { "/".to_string() } else { stripped.to_string() });
        url_variants.insert(stripped.trim_end_matches('/').to_string());
    }

    let upper_method = method.to_ascii_uppercase();

    for endpoint in &url_variants {
        if endpoint.is_empty() {
            continue;
        }

        for body_str in &minified_body_variants {
            let mut hasher = Sha256::new();
            hasher.update(body_str.as_bytes());
            let body_hash = hex::encode(hasher.finalize()).to_ascii_lowercase();

            let string_to_sign = format!("{}:{}:{}:{}", upper_method, endpoint, body_hash, timestamp);

            let mut verifier_hasher = Sha256::new();
            verifier_hasher.update(string_to_sign.as_bytes());
            let digest = verifier_hasher.finalize();

            let scheme = Pkcs1v15Sign::new::<Sha256>();
            if public_key.verify(scheme, &digest, &signature_bytes).is_ok() {
                return Ok(endpoint.clone());
            }
        }
    }

    Err("BI SNAP RSA-SHA256 signature verification failed. Public key or signed string did not match.".to_string())
}
