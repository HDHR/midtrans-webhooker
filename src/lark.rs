use crate::midtrans::{
    format_currency, parse_payment_method, get_status_details,
    get_bi_snap_status_details, get_iris_status_details, StatusDetails,
};
use serde_json::json;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut truncated: String = s.chars().take(max.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    } else {
        s.to_string()
    }
}

/// Strip any inline code backticks because Lark `lark_md` inside fields
/// does not render inline code and shows raw backticks instead.
fn clean_lark_text(s: &str) -> String {
    s.replace('`', "")
}

fn create_lark_field(tag: &str, content: &str, is_short: bool) -> serde_json::Value {
    let cleaned = clean_lark_text(content);
    json!({
        "is_short": is_short,
        "text": {
            "tag": "lark_md",
            "content": format!("**{}**\n{}", tag, truncate(&cleaned, 1024))
        }
    })
}

fn attach_raw_action(elements: &mut Vec<serde_json::Value>, raw_url: Option<&str>) {
    if let Some(url) = raw_url {
        elements.push(json!({
            "tag": "action",
            "actions": [
                {
                    "tag": "button",
                    "text": {
                        "tag": "plain_text",
                        "content": "🔍 View Raw JSON"
                    },
                    "type": "default",
                    "url": url
                }
            ]
        }));
    }
}

fn get_template_color(status_info: Option<&StatusDetails>) -> &'static str {
    match status_info {
        Some(info) => {
            if info.is_success {
                "green"
            } else if info.is_pending {
                "orange"
            } else if info.is_failed {
                "red"
            } else if info.color == 0x3498DB {
                "blue"
            } else if info.color == 0xF1C40F {
                "yellow"
            } else {
                "grey"
            }
        }
        None => "blue",
    }
}

/// Generate Lark HMAC-SHA256 signature
/// stringToSign = timestamp + "\n" + secret
/// sign = Base64( HmacSHA256( empty_payload, key = stringToSign ) )
pub fn generate_lark_sign(secret: &str, timestamp: i64) -> Option<String> {
    if secret.trim().is_empty() {
        return None;
    }
    let string_to_sign = format!("{}\n{}", timestamp, secret);
    let mut mac = HmacSha256::new_from_slice(string_to_sign.as_bytes()).ok()?;
    mac.update(b"");
    let result = mac.finalize();
    Some(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
}

pub struct LarkBuildResult {
    pub card: serde_json::Value,
    pub status_info: Option<StatusDetails>,
}

pub fn build_lark_payment_card(
    notification: &serde_json::Value,
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> LarkBuildResult {
    let status_info = get_status_details(notification);
    let payment_method = parse_payment_method(notification);
    let order_id = notification.get("order_id").and_then(|v| v.as_str()).unwrap_or("N/A");

    let gross_amt_str = notification.get("gross_amount").and_then(|v| {
        if v.is_string() { v.as_str() } else { None }
    }).map(|s| s.to_string())
      .or_else(|| notification.get("gross_amount").and_then(|v| v.as_f64()).map(|f| format!("{:.2}", f)));

    let currency = notification.get("currency").and_then(|v| v.as_str());
    let formatted_amount = format_currency(gross_amt_str.as_deref(), currency);

    let mut fields = vec![
        create_lark_field("Order ID", order_id, true),
        create_lark_field("Amount", &format!("**{}**", formatted_amount), true),
        create_lark_field("Status", &status_info.badge, true),
        create_lark_field("Payment Method", &payment_method.name, true),
    ];

    if let Some(detail) = &payment_method.detail {
        fields.push(create_lark_field("Payment Info", detail, true));
    }

    if let Some(trx_time) = notification.get("transaction_time").and_then(|v| v.as_str()) {
        fields.push(create_lark_field("Transaction Time", trx_time, true));
    }

    if let Some(trx_id) = notification.get("transaction_id").and_then(|v| v.as_str()) {
        fields.push(create_lark_field("Midtrans ID", trx_id, false));
    }

    let mut elements = Vec::new();
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        elements.push(json!({
            "tag": "div",
            "text": { "tag": "lark_md", "content": m }
        }));
    }

    elements.push(json!({
        "tag": "div",
        "text": { "tag": "lark_md", "content": format!("Payment update for order **{}**", order_id) }
    }));

    elements.push(json!({
        "tag": "div",
        "fields": fields
    }));

    attach_raw_action(&mut elements, raw_url);

    elements.push(json!({
        "tag": "note",
        "elements": [
            { "tag": "plain_text", "content": format!("Midtrans • Payment Legacy • {}", chrono::Utc::now().to_rfc3339()) }
        ]
    }));

    let template = get_template_color(Some(&status_info));
    let card = json!({
        "config": { "wide_screen_mode": true },
        "header": {
            "title": { "tag": "plain_text", "content": truncate(status_info.title, 100) },
            "template": template
        },
        "elements": elements
    });

    LarkBuildResult {
        card,
        status_info: Some(status_info),
    }
}

pub fn build_lark_recurring_card(
    notification: &serde_json::Value,
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> LarkBuildResult {
    let sub_id = notification.get("subscription_id")
        .or_else(|| notification.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let order_id = notification.get("order_id")
        .or_else(|| notification.get("last_transaction_order_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let status = notification.get("status")
        .or_else(|| notification.get("subscription_status"))
        .or_else(|| notification.get("transaction_status"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_uppercase();

    let amount_str = notification.get("gross_amount")
        .or_else(|| notification.get("amount"))
        .or_else(|| notification.get("schedule").and_then(|s| s.get("amount")))
        .and_then(|v| {
            if v.is_string() { v.as_str().map(|s| s.to_string()) }
            else if let Some(n) = v.as_f64() { Some(format!("{:.2}", n)) }
            else { None }
        });

    let currency = notification.get("currency").and_then(|v| v.as_str()).unwrap_or("IDR");
    let formatted_amount = format_currency(amount_str.as_deref(), Some(currency));

    let (template, status_badge) = match status.as_str() {
        "ACTIVE" | "SETTLEMENT" | "SUCCESS" => ("green", format!("🟢 {}", status)),
        "PENDING" | "SCHEDULED" => ("orange", format!("🟡 {}", status)),
        "CANCELED" | "CANCELLED" | "EXPIRED" | "FAILED" | "SUSPENDED" => ("red", format!("🔴 {}", status)),
        _ => ("blue", format!("🔵 {}", status)),
    };

    let mut fields = vec![
        create_lark_field("Subscription ID", sub_id, true),
        create_lark_field("Order ID", order_id, true),
        create_lark_field("Status", &status_badge, true),
    ];

    if amount_str.is_some() {
        fields.push(create_lark_field("Amount", &format!("**{}**", formatted_amount), true));
    }

    if let Some(schedule) = notification.get("schedule") {
        let interval = schedule.get("interval").and_then(|v| v.as_i64());
        let unit = schedule.get("interval_unit").and_then(|v| v.as_str());
        if let (Some(inv), Some(u)) = (interval, unit) {
            fields.push(create_lark_field("Interval", &format!("Every {} {}", inv, u), true));
        }
    }

    if let Some(pt) = notification.get("payment_type").and_then(|v| v.as_str()) {
        fields.push(create_lark_field("Payment Type", pt, true));
    }

    let mut elements = Vec::new();
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        elements.push(json!({
            "tag": "div",
            "text": { "tag": "lark_md", "content": m }
        }));
    }

    elements.push(json!({
        "tag": "div",
        "text": { "tag": "lark_md", "content": format!("Subscription **{}** status update: **{}**", sub_id, status) }
    }));

    elements.push(json!({
        "tag": "div",
        "fields": fields
    }));

    attach_raw_action(&mut elements, raw_url);

    elements.push(json!({
        "tag": "note",
        "elements": [
            { "tag": "plain_text", "content": format!("Midtrans • Recurring Legacy • {}", chrono::Utc::now().to_rfc3339()) }
        ]
    }));

    let card = json!({
        "config": { "wide_screen_mode": true },
        "header": {
            "title": { "tag": "plain_text", "content": "🔄 Recurring Payment Notification" },
            "template": template
        },
        "elements": elements
    });

    LarkBuildResult {
        card,
        status_info: None,
    }
}

pub fn build_lark_binding_card(
    notification: &serde_json::Value,
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> LarkBuildResult {
    let account_id = notification.get("account_id").and_then(|v| v.as_str()).unwrap_or("N/A");
    let status = notification.get("status")
        .or_else(|| notification.get("account_status"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_uppercase();

    let channel = notification.get("channel_id")
        .or_else(|| notification.get("payment_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_uppercase();

    let is_enabled = status == "ENABLED" || status == "ACTIVE" || status == "SUCCESS";
    let (template, status_badge) = if is_enabled {
        ("green", format!("🟢 {}", status))
    } else {
        ("red", format!("🔴 {}", status))
    };

    let mut fields = vec![
        create_lark_field("Account ID", account_id, true),
        create_lark_field("Binding Status", &status_badge, true),
        create_lark_field("Channel", &channel, true),
    ];

    if let Some(msg) = notification.get("status_message").and_then(|v| v.as_str()) {
        fields.push(create_lark_field("Status Message", msg, false));
    }

    if let Some(meta) = notification.get("metadata") {
        if meta.is_object() {
            fields.push(create_lark_field("Metadata", &meta.to_string(), false));
        }
    }

    let mut elements = Vec::new();
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        elements.push(json!({
            "tag": "div",
            "text": { "tag": "lark_md", "content": m }
        }));
    }

    elements.push(json!({
        "tag": "div",
        "text": { "tag": "lark_md", "content": format!("Account binding event for **{}**", account_id) }
    }));

    elements.push(json!({
        "tag": "div",
        "fields": fields
    }));

    attach_raw_action(&mut elements, raw_url);

    elements.push(json!({
        "tag": "note",
        "elements": [
            { "tag": "plain_text", "content": format!("Midtrans • Binding Legacy • {}", chrono::Utc::now().to_rfc3339()) }
        ]
    }));

    let title = if is_enabled { "🔗 Account Linked Successfully" } else { "🔌 Account Unlinked" };
    let card = json!({
        "config": { "wide_screen_mode": true },
        "header": {
            "title": { "tag": "plain_text", "content": title },
            "template": template
        },
        "elements": elements
    });

    LarkBuildResult {
        card,
        status_info: None,
    }
}

pub fn build_lark_bi_snap_card(
    notification: &serde_json::Value,
    headers: &[(String, String)],
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> LarkBuildResult {
    let status_code = notification.get("latestTransactionStatus")
        .or_else(|| notification.get("transactionStatus"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");

    let status_desc = notification.get("transactionStatusDesc").and_then(|v| v.as_str());
    let status_info = get_bi_snap_status_details(status_code, status_desc);

    let order_id = notification.get("originalPartnerReferenceNo")
        .or_else(|| notification.get("originalReferenceNo"))
        .or_else(|| notification.get("virtualAccountNo"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let amount_obj = notification.get("amount").or_else(|| notification.get("paidAmount"));
    let amt_val = amount_obj.and_then(|a| a.get("value")).and_then(|v| {
        if v.is_string() { v.as_str().map(|s| s.to_string()) }
        else if let Some(n) = v.as_f64() { Some(format!("{:.2}", n)) }
        else { None }
    });
    let currency = amount_obj.and_then(|a| a.get("currency")).and_then(|v| v.as_str()).unwrap_or("IDR");
    let formatted_amount = format_currency(amt_val.as_deref(), Some(currency));

    let mut fields = vec![
        create_lark_field("Order / Partner Ref", order_id, true),
        create_lark_field("Amount", &format!("**{}**", formatted_amount), true),
        create_lark_field("Status", &status_info.badge, true),
    ];

    if let Some(qris) = notification.get("additionalInfo").and_then(|a| a.get("qris")) {
        let issuer = qris.get("issuerName").and_then(|v| v.as_str()).unwrap_or("N/A").to_uppercase();
        let acquirer = qris.get("acquirerName").and_then(|v| v.as_str()).unwrap_or("N/A").to_uppercase();
        let trx_type = qris.get("transactionType").and_then(|v| v.as_str()).unwrap_or("N/A");
        fields.push(create_lark_field(
            "QRIS Details",
            &format!("Issuer: **{}**\nAcquirer: **{}**\nType: {}", issuer, acquirer, trx_type),
            true,
        ));
    }

    if let Some(upd) = notification.get("additionalInfo").and_then(|a| a.get("userPaymentDetails")).and_then(|v| v.as_array()) {
        let details: Vec<String> = upd.iter().filter_map(|d| {
            let method = d.get("payMethod").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
            let option = d.get("payOption").and_then(|v| v.as_str()).unwrap_or("");
            if method.is_empty() && option.is_empty() {
                None
            } else {
                Some(format!("{} ({})", method, option))
            }
        }).collect();

        if !details.is_empty() {
            fields.push(create_lark_field("Payment Option", &details.join(", "), true));
        }
    }

    if let Some(va) = notification.get("virtualAccountNo").and_then(|v| v.as_str()) {
        let name = notification.get("virtualAccountName").and_then(|v| v.as_str()).unwrap_or("N/A");
        fields.push(create_lark_field(
            "Virtual Account",
            &format!("No: {}\nName: {}", va, name),
            true,
        ));
    }

    if let Some(orig_ref) = notification.get("originalReferenceNo").and_then(|v| v.as_str()) {
        if orig_ref != order_id {
            fields.push(create_lark_field("Midtrans Ref", orig_ref, true));
        }
    }

    let partner_id = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-partner-id")).map(|(_, v)| v.as_str());
    let external_id = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-external-id")).map(|(_, v)| v.as_str());
    if partner_id.is_some() || external_id.is_some() {
        fields.push(create_lark_field(
            "BI SNAP Headers",
            &format!("Partner: {} | Ext ID: {}", partner_id.unwrap_or("N/A"), external_id.unwrap_or("N/A")),
            false,
        ));
    }

    let mut elements = Vec::new();
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        elements.push(json!({
            "tag": "div",
            "text": { "tag": "lark_md", "content": m }
        }));
    }

    elements.push(json!({
        "tag": "div",
        "text": { "tag": "lark_md", "content": format!("BI SNAP Open API notification for **{}**", order_id) }
    }));

    elements.push(json!({
        "tag": "div",
        "fields": fields
    }));

    attach_raw_action(&mut elements, raw_url);

    elements.push(json!({
        "tag": "note",
        "elements": [
            { "tag": "plain_text", "content": format!("Bank Indonesia SNAP • Midtrans Open API • {}", chrono::Utc::now().to_rfc3339()) }
        ]
    }));

    let template = get_template_color(Some(&status_info));
    let card = json!({
        "config": { "wide_screen_mode": true },
        "header": {
            "title": { "tag": "plain_text", "content": truncate(status_info.title, 100) },
            "template": template
        },
        "elements": elements
    });

    LarkBuildResult {
        card,
        status_info: Some(status_info),
    }
}

pub fn build_lark_iris_card(
    notification: &serde_json::Value,
    _headers: &[(String, String)],
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> LarkBuildResult {
    let status = notification.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
    let status_info = get_iris_status_details(status);

    let ref_no = notification.get("reference_no")
        .or_else(|| notification.get("payout_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let amt_val = notification.get("amount").and_then(|v| {
        if v.is_string() { v.as_str().map(|s| s.to_string()) }
        else if let Some(n) = v.as_f64() { Some(format!("{:.2}", n)) }
        else { None }
    });
    let formatted_amount = format_currency(amt_val.as_deref(), Some("IDR"));

    let mut fields = vec![
        create_lark_field("Reference No", ref_no, true),
        create_lark_field("Amount", &format!("**{}**", formatted_amount), true),
        create_lark_field("Status", &status_info.badge, true),
    ];

    let bank_code = notification.get("bank_code").and_then(|v| v.as_str());
    let account = notification.get("account").and_then(|v| v.as_str());
    let ben_name = notification.get("beneficiary_name").and_then(|v| v.as_str());

    if bank_code.is_some() || account.is_some() || ben_name.is_some() {
        let b = bank_code.map(|b| b.to_uppercase()).unwrap_or_else(|| "Bank".to_string());
        let a = account.map(|acc| format!(" {}", acc)).unwrap_or_default();
        let n = ben_name.map(|name| format!(" ({})", name)).unwrap_or_default();
        fields.push(create_lark_field("Beneficiary", format!("{}{}{}", b, a, n).trim(), true));
    }

    if let Some(notes) = notification.get("notes").and_then(|v| v.as_str()) {
        fields.push(create_lark_field("Notes", notes, true));
    }

    if let Some(err_msg) = notification.get("error_message").and_then(|v| v.as_str()) {
        fields.push(create_lark_field("Error Message", err_msg, false));
    }

    let timestamp_str = notification.get("updated_at")
        .or_else(|| notification.get("created_at"))
        .and_then(|v| v.as_str());

    if let Some(ts) = timestamp_str {
        fields.push(create_lark_field("Timestamp", ts, true));
    }

    let mut elements = Vec::new();
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        elements.push(json!({
            "tag": "div",
            "text": { "tag": "lark_md", "content": m }
        }));
    }

    elements.push(json!({
        "tag": "div",
        "text": { "tag": "lark_md", "content": format!("[IRIS Disbursement] Update for reference **{}**", ref_no) }
    }));

    elements.push(json!({
        "tag": "div",
        "fields": fields
    }));

    attach_raw_action(&mut elements, raw_url);

    elements.push(json!({
        "tag": "note",
        "elements": [
            { "tag": "plain_text", "content": format!("Midtrans • IRIS Disbursement • {}", chrono::Utc::now().to_rfc3339()) }
        ]
    }));

    let template = get_template_color(Some(&status_info));
    let card = json!({
        "config": { "wide_screen_mode": true },
        "header": {
            "title": { "tag": "plain_text", "content": truncate(status_info.title, 100) },
            "template": template
        },
        "elements": elements
    });

    LarkBuildResult {
        card,
        status_info: Some(status_info),
    }
}

pub async fn send_lark_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    card: &serde_json::Value,
    secret: Option<&str>,
) -> Result<(), String> {
    if webhook_url.trim().is_empty() {
        return Ok(());
    }

    let mut payload = json!({
        "msg_type": "interactive",
        "card": card
    });

    if let Some(sec) = secret.filter(|s| !s.trim().is_empty()) {
        let timestamp = chrono::Utc::now().timestamp();
        if let Some(sign) = generate_lark_sign(sec, timestamp) {
            payload["timestamp"] = json!(timestamp.to_string());
            payload["sign"] = json!(sign);
        }
    }

    let res = client.post(webhook_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Lark network error: {}", e))?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(format!("Lark API HTTP {}: {}", status, body));
    }

    Ok(())
}
