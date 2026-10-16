use crate::midtrans::{
    format_currency, parse_payment_method, get_status_details,
    get_bi_snap_status_details, get_iris_status_details, StatusDetails,
};
use serde_json::json;

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut truncated: String = s.chars().take(max.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    } else {
        s.to_string()
    }
}

fn create_field(name: &str, value: &str, inline: bool) -> serde_json::Value {
    json!({
        "name": truncate(name, 256),
        "value": truncate(value, 1024),
        "inline": inline
    })
}

fn attach_raw_button(payload: &mut serde_json::Value, raw_url: Option<&str>) {
    if let Some(url) = raw_url {
        payload["components"] = json!([
            {
                "type": 1, // Action Row
                "components": [
                    {
                        "type": 2, // Button
                        "style": 5, // Link button
                        "label": "View Raw JSON",
                        "emoji": {
                            "name": "🔍"
                        },
                        "url": url
                    }
                ]
            }
        ]);
    }
}

pub struct DiscordBuildResult {
    pub payload: serde_json::Value,
    pub status_info: Option<StatusDetails>,
}

pub fn build_legacy_payment_embed(
    notification: &serde_json::Value,
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> DiscordBuildResult {
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
        create_field("🏷️ Order ID", &format!("`{}`", order_id), true),
        create_field("💰 Amount", &format!("**{}**", formatted_amount), true),
        create_field("📌 Status", &status_info.badge, true),
        create_field("💳 Payment Method", &payment_method.name, true),
    ];

    if let Some(detail) = &payment_method.detail {
        fields.push(create_field("🔢 Payment Info", detail, true));
    }

    if let Some(trx_time) = notification.get("transaction_time").and_then(|v| v.as_str()) {
        fields.push(create_field("🕒 Transaction Time", &format!("`{}`", trx_time), true));
    }

    if let Some(trx_id) = notification.get("transaction_id").and_then(|v| v.as_str()) {
        fields.push(create_field("🆔 Midtrans ID", &format!("`{}`", trx_id), false));
    }

    let desc_base = format!("[Legacy Payment] Update for order **{}**", order_id);
    let description = if let Some(url) = raw_url {
        format!("{}\n[🔍 View Raw JSON]({})", desc_base, url)
    } else {
        desc_base
    };

    let mut embed = json!({
        "title": truncate(status_info.title, 256),
        "description": truncate(&description, 4096),
        "color": status_info.color,
        "fields": fields,
        "footer": { "text": "Midtrans • Payment Legacy" },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if let Some(url) = raw_url {
        embed["url"] = json!(url);
    }

    let mut payload = json!({ "embeds": [embed] });
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        payload["content"] = json!(m);
    }
    attach_raw_button(&mut payload, raw_url);

    DiscordBuildResult {
        payload,
        status_info: Some(status_info),
    }
}

pub fn build_recurring_embed(
    notification: &serde_json::Value,
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> DiscordBuildResult {
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

    let (color, status_badge) = match status.as_str() {
        "ACTIVE" | "SETTLEMENT" | "SUCCESS" => (0x2ECC71, format!("🟢 {}", status)),
        "PENDING" | "SCHEDULED" => (0xF1C40F, format!("🟡 {}", status)),
        "CANCELED" | "CANCELLED" | "EXPIRED" | "FAILED" | "SUSPENDED" => (0xE74C3C, format!("🔴 {}", status)),
        _ => (0x3498DB, format!("🔵 {}", status)),
    };

    let mut fields = vec![
        create_field("🔁 Subscription ID", &format!("`{}`", sub_id), true),
        create_field("🏷️ Order ID", &format!("`{}`", order_id), true),
        create_field("📌 Status", &status_badge, true),
    ];

    if amount_str.is_some() {
        fields.push(create_field("💰 Amount", &format!("**{}**", formatted_amount), true));
    }

    if let Some(schedule) = notification.get("schedule") {
        let interval = schedule.get("interval").and_then(|v| v.as_i64());
        let unit = schedule.get("interval_unit").and_then(|v| v.as_str());
        if let (Some(iv), Some(un)) = (interval, unit) {
            fields.push(create_field("🔄 Billing Cycle", &format!("Every {} {}(s)", iv, un), true));
        }
    }

    if let Some(pt) = notification.get("payment_type").and_then(|v| v.as_str()) {
        fields.push(create_field("💳 Payment Type", pt, true));
    }

    let desc_base = format!("Subscription **{}** status update: **{}**", sub_id, status);
    let description = if let Some(url) = raw_url {
        format!("{}\n[🔍 View Raw JSON]({})", desc_base, url)
    } else {
        desc_base
    };

    let mut embed = json!({
        "title": "🔁 Recurring Payment Notification",
        "description": truncate(&description, 4096),
        "color": color,
        "fields": fields,
        "footer": { "text": "Midtrans • Recurring Legacy" },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if let Some(url) = raw_url {
        embed["url"] = json!(url);
    }

    let mut payload = json!({ "embeds": [embed] });
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        payload["content"] = json!(m);
    }
    attach_raw_button(&mut payload, raw_url);

    DiscordBuildResult {
        payload,
        status_info: None,
    }
}

pub fn build_binding_embed(
    notification: &serde_json::Value,
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> DiscordBuildResult {
    let account_id = notification.get("account_id")
        .or_else(|| notification.get("payment_account_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let account_status = notification.get("account_status")
        .or_else(|| notification.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_uppercase();

    let status_code = notification.get("status_code").and_then(|v| v.as_str()).unwrap_or("N/A");
    let channel = notification.get("channel")
        .or_else(|| notification.get("payment_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_uppercase();

    let is_enabled = account_status == "ENABLED" || account_status == "ACTIVE";
    let (color, badge) = match account_status.as_str() {
        "ENABLED" | "ACTIVE" => (0x2ECC71, format!("🟢 {}", account_status)),
        "DISABLED" | "REVOKED" | "EXPIRED" => (0xE74C3C, format!("🔴 {}", account_status)),
        "PENDING" => (0xF1C40F, format!("🟡 {}", account_status)),
        _ => (0x95A5A6, format!("⚪ {}", account_status)),
    };

    let mut fields = vec![
        create_field("🆔 Account ID", &format!("`{}`", account_id), true),
        create_field("💳 Channel", &format!("**{}**", channel), true),
        create_field("📌 Status", &badge, true),
        create_field("🔢 Status Code", &format!("`{}`", status_code), true),
    ];

    if let Some(msg) = notification.get("status_message").and_then(|v| v.as_str()) {
        fields.push(create_field("📝 Message", msg, false));
    }

    let desc_base = format!("Account binding event for **{}**", account_id);
    let description = if let Some(url) = raw_url {
        format!("{}\n[🔍 View Raw JSON]({})", desc_base, url)
    } else {
        desc_base
    };

    let mut embed = json!({
        "title": if is_enabled { "🔗 Account Linked Successfully" } else { "🔌 Account Unlinked" },
        "description": truncate(&description, 4096),
        "color": color,
        "fields": fields,
        "footer": { "text": "Midtrans • Binding Legacy" },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if let Some(url) = raw_url {
        embed["url"] = json!(url);
    }

    let mut payload = json!({ "embeds": [embed] });
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        payload["content"] = json!(m);
    }
    attach_raw_button(&mut payload, raw_url);

    DiscordBuildResult {
        payload,
        status_info: None,
    }
}

pub fn build_bi_snap_embed(
    notification: &serde_json::Value,
    headers: &[(String, String)],
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> DiscordBuildResult {
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
        create_field("🏷️ Order / Partner Ref", &format!("`{}`", order_id), true),
        create_field("💰 Amount", &format!("**{}**", formatted_amount), true),
        create_field("📌 Status", &status_info.badge, true),
    ];

    if let Some(qris) = notification.get("additionalInfo").and_then(|a| a.get("qris")) {
        let issuer = qris.get("issuerName").and_then(|v| v.as_str()).unwrap_or("N/A").to_uppercase();
        let acquirer = qris.get("acquirerName").and_then(|v| v.as_str()).unwrap_or("N/A").to_uppercase();
        let trx_type = qris.get("transactionType").and_then(|v| v.as_str()).unwrap_or("N/A");
        fields.push(create_field(
            "📱 QRIS Details",
            &format!("Issuer: **{}**\nAcquirer: **{}**\nType: `{}`", issuer, acquirer, trx_type),
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
            fields.push(create_field("💳 Payment Option", &details.join(", "), true));
        }
    }

    if let Some(va) = notification.get("virtualAccountNo").and_then(|v| v.as_str()) {
        let name = notification.get("virtualAccountName").and_then(|v| v.as_str()).unwrap_or("N/A");
        fields.push(create_field(
            "🔢 Virtual Account",
            &format!("No: `{}`\nName: {}", va, name),
            true,
        ));
    }

    if let Some(orig_ref) = notification.get("originalReferenceNo").and_then(|v| v.as_str()) {
        if orig_ref != order_id {
            fields.push(create_field("🆔 Midtrans Ref", &format!("`{}`", orig_ref), true));
        }
    }

    let partner_id = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-partner-id")).map(|(_, v)| v.as_str());
    let external_id = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-external-id")).map(|(_, v)| v.as_str());
    if partner_id.is_some() || external_id.is_some() {
        fields.push(create_field(
            "🔐 BI SNAP Headers",
            &format!("Partner: `{}` | Ext ID: `{}`", partner_id.unwrap_or("N/A"), external_id.unwrap_or("N/A")),
            false,
        ));
    }

    let desc_base = format!("BI SNAP Open API notification for **{}**", order_id);
    let description = if let Some(url) = raw_url {
        format!("{}\n[🔍 View Raw JSON]({})", desc_base, url)
    } else {
        desc_base
    };

    let mut embed = json!({
        "title": truncate(status_info.title, 256),
        "description": truncate(&description, 4096),
        "color": status_info.color,
        "fields": fields,
        "footer": { "text": "Bank Indonesia SNAP • Midtrans Open API" },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if let Some(url) = raw_url {
        embed["url"] = json!(url);
    }

    let mut payload = json!({ "embeds": [embed] });
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        payload["content"] = json!(m);
    }
    attach_raw_button(&mut payload, raw_url);

    DiscordBuildResult {
        payload,
        status_info: Some(status_info),
    }
}

pub fn build_iris_embed(
    notification: &serde_json::Value,
    _headers: &[(String, String)],
    mention: Option<&str>,
    raw_url: Option<&str>,
) -> DiscordBuildResult {
    let status = notification.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
    let status_info = get_iris_status_details(status);

    let ref_no = notification.get("reference_no")
        .or_else(|| notification.get("payout_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A");

    let amount_str = notification.get("amount").and_then(|v| {
        if v.is_string() { v.as_str().map(|s| s.to_string()) }
        else if let Some(n) = v.as_f64() { Some(format!("{:.2}", n)) }
        else if let Some(i) = v.as_i64() { Some(i.to_string()) }
        else { None }
    });
    let formatted_amount = format_currency(amount_str.as_deref(), Some("IDR"));

    let mut fields = vec![
        create_field("🏷️ Reference No", &format!("`{}`", ref_no), true),
        create_field("💰 Amount", &format!("**{}**", formatted_amount), true),
        create_field("📌 Status", &status_info.badge, true),
    ];

    let bank_code = notification.get("bank_code").and_then(|v| v.as_str());
    let account = notification.get("account").and_then(|v| v.as_str());
    let bene_name = notification.get("beneficiary_name").and_then(|v| v.as_str());

    if bank_code.is_some() || account.is_some() || bene_name.is_some() {
        let bank = bank_code.unwrap_or("Bank").to_uppercase();
        let acc_str = account.map(|a| format!("`{}`", a)).unwrap_or_default();
        let name_str = bene_name.map(|n| format!(" ({})", n)).unwrap_or_default();
        let val = format!("{} {}{}", bank, acc_str, name_str).trim().to_string();
        fields.push(create_field("🏦 Beneficiary", &val, true));
    }

    if let Some(notes) = notification.get("notes").and_then(|v| v.as_str()) {
        fields.push(create_field("📝 Notes", notes, true));
    }

    if let Some(err) = notification.get("error_message").and_then(|v| v.as_str()) {
        fields.push(create_field("⚠️ Error Message", &format!("`{}`", err), false));
    }

    if let Some(time) = notification.get("updated_at").or_else(|| notification.get("created_at")).and_then(|v| v.as_str()) {
        fields.push(create_field("🕒 Timestamp", &format!("`{}`", time), true));
    }

    let desc_base = format!("[IRIS Disbursement] Update for reference **{}**", ref_no);
    let description = if let Some(url) = raw_url {
        format!("{}\n[🔍 View Raw JSON]({})", desc_base, url)
    } else {
        desc_base
    };

    let mut embed = json!({
        "title": truncate(status_info.title, 256),
        "description": truncate(&description, 4096),
        "color": status_info.color,
        "fields": fields,
        "footer": { "text": "Midtrans IRIS • Disbursement" },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if let Some(url) = raw_url {
        embed["url"] = json!(url);
    }

    let mut payload = json!({ "embeds": [embed] });
    if let Some(m) = mention.filter(|m| !m.trim().is_empty()) {
        payload["content"] = json!(m);
    }
    attach_raw_button(&mut payload, raw_url);

    DiscordBuildResult {
        payload,
        status_info: Some(status_info),
    }
}

pub async fn send_discord_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    if webhook_url.trim().is_empty() {
        return Ok(());
    }

    let url_to_send = if payload.get("components").is_some() && !webhook_url.contains("with_components=") {
        if webhook_url.contains('?') {
            format!("{}&with_components=true", webhook_url)
        } else {
            format!("{}?with_components=true", webhook_url)
        }
    } else {
        webhook_url.to_string()
    };

    let res = client.post(&url_to_send)
        .json(payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Discord network error: {}", e))?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(format!("Discord API HTTP {}: {}", status, body));
    }

    Ok(())
}
