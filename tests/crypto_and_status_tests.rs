use midtrans_webhooker::midtrans::{
    format_currency, get_status_details, get_bi_snap_status_details,
    get_iris_status_details, verify_midtrans_signature, verify_bi_snap_signature,
    verify_iris_signature, load_public_key,
};
use midtrans_webhooker::lark::generate_lark_sign;
use serde_json::json;
use sha2::{Sha512, Digest};

#[test]
fn test_currency_formatting() {
    assert_eq!(format_currency(Some("150000"), Some("IDR")), "Rp 150.000");
    assert_eq!(format_currency(Some("150000.50"), Some("IDR")), "Rp 150.000,50");
    assert_eq!(format_currency(Some("150000.00"), Some("IDR")), "Rp 150.000");
    assert_eq!(format_currency(None, None), "N/A");
}

#[test]
fn test_legacy_status_mapping() {
    let auth = json!({ "transaction_status": "authorize" });
    let auth_info = get_status_details(&auth);
    assert_eq!(auth_info.badge, "🟡 Authorize (Must be Captured)");
    assert!(auth_info.is_pending);

    let capture = json!({ "transaction_status": "capture", "fraud_status": "accept" });
    let cap_info = get_status_details(&capture);
    assert_eq!(cap_info.badge, "🟢 Capture / Success");
    assert!(cap_info.is_success);

    let chargeback = json!({ "transaction_status": "chargeback" });
    let cb_info = get_status_details(&chargeback);
    assert_eq!(cb_info.badge, "🔴 Chargeback");
    assert!(cb_info.is_failed);
}

#[test]
fn test_bi_snap_status_mapping() {
    let s00 = get_bi_snap_status_details("00", None);
    assert_eq!(s00.badge, "🟢 Success (00)");
    assert!(s00.is_success);

    let s03 = get_bi_snap_status_details("03", None);
    assert_eq!(s03.badge, "🟡 Pending (03)");
    assert!(s03.is_pending);

    let s06 = get_bi_snap_status_details("06", None);
    assert_eq!(s06.badge, "🔴 Failure (06)");
    assert!(s06.is_failed);
}

#[test]
fn test_iris_status_mapping() {
    let completed = get_iris_status_details("completed");
    assert_eq!(completed.badge, "🟢 Completed (Disbursed)");
    assert!(completed.is_success);

    let processed = get_iris_status_details("processed");
    assert_eq!(processed.badge, "🔵 Processed (Processing at Bank)");
    assert!(processed.is_pending);

    let approved = get_iris_status_details("approved");
    assert_eq!(approved.badge, "🟡 Approved (Pending Processing)");
    assert_eq!(approved.color, 0xF39C12);
    assert!(approved.is_pending);
}

#[test]
fn test_legacy_signature_verification() {
    let server_key = "SB-Mid-server-TEST12345";
    let order_id = "ORDER-101";
    let status_code = "200";
    let gross_amount = "150000.00";

    // SHA512(order_id + status_code + gross_amount + ServerKey)
    let raw = format!("{}{}{}{}", order_id, status_code, gross_amount, server_key);
    let mut hasher = Sha512::new();
    hasher.update(raw.as_bytes());
    let sig = hex::encode(hasher.finalize());

    let payload = json!({
        "order_id": order_id,
        "status_code": status_code,
        "gross_amount": gross_amount,
        "signature_key": sig
    });

    let res = verify_midtrans_signature(&payload, &[server_key.to_string()]);
    assert!(res.is_ok());
}

#[test]
fn test_iris_signature_verification() {
    let merchant_key = "iris-merchant-key-secret";
    let payload = json!({
        "reference_no": "REF-999",
        "status": "completed",
        "amount": "500000"
    });
    let raw_json = serde_json::to_string(&payload).unwrap();

    let string_to_sign = format!("{}{}", raw_json, merchant_key);
    let mut hasher = Sha512::new();
    hasher.update(string_to_sign.as_bytes());
    let sig = hex::encode(hasher.finalize());

    let res = verify_iris_signature(
        raw_json.as_bytes(),
        Some(&payload),
        Some(&sig),
        merchant_key,
    );
    assert!(res.is_ok());
}

#[test]
fn test_lark_signature_generation() {
    let secret = "lark-bot-secret-xyz";
    let timestamp = 1729000000;
    let sign = generate_lark_sign(secret, timestamp);
    assert!(sign.is_some());
}
