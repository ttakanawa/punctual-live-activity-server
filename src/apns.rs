use crate::{job::Outcome, protocol::*};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use serde_json::{json, Value};

pub fn payload(t: &Timing, now: i64) -> Value {
    json!({"aps": { "timestamp":now, "event":"end", "dismissal-date":now-1,
        "content-state": { "title":"", "startDate":t.start-SWIFT_EPOCH,
            "endDate":t.end-SWIFT_EPOCH, "activityEndDate":t.activity_end-SWIFT_EPOCH,
            "notificationDate":t.notification-SWIFT_EPOCH, "displayVersion":8,
            "notificationHasOccurred":true } }})
}
pub fn jwt(pem: &str, key_id: &str, team_id: &str, now: i64) -> Result<String, &'static str> {
    if key_id.len() != 10
        || team_id.len() != 10
        || !key_id
            .bytes()
            .chain(team_id.bytes())
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Err("INVALID_APNS_CONFIGURATION");
    }
    let key = SigningKey::from_pkcs8_pem(pem).map_err(|_| "INVALID_APNS_PRIVATE_KEY")?;
    let header = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":key_id}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(json!({"iss":team_id,"iat":now}).to_string());
    let input = format!("{header}.{claims}");
    let signature: Signature = key.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}
pub fn retry_after(value: Option<&str>, now: i64) -> Option<i64> {
    let s = value?;
    if let Ok(delay) = s.parse::<u32>() {
        return Some(now + i64::from(delay));
    }
    httpdate::parse_http_date(s)
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}
pub fn classify(status: u16, reason: &str, after: Option<i64>) -> Outcome {
    if status == 200 {
        return Outcome::Accepted;
    }
    // Restrict stored errors to documented machine codes; never persist response text.
    let safe = match reason {
        "BadDeviceToken"
        | "DeviceTokenNotForTopic"
        | "Unregistered"
        | "ExpiredProviderToken"
        | "InvalidProviderToken"
        | "BadTopic"
        | "TopicDisallowed"
        | "Forbidden"
        | "MissingProviderToken"
        | "TooManyRequests"
        | "TooManyProviderTokenUpdates"
        | "InternalServerError"
        | "ServiceUnavailable"
        | "Shutdown"
        | "BadCertificate"
        | "BadCertificateEnvironment"
        | "PayloadTooLarge" => reason,
        _ => "APNS_REJECTED",
    }
    .to_string();
    if status == 429 || status >= 500 {
        Outcome::Retry(safe, after, false)
    } else if ["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"].contains(&reason) {
        Outcome::TokenRejected(safe)
    } else {
        Outcome::Configuration(safe)
    }
}
