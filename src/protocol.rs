use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{macros::format_description, OffsetDateTime, PrimitiveDateTime};

pub const BUNDLE_ID: &str = "org.tknw.punctual";
pub const TOPIC: &str = "org.tknw.punctual.push-type.liveactivity";
pub const SWIFT_EPOCH: i64 = 978307200;
pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
    pub retry_after: Option<u32>,
}
impl ApiError {
    pub fn new(status: u16, code: &str) -> Self {
        Self {
            status,
            code: code.into(),
            message: code.replace('_', " "),
            details: json!({}),
            retry_after: None,
        }
    }
    pub fn rate(code: &str) -> Self {
        Self {
            retry_after: Some(60),
            ..Self::new(429, code)
        }
    }
    pub fn auth() -> Self {
        Self::new(401, "INVALID_AUTHENTICATION")
    }
    pub fn invalid() -> Self {
        Self::new(400, "INVALID_REQUEST")
    }
}
pub fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
pub fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(hash(bytes))
}
pub fn b64(value: &str, max: usize) -> ApiResult<Vec<u8>> {
    if value.len() > max {
        return Err(ApiError::invalid());
    }
    let bytes = STANDARD.decode(value).map_err(|_| ApiError::invalid())?;
    if STANDARD.encode(&bytes) != value {
        return Err(ApiError::invalid());
    }
    Ok(bytes)
}
pub fn key_id(value: &str) -> ApiResult<Vec<u8>> {
    let bytes = b64(value, 44)?;
    if bytes.len() != 32 {
        return Err(ApiError::invalid());
    }
    Ok(bytes)
}
pub fn uuid(value: &str) -> ApiResult<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
    {
        return Err(ApiError::invalid());
    }
    Ok(())
}
pub fn revision(value: &str) -> ApiResult<u64> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ApiError::invalid());
    }
    value.parse().map_err(|_| ApiError::invalid())
}
pub fn token(value: &str) -> ApiResult<()> {
    if !(2..=4096).contains(&value.len())
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(ApiError::invalid());
    }
    Ok(())
}
pub fn date(value: &str) -> ApiResult<i64> {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    if value.len() != 20 {
        return Err(ApiError::invalid());
    }
    let d = PrimitiveDateTime::parse(value, &format).map_err(|_| ApiError::invalid())?;
    let ts = d.assume_utc().unix_timestamp();
    if ts < 0 || d.format(&format).map_err(|_| ApiError::invalid())? != value {
        return Err(ApiError::invalid());
    }
    Ok(ts)
}
pub fn iso(ts: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ts)
        .expect("validated timestamp")
        .format(&format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .expect("timestamp format")
}
pub fn signing_message(
    env: &str,
    key: &str,
    id: &str,
    challenge: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    format!(
        "punctual-api-v1\n{env}\n{key}\n{id}\n{challenge}\n{method}\n{path}\n{}\n",
        hash_hex(body)
    )
}
pub fn json_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|_| ApiError::invalid())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutJob {
    pub revision: String,
    pub push_token: String,
    pub starts_at: String,
    pub notification_at: String,
    pub ends_at: String,
    pub activity_ends_at: String,
    pub content_state_version: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timing {
    pub start: i64,
    pub notification: i64,
    pub end: i64,
    pub activity_end: i64,
}
impl PutJob {
    pub fn validate(&self) -> ApiResult<Timing> {
        revision(&self.revision)?;
        token(&self.push_token)?;
        let t = Timing {
            start: date(&self.starts_at)?,
            notification: date(&self.notification_at)?,
            end: date(&self.ends_at)?,
            activity_end: date(&self.activity_ends_at)?,
        };
        if self.content_state_version != 1
            || t.start >= t.end
            || t.notification < t.start
            || t.notification > t.end
            || t.activity_end != t.end.min(t.start + 28800)
        {
            return Err(ApiError::invalid());
        }
        Ok(t)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchToken {
    pub revision: String,
    pub push_token: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub revision: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeRequest {
    pub purpose: String,
    pub key_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationRequest {
    pub key_id: String,
    pub challenge_id: String,
    pub attestation_object: String,
}
