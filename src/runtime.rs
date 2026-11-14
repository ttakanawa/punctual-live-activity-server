use crate::{
    apns,
    attest::{self, Policy, Registration},
    job::*,
    protocol::*,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{
    future::{select, Either},
    StreamExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cell::RefCell, rc::Rc, time::Duration};
use worker::*;

fn now() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}
fn random_id() -> String {
    random_uuid()
}
use wasm_bindgen::prelude::wasm_bindgen;
#[wasm_bindgen(
    inline_js = "export function random_uuid(){return crypto.randomUUID()} export function random_bytes(){return crypto.getRandomValues(new Uint8Array(32))}"
)]
extern "C" {
    fn random_uuid() -> String;
    fn random_bytes() -> Vec<u8>;
}
fn variable(env: &Env, name: &str) -> String {
    env.var(name).map(|v| v.to_string()).unwrap_or_default()
}
fn limit(env: &Env, name: &str, default: u32) -> u32 {
    variable(env, name)
        .parse()
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(default)
}
fn policy(env: &Env) -> Result<Policy> {
    let environment = variable(env, "APP_ATTEST_ENVIRONMENT");
    let deployment = variable(env, "DEPLOYMENT_ENVIRONMENT");
    let prefix = variable(env, "APPLE_APP_ID_PREFIX");
    if !["development", "production"].contains(&environment.as_str())
        || !["development", "production"].contains(&deployment.as_str())
        || prefix.len() != 10
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(Error::RustError("INVALID_ATTEST_CONFIGURATION".into()));
    }
    let categories = variable(env, "ATTEST_ALLOWED_CATEGORIES");
    let categories = if categories.is_empty() {
        if environment == "production" {
            vec![2, 4]
        } else {
            vec![3]
        }
    } else {
        categories
            .split(',')
            .map(str::parse)
            .collect::<std::result::Result<Vec<u32>, _>>()
            .map_err(|_| Error::RustError("INVALID_ATTEST_CONFIGURATION".into()))?
    };
    if categories.iter().any(|n| ![2, 3, 4, 5].contains(n)) {
        return Err(Error::RustError("INVALID_ATTEST_CONFIGURATION".into()));
    }
    Ok(Policy {
        environment,
        app_id: format!("{prefix}.{BUNDLE_ID}"),
        allowed_categories: categories,
        allowed_versions: variable(env, "ATTEST_ALLOWED_BUNDLE_VERSIONS")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    })
}
fn response(result: ApiResult<(u16, Value)>) -> Result<Response> {
    let (status, value, retry) = match result {
        Ok((s, v)) => (s, v, None),
        Err(e) => (
            e.status,
            json!({"error":{"code":e.code,"message":e.message,"requestId":random_id(),"details":e.details}}),
            e.retry_after,
        ),
    };
    let mut r = Response::from_json(&value)?.with_status(status);
    r.headers_mut().set("Cache-Control", "no-store")?;
    if let Some(retry) = retry {
        r.headers_mut().set("Retry-After", &retry.to_string())?;
    }
    Ok(r)
}
fn unavailable() -> ApiError {
    ApiError {
        retry_after: Some(5),
        ..ApiError::new(503, "SERVICE_UNAVAILABLE")
    }
}
async fn bounded(req: &mut Request, max: usize) -> ApiResult<Vec<u8>> {
    if req
        .headers()
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|s| s.parse::<usize>().ok())
        .is_some_and(|n| n > max)
    {
        return Err(ApiError::new(413, "BODY_TOO_LARGE"));
    }
    let mut out = Vec::new();
    // A bodyless GET still signs exactly zero bytes.
    let Ok(mut stream) = req.stream() else {
        return Ok(out);
    };
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::invalid())?;
        if out.len() + chunk.len() > max {
            return Err(ApiError::new(413, "BODY_TOO_LARGE"));
        }
        out.extend(chunk);
    }
    Ok(out)
}
fn route(method: &str, path: &str) -> ApiResult<Option<String>> {
    if ["/v1/auth/challenges", "/v1/auth/attestations"].contains(&path) && method == "POST" {
        return Ok(None);
    }
    if let Some(rest) = path.strip_prefix("/v1/end-jobs/") {
        let id = rest.strip_suffix("/push-token").unwrap_or(rest);
        uuid(id)?;
        if (rest == id && ["GET", "PUT", "DELETE"].contains(&method))
            || (rest != id && method == "PATCH")
        {
            return Ok(Some(id.into()));
        }
    }
    Err(ApiError::new(404, "NOT_FOUND"))
}
#[event(fetch)]
pub async fn main(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let result = async {
        let url = req.url().map_err(|_| ApiError::invalid())?;
        if url.query().is_some() || url.path().contains('%') {
            return Err(ApiError::invalid());
        }
        let method = req.method().to_string();
        let path = url.path();
        let job = route(&method, path)?;
        if job.is_none() {
            let ip = req
                .headers()
                .get("CF-Connecting-IP")
                .map_err(|_| unavailable())?
                .unwrap_or_else(|| "local".into());
            let limiter = env.rate_limiter("AUTH_IP").map_err(|_| unavailable())?;
            if !limiter
                .limit(hash_hex(ip.as_bytes()))
                .await
                .map_err(|_| unavailable())?
                .success
            {
                return Err(ApiError::rate("IP_AUTH_RATE_LIMIT"));
            }
        }
        let bytes = bounded(
            &mut req,
            if path.ends_with("/attestations") {
                128 * 1024
            } else {
                8192
            },
        )
        .await?;
        if method == "GET" && !bytes.is_empty() {
            return Err(ApiError::invalid());
        }
        if method != "GET"
            && req
                .headers()
                .get("Content-Type")
                .map_err(|_| ApiError::invalid())?
                .is_none_or(|s| s.split(';').next().unwrap_or("").trim() != "application/json")
        {
            return Err(ApiError::invalid());
        }
        let key = match path {
            "/v1/auth/challenges" => {
                let c: ChallengeRequest = json_body(&bytes)?;
                if !["attestation", "assertion"].contains(&c.purpose.as_str()) {
                    return Err(ApiError::invalid());
                }
                c.key_id
            }
            "/v1/auth/attestations" => {
                let a: AttestationRequest = json_body(&bytes)?;
                uuid(&a.challenge_id)?;
                a.key_id
            }
            _ => req
                .headers()
                .get("X-App-Attest-Key-Id")
                .map_err(|_| ApiError::auth())?
                .ok_or_else(ApiError::auth)?,
        };
        key_id(&key)?;
        let deployment = variable(&env, "DEPLOYMENT_ENVIRONMENT");
        policy(&env).map_err(|_| unavailable())?;
        let namespace = env
            .durable_object("INSTALLATIONS")
            .map_err(|_| unavailable())?;
        let stub = namespace
            .id_from_name(&format!("{deployment}:{key}"))
            .and_then(|id| id.get_stub())
            .map_err(|_| unavailable())?;
        let mut init = RequestInit::new();
        init.with_method(req.method())
            .with_body(if bytes.is_empty() {
                None
            } else {
                Some(js_sys::Uint8Array::from(bytes.as_slice()).into())
            });
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|_| unavailable())?;
        headers
            .set("X-App-Attest-Key-Id", &key)
            .map_err(|_| unavailable())?;
        for name in ["X-App-Attest-Challenge-Id", "X-App-Attest-Assertion"] {
            if let Some(v) = req.headers().get(name).map_err(|_| ApiError::auth())? {
                headers.set(name, &v).map_err(|_| ApiError::auth())?;
            }
        }
        init.with_headers(headers);
        let internal = Request::new_with_init(&format!("https://installation{path}"), &init)
            .map_err(|_| unavailable())?;
        stub.fetch_with_request(internal)
            .await
            .map_err(|_| unavailable())
    }
    .await;
    match result {
        Ok(r) => Ok(r),
        Err(e) => response(Err(e)),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Challenge {
    id: String,
    value: String,
    purpose: String,
    expires: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Bucket {
    minute: i64,
    count: u32,
}
impl Bucket {
    fn take(&mut self, now: i64, max: u32) -> bool {
        if self.minute != now / 60 {
            self.minute = now / 60;
            self.count = 0;
        }
        if self.count >= max {
            return false;
        }
        self.count += 1;
        true
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Meta {
    key: String,
    deployment: String,
    identity: Option<String>,
    registration: Option<Registration>,
    fingerprint: Option<String>,
    counter: u32,
    challenges: Vec<Challenge>,
    issue: Bucket,
    requests: Bucket,
    markers: u32,
    active: u32,
}
async fn tx_get<T: serde::de::DeserializeOwned>(tx: &Transaction, key: &str) -> Result<Option<T>> {
    let map = tx.get_multiple(vec![key]).await?;
    let value = map.get(&key.into());
    if value.is_undefined() {
        Ok(None)
    } else {
        Ok(Some(serde_wasm_bindgen::from_value(value)?))
    }
}
fn queue_key(due: i64, id: &str) -> String {
    format!("due/{due:012}/{id}")
}
async fn save_job(tx: &Transaction, meta: &mut Meta, old: Option<&Job>, job: &Job) -> Result<()> {
    if let Some(old_due) = old.and_then(|j| j.due) {
        tx.delete(&queue_key(old_due, &job.id)).await?;
    }
    if let Some(due) = job.due {
        tx.put(&queue_key(due, &job.id), &job.id).await?;
    }
    if old.is_none() {
        meta.markers += 1;
    }
    let was_active = old.is_some_and(|j| !j.status.terminal());
    let is_active = !job.status.terminal();
    if was_active && !is_active {
        meta.active -= 1;
    }
    if !was_active && is_active {
        meta.active += 1;
    }
    tx.put(&format!("job/{}", job.id), job).await
}
#[durable_object]
pub struct Installation {
    state: State,
    env: Env,
    provider: RefCell<Option<(i64, String)>>,
}
impl Installation {
    // Persist a recovery wakeup before any transaction, so a crash between its commit
    // and normal alarm selection cannot strand work. This never delays an existing alarm.
    async fn watchdog(&self) -> Result<()> {
        let storage = self.state.storage();
        let due = now() * 1000 + 1000;
        if storage.get_alarm().await?.is_none_or(|a| a > due) {
            storage.set_alarm(due).await?;
        }
        Ok(())
    }
    async fn rearm(&self) -> Result<()> {
        let storage = self.state.storage();
        let index = storage
            .list_with_options(ListOptions::new().prefix("due/").limit(1))
            .await?;
        let meta: Option<Meta> = storage.get("meta").await?;
        let next_job = index
            .keys()
            .next()?
            .value()
            .as_string()
            .and_then(|s| s.split('/').nth(1).and_then(|s| s.parse::<i64>().ok()));
        let next_challenge = meta.and_then(|m| m.challenges.iter().map(|c| c.expires).min());
        if let Some(due) = next_job.into_iter().chain(next_challenge).min() {
            storage
                .set_alarm((due * 1000).max(now() * 1000 + 100))
                .await?;
        } else {
            storage.delete_alarm().await?;
        }
        Ok(())
    }
    async fn request(&self, mut req: Request) -> Result<ApiResult<(u16, Value)>> {
        let url = req.url()?;
        let method = req.method().to_string();
        let path = url.path().to_string();
        let key = req
            .headers()
            .get("X-App-Attest-Key-Id")?
            .unwrap_or_default();
        let body = bounded(
            &mut req,
            if path.ends_with("/attestations") {
                128 * 1024
            } else {
                8192
            },
        )
        .await;
        let body = match body {
            Ok(b) => b,
            Err(e) => return Ok(Err(e)),
        };
        let job_id = match route(&method, &path) {
            Ok(id) => id,
            Err(e) => return Ok(Err(e)),
        };
        let policy = policy(&self.env)?;
        let deployment = variable(&self.env, "DEPLOYMENT_ENVIRONMENT");
        let challenge_id = req
            .headers()
            .get("X-App-Attest-Challenge-Id")?
            .unwrap_or_default();
        let assertion = req
            .headers()
            .get("X-App-Attest-Assertion")?
            .unwrap_or_default();
        let issue_limit = limit(&self.env, "KEY_ISSUE_LIMIT", 30);
        let request_limit = limit(&self.env, "AUTH_REQUEST_LIMIT", 120);
        let active_limit = limit(&self.env, "ACTIVE_JOB_LIMIT", 16);
        let marker_limit = limit(&self.env, "MARKER_LIMIT", 100000);
        // Unknown rejected requests must not create persistent metadata or an Alarm.
        if self.state.storage().get::<Meta>("meta").await?.is_none() {
            let may_create = path == "/v1/auth/challenges"
                && json_body::<ChallengeRequest>(&body).is_ok_and(|c| c.purpose == "attestation");
            if !may_create {
                return Ok(Err(ApiError::auth()));
            }
        }
        self.watchdog().await?;
        let output = Rc::new(RefCell::new(Err(unavailable())));
        let result = output.clone();
        self.state.storage().transaction(move |tx| async move {
            let time = now();
            let stored:Option<Meta> = tx_get(&tx,"meta").await?;
            let had_metadata=stored.is_some();
            let mut meta:Meta = stored.unwrap_or_default();
            meta.challenges.retain(|c|c.expires > time);
            if meta.key.is_empty() { meta.key=key.clone(); meta.deployment=deployment.clone(); }
            let r = async {
                if meta.key != key || meta.deployment != deployment { return Err(ApiError::auth()); }
                if meta.registration.as_ref().is_some_and(|r|r.environment!=policy.environment || r.app_id!=policy.app_id) { return Err(ApiError::auth()); }
                key_id(&key)?;
                if job_id.is_none() && !meta.issue.take(time,issue_limit) { return Err(ApiError::rate("KEY_ISSUE_RATE_LIMIT")); }
                if path == "/v1/auth/challenges" {
                    let input:ChallengeRequest = json_body(&body)?;
                    if input.key_id != key || !["attestation","assertion"].contains(&input.purpose.as_str()) { return Err(ApiError::invalid()); }
                    if input.purpose == "assertion" && meta.registration.is_none() { return Err(ApiError::auth()); }
                    if meta.challenges.len() >= 8 { return Err(ApiError::rate("PENDING_CHALLENGE_LIMIT")); }
                    let c = Challenge { id:random_id(), value:STANDARD.encode(random_bytes()), purpose:input.purpose, expires:time+300 };
                    let view = json!({"challengeId":c.id,"challenge":c.value,"expiresAt":iso(c.expires)});
                    meta.challenges.push(c);
                    return Ok((201,view));
                }
                if path == "/v1/auth/attestations" {
                    let input:AttestationRequest = json_body(&body)?;
                    if input.key_id != key { return Err(ApiError::auth()); }
                    uuid(&input.challenge_id)?;
                    // Canonical registration fingerprint survives challenge cleanup and counter advances.
                    let fingerprint = hash_hex(format!("{deployment}\n{key}\n{}\n{}",input.challenge_id,input.attestation_object).as_bytes());
                    if meta.registration.is_some() {
                        if meta.fingerprint.as_deref() != Some(&fingerprint) { return Err(ApiError::auth()); }
                        return Ok((200,json!({"installationId":meta.identity,"authScheme":"app-attest-v1"})));
                    }
                    let c = meta.challenges.iter().find(|c|c.id == input.challenge_id && c.purpose == "attestation").ok_or_else(ApiError::auth)?;
                    let registration = attest::verify_attestation(&b64(&input.attestation_object,175000)?,&key_id(&key)?,&b64(&c.value,44)?,&policy,time)?;
                    meta.challenges.retain(|c|c.id != input.challenge_id);
                    meta.registration=Some(registration); meta.fingerprint=Some(fingerprint); meta.identity=Some(random_id());
                    return Ok((201,json!({"installationId":meta.identity,"authScheme":"app-attest-v1"})));
                }
                let registration = meta.registration.as_ref().ok_or_else(ApiError::auth)?;
                uuid(&challenge_id).map_err(|_|ApiError::auth())?;
                let c = meta.challenges.iter().find(|c|c.id == challenge_id && c.purpose == "assertion").ok_or_else(ApiError::auth)?;
                let message = signing_message(&deployment,&key,&challenge_id,&c.value,&method,&path,&body);
                let counter = attest::verify_assertion(&b64(&assertion,32768).map_err(|_|ApiError::auth())?,&registration.public_key,&hash(message.as_bytes()),&policy,meta.counter)?;
                // No external I/O occurs between this recheck and durable mutation.
                meta.counter=counter; meta.challenges.retain(|c|c.id != challenge_id);
                if !meta.requests.take(time,request_limit) { return Err(ApiError::rate("AUTH_REQUEST_RATE_LIMIT")); }
                let id = job_id.as_deref().ok_or_else(ApiError::invalid)?;
                let old:Option<Job> = tx_get(&tx,&format!("job/{id}")).await.map_err(|_|unavailable())?;
                if method == "GET" { return old.map(|j|(200,j.view())).ok_or_else(||ApiError::new(404,"NOT_FOUND")); }
                let mutation = Mutation::parse(&method,&body)?;
                if old.is_none() {
                    if method == "PATCH" { return Err(ApiError::new(404,"NOT_FOUND")); }
                    if meta.markers >= marker_limit { return Err(ApiError::rate("JOB_MARKER_CAPACITY")); }
                    if method == "PUT" && meta.active >= active_limit { return Err(ApiError::rate("ACTIVE_JOB_CAPACITY")); }
                }
                let mut job = old.clone().unwrap_or_else(||Job::new(id));
                let applied = job.apply(&method,&hash_hex(&body),mutation,time);
                if applied.is_ok() || applied.as_ref().is_err_and(|e|e.code == "ACTIVITY_LIFETIME_EXCEEDED") {
                    save_job(&tx,&mut meta,old.as_ref(),&job).await.map_err(|_| { let _=tx.rollback(); unavailable() })?;
                }
                applied?;
                Ok((200,job.view()))
            }.await;
            // Persist consumed authentication even when a valid signed operation fails.
            if had_metadata || r.is_ok() { tx.put("meta",&meta).await?; }
            *result.borrow_mut()=r;
            Ok(())
        }).await?;
        self.rearm().await?;
        let value = output.borrow().clone();
        Ok(value)
    }
    fn provider_token(
        &self,
        time: i64,
        force_fresh: bool,
    ) -> std::result::Result<String, &'static str> {
        let window = apns::provider_issued_at(time);
        if let Some((issued, token)) = self
            .provider
            .borrow()
            .as_ref()
            .filter(|(issued, _)| !force_fresh && *issued >= window && time - *issued < 1200)
        {
            let _ = issued;
            return Ok(token.clone());
        }
        let private = self
            .env
            .secret("APNS_PRIVATE_KEY")
            .map_err(|_| "MISSING_APNS_PRIVATE_KEY")?
            .to_string();
        let issued = if force_fresh { time } else { window };
        let token = apns::jwt(
            &private,
            &variable(&self.env, "APNS_KEY_ID"),
            &variable(&self.env, "APPLE_TEAM_ID"),
            issued,
        )?;
        *self.provider.borrow_mut() = Some((issued, token.clone()));
        Ok(token)
    }
    async fn deliver(&self, token: &str, timing: &Timing, attempt_id: &str) -> Outcome {
        let environment = variable(&self.env, "APNS_ENVIRONMENT");
        let host = match environment.as_str() {
            "sandbox" => "api.sandbox.push.apple.com",
            "production" => "api.push.apple.com",
            _ => return Outcome::Configuration("INVALID_APNS_ENVIRONMENT".into()),
        };
        let jwt = match self.provider_token(now(), false) {
            Ok(t) => t,
            Err(e) => return Outcome::Configuration(e.into()),
        };
        let abort = AbortController::default();
        let signal = abort.signal();
        let call = async {
            let headers = Headers::new();
            for (k, v) in [
                ("authorization", format!("bearer {jwt}")),
                ("apns-topic", TOPIC.into()),
                ("apns-push-type", "liveactivity".into()),
                ("apns-priority", "10".into()),
                ("apns-expiration", (timing.start + 43200).to_string()),
                ("apns-id", attempt_id.into()),
                ("content-type", "application/json".into()),
            ] {
                headers.set(k, &v)?;
            }
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(apns::payload(timing, now()).to_string().into()));
            let req = Request::new_with_init(&format!("https://{host}/3/device/{token}"), &init)?;
            let mut res = Fetch::Request(req).send_with_signal(&signal).await?;
            let status = res.status_code();
            let after = apns::retry_after(res.headers().get("retry-after")?.as_deref(), now());
            let reason = res
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v["reason"].as_str().map(str::to_string))
                .unwrap_or_default();
            Ok::<_, Error>((status, reason, after))
        };
        // Timeout also bounds response body reads; unknown outcomes stay retryable.
        let result = select(
            Box::pin(call),
            Box::pin(Delay::from(Duration::from_secs(20))),
        )
        .await;
        match result {
            Either::Left((Ok((status, reason, after)), _)) => {
                if reason == "ExpiredProviderToken" {
                    *self.provider.borrow_mut() = None;
                    if let Err(error) = self.provider_token(now(), true) {
                        return Outcome::Configuration(error.into());
                    }
                    Outcome::Retry("PROVIDER_TOKEN_REFRESH".into(), after, false)
                } else {
                    apns::classify(status, &reason, after)
                }
            }
            _ => {
                abort.abort();
                Outcome::Retry("NETWORK_UNKNOWN".into(), None, true)
            }
        }
    }
    async fn process_alarm(&self) -> Result<()> {
        self.watchdog().await?;
        for _ in 0..32 {
            let entries = self
                .state
                .storage()
                .list_with_options(ListOptions::new().prefix("due/").limit(1))
                .await?;
            let key = entries.keys().next()?.value().as_string();
            let Some(key) = key else {
                break;
            };
            let parts: Vec<_> = key.split('/').collect();
            if parts.len() != 3 || parts[1].parse::<i64>().unwrap_or(i64::MAX) > now() {
                break;
            }
            let id = parts[2].to_string();
            let attempt_id = random_id();
            let attempt_for_tx = attempt_id.clone();
            let dispatch = Rc::new(RefCell::new(None));
            let output = dispatch.clone();
            self.state
                .storage()
                .transaction(move |tx| async move {
                    let mut meta: Meta = tx_get(&tx, "meta").await?.unwrap_or_default();
                    meta.challenges.retain(|c| c.expires > now());
                    let old: Option<Job> = tx_get(&tx, &format!("job/{id}")).await?;
                    if let Some(old) = old {
                        let mut job = old.clone();
                        if job.due.is_some_and(|d| d <= now()) {
                            if let Some(token) = job.begin(now(), attempt_for_tx) {
                                *output.borrow_mut() = Some((job.clone(), token));
                            }
                            save_job(&tx, &mut meta, Some(&old), &job).await?;
                        }
                    } else {
                        tx.delete(&key).await?;
                    }
                    tx.put("meta", meta).await?;
                    Ok(())
                })
                .await?;
            self.rearm().await?;
            let next = dispatch.borrow_mut().take();
            if let Some((job, token)) = next {
                // Ensure intent and watchdog are on disk before sending a sensitive token.
                self.state.storage().sync().await?;
                let timing = job
                    .timing
                    .as_ref()
                    .ok_or_else(|| Error::RustError("MISSING_TIMING".into()))?;
                let outcome = self.deliver(&token, timing, &attempt_id).await;
                if matches!(outcome, Outcome::Configuration(_)) {
                    console_error!("APNs configuration rejected; inspect deployment credentials and job lastError");
                }
                self.watchdog().await?;
                self.state
                    .storage()
                    .transaction(move |tx| async move {
                        let mut meta: Meta = tx_get(&tx, "meta").await?.unwrap_or_default();
                        if let Some(old) = tx_get::<Job>(&tx, &format!("job/{}", job.id)).await? {
                            let mut latest = old.clone();
                            latest.complete(&attempt_id, outcome, now());
                            save_job(&tx, &mut meta, Some(&old), &latest).await?;
                        }
                        tx.put("meta", meta).await?;
                        Ok(())
                    })
                    .await?;
            }
        }
        // Challenge expiry is indexed in bounded metadata, never in closed-job scans.
        self.state
            .storage()
            .transaction(|tx| async move {
                if let Some(mut meta) = tx_get::<Meta>(&tx, "meta").await? {
                    meta.challenges.retain(|c| c.expires > now());
                    tx.put("meta", meta).await?;
                }
                Ok(())
            })
            .await?;
        self.rearm().await
    }
}
impl DurableObject for Installation {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            provider: RefCell::new(None),
        }
    }
    async fn fetch(&self, req: Request) -> Result<Response> {
        match self.request(req).await {
            Ok(r) => response(r),
            Err(_) => response(Err(unavailable())),
        }
    }
    async fn alarm(&self) -> Result<Response> {
        self.process_alarm().await?;
        Response::empty()
    }
}
