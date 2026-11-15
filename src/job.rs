use crate::protocol::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Scheduled,
    Dispatching,
    Retrying,
    AwaitingToken,
    ApnsAccepted,
    Cancelled,
    Failed,
    Expired,
}
impl Status {
    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::ApnsAccepted | Self::Cancelled | Self::Failed | Self::Expired
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivery {
    pub state: String,
    pub attempt_count: u8,
    pub accepted_at: Option<String>,
    pub may_have_been_sent: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub id: String,
    pub token_hash: String,
    pub started: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub revision: String,
    pub method: String,
    pub body_hash: String,
    pub status: Status,
    pub delivery: Delivery,
    pub last_error: Option<String>,
    pub timing: Option<Timing>,
    pub token: Option<String>,
    pub first_attempt: Option<i64>,
    pub dispatch_started: bool,
    pub attempt: Option<Attempt>,
    pub due: Option<i64>,
    pub terminal_at: Option<i64>,
}
#[derive(Clone, Debug)]
pub enum Mutation {
    Put(PutJob, Timing),
    Patch(PatchToken),
    Cancel(Cancel),
}
impl Mutation {
    pub fn parse(method: &str, body: &[u8]) -> ApiResult<Self> {
        match method {
            "PUT" => {
                let p: PutJob = json_body(body)?;
                let t = p.validate()?;
                Ok(Self::Put(p, t))
            }
            "PATCH" => {
                let p: PatchToken = json_body(body)?;
                revision(&p.revision)?;
                token(&p.push_token)?;
                Ok(Self::Patch(p))
            }
            "DELETE" => {
                let c: Cancel = json_body(body)?;
                revision(&c.revision)?;
                Ok(Self::Cancel(c))
            }
            _ => Err(ApiError::invalid()),
        }
    }
    pub fn revision(&self) -> &str {
        match self {
            Self::Put(p, _) => &p.revision,
            Self::Patch(p) => &p.revision,
            Self::Cancel(p) => &p.revision,
        }
    }
}
impl Job {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.into(),
            revision: "0".into(),
            method: String::new(),
            body_hash: String::new(),
            status: Status::Scheduled,
            delivery: Delivery {
                state: "not_sent".into(),
                attempt_count: 0,
                accepted_at: None,
                may_have_been_sent: false,
            },
            last_error: None,
            timing: None,
            token: None,
            first_attempt: None,
            dispatch_started: false,
            attempt: None,
            due: None,
            terminal_at: None,
        }
    }
    pub fn view(&self) -> Value {
        json!({ "jobId":self.id, "revision":self.revision, "status":self.status, "activityEndsAt":self.timing.as_ref().map(|t| iso(t.activity_end)), "delivery":self.delivery, "lastError":self.last_error })
    }
    pub fn close(&mut self, status: Status, now: i64) {
        self.status = status;
        if self.terminal_at.is_none() {
            self.terminal_at = Some(now);
        }
        self.due = self.terminal_at.map(|t| t + 86400);
    }
    pub fn apply(
        &mut self,
        method: &str,
        body_hash: &str,
        op: Mutation,
        now: i64,
    ) -> ApiResult<()> {
        let rev = revision(op.revision())?;
        let old = self.revision.parse::<u64>().expect("stored revision");
        if rev < old || (rev == old && (self.method != method || self.body_hash != body_hash)) {
            let mut e = ApiError::new(
                409,
                if rev < old {
                    "STALE_REVISION"
                } else {
                    "REVISION_CONFLICT"
                },
            );
            e.details = json!({"currentRevision":self.revision,"status":self.status});
            return Err(e);
        }
        if rev == old {
            return Ok(());
        }
        if !matches!(op, Mutation::Cancel(_)) && self.status.terminal() {
            return Err(ApiError::new(410, "JOB_CLOSED"));
        }
        if matches!(op, Mutation::Put(..)) && self.dispatch_started {
            let mut error = ApiError::new(409, "DISPATCH_STARTED");
            error.details = json!({"currentRevision":self.revision,"status":self.status});
            return Err(error);
        }
        self.revision = op.revision().into();
        self.method = method.into();
        self.body_hash = body_hash.into();
        match op {
            Mutation::Cancel(_) => {
                if self.attempt.is_some() {
                    self.delivery.may_have_been_sent = true;
                }
                self.close(Status::Cancelled, now);
            }
            Mutation::Put(p, t) => {
                self.token = Some(p.push_token);
                self.timing = Some(t.clone());
                if now >= t.start + 43200 {
                    self.close(Status::Expired, now);
                    return Err(ApiError::new(410, "ACTIVITY_LIFETIME_EXCEEDED"));
                }
                self.status = Status::Scheduled;
                self.due = Some(t.activity_end.max(now));
            }
            Mutation::Patch(p) => {
                if self.timing.is_none() {
                    return Err(ApiError::new(404, "NOT_FOUND"));
                }
                let changed = self.token.as_deref() != Some(p.push_token.as_str());
                self.token = Some(p.push_token);
                if self.deadline().is_some_and(|d| now >= d) {
                    self.close(Status::Expired, now);
                } else if changed && self.status == Status::AwaitingToken {
                    self.status = Status::Retrying;
                    self.last_error = None;
                    self.due = Some(now);
                }
            }
        }
        Ok(())
    }
    pub fn deadline(&self) -> Option<i64> {
        self.timing
            .as_ref()
            .map(|t| (t.start + 43200).min(self.first_attempt.map_or(i64::MAX, |f| f + 900)))
    }
    /// Returns the token only after the caller durably stores this attempt.
    pub fn begin(&mut self, now: i64, attempt_id: String) -> Option<String> {
        if self.status.terminal() {
            if self.due.is_some_and(|d| d <= now) {
                self.token = None;
                self.timing = None;
                self.attempt = None;
                self.delivery.accepted_at = None;
                self.first_attempt = None;
                self.due = None;
            }
            return None;
        }
        if self.deadline().is_some_and(|d| now >= d) {
            self.close(Status::Expired, now);
            return None;
        }
        if self.status == Status::AwaitingToken {
            self.close(Status::Expired, now);
            return None;
        }
        if self.attempt.is_some() {
            // A prior runtime died after persisting intent, or the network call timed out.
            self.delivery.state = "unknown".into();
            self.delivery.may_have_been_sent = true;
            self.attempt = None;
            self.retry(now, None, "UNKNOWN_OUTCOME");
            return None;
        }
        if self.delivery.attempt_count >= 8 {
            self.close(Status::Failed, now);
            return None;
        }
        let token = self.token.clone()?;
        self.first_attempt.get_or_insert(now);
        self.dispatch_started = true;
        self.delivery.attempt_count += 1;
        self.delivery.state = "in_flight".into();
        self.status = Status::Dispatching;
        self.attempt = Some(Attempt {
            id: attempt_id,
            token_hash: hash_hex(token.as_bytes()),
            started: now,
        });
        self.due = Some((now + 30).min(self.deadline()?));
        Some(token)
    }
    pub fn retry(&mut self, now: i64, retry_after: Option<i64>, error: &str) {
        self.last_error = Some(error.into());
        let backoff = [5, 15, 30, 60, 120, 240, 300];
        if self.delivery.attempt_count >= 8 {
            self.close(Status::Failed, now);
            return;
        }
        let next = (now
            + backoff[usize::from(self.delivery.attempt_count.saturating_sub(1)).min(6)])
        .max(retry_after.unwrap_or(0));
        if self.deadline().is_none_or(|d| next >= d) {
            self.close(Status::Expired, now);
            return;
        }
        self.status = Status::Retrying;
        self.due = Some(next);
    }
    pub fn complete(&mut self, attempt_id: &str, outcome: Outcome, now: i64) {
        let Some(a) = self.attempt.as_ref().filter(|a| a.id == attempt_id) else {
            return;
        };
        let current = self
            .token
            .as_ref()
            .is_some_and(|t| hash_hex(t.as_bytes()) == a.token_hash);
        self.attempt = None;
        let cancelled = self.status == Status::Cancelled;
        match outcome {
            Outcome::Accepted => {
                self.delivery.state = "accepted".into();
                self.delivery.accepted_at = Some(iso(now));
                self.delivery.may_have_been_sent = true;
                if !cancelled {
                    if current {
                        self.last_error = None;
                        self.close(Status::ApnsAccepted, now);
                    } else {
                        self.retry(now, Some(now), "TOKEN_ROTATED");
                    }
                }
            }
            Outcome::TokenRejected(reason) => {
                if self.delivery.accepted_at.is_none() {
                    self.delivery.state = "rejected".into();
                }
                if !cancelled {
                    if current {
                        self.status = Status::AwaitingToken;
                        self.last_error = Some(reason);
                        self.due = self.deadline();
                    } else {
                        self.retry(now, Some(now), "TOKEN_ROTATED");
                    }
                }
            }
            Outcome::Retry(reason, after, unknown) => {
                if unknown {
                    self.delivery.may_have_been_sent = true;
                }
                if self.delivery.accepted_at.is_none() {
                    self.delivery.state = if unknown { "unknown" } else { "rejected" }.into();
                }
                if !cancelled {
                    self.retry(now, after, &reason);
                }
            }
            Outcome::Configuration(reason) => {
                if self.delivery.accepted_at.is_none() {
                    self.delivery.state = "rejected".into();
                }
                self.last_error = Some(reason);
                if !cancelled {
                    self.close(Status::Failed, now);
                }
            }
        }
    }
}
#[derive(Clone, Debug)]
pub enum Outcome {
    Accepted,
    TokenRejected(String),
    Retry(String, Option<i64>, bool),
    Configuration(String),
}
