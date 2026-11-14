use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use punctual_end_api::{
    apns,
    attest::{self, Policy},
    job::*,
    protocol::*,
};
use serde_json::{json, Value};

fn fixture() -> PutJob {
    serde_json::from_value(
        serde_json::from_str::<Value>(include_str!("../contracts/end-content-state-v1.json"))
            .unwrap()["request"]
            .clone(),
    )
    .unwrap()
}
fn new_job() -> Job {
    let p = fixture();
    let t = p.validate().unwrap();
    let mut j = Job::new("8f5b583d-c03a-4c35-9ad7-6c18cda0c063");
    j.apply("PUT", "original", Mutation::Put(p, t), 1794800000)
        .unwrap();
    j
}
fn patch(j: &mut Job, rev: &str, token: &str, now: i64) {
    j.apply(
        "PATCH",
        rev,
        Mutation::Patch(PatchToken {
            revision: rev.into(),
            push_token: token.into(),
        }),
        now,
    )
    .unwrap();
}
fn cancel(j: &mut Job, rev: &str, now: i64) {
    j.apply(
        "DELETE",
        rev,
        Mutation::Cancel(Cancel {
            revision: rev.into(),
        }),
        now,
    )
    .unwrap();
}
#[test]
fn exact_shared_vectors() {
    let s: Value = serde_json::from_str(include_str!("../contracts/signing-v1.json")).unwrap();
    let get = |k: &str| s[k].as_str().unwrap();
    let msg = signing_message(
        get("environment"),
        get("keyId"),
        get("challengeId"),
        get("challenge"),
        get("method"),
        get("path"),
        get("rawBody").as_bytes(),
    );
    assert_eq!(msg, get("signingMessage"));
    assert_eq!(hash_hex(msg.as_bytes()), get("clientDataHashHex"));
    assert_eq!(hash_hex(get("rawBody").as_bytes()), get("bodySHA256Hex"));
    assert_eq!(hash_hex(&[]), get("emptyBodySHA256Hex"));
    assert_eq!(
        hash_hex(&b64(get("challenge"), 44).unwrap()),
        get("attestationClientDataHashHex")
    );
    let end: Value =
        serde_json::from_str(include_str!("../contracts/end-content-state-v1.json")).unwrap();
    let p = fixture();
    let t = p.validate().unwrap();
    assert_eq!(
        apns::payload(&t, date(end["sentAt"].as_str().unwrap()).unwrap()),
        end["payload"]
    );
    assert_eq!(
        (t.start + 43200).to_string(),
        end["headers"]["apns-expiration"].as_str().unwrap()
    );
}
#[test]
fn shared_revision_error_responses() {
    let errors: Value =
        serde_json::from_str(include_str!("../contracts/revision-errors-v1.json")).unwrap();
    for case in errors["cases"].as_array().unwrap() {
        let mut original = fixture();
        original.revision = case["currentRevision"].as_str().unwrap().into();
        let timing = original.validate().unwrap();
        let mut job = Job::new("8f5b583d-c03a-4c35-9ad7-6c18cda0c063");
        job.apply(
            "PUT",
            "original",
            Mutation::Put(original.clone(), timing.clone()),
            1794800000,
        )
        .unwrap();
        job.status = serde_json::from_value(case["currentStatus"].clone()).unwrap();
        job.dispatch_started = job.status != Status::Scheduled;
        let mut request = original;
        request.revision = case["requestRevision"].as_str().unwrap().into();
        request.push_token = "ccdd".into();
        let error = job
            .apply(
                case["method"].as_str().unwrap(),
                "changed",
                Mutation::Put(request, timing),
                1794800000,
            )
            .unwrap_err();
        assert_eq!(error.status, case["statusCode"].as_u64().unwrap() as u16);
        let request_id = case["response"]["error"]["requestId"].as_str().unwrap();
        uuid(request_id).unwrap();
        assert_eq!(
            json!({"error":{"code":error.code,"message":error.message,"requestId":request_id,"details":error.details}}),
            case["response"],
            "{}",
            case["name"]
        );
        assert_eq!(job.revision, case["currentRevision"]);
        assert_eq!(job.body_hash, "original");
    }
}
#[test]
fn strict_wire_validation() {
    for bad in ["0", "01", "18446744073709551616", "-1", "1.0", "1\n", ""] {
        assert!(revision(bad).is_err(), "{bad}");
    }
    assert_eq!(revision("18446744073709551615").unwrap(), u64::MAX);
    for bad in [
        "2026-02-30T00:00:00Z",
        "2026-01-01T00:00:00.0Z",
        "2026-01-01T00:00:00+00:00",
        "1969-12-31T23:59:59Z",
        "2026-01-01T00:00:60Z",
    ] {
        assert!(date(bad).is_err(), "{bad}");
    }
    assert!(date("2028-02-29T00:00:00Z").is_ok());
    assert!(date("9999-12-31T23:59:59Z").is_ok());
    for bad in ["AABB", "a", "aa ", ""] {
        assert!(token(bad).is_err());
    }
    assert!(token(&"aa".repeat(2048)).is_ok());
    assert!(token(&"aa".repeat(2049)).is_err());
    let canonical = STANDARD.encode([0u8; 32]);
    assert!(key_id(&canonical).is_ok());
    assert!(key_id(canonical.trim_end_matches('=')).is_err());
    let mut p = serde_json::to_value(fixture()).unwrap();
    p["title"] = json!("private");
    assert!(serde_json::from_value::<PutJob>(p).is_err());
    let mut p = fixture();
    p.activity_ends_at = "2026-11-16T10:00:01Z".into();
    assert!(p.validate().is_err());
}
#[test]
fn revisions_replays_and_durable_closed_markers() {
    let mut j = new_job();
    let p = fixture();
    let t = p.validate().unwrap();
    j.apply(
        "PUT",
        "original",
        Mutation::Put(p.clone(), t.clone()),
        1794823200,
    )
    .unwrap();
    let mut stale = p.clone();
    stale.revision = "11".into();
    assert_eq!(
        j.apply("PUT", "old", Mutation::Put(stale, t.clone()), 1794823200)
            .unwrap_err()
            .code,
        "STALE_REVISION"
    );
    assert_eq!(
        j.apply(
            "PUT",
            "different",
            Mutation::Put(p.clone(), t.clone()),
            1794823200
        )
        .unwrap_err()
        .code,
        "REVISION_CONFLICT"
    );
    cancel(&mut j, "13", 1794823200);
    assert!(j.status.terminal());
    let delivery = j.delivery.clone();
    j.begin(1794910000, "cleanup".into());
    assert!(j.token.is_none() && j.timing.is_none());
    let mut p = p;
    p.revision = "14".into();
    assert_eq!(
        j.apply("PUT", "resurrect", Mutation::Put(p, t), 1795000000)
            .unwrap_err()
            .code,
        "JOB_CLOSED"
    );
    assert_eq!(j.revision, "13");
    assert_eq!(j.delivery.attempt_count, delivery.attempt_count);
    let mut unknown = Job::new("new");
    cancel(&mut unknown, "100", 1794823200);
    assert_eq!(unknown.status, Status::Cancelled);
    let mut p = fixture();
    p.revision = "101".into();
    let t = p.validate().unwrap();
    assert_eq!(
        unknown
            .apply("PUT", "resurrect", Mutation::Put(p, t), 1795000000)
            .unwrap_err()
            .status,
        410
    );
}
#[test]
fn rotation_acceptance_and_rejection_races() {
    let mut j = new_job();
    let time = 1794823200;
    j.begin(time, "attempt1".into()).unwrap();
    patch(&mut j, "13", "aabb", time + 1);
    j.complete(
        "attempt1",
        Outcome::TokenRejected("BadDeviceToken".into()),
        time + 2,
    );
    assert_eq!(j.status, Status::Retrying);
    assert_eq!(j.token.as_deref(), Some("aabb"));
    let token = j.begin(time + 7, "attempt2".into()).unwrap();
    assert_eq!(token, "aabb");
    patch(&mut j, "14", "ccdd", time + 8);
    j.complete("attempt2", Outcome::Accepted, time + 9);
    assert_eq!(j.status, Status::Retrying);
    assert_eq!(j.delivery.state, "accepted");
    assert_eq!(j.begin(time + 14, "attempt3".into()).unwrap(), "ccdd");
    j.complete("attempt2", Outcome::Configuration("late".into()), time + 15);
    assert_eq!(j.status, Status::Dispatching);
    j.complete("attempt3", Outcome::Accepted, time + 16);
    assert_eq!(j.status, Status::ApnsAccepted);
    assert_eq!(j.delivery.attempt_count, 3);
}
#[test]
fn rejected_current_token_waits_and_cancellation_preserves_evidence() {
    let mut j = new_job();
    let time = 1794823200;
    let original = j.begin(time, "a".into()).unwrap();
    j.complete("a", Outcome::TokenRejected("Unregistered".into()), time + 1);
    assert_eq!(j.status, Status::AwaitingToken);
    let deadline = j.due;
    patch(&mut j, "13", &original, time + 2);
    assert_eq!(j.status, Status::AwaitingToken);
    assert_eq!(j.due, deadline);
    patch(&mut j, "14", "abcd", time + 3);
    assert_eq!(j.status, Status::Retrying);
    j.begin(time + 3, "b".into()).unwrap();
    cancel(&mut j, "15", time + 4);
    assert!(j.delivery.may_have_been_sent);
    j.complete("b", Outcome::Accepted, time + 5);
    assert_eq!(j.status, Status::Cancelled);
    assert_eq!(j.delivery.state, "accepted");
    assert!(j.begin(time + 86410, "cleanup".into()).is_none());
    assert!(j.timing.is_none());
    assert!(j.delivery.accepted_at.is_none());
    assert!(j.delivery.may_have_been_sent);
}
#[test]
fn alarm_restart_retry_limits_and_lifetime() {
    let mut j = new_job();
    let t = 1794823200;
    j.begin(t, "crashed".into());
    let encoded = serde_json::to_vec(&j).unwrap();
    let mut j: Job = serde_json::from_slice(&encoded).unwrap();
    assert!(j.begin(t + 30, "recovery".into()).is_none());
    assert_eq!(j.status, Status::Retrying);
    assert_eq!(j.delivery.state, "unknown");
    let mut clock = t + 35;
    while !j.status.terminal() {
        let id = format!("{clock}");
        j.begin(clock, id.clone());
        j.complete(&id, Outcome::Retry("503".into(), None, false), clock);
        clock = j.due.unwrap();
    }
    assert_eq!(j.delivery.attempt_count, 8);
    assert_eq!(j.status, Status::Failed);
    let mut j = new_job();
    j.begin(t, "a".into());
    j.complete(
        "a",
        Outcome::Retry("429".into(), Some(t + 901), false),
        t + 1,
    );
    assert_eq!(j.status, Status::Expired);
    let mut p = fixture();
    p.revision = "1".into();
    let timing = p.validate().unwrap();
    let mut expired = Job::new("late");
    assert_eq!(
        expired
            .apply(
                "PUT",
                "hash",
                Mutation::Put(p, timing.clone()),
                timing.start + 43200
            )
            .unwrap_err()
            .code,
        "ACTIVITY_LIFETIME_EXCEEDED"
    );
    assert_eq!(expired.status, Status::Expired);
    let mut future = fixture();
    future.starts_at = "2099-01-01T00:00:00Z".into();
    future.notification_at = "2099-01-01T00:00:00Z".into();
    future.ends_at = "2099-01-02T00:00:00Z".into();
    future.activity_ends_at = "2099-01-01T08:00:00Z".into();
    assert!(future.validate().is_ok());
}
fn cbor(value: ciborium::Value) -> Vec<u8> {
    let mut out = vec![];
    ciborium::ser::into_writer(&value, &mut out).unwrap();
    out
}
#[test]
fn real_assertion_crypto_replay_environment_and_tampering() {
    use ciborium::Value as C;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let public = key.verifying_key().to_encoded_point(false);
    let policy = Policy {
        environment: "development".into(),
        app_id: format!("TESTPREFIX.{BUNDLE_ID}"),
        allowed_categories: vec![3],
        allowed_versions: vec![],
    };
    let mut auth = hash(policy.app_id.as_bytes());
    auth.push(0);
    auth.extend(1u32.to_be_bytes());
    let client = hash(b"bound request");
    let mut message = auth.clone();
    message.extend(&client);
    let signature: Signature = key.sign_prehash(&hash(&message)).unwrap();
    let assertion = cbor(C::Map(vec![
        (C::Text("authenticatorData".into()), C::Bytes(auth.clone())),
        (
            C::Text("signature".into()),
            C::Bytes(signature.to_der().as_bytes().to_vec()),
        ),
    ]));
    assert_eq!(
        attest::verify_assertion(&assertion, public.as_bytes(), &client, &policy, 0).unwrap(),
        1
    );
    assert!(attest::verify_assertion(&assertion, public.as_bytes(), &client, &policy, 1).is_err());
    assert!(attest::verify_assertion(
        &assertion,
        public.as_bytes(),
        &hash(b"production request"),
        &policy,
        0
    )
    .is_err());
    let mut wrong = policy.clone();
    wrong.app_id = "WRONGPREFIX.org.tknw.punctual".into();
    assert!(attest::verify_assertion(&assertion, public.as_bytes(), &client, &wrong, 0).is_err());
    let mut extra = assertion.clone();
    extra.push(0);
    assert!(attest::verify_assertion(&extra, public.as_bytes(), &client, &policy, 0).is_err());
    assert!(attest::verify_attestation(
        &assertion,
        &hash(public.as_bytes()),
        b"challenge",
        &policy,
        1794823200
    )
    .is_err());
}
#[test]
fn apns_es256_jwt_and_failure_classification() {
    assert_eq!(apns::provider_issued_at(1200), 1200);
    assert_eq!(apns::provider_issued_at(2399), 1200);
    assert_eq!(apns::provider_issued_at(2400), 2400);
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::{
        ecdsa::{signature::Verifier, VerifyingKey},
        pkcs8::{EncodePrivateKey, LineEnding},
    };
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let jwt = apns::jwt(pem.as_str(), "ABCDEF1234", "1234ABCDEF", 1794823200).unwrap();
    let parts: Vec<_> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    let public: VerifyingKey = *key.verifying_key();
    public
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .unwrap();
    assert!(matches!(apns::classify(200, "", None), Outcome::Accepted));
    assert!(matches!(
        apns::classify(410, "Unregistered", None),
        Outcome::TokenRejected(_)
    ));
    assert!(matches!(
        apns::classify(503, "ServiceUnavailable", None),
        Outcome::Retry(_, _, false)
    ));
    assert!(matches!(
        apns::classify(403, "InvalidProviderToken", None),
        Outcome::Configuration(_)
    ));
    assert_eq!(apns::retry_after(Some("120"), 100), Some(220));
    assert_eq!(apns::retry_after(Some("bad"), 100), None);
}
#[test]
fn apple_published_certificate_chain_and_pinned_root() {
    let chain = vec![
        include_bytes!("fixtures/apple-guide-leaf.der").to_vec(),
        include_bytes!("fixtures/apple-guide-intermediate.der").to_vec(),
    ];
    let historical = date("2026-04-21T00:00:00Z").unwrap();
    assert_eq!(attest::verify_chain(&chain, historical).unwrap().len(), 65);
    assert!(attest::verify_chain(&chain, date("2026-11-16T00:00:00Z").unwrap()).is_err());
    let mut tampered = chain.clone();
    let last = tampered[0].len() - 1;
    tampered[0][last] ^= 1;
    assert!(attest::verify_chain(&tampered, historical).is_err());
    assert!(attest::verify_chain(&[chain[0].clone(), chain[0].clone()], historical).is_err());
    assert_eq!(
        hash_hex(include_bytes!("../trust/apple-app-attest-root.der")),
        "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"
    );
}
