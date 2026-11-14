# Deployment and owner registration

The repository contains no production credentials. Automated checks run locally
and in GitHub Actions; deployment, Apple registration, APNs acceptance and device
delivery require the owner to complete the steps below. The maintained behavior
is [API v1](api-v1.md#L1), with infrastructure in
[wrangler.toml](../wrangler.toml#L1).

## GitHub configuration

In this repository, open **Settings → Secrets and variables → Actions**. Create:

| Scope | Kind | Exact name | Value |
| ----- | ---- | ---------- | ----- |
| Repository | Secret | CLOUDFLARE_API_TOKEN | Scoped Cloudflare API token described below |
| Repository | Variable | CLOUDFLARE_ACCOUNT_ID | Cloudflare account's 32-character hexadecimal ID |
| Environment, separately for development and production | Secret | APNS_PRIVATE_KEY | Complete Apple APNs .p8 PKCS#8 PEM, including BEGIN/END lines and newlines |
| Environment | Variable | APNS_KEY_ID | Apple APNs authentication key's 10-character key ID |
| Environment | Variable | APPLE_TEAM_ID | Apple Developer team's 10-character team ID, for APNs JWT issuer |
| Environment | Variable | APPLE_APP_ID_PREFIX | App ID prefix from the bundle identifier's Apple registration; confirm it rather than assuming it equals the team ID |
| Environment | Variable | APP_ATTEST_ENVIRONMENT | development or production, matching the signed app's App Attest entitlement |
| Environment | Variable | APNS_ENVIRONMENT | sandbox or production, matching this ActivityKit token's provisioning environment |
| Environment | Optional variable | ATTEST_ALLOWED_CATEGORIES | Comma-separated Apple validation categories; default development=3, production=2,4 |
| Environment | Optional variable | ATTEST_ALLOWED_BUNDLE_VERSIONS | Comma-separated approved CFBundleVersion strings; empty permits any valid numeric/dotted version |

Under **Settings → Environments**, create the exact names **development** and
**production**. Register the environment-scoped entries independently, even if
the same APNs signing key is authorized for both. Protect production with owner
review and appropriate branch restrictions. The app's deployment environment in
the signing message is development/production, independently of both Apple
environment variables. TestFlight uses production App Attest and production APNs;
it can use the isolated development service only after those two environment
variables and validation categories are explicitly configured there.

Never paste a key or ActivityKit token into a PR, issue, command-line argument,
committed fixture, log, or artifact. Do not enable verbose HTTP tracing. The
workflow passes the APNs key through a mode-0600 temporary JSON file, supplies it
with the same Worker version using Wrangler's secrets-file option, then deletes
the temporary directory. No deployment artifact is uploaded to GitHub.

## Apple registration

1. Use a paid Apple Developer membership and the existing explicit App ID
   **org.tknw.punctual**. Confirm the App ID prefix and team ID in Certificates,
   Identifiers & Profiles. Never change the bundle ID to match a test example.
2. Enable **App Attest** for that identifier and regenerate development and
   distribution provisioning profiles. The app needs the matching
   com.apple.developer.devicecheck.appattest-environment entitlement. Use a
   supported physical device for registration; unsupported devices receive no
   unauthenticated fallback.
3. Enable **Push Notifications** on the app identifier, and use a provisioning
   profile with the correct aps-environment. Enable Live Activities in the app
   (NSSupportsLiveActivities), with ActivityKit pushType.token. Obtain the token
   for the individual Activity, not the UserNotifications device token or a
   push-to-start token. Do not synchronize it through iCloud.
4. Create an **Apple Push Notifications service (APNs)** authentication key with
   permission for this app/topic and the intended environment. Download the .p8
   once, store it securely, and record its key ID. Set the GitHub entries above.
   The service signs ES256 JWTs and always sends the fixed topic
   **org.tknw.punctual.push-type.liveactivity**.
5. Keep the app's durable outbox, challenge signing and commit gating aligned
   with [the contract](api-v1.md#L1). Register against the intended service URL;
   each signed business operation needs a fresh challenge and increasing Apple
   counter. An exact registration retry preserves its identity and counter.

Recovery machine codes are KEY_NOT_REGISTERED for an assertion challenge on an
unknown key, CHALLENGE_EXPIRED for an unavailable/expired challenge, and
CHALLENGE_REPLAYED for a different attestation registration payload on an already
registered key. The client can probe an assertion challenge after a lost initial
registration response; an exact successful registration replay returns 200 even
after challenge expiry. Invalid signatures retain INVALID_AUTHENTICATION.
DISPATCH_STARTED includes current revision/status details so the client can stop
timing PUT retries while retaining PATCH/cancellation for that same job.

Follow [Apple's server validation guide](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
and [Live Activity push guidance](https://developer.apple.com/documentation/activitykit/starting-and-updating-live-activities-with-activitykit-push-notifications).
The pinned App Attest root is Apple's published certificate, with SHA-256
**1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932**.
Its provenance and test certificate sources are in
[trust documentation](trust.md#L1). Root rotation requires a reviewed code change.

## Cloudflare registration and deployment

1. Select the intended Cloudflare account and a Workers Paid plan (the configured
   CPU allowance requires it). Enable its workers.dev subdomain. The service uses
   workers.dev URLs initially; no DNS zone, external Workers KV, D1, Terraform or
   separately provisioned database is required.
2. Create a custom API token scoped to this account with **Account → Workers
   Scripts → Edit** and **Account → Account Settings → Read**. Zone permissions
   are unnecessary for workers.dev. Keep the token in CLOUDFLARE_API_TOKEN and
   the account ID in CLOUDFLARE_ACCOUNT_ID. Separate deployment tokens may be
   used as environment-scoped overrides of that repository secret.
3. Review [the Wrangler configuration](../wrangler.toml#L1). Deployment creates
   two scripts, punctual-end-api-development and punctual-end-api-production,
   with separate Installation namespaces. The v1 migration uses
   new_sqlite_classes. Storage uses only Durable Object KV methods and Alarms;
   no SQL API or external storage binding is used. Edge rate-limit namespaces
   1001 and 1002 are transient counters, not stored IP histories.
4. In **Actions → Manual deploy → Run workflow**, choose the reviewed branch and
   development. The workflow runs tests, checks required configuration, then
   deploys code, variables and APNs secret together. Record the resulting HTTPS
   URL in the app's environment configuration. Repeat separately for production
   after reviewing the development evidence. Do not point a production app at
   an unconfigured development service.
5. Keep the Durable Object class name, migration history and deployment names
   stable. Changing the App ID prefix or App Attest environment after identity
   registration fails authentication for those keys; plan a separate namespace
   and client re-registration before such a change. Never delete identity storage
   to unblock a replay or a stale revision. Roll code back with a reviewed prior
   deployment; do not roll durable counters or closed markers back.

GitHub exposes a newly added workflow_dispatch workflow after it reaches the
default branch. The owner must review and merge this draft PR before that first
Actions run; this implementation work does not merge it. For an explicitly
owner-run pre-merge deployment, provide the same values in a private local shell,
set DEPLOY_TARGET to development or production, and run
[the deployment script](../scripts/deploy.mjs#L1) with Node. That path performs
the same configuration validation and atomic secret upload.

The top-level Wrangler target is disabled; always choose an environment.
For local work, install Node 22+, Rust 1.100+, the wasm32-unknown-unknown target,
and worker-build 0.9.0. Use [the scripts](../package.json#L1):

  ```sh
  npm ci
  cargo install worker-build --version 0.9.0 --locked
  cargo test --locked
  npm run build
  npm test
  npm run dev
  ```

Local configuration uses an ignored .dev.vars.development file for owner values,
including APPLE_APP_ID_PREFIX and the APNs secret if local delivery is intended.
Local development still performs real App Attest verification; automated tests
seed ephemeral identities directly into isolated test storage and verify genuine
ECDSA assertions. That test mechanism is absent from the HTTP service.

## Owner APNs smoke and device test

First run an app-integrated test through the deployed service on a physical
device. Create a disposable Activity with a near-future end, verify registration
and signed PUT, then observe the scheduled → apns_accepted state using a newly
signed GET. Confirm that the Activity ends and disappears on Lock Screen and
Dynamic Island. HTTP acceptance alone does not prove device delivery.

To isolate Apple credentials from service/outbox integration, the owner can run
[the direct smoke script](../scripts/apns-smoke.mjs#L1). Supply these variables
in a private local shell, without shell tracing or history containing values:
APNS_PRIVATE_KEY_FILE (path to the .p8), APNS_KEY_ID, APPLE_TEAM_ID,
APNS_ENVIRONMENT, APNS_ACTIVITY_TOKEN, ACTIVITY_STARTS_AT, ACTIVITY_ENDS_AT,
ACTIVITY_NOTIFICATION_AT (actual Activity times in UTC), and
CONFIRM_END_ACTIVITY=yes. The test immediately ends that disposable Activity.

  ```sh
  node scripts/apns-smoke.mjs
  ```

The script emits only HTTP status and response size. Record the build,
environment, nonsecret job UUID, server state, approximate timing and observed
device result; clear token environment variables afterward. Run sandbox with a
development build and production with TestFlight/distribution as appropriate.
Also exercise a token change, close-button cancellation, offline outbox retry,
and a schedule beyond eight hours. Verify that no reminder text is transmitted.

## Operational limits and evidence

Defaults are 128 KiB attestation body, 8 KiB other bodies, 4096 token hex digits,
eight pending five-minute challenges, 16 active jobs, 100000 lifetime job markers,
30 key-local challenge/registration requests per minute, and 120 authenticated
requests per minute. KEY_ISSUE_LIMIT, AUTH_REQUEST_LIMIT, ACTIVE_JOB_LIMIT and
MARKER_LIMIT in [the configuration](../wrangler.toml#L1) are operational overrides.
The first two rate buckets use fixed UTC minutes. The transient edge binding
limits unauthenticated authentication routes to 60/minute/IP, approximately per
Cloudflare location; use an additional owner-managed WAF rule if a global edge
limit is needed. Its configured limit is changed in the corresponding ratelimits
block. Requests return a specific 429 code: IP_AUTH_RATE_LIMIT,
KEY_ISSUE_RATE_LIMIT, PENDING_CHALLENGE_LIMIT, AUTH_REQUEST_RATE_LIMIT,
ACTIVE_JOB_CAPACITY or JOB_MARKER_CAPACITY, with Retry-After. Existing jobs can
always be cancelled despite marker capacity.

An indexed due queue covers scheduled jobs, retries, in-flight recovery and
24-hour terminal cleanup. Expired challenges for keys that never registered
release their metadata and Alarm, preventing persistent orphan storage. Closed markers retain only ordering and delivery
evidence for the identity's lifetime; active token/timing data and acceptedAt are
cleared at cleanup. Cloudflare platform backups/PITR may retain older storage
versions according to the account retention policy. Application logs contain no
tokens/assertions; invocation logging and tracing are disabled to avoid recording
an APNs token in a subrequest URL. Configuration failures produce a bounded
operational error and a failed job; investigate credentials before new jobs.

Retries are bounded by eight calls, the 15-minute delivery window and maximum
Activity lifetime. Deterministic provider JWTs use aligned 20-minute issuance
windows across installations and evictions to avoid excessive token changes on
pooled APNs connections. Expired provider JWTs invalidate the cache and generate
a fresh JWT for the next bounded attempt. A Worker crash after APNs accepted but before the
completion transaction can cause duplicate end pushes. Old-token acceptance
does not complete a replacement token. Cancellation preserves any accepted or
unknown delivery evidence. Alarms and APNs cannot promise exact-time dismissal.

Automated validation covers synthetic complete attestation with ephemeral test
roots, Apple's published certificate chain, real assertion/JWT cryptography,
the shared vectors, revision/replay/ownership checks, cancellation, token races,
Alarm restart and cleanup. Apple's optional fraud-risk receipt refresh service
is not integrated; attestation receipts are retained with the identity, are not
used to grant authentication, and are never returned. Legacy iOS authenticator
data without extension fields is supported; when present, validation category
and bundle version are checked against deployment policy. Real attestation,
deployed APNs acceptance and device dismissal remain unverified until the owner
runs and records the credential-dependent tests above.
