# End API v1 behavior

[OpenAPI](../contracts/openapi.json) is the HTTP schema. All JSON is UTF-8 and all
responses use `Cache-Control: no-store`. The service only schedules ActivityKit
end pushes. It does not start Live Activities, issue regular notifications,
store reminder content, or authenticate an iCloud account.

## Identity and authentication

An installation is a registered App Attest key. Create one SQLite-backed Durable
Object per key/environment; its server-generated installation UUID is immutable.
The request owner is derived from the verified key, never a body parameter.
Development and production have separate deployments, storage, attestation
expectations and APNs configuration. APNs environment and App Attest environment
are independently configured, not inferred from a client field.

The challenge endpoint accepts a key identifier and purpose. Challenges contain
32 random bytes, use canonical padded standard Base64, expire after five minutes,
are bound to that key, purpose and deployment, and are one-use. Assertion
challenges require an already registered key. Limit unused challenges to eight
per key. Clean up expired challenges without scanning closed job history.

Attestation uses SHA256 of the decoded challenge as clientDataHash. Verify the
certificate chain against Apple's App Attest root, nonce, RP/App ID hash,
credential ID, environment, initial counter and applicable Apple validation
requirements. Follow [Apple's validation guide](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
An identical successful registration replay returns the original identity and
does not reset a counter, replace a public key or overwrite an environment.
Persist the successful registration fingerprint so a response-loss retry can be
recognized without granting replayable business operations. For expired initial
registration recovery, an already registered key can obtain an assertion
challenge; an unknown key must complete valid attestation.

Authenticated business requests carry the three App Attest headers specified by
[OpenAPI](../contracts/openapi.json). clientDataHash is SHA256 of this exact UTF-8
string (LF after every line, including the final line):

  ```text
  punctual-api-v1
  environment
  keyId
  challengeId
  challenge
  METHOD
  /v1/end-jobs/...
  lowercase-hex-SHA256-of-raw-body
  ```

Environment is `development` or `production`; keyId/challenge are strict
canonical standard Base64, challengeId and jobId are lowercase UUIDs, METHOD is
uppercase, query strings are unsupported, and GET hashes zero body bytes. Hash
the body bytes as received, not reserialized JSON. These fields cannot contain
LF. [The signing vector](../contracts/signing-v1.json) fixes the format.

Verify the assertion signature and strictly increasing Apple counter. Atomically
recheck/consume the challenge, advance the counter and apply the business
operation in the owning Durable Object. A retry obtains fresh authentication but
reuses its durable body/revision. The client serializes signed requests per key.

App Attest proves a legitimate app/key and protects ownership of the stored job;
it is not proof that an arbitrary supplied APNs token belongs to that key. The
app keeps tokens private to its installation, never in iCloud, shared exports or
logs. There is no unauthenticated production fallback for unsupported devices.

## Job lifecycle

The client generates a lowercase UUID for each Activity instance's job and keeps
that mapping locally. A revision is a positive UInt64 decimal string without
leading zeroes; gaps are valid. Never sync either identifier or the counter to
iCloud. A replacement Activity gets a new job UUID.

PUT creates or changes a schedule, PATCH changes only its token, DELETE prevents
future delivery, and GET returns only the authenticated installation's state.
A different owner sees 404. Unknown properties and invalid body values are
rejected. A DELETE received before PUT persists a closed marker even for an
unknown UUID.

After authentication, compare revisions in this order:

1. Lower than stored: 409 STALE_REVISION with current revision/status.
2. Equal and same method plus raw body hash: 200 current state, no repeated effect.
3. Equal with different method/body: 409 REVISION_CONFLICT.
4. Higher PUT/PATCH on a terminal job: 410 JOB_CLOSED.
5. Higher PUT after first dispatch began: 409 DISPATCH_STARTED.
6. Otherwise apply the update, or idempotently cancel, and persist the next alarm.

Replayed requests return current state, not an archived response. Thus an
identical accepted PUT can later return apns_accepted with the same revision.
DELETE also works after a terminal state; it never erases delivery evidence or
claims an in-flight/accepted push was recalled. Cancellation stops retries.
Represent cancellation and delivery evidence separately. A cancelled job can
have accepted delivery or mayHaveBeenSent=true.

PATCH is allowed while scheduled, dispatching, retrying or awaiting_token. A
completion from an older token/attempt must not overwrite newer token state. If
an old-token attempt was accepted after rotation, complete an end attempt for the
current token within the remaining delivery budget. A rejection of an old token
does not reject its replacement. Permanent rejection of the current token enters
awaiting_token without repeatedly retrying that token. A new token resumes
delivery if still within the retry deadline.

Terminal states are apns_accepted, cancelled, failed and expired. Detailed states
and response fields are in [OpenAPI](../contracts/openapi.json). Token updates and
schedule changes must not reopen a terminal job.

Store sensitive job details only while needed, and remove token/timing details
from active storage within 24 hours after reaching a terminal state. Keep a
minimal closed marker (jobId, final revision, last method/body hash, status and
minimal delivery evidence) for the lifetime of the registered identity. This
replaces the earlier unsafe proposal to remove all tombstones after 24 hours.
Cleared timing/acceptedAt fields in GET may be null. Do not scan all closed
markers when selecting the next scheduled job.

## Time and delivery

Input dates are real UTC calendar timestamps, whole seconds, years 1970-9999.
Require startsAt < endsAt and startsAt <= notificationAt <= endsAt.
activityEndsAt must equal min(endsAt, startsAt + 8 hours). Do not impose a short
booking horizon: iOS 26 scheduled Activities can start well into the future.
If the end time has passed but startsAt + 12 hours has not, send immediately.
After that maximum Activity lifetime, return 410 ACTIVITY_LIFETIME_EXCEEDED and
keep a terminal marker.

Persist intent/attempt state before APNs I/O. Use one Alarm to handle the earliest
due job, retry and cleanup, then re-arm it. Alarm invocation is at-least-once;
exactly-once delivery across an APNs call and storage is impossible. Allow
duplicate end pushes and guard completion with its attempt identity.

APNs headers/payload are fixed by the shared
[end-content vector](../contracts/end-content-state-v1.json). Use liveactivity,
priority 10, fixed topic org.tknw.punctual.push-type.liveactivity, event=end,
current Unix timestamp, dismissal-date in the past and minimal content-state.
Do not include reminder text, custom templates, a sound, or an alert.
APNs expiration is startsAt + 12 hours. APNs acceptance is not device delivery.

contentStateVersion=1 uses displayVersion=8 and the existing required ContentState
fields. Content-state Date values use Swift's reference epoch (2001-01-01), while
APNs timestamp/dismissal-date/expiration use Unix seconds. New optional custom
presentation fields must have decoder defaults so this minimal end payload stays
compatible. This encoding must be tested on both sides and then with a device.

Retry network/unknown outcomes, 429 and 5xx up to eight total attempts within 15
minutes of the first attempt, clipped at startsAt + 12 hours. Backoff delays are
5, 15, 30, 60, 120, 240, 300 seconds; honor a later Retry-After, and expire instead
if it lies beyond the deadline. Authentication-provider token expiry triggers a
fresh server JWT rather than exposing an app error; fixed configuration errors
must be visible operationally, not retried forever. Do not resend a rejected
activity token without a new token update. No promise of exact-time dismissal.

## iCloud ordering

This service does not receive or verify CloudKit save receipts. The app enforces:

- Sync ON: durable local save, exact corresponding CloudKit commit, then enqueue API work.
- Sync OFF: durable local save, then enqueue API work.
- A cloud import already represents committed cloud data for that device.
- A stale acknowledgment cannot acknowledge a newer mutation.
- Outbox intent/body and revision survive restart; coalesce unsent stale intent.
- Re-read current committed desired state on conflict, never just increase the
  revision of an obsolete body.
- Activity token rotation and local Activity dismissal/cancellation do not wait
  for CloudKit: those identifiers and actions are device-local.
- Each device updates its own jobs after its own cloud import/export. No global
  account registry or cross-device direct job updates in v1.

## Limits and errors

Use the structured error schema from [OpenAPI](../contracts/openapi.json) and
Retry-After on 429/503. Do not return or log tokens, assertions or reminder data.

Initial configurable limits: 128 KiB attestation request, 8 KiB business request,
4096 hex characters per token, 16 nonterminal jobs per key, eight pending
challenges per key, 120 authenticated requests/minute/key, and 100000 distinct
job markers per key. Marker capacity cannot block cancellation of an existing
job. Apply an edge IP limit of 60 unauthenticated challenge/registration
requests/minute/IP and a key-local issue limit; keep any IP rate state transient.
Do not allocate unbounded storage for rejected unauthenticated input. Document
operational overrides and the exact 429 reason.
