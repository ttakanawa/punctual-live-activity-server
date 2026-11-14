# Implementation coordination

## Authorized work

The owner approved implementation, a new public server repository registered in
Orca, a separate server Orca worker, a separate iCloud Orca worker/worktree, and
app integration by the coordinating worker. The server uses Rust, Workers,
Wrangler, SQLite-backed Durable Objects via KV API, Alarms and GitHub Actions.
Never add external Workers KV. API identity and time details are in
[API v1](api-v1.md); signatures and ContentState use the shared
[contract directory](../contracts/).

The app repository is https://github.com/ttakanawa/notification-ios. Its coordinator
workspace is /Users/tknw/orca/workspaces/nomad-reminder/oystercatcher. The starting
commit is 184a43cddbfc6324024402934e537c730fb77017 on fix-live-activity-expiration.
That workspace is a separate repository, so this directory is not linked as a
source path. Read the app files locally when checking compatibility.

## iCloud worker ownership

Implement local persistence independent of the account-bound SwiftData CloudKit
mirror. Turning off app/system iCloud or signing out must not lose local data.
Re-enabling sync must preserve and merge local/cloud data. Preserve UUIDs, tags,
relationships and raw schedule payload bytes, including unsupported/corrupt
payloads; do not decode/re-encode them destructively. Preserve losing values in
material conflicts rather than relying solely on device updatedAt clocks.

Add a per-device in-app sync switch. Both the OS permission and app preference
must permit sync. Persist OFF across relaunch. Check the current container user
record identity before publishing to a different account. Ask in the app before
moving retained data to a new account; refusing leaves the app switch OFF.
Unknown/offline identity is not evidence of a different account. Do not let
automatic sync publish before that decision.

SwiftData automatic CloudKit export notifications do not identify individual
saved mutations. Use a mechanism with exact mutation/record commit results,
normally CKSyncEngine plus a local-only store. Existing CloudKit data/schema
must be migrated without silent deletion. Analyze compatibility with legacy
CD_* records and devices; retain recovery copies. Do not purge production data
or account settings as part of development/testing.

Provide a Sendable application-layer commit gate, preferably named
ReminderCloudCommitChecking, with asynchronous canPublish(ReminderSnapshot) and
changes() -> AsyncStream<Void>. Return true only after durable local save in
local-only mode, or cloud acknowledgment for the exact current snapshot in
cloud mode; imported cloud snapshots count as committed. Include account scope
and precise mutation fingerprints internally; updatedAt alone is insufficient.
An old acknowledgment must never release a newer edit. Notify the coordinator
early with the exact public symbols and paths so app integration can start.

Implement persistence and iCloud sync for both a global display customization and
optional per-reminder overrides. Shared proposed domain value types (owned by
this worker, coordinate any changes before app integration):

- DisplayCustomization: Codable/Equatable/Sendable, schemaVersion=1, optional
  notification and liveActivity templates.
- Each template has title and body strings; nil per-surface override inherits
  the global setting, and nil global setting inherits the built-in appearance.
- Per-reminder customization defaults to nil. Preserve unknown future payloads.
- Supported token editing/rendering and purchase gating are coordinator-owned.

Own persistence, migration, CloudKit services, cloud sync status/settings UI and
related domain/repository changes. You may adapt app composition/lifecycle as
needed; report these paths. The coordinator will not concurrently edit those
shared composition files before integration. Prefer a standalone iCloud settings
section to limit SettingsView conflicts. Do not implement StoreKit, API transport,
ActivityKit close UI, or notification customization UI.

Do not add cloud-data deletion, storage-size display, or remotely disabling other
devices: the user explicitly removed those requirements. Send API/symbol
decisions early, then complete tests, commits and a separate draft PR against
main. Do not merge. Report migration risks and unverified real-device cases.

## Coordinator ownership

Implement App Attest API client and durable outbox; adopt pushType.token,
token/state observation, and exact cloud commit gating. Each live Activity gets
a local job UUID and monotonic revision. Offline work survives restart.

Add a close button to expanded Dynamic Island and Lock Screen presentations via
LiveActivityIntent. It ends only that occurrence on that device, persists local
suppression before awaiting ActivityKit, and queues server cancellation. Normal
reminder alerts and future occurrences remain. This is free for every user.

Add a non-consumable StoreKit purchase unlocking notification/Live Activity
display customization. The owner selected free-form text templates in addition
to field selection, global defaults plus per-reminder overrides, and iCloud sync
of both. Purchase rights are verified StoreKit entitlements, not an iCloud flag.
An unentitled device retains synced preferences but renders the standard view.
Never charge for close buttons or end scheduling. Preserve preference data on
revocation. Implement restore, preview, validation, pending/cancelled purchase
handling and appropriate StoreKit tests.

Use one product ID, org.tknw.punctual.display_customization, configured in App
Store Connect by the owner. Display StoreKit's localized product price; never
hardcode a sales price. Provide both notification and Live Activity settings.
Initially support title, notes, notification time and source time zone tokens;
remaining/elapsed native timers are Live Activity-only. Keep standard notification
title/body system layout and fixed app safety/close controls outside templates.

## Server worker ownership and delivery

Implement the complete service, real App Attest validation, durable lifecycle,
APNs signing/delivery and retry behavior, Rust unit tests and Workers runtime
integration tests. Use the pre-existing shared fixtures. API contract changes
must be proposed to the coordinator, not silently made.

Build IaC/deployment with Wrangler, separate dev/prod namespaces/migrations and
manual GitHub Actions deployment. Document exact owner setup and registration:
CLOUDFLARE_API_TOKEN secret, CLOUDFLARE_ACCOUNT_ID variable, environment-scoped
APNS_PRIVATE_KEY secret, APNS_KEY_ID variable, APPLE_TEAM_ID and
APPLE_APP_ID_PREFIX variables, plus independently configured APNs/App Attest
environments and the fixed bundle/topic. No secret may enter source or artifacts.
The owner will manually register those values; use a manual credential-dependent
APNs smoke test and explicitly report it unverified until run.

Prepare a draft PR with a concrete implementation description, tests, exact
GitHub environment/repository setup, links to documentation and known limitations.
Do not merge or pretend credentials-dependent deployment/device testing passed.

## Evidence

Test replay and environment mismatch, foreign ownership, stale/equal/conflicting
revisions, cancel-before-create, late resurrection beyond 24h, token rotation
races, cancellation during an in-flight APNs request, Alarm restart, and storage
cleanup. Report command results and remaining blockers; nonzero checks are
failures to fix or explain, not a successful deliverable.
