# Punctual Live Activity Server

Authenticated end scheduling for Punctual Live Activities, implemented with Rust,
Cloudflare Workers, SQLite-backed Durable Objects, and Alarms.

The service stores an ActivityKit push token and timing information for each
installation's Live Activity. It does not store reminder titles, notes, URLs,
custom text, or iCloud account identifiers.

## Contract

- [OpenAPI](contracts/openapi.json) defines the HTTP interface.
- [API behavior](docs/api-v1.md) defines authentication, ordering, and delivery behavior.
- [Signing fixture](contracts/signing-v1.json) is shared by Rust and Swift tests.
- [End-content fixture](contracts/end-content-state-v1.json) fixes the ActivityKit wire format.
- [Coordination](docs/coordination.md) records implementation ownership and integration requirements.

Production deployment and real-device APNs verification require credentials
provided by the repository owner. Never commit credentials or deployment secrets.

## Implementation and validation

The service uses one SQLite Durable Object per deployment/key. Transactions
consume assertions and update jobs atomically; a due-time index and Alarms drive
APNs dispatch, bounded retries, recovery and sensitive-data cleanup. Closed job
markers remain for the registered identity's lifetime.

  ```sh
  cargo test --locked
  npm ci
  cargo install worker-build --version 0.9.0 --locked
  npm run build
  npm test
  npm run check:contract
  ```

Read [deployment and owner setup](docs/deployment.md#L1) for exact GitHub values,
Apple capabilities, Cloudflare registration and manual device testing. Deployment
uses a manually dispatched workflow, separately for development and production.
Automated runtime tests generate temporary keys locally and mock APNs; they do
not demonstrate deployed delivery.
