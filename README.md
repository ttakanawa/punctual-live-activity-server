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
- [409 error fixture](contracts/revision-errors-v1.json#L1) fixes currentRevision/status error details for Rust, Workers and Swift.
- [Coordination](docs/coordination.md) records implementation ownership and integration requirements.

Production deployment and real-device APNs verification require credentials
provided by the repository owner. Never commit credentials or deployment secrets.

## Implementation and validation

The service uses one SQLite Durable Object per deployment/key. Transactions
consume assertions and update jobs atomically; a due-time index and Alarms drive
APNs dispatch, bounded retries, recovery and sensitive-data cleanup. Closed job
markers remain for the registered identity's lifetime.

  ```sh
  mise trust
  mise install
  mise exec -- npm ci
  mise exec -- cargo test --locked
  mise exec -- npm run build
  mise exec -- npm test
  mise exec -- npm run check:contract
  ```

Local tools are pinned in [mise.toml](mise.toml#L1), including Rust, its Wasm
target, rustfmt, clippy, Node and worker-build. Use mise for local installation;
no standalone Rust installer or shell startup file changes are needed.

Read [deployment and owner setup](docs/deployment.md#L1) for exact GitHub values,
Apple capabilities, Cloudflare registration and manual device testing. Deployment
uses a manually dispatched workflow, separately for development and production.
Automated runtime tests generate temporary keys locally and mock APNs; they do
not demonstrate deployed delivery.
