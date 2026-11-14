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
