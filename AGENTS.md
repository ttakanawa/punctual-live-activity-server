# Repository instructions

Implement the service in Rust for Cloudflare Workers. Use SQLite-backed Durable
Objects with their key-value storage API and Alarms. Do not add Workers KV or a
separate database service.

The approved interface is [OpenAPI](contracts/openapi.json) and the behavioral
contract is [API v1](docs/api-v1.md). Use the shared
[signing fixture](contracts/signing-v1.json) and
[end-content fixture](contracts/end-content-state-v1.json) in tests.

Do not silently weaken authentication or change the public contract. Ask the
coordinator about contract changes. Never add an unauthenticated production
fallback, fake attestation verification, embedded private keys, or production
test credentials.

The user has authorized implementing, committing, pushing the feature branch,
and opening a draft PR for this service. Do not merge the PR. Put exact GitHub
Secrets/Variables and Apple/Cloudflare setup steps in the PR and link maintained
deployment documentation. The account owner will register the credentials.

Report automated validation separately from deployed APNs and device testing.
Do not claim deployment or device delivery was verified without actual evidence.
