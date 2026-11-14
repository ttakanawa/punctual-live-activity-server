# Automated validation and remaining owner tests

The implementation was checked with these commands, all with exit status 0:

  ```sh
  cargo fmt --check
  cargo clippy --locked --all-targets -- -D warnings
  cargo clippy --locked --target wasm32-unknown-unknown -- -D warnings
  cargo test --locked
  npm run check:contract
  npm run build
  npm test
  npx wrangler deploy --dry-run --env development --outdir /tmp/punctual-dev-dry
  npx wrangler deploy --dry-run --env production --outdir /tmp/punctual-prod-dry
  npm audit --audit-level=moderate
  git diff --check
  ```

Rust tests: 10 passed. Workers runtime tests: 10 passed. Dependency audit: zero
reported npm vulnerabilities. Both dry runs package a 1.28 MiB Worker (about
433 KiB compressed); they do not upload a Worker or provision a namespace.

Coverage includes both unchanged shared fixtures, strict input validation, a
complete synthetic attestation with ephemeral keys, Apple's real certificate
chain at its historical validity time, genuine ECDSA assertions and APNs ES256
JWTs, counter and challenge replay, environment mismatch, foreign ownership,
stale/equal/conflicting revisions, UInt64 boundaries, cancel-before-create,
resurrection after cleanup, bounded retry/lifetime behavior, permanent token
rejection, token rotation during an APNs call, cancellation during an APNs call,
actual Durable Object eviction with recovery, terminal cleanup, and cancellation
at marker capacity. APNs is mocked only in runtime tests; the production HTTP
handler always verifies App Attest.

No credentials were supplied for deployment. Real Apple attestation on a device,
deployed APNs acceptance, and ActivityKit dismissal on a device have **not** been
verified. The owner must register the exact GitHub/Apple/Cloudflare values and
execute [the smoke/device procedure](deployment.md#L1). Optional Apple fraud-risk
receipt refresh and a globally aggregated edge IP rate limit are not implemented;
the retained receipt is not an authentication grant, and Cloudflare's transient
edge rate limiter operates approximately per location. Detailed operational
behavior is in [the deployment guide](deployment.md#L1).
