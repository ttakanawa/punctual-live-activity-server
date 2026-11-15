import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const signing=JSON.parse(readFileSync('contracts/signing-v1.json'));
const end=JSON.parse(readFileSync('contracts/end-content-state-v1.json'));
const spec=JSON.parse(readFileSync('contracts/openapi.json'));
const revisionErrors=JSON.parse(readFileSync('contracts/revision-errors-v1.json'));
const sha=s=>createHash('sha256').update(s).digest('hex');
assert.equal(sha(signing.rawBody),signing.bodySHA256Hex);
assert.equal(sha(signing.signingMessage),signing.clientDataHashHex);
assert.equal(sha(Buffer.from(signing.challenge,'base64')),signing.attestationClientDataHashHex);
assert.equal(Object.keys(spec.paths).length,4);
assert.deepEqual(JSON.parse(signing.rawBody),end.request);
assert.equal(Date.parse(end.request.startsAt)/1000+43200,Number(end.headers['apns-expiration']));
assert.equal(end.payload.aps['content-state'].startDate+978307200,Date.parse(end.request.startsAt)/1000);
assert.deepEqual(revisionErrors.cases.map(c=>c.response.error.code),['STALE_REVISION','REVISION_CONFLICT','DISPATCH_STARTED']);
for(const c of revisionErrors.cases) {
  assert.equal(c.statusCode,409);
  assert.deepEqual(Object.keys(c.response),spec.components.schemas.Error.required);
  assert.deepEqual(Object.keys(c.response.error).sort(),[...spec.components.schemas.Error.properties.error.required,'details'].sort());
  assert.equal(c.response.error.details.currentRevision,c.currentRevision);
  assert.equal(c.response.error.details.status,c.currentStatus);
  assert.deepEqual(Object.keys(c.response.error.details).sort(),['currentRevision','status']);
  for(const revision of [c.currentRevision,c.requestRevision]) {
    assert.equal(typeof revision,'string');
    assert.match(revision,/^[1-9][0-9]{0,19}$/);assert.ok(BigInt(revision)<=18446744073709551615n);
  }
}
console.log('Shared signing, UTC, Swift reference-epoch and 409 revision error fixtures passed');
