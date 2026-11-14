import { env, SELF, runInDurableObject, runDurableObjectAlarm, evictDurableObject, reset } from 'cloudflare:test';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';

const text=new TextEncoder();
const bytes=s=>text.encode(s);
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
const sha=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
const iso=t=>new Date(t*1000).toISOString().replace('.000','');
const now=()=>Math.floor(Date.now()/1000);
function cbor(v) {
  const cat=(...xs)=>new Uint8Array(xs.flatMap(x=>Array.from(x)));
  const head=(major,n)=>n<24?[major*32+n]:n<256?[major*32+24,n]:[major*32+25,n>>8,n&255];
  if(typeof v==='string') { const x=bytes(v); return cat(head(3,x.length),x); }
  if(v instanceof Uint8Array) return cat(head(2,v.length),v);
  const entries=Object.entries(v); return cat(head(5,entries.length),...entries.flatMap(([k,x])=>[cbor(k),cbor(x)]));
}
function der(raw) {
  const number=b=>{ let a=Array.from(b); while(a.length>1&&a[0]===0)a.shift(); if(a[0]&128)a.unshift(0); return [2,a.length,...a]; };
  const r=number(raw.slice(0,32)),s=number(raw.slice(32)); return new Uint8Array([48,r.length+s.length,...r,...s]);
}
async function post(path,body) {
  return SELF.fetch(`https://api.test${path}`,{method:'POST',headers:{'Content-Type':'application/json','CF-Connecting-IP':`192.0.2.${Math.floor(Math.random()*250)+1}`},body:JSON.stringify(body)});
}
async function installation() {
  const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const publicKey=new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey));
  const keyId=b64(await sha(publicKey));
  const stub=env.INSTALLATIONS.get(env.INSTALLATIONS.idFromName(`development:${keyId}`));
  const identity=crypto.randomUUID();
  // Seed only local test storage; every business HTTP request still verifies a real signature.
  await runInDurableObject(stub,async (_obj,state)=>state.storage.put('meta',{
    key:keyId,deployment:'development',identity,registration:{public_key:Array.from(publicKey),receipt:[],environment:'development',app_id:'TESTPREFIX.org.tknw.punctual'},fingerprint:'test',counter:0,challenges:[],
    issue:{minute:0,count:0},requests:{minute:0,count:0},markers:0,active:0
  }));
  let counter=0;
  async function signed(method,path,body,overrides={}) {
    const challengeRes=await post('/v1/auth/challenges',{purpose:'assertion',keyId});
    expect(challengeRes.status).toBe(201); const challenge=await challengeRes.json();
    const raw=method==='GET'?'':JSON.stringify(body);
    const message=`punctual-api-v1\n${overrides.environment??'development'}\n${keyId}\n${challenge.challengeId}\n${challenge.challenge}\n${method}\n${path}\n${hex(await sha(bytes(raw)))}\n`;
    const auth=new Uint8Array(37); auth.set(await sha(bytes('TESTPREFIX.org.tknw.punctual'))); new DataView(auth.buffer).setUint32(33,++counter);
    const hash=await sha(bytes(message)); const composite=new Uint8Array(auth.length+hash.length); composite.set(auth); composite.set(hash,auth.length);
    const signature=der(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.privateKey,composite)));
    const headers={'Content-Type':'application/json','X-App-Attest-Key-Id':keyId,'X-App-Attest-Challenge-Id':challenge.challengeId,'X-App-Attest-Assertion':b64(cbor({signature,authenticatorData:auth}))};
    const request=new Request(`https://api.test${path}`,{method,headers,...(method==='GET'?{}:{body:raw})});
    const received=await SELF.fetch(request.clone());
    // Drain the binding response before a test evicts its Durable Object.
    const response=new Response(await received.text(),{status:received.status,headers:received.headers});
    return {response,request};
  }
  return {keyId,stub,identity,signed};
}
const jobBody=(revision='1',seconds=120)=>({revision,pushToken:'aabb',startsAt:iso(now()-60),notificationAt:iso(now()+seconds),endsAt:iso(now()+seconds),activityEndsAt:iso(now()+seconds),contentStateVersion:1});
async function dueNow(stub,id,change=()=>{}) {
  await runInDurableObject(stub,async (_obj,state)=>{
    const job=await state.storage.get(`job/${id}`);
    if(job.due!=null)await state.storage.delete(`due/${String(job.due).padStart(12,'0')}/${id}`);
    change(job);job.due=now()-1;await state.storage.put(`job/${id}`,job);
    await state.storage.put(`due/${String(job.due).padStart(12,'0')}/${id}`,id);await state.storage.setAlarm(Date.now()+1000);
  });
}
let apnsReplies=[];
function apnsReply(path,reply) { apnsReplies.push({path,reply}); }
beforeEach(()=>{
  apnsReplies=[];
  vi.stubGlobal('fetch',async (input,init)=>{
    const request=new Request(input,init);const expected=apnsReplies.shift();
    expect(expected,`unexpected network fetch to ${new URL(request.url).host}`).toBeDefined();
    expect(request.url).toBe(`https://api.sandbox.push.apple.com${expected.path}`);
    expect(request.method).toBe('POST');
    return expected.reply(request);
  });
});
afterEach(async()=>{expect(apnsReplies).toHaveLength(0);vi.unstubAllGlobals();await reset();});

it('fails closed for unknown keys, malformed bodies, queries and fake attestation',async()=>{
  const keyId=b64(new Uint8Array(32));
  const unknown=await post('/v1/auth/challenges',{purpose:'assertion',keyId});expect(unknown.status).toBe(401);expect((await unknown.json()).error.code).toBe('KEY_NOT_REGISTERED');
  expect((await post('/v1/auth/challenges',{purpose:'attestation',keyId:keyId.slice(0,-1)})).status).toBe(400);
  const challenge=await (await post('/v1/auth/challenges',{purpose:'attestation',keyId})).json();
  const invalid=await post('/v1/auth/attestations',{keyId,challengeId:challenge.challengeId,attestationObject:b64(bytes('fake'))});
  expect(invalid.status).toBe(401);expect(invalid.headers.get('Cache-Control')).toBe('no-store');
  expect((await SELF.fetch('https://api.test/v1/auth/challenges?bad=1',{method:'POST'})).status).toBe(400);
  expect((await post('/v1/auth/challenges',{purpose:'attestation',keyId,extra:true})).status).toBe(400);
  const huge=await SELF.fetch('https://api.test/v1/auth/attestations',{method:'POST',headers:{'Content-Type':'application/json'},body:'a'.repeat(131073)});expect(huge.status).toBe(413);
});
it('consumes challenges atomically, protects ownership and preserves revision idempotency',async()=>{
  const a=await installation(),b=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`,body=jobBody('18446744073709551614');
  const first=await a.signed('PUT',path,body);expect(first.response.status).toBe(200);
  expect((await SELF.fetch(first.request)).status).toBe(401);
  expect((await b.signed('GET',path)).response.status).toBe(404);
  expect((await a.signed('PUT',path,body)).response.status).toBe(200);
  const conflict=await a.signed('PUT',path,{...body,pushToken:'ccdd'});expect(conflict.response.status).toBe(409);expect((await conflict.response.json()).error.code).toBe('REVISION_CONFLICT');
  const stale=await a.signed('DELETE',path,{revision:'1'});expect(stale.response.status).toBe(409);
  const mismatch=await a.signed('GET',path,undefined,{environment:'production'});expect(mismatch.response.status).toBe(401);
  expect((await a.signed('DELETE',path,{revision:'18446744073709551615'})).response.status).toBe(200);
  expect((await a.signed('GET',path)).response.status).toBe(200);
});
it('keeps cancel-before-create closed markers after cleanup without scanning history',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`;
  expect((await a.signed('DELETE',path,{revision:'2'})).response.status).toBe(200);
  await runInDurableObject(a.stub,async (_obj,state)=>{
    const job=await state.storage.get(`job/${id}`);await state.storage.delete(`due/${String(job.due).padStart(12,'0')}/${id}`);
    job.due=now()-1;job.terminal_at=now()-86401;await state.storage.put(`job/${id}`,job);await state.storage.put(`due/${String(job.due).padStart(12,'0')}/${id}`,id);
  });
  expect(await runDurableObjectAlarm(a.stub)).toBe(true);
  const resurrect=await a.signed('PUT',path,jobBody('3'));expect(resurrect.response.status).toBe(410);
  await runInDurableObject(a.stub,async (_obj,state)=>{const job=await state.storage.get(`job/${id}`);expect(job.token==null).toBe(true);expect(job.due==null).toBe(true);expect(job.revision).toBe('2');});
});
it('dispatches the fixed minimal APNs end payload and cleans sensitive storage',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`,body=jobBody('1',-1);
  let captured;
  apnsReply('/3/device/aabb',async request=>{
    captured={body:await request.text(),headers:request.headers};return new Response('',{status:200});
  });
  expect((await a.signed('PUT',path,body)).response.status).toBe(200);
  await runDurableObjectAlarm(a.stub);
  const view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('apns_accepted');expect(view.delivery.attemptCount).toBe(1);
  const payload=JSON.parse(captured.body);expect(payload.aps.event).toBe('end');expect(payload.aps['content-state'].title).toBe('');expect(payload.aps['content-state'].startDate).toBe(Date.parse(body.startsAt)/1000-978307200);expect(payload.aps.alert).toBeUndefined();
  expect(view.delivery.mayHaveBeenSent).toBe(true);
  expect(captured.headers.get('apns-push-type')).toBe('liveactivity');expect(captured.headers.get('apns-topic')).toBe('org.tknw.punctual.push-type.liveactivity');expect(captured.headers.get('authorization')).toMatch(/^bearer /);
  await dueNow(a.stub,id,job=>{job.terminal_at=now()-86401;});await runDurableObjectAlarm(a.stub);
  const cleaned=await (await a.signed('GET',path)).response.json();expect(cleaned.activityEndsAt).toBeNull();expect(cleaned.delivery.acceptedAt).toBeNull();expect(cleaned.delivery.mayHaveBeenSent).toBe(true);
});
it('restarts persisted in-flight work, honors retry-after and stops rejected tokens',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`,body=jobBody('1',-1);
  expect((await a.signed('PUT',path,body)).response.status).toBe(200);
  apnsReply('/3/device/aabb',async()=>Response.json({reason:'Unregistered'},{status:410}));
  await runDurableObjectAlarm(a.stub);expect((await (await a.signed('GET',path)).response.json()).status).toBe('awaiting_token');
  expect((await a.signed('PATCH',`${path}/push-token`,{revision:'2',pushToken:'ccdd'})).response.status).toBe(200);
  apnsReply('/3/device/ccdd',async()=>Response.json({reason:'TooManyRequests'},{status:429,headers:{'retry-after':'120'}}));
  await runDurableObjectAlarm(a.stub);const view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('retrying');expect(view.delivery.attemptCount).toBe(2);
  await runInDurableObject(a.stub,async (_obj,state)=>{const job=await state.storage.get(`job/${id}`);expect(job.due).toBeGreaterThanOrEqual(now()+118);});
});
it('fences an old-token acceptance after a concurrent rotation and finishes the replacement',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`;
  expect((await a.signed('PUT',path,jobBody('1',-1))).response.status).toBe(200);
  apnsReply('/3/device/aabb',async()=>{
    expect((await a.signed('PATCH',`${path}/push-token`,{revision:'2',pushToken:'ccdd'})).response.status).toBe(200);
    return new Response('',{status:200});
  });
  await runDurableObjectAlarm(a.stub);
  let view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('retrying');expect(view.revision).toBe('2');expect(view.delivery.state).toBe('accepted');
  const changed=await a.signed('PUT',path,jobBody('3',300));expect(changed.response.status).toBe(409);const error=(await changed.response.json()).error;expect(error.code).toBe('DISPATCH_STARTED');expect(error.details).toEqual({revision:'2',status:'retrying'});
  await dueNow(a.stub,id);apnsReply('/3/device/ccdd',async()=>new Response('',{status:200}));await runDurableObjectAlarm(a.stub);
  view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('apns_accepted');expect(view.delivery.attemptCount).toBe(2);
});
it('preserves cancellation when an in-flight APNs request later succeeds',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`;
  expect((await a.signed('PUT',path,jobBody('1',-1))).response.status).toBe(200);
  apnsReply('/3/device/aabb',async()=>{
    expect((await a.signed('DELETE',path,{revision:'2'})).response.status).toBe(200);
    return new Response('',{status:200});
  });
  await runDurableObjectAlarm(a.stub);const view=await (await a.signed('GET',path)).response.json();
  expect(view.status).toBe('cancelled');expect(view.delivery.state).toBe('accepted');expect(view.delivery.mayHaveBeenSent).toBe(true);
});
it('recovers an attempt after actual Durable Object eviction without losing intent',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`;
  expect((await a.signed('PUT',path,jobBody('1',-1))).response.status).toBe(200);
  await dueNow(a.stub,id,job=>{job.dispatch_started=true;job.first_attempt=now()-30;job.status='dispatching';job.delivery.state='in_flight';job.delivery.attemptCount=1;job.attempt={id:crypto.randomUUID(),token_hash:'old',started:now()-30};});
  await evictDurableObject(a.stub);await runDurableObjectAlarm(a.stub);
  let view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('retrying');expect(view.delivery.state).toBe('unknown');expect(view.delivery.mayHaveBeenSent).toBe(true);
  await dueNow(a.stub,id);apnsReply('/3/device/aabb',async()=>new Response('',{status:200}));await runDurableObjectAlarm(a.stub);
  view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('apns_accepted');expect(view.delivery.attemptCount).toBe(2);
});
it('does not let marker capacity prevent cancelling an existing job',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`;
  expect((await a.signed('PUT',path,jobBody())).response.status).toBe(200);
  await runInDurableObject(a.stub,async(_obj,state)=>{const meta=await state.storage.get('meta');meta.markers=100000;await state.storage.put('meta',meta);});
  const rejected=await a.signed('DELETE',`/v1/end-jobs/${crypto.randomUUID()}`,{revision:'1'});expect(rejected.response.status).toBe(429);expect(rejected.response.headers.get('retry-after')).toBe('60');expect((await rejected.response.json()).error.code).toBe('JOB_MARKER_CAPACITY');
  expect((await a.signed('DELETE',path,{revision:'2'})).response.status).toBe(200);
});
it('recognizes an identical successful registration replay without resetting identity or counter',async()=>{
  const a=await installation(),challengeId=crypto.randomUUID(),attestationObject=b64(bytes('opaque previously verified object'));
  const fingerprint=hex(await sha(bytes(`development\n${a.keyId}\n${challengeId}\n${attestationObject}`)));
  await runInDurableObject(a.stub,async(_obj,state)=>{const meta=await state.storage.get('meta');meta.counter=7;meta.fingerprint=fingerprint;meta.challenges=[];await state.storage.put('meta',meta);});
  const replay=await post('/v1/auth/attestations',{keyId:a.keyId,challengeId,attestationObject});
  expect(replay.status).toBe(200);expect((await replay.json()).installationId).toBe(a.identity);
  const different=await post('/v1/auth/attestations',{keyId:a.keyId,challengeId:crypto.randomUUID(),attestationObject});expect(different.status).toBe(401);expect((await different.json()).error.code).toBe('CHALLENGE_REPLAYED');
  await runInDurableObject(a.stub,async(_obj,state)=>{const meta=await state.storage.get('meta');expect(meta.counter).toBe(7);expect(meta.identity).toBe(a.identity);});
});
it('refreshes an expired APNs provider JWT inside the bounded delivery budget',async()=>{
  const a=await installation(),id=crypto.randomUUID(),path=`/v1/end-jobs/${id}`;
  const issued=request=>JSON.parse(atob(request.headers.get('authorization').slice(7).split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).iat;
  expect((await a.signed('PUT',path,jobBody('1',-1))).response.status).toBe(200);
  let original;
  apnsReply('/3/device/aabb',async request=>{original=issued(request);return Response.json({reason:'ExpiredProviderToken'},{status:403});});
  await runDurableObjectAlarm(a.stub);
  let view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('retrying');expect(original%1200).toBe(0);
  await dueNow(a.stub,id);
  apnsReply('/3/device/aabb',async request=>{expect(issued(request)).toBeGreaterThanOrEqual(now()-2);return new Response('',{status:200});});
  await runDurableObjectAlarm(a.stub);view=await (await a.signed('GET',path)).response.json();expect(view.status).toBe('apns_accepted');expect(view.delivery.attemptCount).toBe(2);
});
it('releases storage for expired challenges that never registered an identity',async()=>{
  const raw=crypto.getRandomValues(new Uint8Array(32)),keyId=b64(raw);
  const challenge=await post('/v1/auth/challenges',{purpose:'attestation',keyId});expect(challenge.status).toBe(201);await challenge.text();
  const stub=env.INSTALLATIONS.get(env.INSTALLATIONS.idFromName(`development:${keyId}`));
  await runInDurableObject(stub,async(_obj,state)=>{const meta=await state.storage.get('meta');meta.challenges.forEach(c=>c.expires=now()-1);await state.storage.put('meta',meta);await state.storage.setAlarm(Date.now()+1000);});
  await runDurableObjectAlarm(stub);
  await runInDurableObject(stub,async(_obj,state)=>{expect((await state.storage.list()).size).toBe(0);expect(await state.storage.getAlarm()).toBeNull();});
  const expired=await post('/v1/auth/attestations',{keyId,challengeId:crypto.randomUUID(),attestationObject:b64(bytes('expired proof'))});expect(expired.status).toBe(401);expect((await expired.json()).error.code).toBe('CHALLENGE_EXPIRED');
});
