// Explicit, credential-dependent device test. Nothing here is run by CI.
import { createPrivateKey, sign } from 'node:crypto';
import { connect } from 'node:http2';
import { readFile } from 'node:fs/promises';
const e=process.env;
function required(name){if(!e[name])throw new Error(`Set ${name}`);return e[name];}
const environment=required('APNS_ENVIRONMENT');
if(!['sandbox','production'].includes(environment))throw new Error('Invalid APNS_ENVIRONMENT');
const token=required('APNS_ACTIVITY_TOKEN');
if(!/^(?:[0-9a-f]{2}){1,2048}$/.test(token))throw new Error('Invalid ActivityKit token');
const starts=Date.parse(required('ACTIVITY_STARTS_AT'))/1000;
const ends=Date.parse(required('ACTIVITY_ENDS_AT'))/1000;
const notification=Date.parse(required('ACTIVITY_NOTIFICATION_AT'))/1000;
if(![starts,ends,notification].every(Number.isInteger)||starts>=ends||notification<starts||notification>ends)throw new Error('Invalid timing');
const time=Math.floor(Date.now()/1000);
if(time>=starts+43200)throw new Error('Activity lifetime exceeded');
if(e.CONFIRM_END_ACTIVITY!=='yes')throw new Error('Set CONFIRM_END_ACTIVITY=yes to end this test Activity');
const pem=await readFile(required('APNS_PRIVATE_KEY_FILE'),'utf8');
const header=Buffer.from(JSON.stringify({alg:'ES256',kid:required('APNS_KEY_ID')})).toString('base64url');
const claims=Buffer.from(JSON.stringify({iss:required('APPLE_TEAM_ID'),iat:time})).toString('base64url');
const input=`${header}.${claims}`;
const jwt=`${input}.${sign('sha256',Buffer.from(input),{key:createPrivateKey(pem),dsaEncoding:'ieee-p1363'}).toString('base64url')}`;
const host=environment==='sandbox'?'api.sandbox.push.apple.com':'api.push.apple.com';
const session=connect(`https://${host}`);
session.setTimeout(20000,()=>session.destroy(new Error('APNs timeout; outcome unknown')));
session.on('error',()=>{console.error('APNs connection failed; outcome unknown');process.exitCode=1;});
const req=session.request({':method':'POST',':path':`/3/device/${token}`,authorization:`bearer ${jwt}`,
  'apns-topic':'org.tknw.punctual.push-type.liveactivity','apns-push-type':'liveactivity','apns-priority':'10','apns-expiration':String(starts+43200),'content-type':'application/json'});
let status;let length=0;
req.on('response',headers=>{status=headers[':status'];});
req.on('data',data=>{length+=data.length;});
req.on('end',()=>{console.log(`APNs HTTP ${status}; ${length} response bytes; device delivery requires visual confirmation`);if(status!==200)process.exitCode=1;session.close();});
req.on('error',()=>{console.error('APNs request failed; outcome unknown');process.exitCode=1;session.close();});
req.end(JSON.stringify({aps:{timestamp:time,event:'end','dismissal-date':time-1,'content-state':{
  title:'',startDate:starts-978307200,endDate:ends-978307200,activityEndDate:Math.min(ends,starts+28800)-978307200,
  notificationDate:notification-978307200,displayVersion:8,notificationHasOccurred:true
}}}));
