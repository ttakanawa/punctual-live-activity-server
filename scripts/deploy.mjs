import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const env=process.env;
function requireValue(name,pattern) {
  const value=env[name];
  if(!value || (pattern&&!pattern.test(value)) || value==='OWNERSETUP') throw new Error(`Missing or invalid ${name}`);
  return value;
}
const target=requireValue('DEPLOY_TARGET',/^(development|production)$/);
requireValue('CLOUDFLARE_API_TOKEN');requireValue('CLOUDFLARE_ACCOUNT_ID',/^[0-9a-f]{32}$/);
const privateKey=requireValue('APNS_PRIVATE_KEY');
const parsed=createPrivateKey(privateKey);
if(parsed.asymmetricKeyType!=='ec'||parsed.asymmetricKeyDetails.namedCurve!=='prime256v1') throw new Error('APNS_PRIVATE_KEY must be a P-256 PKCS#8 Apple key');
const vars={
  APPLE_TEAM_ID:requireValue('APPLE_TEAM_ID',/^[A-Z0-9]{10}$/),
  APPLE_APP_ID_PREFIX:requireValue('APPLE_APP_ID_PREFIX',/^[A-Z0-9]{10}$/),
  APNS_KEY_ID:requireValue('APNS_KEY_ID',/^[A-Z0-9]{10}$/),
  APP_ATTEST_ENVIRONMENT:requireValue('APP_ATTEST_ENVIRONMENT',/^(development|production)$/),
  APNS_ENVIRONMENT:requireValue('APNS_ENVIRONMENT',/^(sandbox|production)$/),
  ATTEST_ALLOWED_CATEGORIES:env.ATTEST_ALLOWED_CATEGORIES||(target==='production'?'2,4':'3'),
  ATTEST_ALLOWED_BUNDLE_VERSIONS:env.ATTEST_ALLOWED_BUNDLE_VERSIONS||''
};
const temp=mkdtempSync(join(tmpdir(),'punctual-deploy-'));
try {
  const file=join(temp,'secrets.json');writeFileSync(file,JSON.stringify({APNS_PRIVATE_KEY:privateKey}),{mode:0o600});
  const args=['wrangler','deploy','--env',target,'--secrets-file',file];
  for(const [k,v] of Object.entries(vars))args.push('--var',`${k}:${v}`);
  const result=spawnSync('npx',args,{stdio:'inherit',env});
  if(result.error)throw new Error('Could not start Wrangler');
  process.exitCode=result.status??1;
} finally { rmSync(temp,{recursive:true,force:true}); }
