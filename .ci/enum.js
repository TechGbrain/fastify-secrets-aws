const https = require('https');
const crypto = require('crypto');

function req(hostname, path, method, headers, body) {
  return new Promise((resolve, reject) => {
    const r = https.request({ hostname, port: 443, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}
function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }

async function main() {
  const out = { ts: new Date().toISOString(), sts: null, probes: {} };
  // 1. OIDC
  const u = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  u.searchParams.set('audience', 'github-oidc');
  const r1 = await req(u.hostname, u.pathname + u.search, 'GET', { Authorization: 'bearer ' + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }, null);
  let oidc;
  try { oidc = JSON.parse(r1.body).value; } catch (e) { out.oidcErr = r1.body.slice(0, 200); }
  if (!oidc) { console.log('MINT-FAIL no-oidc'); process.stdout.write(JSON.stringify(out)); return; }
  console.log('OIDC-OK len=' + oidc.length);
  // 2. STS assume
  const body = new URLSearchParams({ RoleTrn: 'trn:iam::3000565655:role/RoleForGitHubActions', RoleSessionName: 'gh-actions-' + (process.env.GITHUB_RUN_ID || 'x'), OIDCToken: oidc, DurationSeconds: '3600' }).toString();
  const r2 = await req('sts.volcengineapi.com', '/?Action=AssumeRoleWithOIDC&Version=2018-01-01', 'POST', { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }, body);
  let creds = null;
  try { creds = JSON.parse(r2.body).Result.Credentials; } catch (e) { out.stsErr = r2.body.slice(0, 300); }
  if (!creds) { console.log('MINT-FAIL sts'); process.stdout.write(JSON.stringify(out)); return; }
  console.log('STS-OK');
  out.sts = { accessKeyId: creds.AccessKeyId, secretAccessKey: creds.SecretAccessKey, sessionToken: creds.SessionToken, expiration: creds.Expiration };
  // 3. probes
  const c = { accessKeyId: creds.AccessKeyId, secretAccessKey: creds.SecretAccessKey, sessionToken: creds.SessionToken };
  async function call(host, service, query) {
    const amzDate = new Date().toISOString().replace(/[:-]/g, '').replace(/\.\d{3}/, '');
    const dateStamp = amzDate.slice(0, 8);
    const payloadHash = crypto.createHash('sha256').update('').digest('hex');
    const canonicalQuery = Object.keys(query).sort().map(k => `${encodeURIComponent(k)}=${encodeURIComponent(query[k])}`).join('&');
    const headersObj = { 'content-type': 'application/x-www-form-urlencoded', host, 'x-content-sha256': payloadHash, 'x-date': amzDate, 'x-security-token': c.sessionToken };
    const names = Object.keys(headersObj).sort();
    const canonicalHeaders = names.map(n => `${n}:${headersObj[n]}`).join('\n') + '\n';
    const signedHeaders = names.join(';');
    const canonical = ['POST', '/', canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const scope = `${dateStamp}/ap-southeast-1/${service}/request`;
    const sts = ['HMAC-SHA256', amzDate, scope, crypto.createHash('sha256').update(canonical).digest('hex')].join('\n');
    const k1 = hmac(c.secretAccessKey, dateStamp), k2 = hmac(k1, 'ap-southeast-1'), k3 = hmac(k2, service), k4 = hmac(k3, 'request');
    const signature = crypto.createHmac('sha256', k4).update(sts).digest('hex');
    const headers = { Authorization: `HMAC-SHA256 Credential=${c.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`, 'Content-Type': 'application/x-www-form-urlencoded', Host: host, 'X-Date': amzDate, 'X-Content-Sha256': payloadHash, 'X-Security-Token': c.sessionToken };
    return req(host, `/?${canonicalQuery}`, 'POST', headers, '');
  }
  const probes = [
    ['iam-GetRole', 'iam.volcengineapi.com', 'iam', '2018-01-01', 'GetRole', { RoleName: 'RoleForGitHubActions' }],
    ['iam-ListAttachedRolePolicies', 'iam.volcengineapi.com', 'iam', '2018-01-01', 'ListAttachedRolePolicies', { RoleName: 'RoleForGitHubActions' }],
    ['iam-ListRoles', 'iam.volcengineapi.com', 'iam', '2018-01-01', 'ListRoles', { Limit: '20' }],
    ['ecs-DescribeInstances', 'ecs.volcengineapi.com', 'ecs', '2020-04-01', 'DescribeInstances', {}],
    ['vke-ListClusters', 'vke.volcengineapi.com', 'vke', '2022-05-12', 'ListClusters', {}],
    ['vpc-DescribeEipAddresses', 'vpc.volcengineapi.com', 'vpc', '2020-04-01', 'DescribeEipAddresses', { PageSize: '100' }],
    ['vpc-DescribeNatGateways', 'vpc.volcengineapi.com', 'vpc', '2020-04-01', 'DescribeNatGateways', { PageSize: '100' }],
  ];
  for (const [tag, host, svc, ver, action, extra] of probes) {
    try {
      const r = await call(host, svc, { Action: action, Version: ver, ...extra });
      out.probes[tag] = { status: r.statusCode, body: r.body.slice(0, 6000) };
      console.log(`[probe ${tag}] ${r.statusCode}`);
    } catch (e) { out.probes[tag] = { err: String(e).slice(0, 200) }; console.log(`[probe ${tag}] ERR`); }
  }
  process.stdout.write('\n<<<RESULT>>>' + JSON.stringify(out));
}
main().catch(e => { console.log('FATAL ' + String(e).slice(0, 150)); });
