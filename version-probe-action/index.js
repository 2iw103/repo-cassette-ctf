'use strict';

// Minimal low-version matrix for CreateArtifact.  It checks whether any
// pre-v4 protocol version delivers an unarchived body with stored MIME.

const crypto = require('node:crypto');
const https = require('node:https');

const SERVICE = 'github.actions.results.api.v1.ArtifactService';
const ODD_TYPE = '\x85application/json';

function backendIds(token) {
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  const scope = String(claims.scp || '').split(' ').find(x => x.startsWith('Actions.Results:'));
  const fields = scope?.split(':') || [];
  if (fields.length !== 3) throw new Error('Actions.Results scope unavailable');
  return {run: fields[1], job: fields[2]};
}

function request(url, {method = 'GET', headers = {}, body = null} = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {method, headers}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks)}));
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
  let parsed = {};
  try { parsed = JSON.parse(response.body.toString()); } catch {}
  return {response, parsed};
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
  if (response.status < 200 || response.status >= 300) throw new Error(`blob PUT HTTP ${response.status}`);
}

function carrier(repositoryPath) {
  return Buffer.from(JSON.stringify({
    full_name: repositoryPath,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'Repo Cassette low-version carrier',
    stargazers_count: 0,
  }));
}

function contentTypeHex(response) {
  const value = Array.isArray(response.headers['content-type'])
    ? response.headers['content-type'][0] : response.headers['content-type'] || '';
  return Buffer.from(value, 'latin1').toString('hex');
}

async function probe(token, ids, repository, nonce, index, version, mimeLabel, mime) {
  const name = `repo-cassette-version-${nonce}-${index}`;
  const createBody = {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    version,
  };
  if (mime !== undefined) createBody.mime_type = mime;
  const created = await twirp('CreateArtifact', token, createBody);
  const url = created.parsed.signed_upload_url || created.parsed.signedUploadUrl || '';
  const base = {
    version,
    mime: mimeLabel,
    createStatus: created.response.status,
    createOk: Boolean(created.parsed.ok),
    error: created.response.status >= 400
      ? String(created.parsed.msg || created.response.body.toString()).slice(0, 240) : '',
  };
  if (!url) return base;
  const placeholder = Buffer.from('{}');
  await putBlob(url, placeholder);
  const finalized = await twirp('FinalizeArtifact', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
    size: String(placeholder.length),
  });
  const artifactId = String(finalized.parsed.artifact_id || finalized.parsed.artifactId || '');
  if (!/^\d+$/.test(artifactId)) return {...base, finalizeStatus: finalized.response.status};
  const repositoryPath = `${repository}/actions/artifacts/${artifactId}/zip`;
  const body = carrier(repositoryPath);
  await putBlob(url, body);
  const signed = await twirp('GetSignedArtifactURL', token, {
    workflow_run_backend_id: ids.run,
    workflow_job_run_backend_id: ids.job,
    name,
  });
  const downloadUrl = signed.parsed.signed_url || signed.parsed.signedUrl || '';
  const direct = downloadUrl ? await request(downloadUrl, {headers: {'user-agent': 'repo-cassette-version-probe'}}) : null;
  return {
    ...base,
    finalizeStatus: finalized.response.status,
    artifactId,
    repositoryPath,
    directStatus: direct?.status || 0,
    contentTypeHex: direct ? contentTypeHex(direct) : '',
    bodyMatch: Boolean(direct?.body.equals(body)),
  };
}

async function main() {
  const token = process.env.ACTIONS_RUNTIME_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!token || !repository) throw new Error('Actions environment incomplete');
  const ids = backendIds(token);
  const nonce = `${process.env.GITHUB_RUN_ID}-${crypto.randomBytes(4).toString('hex')}`;
  const matrix = [];
  for (const version of [0, 1, 2, 3]) {
    matrix.push([version, 'nel', ODD_TYPE], [version, 'valid', 'application/json'], [version, 'omitted', undefined]);
  }
  matrix.push([-1, 'nel', ODD_TYPE]);
  for (const [index, [version, mimeLabel, mime]] of matrix.entries()) {
    const row = await probe(token, ids, repository, nonce, index, version, mimeLabel, mime);
    console.log(`VERSION_RESULT ${JSON.stringify(row)}`);
  }
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
