'use strict';

// Bounded release-asset transport audit for Repo Cassette. Creates one
// temporary release, attempts three Content-Type values, reads a small query /
// Accept matrix, then deletes the release and tag. Tokens and redirect URLs are
// never printed.

const crypto = require('node:crypto');
const https = require('node:https');

const REPOSITORY = process.env.GITHUB_REPOSITORY;
const TOKEN = process.env.GITHUB_TOKEN;
const API = process.env.GITHUB_API_URL || 'https://api.github.com';

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

function apiHeaders(accept = 'application/vnd.github.v3+json') {
  return {
    accept,
    authorization: `Bearer ${TOKEN}`,
    'user-agent': 'repo-cassette-release-asset-audit',
    'x-github-api-version': '2022-11-28',
  };
}

async function api(path, {method = 'GET', body = null, accept, headers = {}} = {}) {
  const merged = {...apiHeaders(accept), ...headers};
  if (body) merged['content-length'] = String(body.length);
  return request(`${API}${path}`, {method, headers: merged, body});
}

function json(response) {
  try { return JSON.parse(response.body.toString()); } catch { return {}; }
}

function contentTypeHex(response) {
  const value = Array.isArray(response.headers['content-type'])
    ? response.headers['content-type'][0] : response.headers['content-type'] || '';
  return Buffer.from(value, 'latin1').toString('hex');
}

function locationShape(location) {
  if (!location) return null;
  const url = new URL(location);
  const counts = {};
  for (const key of url.searchParams.keys()) counts[key] = (counts[key] || 0) + 1;
  return {
    host: url.host,
    pathHash: crypto.createHash('sha256').update(url.pathname).digest('hex').slice(0, 12),
    queryKeys: Object.keys(counts).sort(),
    queryKeyCounts: counts,
  };
}

async function upload(uploadBase, name, mime, body) {
  const url = new URL(uploadBase.replace('{?name,label}', ''));
  url.searchParams.set('name', name);
  const response = await request(url, {
    method: 'POST',
    headers: {
      ...apiHeaders(),
      'content-type': mime,
      'content-length': String(body.length),
    },
    body,
  });
  const parsed = json(response);
  return {
    response,
    id: Number.isSafeInteger(parsed.id) ? parsed.id : 0,
    bodyMatch: false,
    error: response.status >= 400 ? String(parsed.message || response.body.toString()).slice(0, 180) : '',
  };
}

async function readAsset(assetId, suffix, accept, expected) {
  const first = await api(
    `/repos/${REPOSITORY}/releases/assets/${assetId}${suffix}`,
    {accept},
  );
  const location = first.headers.location || '';
  const final = location
    ? await request(location, {headers: {'user-agent': 'repo-cassette-release-asset-audit'}})
    : first;
  return {
    suffix,
    accept,
    firstStatus: first.status,
    firstContentTypeHex: contentTypeHex(first),
    location: locationShape(location),
    finalStatus: final.status,
    finalContentTypeHex: contentTypeHex(final),
    bodyMatch: final.body.equals(expected),
    bodyBytes: final.body.length,
  };
}

async function main() {
  if (!REPOSITORY || !TOKEN) throw new Error('Actions environment incomplete');
  const tag = `repo-cassette-release-audit-${process.env.GITHUB_RUN_ID}`;
  const createBody = Buffer.from(JSON.stringify({tag_name: tag, name: tag, draft: false, prerelease: false}));
  let releaseId = 0;
  try {
    const created = await api(`/repos/${REPOSITORY}/releases`, {
      method: 'POST',
      body: createBody,
      headers: {'content-type': 'application/json'},
    });
    const release = json(created);
    releaseId = Number(release.id || 0);
    if (created.status !== 201 || !releaseId || typeof release.upload_url !== 'string') {
      throw new Error(`release create failed HTTP ${created.status}`);
    }

    const specs = [
      ['normal', 'application/json'],
      ['nel-leading', `${String.fromCharCode(0x85)}application/json`],
      ['nel-trailing', `application/json${String.fromCharCode(0x85)}`],
    ];
    for (const [index, [label, mime]] of specs.entries()) {
      const body = Buffer.from(JSON.stringify({probe: label, run: process.env.GITHUB_RUN_ID}));
      const uploaded = await upload(release.upload_url, `asset-${index}.json`, mime, body);
      const summary = {label, uploadStatus: uploaded.response.status, error: uploaded.error};
      if (uploaded.id) {
        summary.assetId = uploaded.id;
        summary.reads = [];
        for (const suffix of ['', '?download=1', '?raw=1', '?archive_format=raw', '?rsct=%85application%2Fjson']) {
          summary.reads.push(await readAsset(uploaded.id, suffix, 'application/vnd.github.v3+json', body));
        }
        summary.reads.push(await readAsset(uploaded.id, '', 'application/octet-stream', body));
      }
      console.log(`RELEASE_ASSET_RESULT ${JSON.stringify(summary)}`);
    }
  } finally {
    if (releaseId) {
      const deleted = await api(`/repos/${REPOSITORY}/releases/${releaseId}`, {method: 'DELETE'});
      console.log(`RELEASE_CLEANUP ${JSON.stringify({releaseDeleteStatus: deleted.status})}`);
    }
    const tagDeleted = await api(`/repos/${REPOSITORY}/git/refs/tags/${encodeURIComponent(tag)}`, {method: 'DELETE'});
    console.log(`TAG_CLEANUP ${JSON.stringify({tagDeleteStatus: tagDeleted.status})}`);
  }
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
