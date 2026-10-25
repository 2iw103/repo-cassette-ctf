'use strict';
const https = require('node:https');

function request(path, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = https.request({
      protocol: 'https:',
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        accept: 'application/vnd.github.v3+json',
        authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        'user-agent': 'repo-cassette-cleanup',
        'x-github-api-version': '2022-11-28',
        ...(method === 'DELETE' ? {'content-length': '0'} : {}),
      },
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({status: response.statusCode || 0, body: Buffer.concat(chunks)}));
    });
    req.setTimeout(20000, () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
    req.end();
  });
}

async function main() {
  const repository = process.env.GITHUB_REPOSITORY;
  const run = process.env.TARGET_RUN_ID;
  if (!repository || !/^\d+$/.test(run || '')) throw new Error('cleanup inputs missing');
  const listed = await request(`/repos/${repository}/actions/runs/${run}/artifacts?per_page=100`);
  if (listed.status !== 200) throw new Error(`list HTTP ${listed.status}`);
  const artifacts = JSON.parse(listed.body.toString()).artifacts || [];
  let deleted = 0;
  for (const artifact of artifacts) {
    const result = await request(`/repos/${repository}/actions/artifacts/${artifact.id}`, 'DELETE');
    if (![204, 404].includes(result.status)) throw new Error(`delete HTTP ${result.status}`);
    deleted += 1;
  }
  console.log(`ACCIDENTAL_RUN_CLEANUP ${JSON.stringify({targetRun: run, deleted})}`);
}

main().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
