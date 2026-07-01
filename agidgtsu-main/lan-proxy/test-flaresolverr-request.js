const assert = require('assert');
const { buildFlareSolverrRequest } = require('./flaresolverr-request');

const simpleGet = buildFlareSolverrRequest({ body: { url: 'https://api.github.com', method: 'GET' } });
assert.strictEqual(simpleGet.cmd, 'request.get');
assert.strictEqual(simpleGet.url, 'https://api.github.com');
assert.strictEqual(simpleGet.maxTimeout, 120000);

const simplePost = buildFlareSolverrRequest({ body: { url: 'https://example.com', method: 'POST', payload: 'hello' } });
assert.strictEqual(simplePost.cmd, 'request.post');
assert.strictEqual(simplePost.postData, 'hello');

console.log('FlareSolverr request translation checks passed');
