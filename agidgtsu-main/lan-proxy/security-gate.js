const { spawn } = require('child_process');
const https = require('https');

function waitForHealth(url, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        const attempt = () => {
            const req = https.get(url, { rejectUnauthorized: false }, (res) => {
                res.resume();
                if (res.statusCode === 200) {
                    resolve();
                    return;
                }
                if (Date.now() - start >= timeoutMs) {
                    reject(new Error(`Health check returned ${res.statusCode}`));
                    return;
                }
                setTimeout(attempt, 1000);
            });

            req.on('error', () => {
                if (Date.now() - start >= timeoutMs) {
                    reject(new Error('Health check never became ready'));
                    return;
                }
                setTimeout(attempt, 1000);
            });
        };

        attempt();
    });
}

function postBlockedRequest() {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' });
        const req = https.request(
            {
                hostname: 'localhost',
                port: 8789,
                path: '/v1-internal',
                method: 'POST',
                rejectUnauthorized: false,
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(data),
                    'X-API-Key': 'sk_test_key'
                }
            },
            (res) => {
                let body = '';
                res.setEncoding('utf8');
                res.on('data', (chunk) => {
                    body += chunk;
                });
                res.on('end', () => {
                    if (res.statusCode === 403 || res.statusCode === 429) {
                        resolve({ statusCode: res.statusCode, body });
                    } else {
                        reject(new Error(`Unexpected SSRF response ${res.statusCode}: ${body}`));
                    }
                });
            }
        );

        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

async function main() {
    const child = spawn(process.execPath, ['server.js'], {
        cwd: __dirname,
        env: {
            ...process.env,
            PROXY_API_KEY: 'sk_test_key',
            PROXY_SECRET: 'test-secret'
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let output = '';
    child.stdout.on('data', (chunk) => {
        output += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
        output += chunk.toString();
    });

    const cleanup = () => {
        if (!child.killed) {
            child.kill('SIGTERM');
        }
    };

    process.on('exit', cleanup);
    process.on('SIGINT', () => {
        cleanup();
        process.exit(130);
    });
    process.on('SIGTERM', () => {
        cleanup();
        process.exit(143);
    });

    try {
        await waitForHealth('https://localhost:8789/health');
        const blocked = await postBlockedRequest();
        console.log(`security gate passed: health=200 blocked=${blocked.statusCode}`);
    } catch (error) {
        console.error(error.message);
        console.error(output);
        process.exitCode = 1;
    } finally {
        cleanup();
    }
}

main();
