#!/usr/bin/env node

/**
 * Security Test Diagnostic Analyzer
 * Identifies root causes of test failures without modifying implementation
 * 
 * Purpose: Find what's broken and why, leave everything intact
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

class DiagnosticAnalyzer {
    constructor(baseUrl = 'https://localhost:8789') {
        this.baseUrl = baseUrl;
        this.diagnostics = [];
        this.failedTests = [];
    }

    async runDiagnostics() {
        console.log('\n' + '█'.repeat(80));
        console.log('SECURITY TEST DIAGNOSTIC ANALYZER');
        console.log('Purpose: Identify failures without breaking functionality');
        console.log('█'.repeat(80) + '\n');

        // Test 1: Server Availability
        await this.checkServerAvailability();

        // Test 2: SSRF Protection Status
        await this.checkSSRFProtection();

        // Test 3: Payload Size Limits Status
        await this.checkPayloadSizeLimits();

        // Test 4: Security Headers Status
        await this.checkSecurityHeaders();

        // Test 5: Error Handling Status
        await this.checkErrorHandling();

        // Test 6: Rate Limiting Status
        await this.checkRateLimiting();

        // Test 7: Path Traversal Status
        await this.checkPathTraversal();

        this.printDiagnosticReport();
    }

    async checkServerAvailability() {
        console.log('▶ Test 1: Server Availability\n');

        try {
            const response = await this.makeRequest('GET', '/health', '', {});
            console.log(`   Status Code: ${response.statusCode}`);
            console.log(`   Response Time: ${response.time}ms`);
            console.log(`   Server: OPERATIONAL ✅\n`);

            this.log('Server Availability', true, `HTTP ${response.statusCode}`);
        } catch (err) {
            console.log(`   Error: ${err.message}`);
            console.log(`   Server: NOT RESPONDING ❌\n`);

            this.log('Server Availability', false, err.message);
        }
    }

    async checkSSRFProtection() {
        console.log('▶ Test 2: SSRF Protection Status\n');

        const testCases = [
            { url: 'http://169.254.169.254/latest/meta-data/', name: 'AWS Metadata' },
            { url: 'http://localhost:3306/', name: 'MySQL Localhost' },
            { url: 'http://127.0.0.1:5432/', name: 'PostgreSQL Localhost' }
        ];

        for (const test of testCases) {
            const payload = JSON.stringify({ url: test.url });

            try {
                const response = await this.makeRequest('POST', '/v1-internal', payload, {
                    'Content-Type': 'application/json'
                });

                const blocked = response.statusCode === 403;
                console.log(`   ${test.name}: ${blocked ? 'BLOCKED ✅' : 'ALLOWED ❌'} (${response.statusCode})`);

                this.log(`SSRF: ${test.name}`, blocked, `Status ${response.statusCode}`);
            } catch (err) {
                console.log(`   ${test.name}: ERROR ⚠️  (${err.message})`);
                this.log(`SSRF: ${test.name}`, false, err.message);
            }
        }
        console.log('');
    }

    async checkPayloadSizeLimits() {
        console.log('▶ Test 3: Payload Size Limits\n');

        // Small payload
        const small = JSON.stringify({ url: 'http://example.com/', data: 'A'.repeat(100) });

        try {
            const response = await this.makeRequest('POST', '/v1-internal', small, {
                'Content-Type': 'application/json'
            });
            console.log(`   1KB Payload: ACCEPTED (${response.statusCode})`);
            this.log('Payload Size: 1KB', response.statusCode !== 413, `Status ${response.statusCode}`);
        } catch (err) {
            console.log(`   1KB Payload: ERROR (${err.message})`);
            this.log('Payload Size: 1KB', false, err.message);
        }

        console.log('');
    }

    async checkSecurityHeaders() {
        console.log('▶ Test 4: Security Headers Status\n');

        try {
            const response = await this.makeRequest('GET', '/health', '', {});

            const requiredHeaders = [
                'strict-transport-security',
                'x-frame-options',
                'x-content-type-options',
                'content-security-policy'
            ];

            let present = 0;
            for (const header of requiredHeaders) {
                const hasHeader = header in response.headers;
                console.log(`   ${header}: ${hasHeader ? '✅ PRESENT' : '❌ MISSING'}`);
                if (hasHeader) present++;
                this.log(`Header: ${header}`, hasHeader, `Value: ${response.headers[header] || 'N/A'}`);
            }

            console.log(`   Total: ${present}/${requiredHeaders.length} present\n`);
        } catch (err) {
            console.log(`   Error: ${err.message}\n`);
            this.log('Security Headers', false, err.message);
        }
    }

    async checkErrorHandling() {
        console.log('▶ Test 5: Error Handling Status\n');

        try {
            const response = await this.makeRequest('GET', '/nonexistent-endpoint', '', {});

            console.log(`   404 Status: ${response.statusCode === 404 ? '✅' : '❌'}`);
            console.log(`   Error Generic: ${response.body.includes('/nonexistent') ? 'LEAKS PATH ❌' : 'SANITIZED ✅'}`);

            this.log('Error Handling: 404', response.statusCode === 404, `Status ${response.statusCode}`);
            this.log('Error Handling: Path Leakage', !response.body.includes('/nonexistent'), 'Path not in response');
        } catch (err) {
            console.log(`   Error: ${err.message}`);
            this.log('Error Handling', false, err.message);
        }

        console.log('');
    }

    async checkRateLimiting() {
        console.log('▶ Test 6: Rate Limiting Status\n');

        let blocked = false;
        let blockCount = 0;

        for (let i = 0; i < 150; i++) {
            try {
                const response = await this.makeRequest('GET', '/health', '', {});
                if (response.statusCode === 429) {
                    blocked = true;
                    blockCount = i;
                    break;
                }
            } catch (err) {
                // Continue
            }
        }

        if (blocked) {
            console.log(`   Rate Limit: ENFORCED ✅ (blocked at request ${blockCount})`);
            this.log('Rate Limiting', true, `Blocked at request ${blockCount}`);
        } else {
            console.log(`   Rate Limit: NOT ENFORCED ❌ (no 429 after 150 requests)`);
            this.log('Rate Limiting', false, 'No rate limit enforced');
        }

        console.log('');
    }

    async checkPathTraversal() {
        console.log('▶ Test 7: Path Traversal Protection\n');

        const testCases = [
            { path: '/../../../etc/passwd', name: '../ traversal' },
            { path: '/%2e%2e/%2e%2e/etc/passwd', name: 'URL-encoded %2e%2e' }
        ];

        for (const test of testCases) {
            try {
                const response = await this.makeRequest('GET', test.path, '', {});

                const blocked = response.statusCode === 403 || response.statusCode === 400;
                console.log(`   ${test.name}: ${blocked ? 'BLOCKED ✅' : 'ALLOWED ❌'} (${response.statusCode})`);

                this.log(`Path Traversal: ${test.name}`, blocked, `Status ${response.statusCode}`);
            } catch (err) {
                console.log(`   ${test.name}: ERROR (${err.message})`);
                this.log(`Path Traversal: ${test.name}`, false, err.message);
            }
        }

        console.log('');
    }

    async makeRequest(method, endpoint, body = '', headers = {}) {
        return new Promise((resolve, reject) => {
            const url = new URL(endpoint, this.baseUrl);
            const protocol = url.protocol === 'https:' ? https : http;

            const startTime = Date.now();
            const options = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers
                },
                rejectUnauthorized: false
            };

            if (body) {
                options.headers['Content-Length'] = Buffer.byteLength(body);
            }

            const req = protocol.request(url, options, (res) => {
                let data = '';

                res.on('data', chunk => {
                    data += chunk;
                });

                res.on('end', () => {
                    const time = Date.now() - startTime;
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: data,
                        time
                    });
                });
            });

            req.on('error', reject);
            req.setTimeout(5000, () => {
                req.abort();
                reject(new Error('Request timeout'));
            });

            if (body) req.write(body);
            req.end();
        });
    }

    log(testName, passed, details) {
        const result = { testName, passed, details };
        this.diagnostics.push(result);

        if (!passed) {
            this.failedTests.push(result);
        }
    }

    printDiagnosticReport() {
        console.log('█'.repeat(80));
        console.log('DIAGNOSTIC SUMMARY');
        console.log('█'.repeat(80) + '\n');

        const total = this.diagnostics.length;
        const passed = this.diagnostics.filter(d => d.passed).length;
        const failed = this.failedTests.length;

        console.log(`Total Tests: ${total}`);
        console.log(`✅ Passed: ${passed}`);
        console.log(`❌ Failed: ${failed}`);
        console.log(`Success Rate: ${Math.round((passed / total) * 100)}%\n`);

        if (this.failedTests.length > 0) {
            console.log('FAILED TESTS (Root Cause Analysis):\n');

            this.failedTests.forEach((test, i) => {
                console.log(`${i + 1}. ${test.testName}`);
                console.log(`   Status: ❌ FAILED`);
                console.log(`   Details: ${test.details}`);
                console.log(`   Analysis: Check if protection is implemented in server.js`);
                console.log('');
            });
        }

        console.log('█'.repeat(80));
        console.log('RECOMMENDATION: Review failed tests. DO NOT modify code yet.');
        console.log('█'.repeat(80) + '\n');
    }
}

if (require.main === module) {
    const analyzer = new DiagnosticAnalyzer('https://localhost:8789');
    analyzer.runDiagnostics();
}

module.exports = DiagnosticAnalyzer;
