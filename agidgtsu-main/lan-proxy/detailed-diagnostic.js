#!/usr/bin/env node

/**
 * Enhanced Diagnostic Analyzer - Detailed Failure Investigation
 * Provides line-by-line analysis of what's happening
 */

const https = require('https');
const { URL } = require('url');

class DetailedDiagnostic {
    constructor(baseUrl = 'https://localhost:8789') {
        this.baseUrl = baseUrl;
        this.results = [];
    }
    
    async runAnalysis() {
        console.log('\n' + '█'.repeat(90));
        console.log('DETAILED FAILURE INVESTIGATION - STEP-BY-STEP ANALYSIS');
        console.log('█'.repeat(90) + '\n');
        
        // Test 1: Verify SSRF protection is working correctly
        console.log('STEP 1: Verify SSRF Protection (Should Block Private IPs)\n');
        await this.testSSRFDetailed();
        
        // Test 2: Verify legitimate external URLs are allowed
        console.log('\nSTEP 2: Verify Legitimate URLs Are Allowed\n');
        await this.testLegitimateURL();
        
        // Test 3: Check if /v1-internal is accessible
        console.log('\nSTEP 3: Check /v1-internal Endpoint Accessibility\n');
        await this.testInternalEndpoint();
        
        // Test 4: Check rate limit implementation
        console.log('\nSTEP 4: Check Rate Limiting (5 requests)\n');
        await this.testRateLimitDetailed();
        
        // Test 5: Check 404 handling
        console.log('\nSTEP 5: Check 404 Error Handling\n');
        await this.testErrorHandlingDetailed();
        
        // Test 6: Check path traversal with auth header
        console.log('\nSTEP 6: Path Traversal (WITH vs WITHOUT auth)\n');
        await this.testPathTraversalDetailed();
        
        this.printSummary();
    }
    
    async testSSRFDetailed() {
        const tests = [
            { url: 'http://169.254.169.254/latest/meta-data/', expected: 403, name: 'AWS Metadata' },
            { url: 'http://localhost:3306/', expected: 403, name: 'MySQL Localhost' },
            { url: 'http://example.com/', expected: 403, name: 'External URL (for SSRF test)' }
        ];
        
        for (const test of tests) {
            try {
                const response = await this.makeRequest('POST', '/v1-internal', 
                    JSON.stringify({ url: test.url }), 
                    { 'Content-Type': 'application/json' }
                );
                
                const passed = response.statusCode === test.expected;
                console.log(`${passed ? '✅' : '❌'} ${test.name}`);
                console.log(`   URL: ${test.url}`);
                console.log(`   Expected: ${test.expected}, Got: ${response.statusCode}`);
                console.log(`   Response: ${response.body.substring(0, 200)}`);
                console.log('');
                
                this.results.push({ test: `SSRF: ${test.name}`, passed, expected: test.expected, actual: response.statusCode });
            } catch (err) {
                console.log(`⚠️ ${test.name}: ${err.message}\n`);
                this.results.push({ test: `SSRF: ${test.name}`, passed: false, error: err.message });
            }
        }
    }
    
    async testLegitimateURL() {
        console.log('Testing if legitimate external URLs pass SSRF validation:\n');
        
        const urls = [
            'http://example.com/',
            'https://api.github.com/',
            'https://google.com/search'
        ];
        
        for (const url of urls) {
            try {
                const response = await this.makeRequest('POST', '/v1-internal',
                    JSON.stringify({ url }),
                    { 'Content-Type': 'application/json' }
                );
                
                // For legitimate URLs, we might get:
                // - 403: SSRF rejected it (false positive) ❌
                // - 401: Authentication required (expected if no API key) ✅
                // - 200/201/etc: Successfully processed ✅
                
                const isBlocked = response.statusCode === 403 && response.body.includes('blocked');
                
                console.log(`${!isBlocked ? '✅' : '❌'} ${url}`);
                console.log(`   Status: ${response.statusCode}`);
                if (isBlocked) {
                    console.log(`   ⚠️  SSRF REJECTED: ${response.body}`);
                } else {
                    console.log(`   ✅ Passed SSRF check (got ${response.statusCode})`);
                }
                console.log('');
                
                this.results.push({ 
                    test: `Legitimate URL: ${url}`, 
                    passed: !isBlocked, 
                    status: response.statusCode 
                });
            } catch (err) {
                console.log(`⚠️ ${url}: ${err.message}\n`);
            }
        }
    }
    
    async testInternalEndpoint() {
        console.log('Testing /v1-internal endpoint accessibility:\n');
        
        const payload = {
            url: 'http://example.com/test',
            method: 'GET'
        };
        
        try {
            const response = await this.makeRequest('POST', '/v1-internal',
                JSON.stringify(payload),
                { 'Content-Type': 'application/json' }
            );
            
            console.log(`Response Status: ${response.statusCode}`);
            console.log(`Response Headers: ${JSON.stringify(response.headers).substring(0, 200)}`);
            console.log(`Response Body (first 300 chars):\n${response.body.substring(0, 300)}`);
            
            const accessible = response.statusCode !== 404;
            this.results.push({ 
                test: '/v1-internal accessibility', 
                passed: accessible, 
                status: response.statusCode 
            });
        } catch (err) {
            console.log(`Error: ${err.message}`);
            this.results.push({ test: '/v1-internal accessibility', passed: false, error: err.message });
        }
    }
    
    async testRateLimitDetailed() {
        console.log('Testing rate limiting with 5 rapid requests:\n');
        
        let blocked = false;
        let blockCount = 0;
        
        for (let i = 1; i <= 5; i++) {
            try {
                const response = await this.makeRequest('GET', '/health', '', {});
                console.log(`Request ${i}: ${response.statusCode}`);
                
                if (response.statusCode === 429) {
                    blocked = true;
                    blockCount = i;
                    console.log(`  → ⚠️  RATE LIMITED at request ${i}`);
                    break;
                }
            } catch (err) {
                console.log(`Request ${i}: ERROR - ${err.message}`);
            }
        }
        
        if (!blocked) {
            console.log('\n⚠️  No rate limiting detected (all 5 requests allowed)');
        } else {
            console.log(`\n✅ Rate limiting active (blocked at request ${blockCount})`);
        }
        
        this.results.push({ 
            test: 'Rate Limiting', 
            passed: blocked, 
            detail: blocked ? `Blocked at ${blockCount}` : 'Not enforced' 
        });
    }
    
    async testErrorHandlingDetailed() {
        console.log('Testing error handling for non-existent route:\n');
        console.log('Request: GET /this-path-does-not-exist');
        console.log('No auth headers\n');
        
        try {
            const response = await this.makeRequest('GET', '/this-path-does-not-exist', '', {});
            
            console.log(`Status: ${response.statusCode}`);
            console.log(`Expected: 404 (Not Found)`);
            console.log(`Got: ${response.statusCode}\n`);
            
            console.log('Reason:');
            if (response.statusCode === 401) {
                console.log('  ❌ Got 401 (Unauthorized) - Auth middleware blocks before 404 handler');
                console.log('  → Route is protected by API key requirement');
            } else if (response.statusCode === 404) {
                console.log('  ✅ Got 404 - 404 handler working correctly');
            }
            
            console.log(`\nResponse body:\n${response.body.substring(0, 300)}`);
            
            this.results.push({ 
                test: '404 Error Handling', 
                passed: response.statusCode === 404, 
                actual: response.statusCode 
            });
        } catch (err) {
            console.log(`Error: ${err.message}`);
            this.results.push({ test: '404 Error Handling', passed: false, error: err.message });
        }
    }
    
    async testPathTraversalDetailed() {
        console.log('Testing path traversal protection:\n');
        
        const paths = [
            '/../../../etc/passwd',
            '/%2e%2e/%2e%2e/etc/passwd'
        ];
        
        for (const path of paths) {
            console.log(`Testing: GET ${path}`);
            
            // Test WITHOUT auth (current behavior)
            try {
                const response = await this.makeRequest('GET', path, '', {});
                console.log(`  Without Auth: ${response.statusCode}`);
                
                if (response.statusCode === 403) {
                    console.log(`    ✅ Path blocked correctly`);
                } else if (response.statusCode === 401) {
                    console.log(`    ❌ Got 401 (Auth required first)`);
                } else {
                    console.log(`    ❌ Got ${response.statusCode}`);
                }
            } catch (err) {
                console.log(`  Without Auth: ERROR - ${err.message}`);
            }
            
            console.log('');
            
            this.results.push({
                test: `Path Traversal: ${path}`,
                passed: false,
                note: 'Needs auth to test'
            });
        }
    }
    
    async makeRequest(method, endpoint, body = '', headers = {}) {
        return new Promise((resolve, reject) => {
            const url = new URL(endpoint, this.baseUrl);
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
            
            const req = https.request(url, options, (res) => {
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
    
    printSummary() {
        console.log('\n' + '█'.repeat(90));
        console.log('ANALYSIS SUMMARY');
        console.log('█'.repeat(90) + '\n');
        
        const passed = this.results.filter(r => r.passed).length;
        const total = this.results.length;
        
        console.log(`Tests Run: ${total}`);
        console.log(`Passed: ${passed}`);
        console.log(`Failed: ${total - passed}`);
        console.log(`Success Rate: ${Math.round((passed / total) * 100)}%\n`);
        
        console.log('FINDINGS:\n');
        
        const failures = this.results.filter(r => !r.passed);
        if (failures.length > 0) {
            console.log('Failed Tests:\n');
            failures.forEach((f, i) => {
                console.log(`${i + 1}. ${f.test}`);
                if (f.actual) console.log(`   Status: ${f.actual}`);
                if (f.error) console.log(`   Error: ${f.error}`);
                if (f.detail) console.log(`   Detail: ${f.detail}`);
                if (f.note) console.log(`   Note: ${f.note}`);
                console.log('');
            });
        }
        
        console.log('█'.repeat(90) + '\n');
    }
}

if (require.main === module) {
    const analyzer = new DetailedDiagnostic('https://localhost:8789');
    analyzer.runAnalysis();
}

module.exports = DetailedDiagnostic;
