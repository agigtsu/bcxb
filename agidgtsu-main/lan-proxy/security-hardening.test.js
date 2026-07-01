const assert = require('assert');
const path = require('path');

function run() {
    const { validateRequestURL } = require('./ssrf-guard');
    const { sanitizeForLogging, sanitizeObject } = require('./sanitizer');
    const { validateFilePath } = require('./path-validator');
    const SQLInjectionDetector = require('./sql-detector');
    const { safeRegexTest, safeRegexReplace } = require('./regex-safe');
    const SecurityErrorHandler = require('./error-handler');

    assert.throws(() => validateRequestURL('http://169.254.169.254/latest/meta-data/iam/'), /SSRF/);
    assert.throws(() => validateRequestURL('http://localhost:3306'), /SSRF|Dangerous port/);
    assert.doesNotThrow(() => validateRequestURL('https://example.com/path'));

    const sanitized = sanitizeForLogging('bad\nvalue\twith\rcontrol');
    assert.strictEqual(sanitized.includes('\n'), false);
    assert.strictEqual(sanitized.includes('\r'), false);

    const obj = sanitizeObject({ a: 'x\ny', nested: { b: 'z\tq' } });
    assert.strictEqual(obj.a.includes('\n'), false);
    assert.strictEqual(obj.nested.b.includes('\t'), false);

    assert.throws(() => validateFilePath('../../etc/passwd', '/tmp/app'), /traversal/i);
    assert.throws(() => validateFilePath('/etc/passwd', '/tmp/app'), /absolute/i);
    const safePath = validateFilePath('document.pdf', '/tmp/app');
    assert.ok(safePath.endsWith(path.join('document.pdf')));

    const detector = new SQLInjectionDetector();
    const sqlResult = detector.scan({ q: 'SELECT * FROM users; SLEEP(10)' });
    assert.strictEqual(sqlResult.suspicious, true);

    (async () => {
        const regexResult = await safeRegexTest(/hello/, 'hello world');
        assert.strictEqual(regexResult.matched, true);
        const replaceResult = await safeRegexReplace(/foo/, 'foo bar', 'baz');
        assert.strictEqual(replaceResult.result, 'baz bar');

        const prodError = SecurityErrorHandler.sanitizeError(new Error('secret path'), false);
        assert.strictEqual(prodError.error, 'An error occurred');

        console.log('security hardening tests passed');
    })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
    });
}

try {
    run();
} catch (error) {
    console.error(error);
    process.exitCode = 1;
}
