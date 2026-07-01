class SQLInjectionDetector {
    constructor() {
        this.patterns = {
            keywords: ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'exec', 'execute', 'script'],
            timeBased: /sleep\s*\(\s*\d+\s*\)|benchmark\s*\(/i,
            booleanBased: /and\s+1\s*=\s*1|or\s+1\s*=\s*1/i,
            comments: /--|\#|\/\*|\*\//,
            stacked: /;\s*(select|insert|update|delete|drop|exec)/i,
            nullByte: /\x00/,
            quotes: /['"`]/
        };
    }

    decodeString(str) {
        let decoded = str;
        try {
            decoded = decodeURIComponent(decoded);
        } catch (error) {
            // ignore
        }

        try {
            decoded = decoded.replace(/%([0-9a-f]{2})/gi, (match, hex) => String.fromCharCode(parseInt(hex, 16)));
        } catch (error) {
            // ignore
        }

        decoded = decoded
            .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(dec))
            .replace(/&#x([0-9a-f]+);/gi, (match, hex) => String.fromCharCode(parseInt(hex, 16)));

        return decoded;
    }

    analyzeValue(value) {
        if (typeof value !== 'string') {
            return { suspicious: false };
        }

        const results = { suspicious: false, reasons: [], encodingDetected: false, decodedValue: value };

        if (/%[0-9a-f]{2}|&#\d+|&#x[0-9a-f]+/i.test(value)) {
            results.encodingDetected = true;
            results.decodedValue = this.decodeString(value);
        }

        const toAnalyze = results.decodedValue.toLowerCase();

        if (this.patterns.timeBased.test(toAnalyze)) {
            results.reasons.push('Time-based injection detected (SLEEP/BENCHMARK)');
            results.suspicious = true;
        }

        if (this.patterns.booleanBased.test(toAnalyze)) {
            results.reasons.push('Boolean-based injection detected (1=1 pattern)');
            results.suspicious = true;
        }

        if (this.patterns.comments.test(toAnalyze)) {
            const afterComment = toAnalyze.split(/--|\#|\/\*|\*\//)[1] || '';
            for (const keyword of this.patterns.keywords) {
                if (afterComment.includes(keyword)) {
                    results.reasons.push(`SQL keyword after comment: ${keyword}`);
                    results.suspicious = true;
                }
            }
        }

        if (this.patterns.stacked.test(toAnalyze)) {
            results.reasons.push('Stacked query detected (multiple statements)');
            results.suspicious = true;
        }

        if (this.patterns.nullByte.test(value)) {
            results.reasons.push('Null byte detected');
            results.suspicious = true;
        }

        let keywordCount = 0;
        for (const keyword of this.patterns.keywords) {
            const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
            keywordCount += (toAnalyze.match(regex) || []).length;
        }

        if (keywordCount >= 2 && this.patterns.quotes.test(toAnalyze)) {
            results.reasons.push(`Multiple SQL keywords (${keywordCount}) with quotes`);
            results.suspicious = true;
        }

        return results;
    }

    scan(data) {
        const allResults = [];

        if (typeof data === 'string') {
            return this.analyzeValue(data);
        }

        if (typeof data === 'object' && data !== null) {
            for (const [key, value] of Object.entries(data)) {
                const result = this.analyzeValue(String(value));
                if (result.suspicious) {
                    allResults.push({ field: key, ...result });
                }
            }
        }

        return { suspicious: allResults.length > 0, findings: allResults };
    }
}

module.exports = SQLInjectionDetector;
