const MAX_LOG_LENGTH = 1000;

function sanitizeForLogging(input) {
    if (input === null || input === undefined) return '';
    return String(input)
        .replace(/[\r\n\t\v\f]/g, ' ')
        .replace(/  +/g, ' ')
        .substring(0, MAX_LOG_LENGTH);
}

function sanitizeObject(obj) {
    if (obj === null || obj === undefined) {
        return {};
    }

    if (Array.isArray(obj)) {
        return obj.map((item) => sanitizeValue(item));
    }

    if (typeof obj === 'object') {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            sanitized[key] = sanitizeValue(value);
        }
        return sanitized;
    }

    return sanitizeForLogging(obj);
}

function sanitizeValue(value) {
    if (typeof value === 'string') {
        return sanitizeForLogging(value);
    }
    if (value && typeof value === 'object') {
        return sanitizeObject(value);
    }
    return value;
}

module.exports = { sanitizeForLogging, sanitizeObject };
