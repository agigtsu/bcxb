class SecurityErrorHandler {
    static sanitizeError(error, isDevelopment = false) {
        if (isDevelopment) {
            return { error: error.message, stack: error.stack, details: error.details };
        }
        return { error: 'An error occurred', requestId: error.requestId || 'unknown' };
    }

    static handleDatabaseError(error, isDevelopment = false) {
        if (isDevelopment) {
            return { error: error.message, code: error.code, sqlMessage: error.sqlMessage };
        }
        return { error: 'Database operation failed' };
    }

    static handleFileError(error, isDevelopment = false) {
        if (isDevelopment) {
            return { error: error.message, path: error.path };
        }
        return { error: 'File operation failed' };
    }

    static handleValidationError(error, isDevelopment = false) {
        if (isDevelopment) {
            return { error: error.message, validation: error.validation };
        }
        return { error: 'Validation failed', fields: Object.keys(error.validation || {}) };
    }
}

module.exports = SecurityErrorHandler;
