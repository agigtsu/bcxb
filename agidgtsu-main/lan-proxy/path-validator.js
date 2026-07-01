const path = require('path');

function validateFilePath(userPath, baseDir) {
    if (!userPath || !baseDir) {
        throw new Error('Path validation: missing parameters');
    }

    const normalized = path.normalize(String(userPath));
    const lowerUserPath = String(userPath).toLowerCase();

    if (/%2e%2e|%2f|%5c/.test(lowerUserPath)) {
        throw new Error('Path traversal: encoded sequences detected');
    }

    if (/\.\.[\\/]|[\\/]\.\./.test(normalized)) {
        throw new Error('Path traversal: .. traversal detected');
    }

    if (path.isAbsolute(normalized)) {
        throw new Error('Path traversal: absolute paths not allowed');
    }

    const resolvedBaseDir = path.resolve(baseDir);
    const fullPath = path.resolve(resolvedBaseDir, normalized);

    if (!fullPath.startsWith(resolvedBaseDir)) {
        throw new Error('Path traversal: resolved path outside base directory');
    }

    const sensitiveNames = ['.env', '.git', '.ssh', '.aws', 'docker', 'kubernetes', 'secret', 'private', 'credential', 'key', 'password'];
    const lowerFullPath = fullPath.toLowerCase();
    for (const sensitive of sensitiveNames) {
        if (lowerFullPath.includes(sensitive)) {
            throw new Error(`Path traversal: access to sensitive directory blocked (${sensitive})`);
        }
    }

    return fullPath;
}

function isPathAllowed(filePath, allowedDirs = []) {
    const resolvedPath = path.resolve(filePath);
    return allowedDirs.some((allowedDir) => resolvedPath.startsWith(path.resolve(allowedDir)));
}

module.exports = { validateFilePath, isPathAllowed };
