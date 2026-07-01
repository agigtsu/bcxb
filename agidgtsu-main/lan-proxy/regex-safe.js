const REGEX_TIMEOUT = 100;

function safeRegexTest(regex, input, timeout = REGEX_TIMEOUT) {
    return new Promise((resolve) => {
        const timeoutHandle = setTimeout(() => resolve({ matched: false, timedOut: true }), timeout);

        try {
            const matched = regex.test(input);
            clearTimeout(timeoutHandle);
            resolve({ matched, timedOut: false });
        } catch (error) {
            clearTimeout(timeoutHandle);
            resolve({ matched: false, timedOut: false, error: error.message });
        }
    });
}

function safeRegexReplace(regex, input, replacement, timeout = REGEX_TIMEOUT) {
    return new Promise((resolve) => {
        const timeoutHandle = setTimeout(() => resolve({ result: input, timedOut: true }), timeout);

        try {
            const result = input.replace(regex, replacement);
            clearTimeout(timeoutHandle);
            resolve({ result, timedOut: false });
        } catch (error) {
            clearTimeout(timeoutHandle);
            resolve({ result: input, timedOut: false, error: error.message });
        }
    });
}

module.exports = { safeRegexTest, safeRegexReplace, REGEX_TIMEOUT };
