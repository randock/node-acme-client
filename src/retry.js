/**
 * Request retry policy
 *
 * One policy for every request the client makes. Unsigned requests (directory,
 * new-nonce, ARI renewal info, challenge self-checks) are idempotent and are
 * simply sent again. Signed ACME requests carry a single-use nonce and must be
 * signed again with a fresh one, so HttpClient.signedRequest asks this module
 * how long to wait and does the signing itself. Nothing is retried below this
 * layer: the axios instance only passes responses through.
 *
 * https://datatracker.ietf.org/doc/html/rfc8555#section-6.6
 */

const axios = require('./axios');
const { parseRetryAfterHeader } = require('./util');
const { log } = require('./logger');

/**
 * Transport failures that are not worth repeating
 */

const NON_RETRYABLE_CODES = ['ECONNABORTED', 'ERR_NOCK_NO_MATCH'];

/**
 * Longest wait setTimeout can schedule; anything above fires immediately
 */

const MAX_TIMER_SECONDS = Math.floor(2147483647 / 1000);

/**
 * Retry settings, read defensively
 *
 * Values may be numbers or numeric strings (settings often come from env or
 * config files). A consumer may also replace `acmeSettings` wholesale and leave
 * fields out:
 *
 * - `retryMaxAttempts` missing or invalid: no retries at all, so a bad
 *   configuration can never loop
 * - `retryDefaultDelay` missing or invalid: 5 seconds
 * - `retryMaxDelay` missing or null: no cap (the library default); set but
 *   invalid: 0, so no Retry-After is slept on, rather than silently no cap
 *
 * @returns {{retryMaxAttempts: number, retryDefaultDelay: number, retryMaxDelay: (number|null)}}
 */

function getRetrySettings() {
    const settings = axios.defaults.acmeSettings || {};
    const toNumber = (value) => ((typeof value === 'string') && (value.trim() !== '') ? Number(value) : value);
    const valid = (value) => Number.isFinite(value) && (value >= 0);

    const maxAttempts = toNumber(settings.retryMaxAttempts);
    const defaultDelay = toNumber(settings.retryDefaultDelay);
    const maxDelay = toNumber(settings.retryMaxDelay);

    let retryMaxDelay = null;

    if ((maxDelay !== null) && (typeof maxDelay !== 'undefined')) {
        retryMaxDelay = valid(maxDelay) ? maxDelay : 0;
    }

    return {
        retryMaxAttempts: valid(maxAttempts) ? Math.floor(maxAttempts) : 0,
        retryDefaultDelay: valid(defaultDelay) ? defaultDelay : 5,
        retryMaxDelay,
    };
}

/**
 * Seconds to wait before trying a request again, or null to give up
 *
 * Rate limits (429), server errors (5xx) and transport failures are retried,
 * at most `retryMaxAttempts` times. Retry-After is honoured; a Retry-After above
 * `retryMaxDelay` is handed back to the caller instead of being slept on, so
 * the caller can decide what a long rate limit means. Without Retry-After the
 * wait grows with `retryDefaultDelay` per attempt.
 *
 * @param {object} outcome Result of the attempt
 * @param {object} [outcome.response] HTTP response, when there was one
 * @param {Error} [outcome.error] Transport error, when there was no response
 * @param {number} attempt Retries done so far
 * @returns {number|null} Delay in seconds, or null
 */

function getRetryDelay({ response = null, error = null }, attempt) {
    const { retryMaxAttempts, retryDefaultDelay, retryMaxDelay } = getRetrySettings();

    if (attempt >= retryMaxAttempts) {
        return null;
    }

    if (!response) {
        if (!error || NON_RETRYABLE_CODES.includes(error.code)) {
            return null;
        }

        return retryDefaultDelay * (attempt + 1);
    }

    const retryable = (response.status === 429) || ((response.status >= 500) && (response.status <= 599));

    if (!retryable) {
        return null;
    }

    const cap = (retryMaxDelay !== null) ? Math.min(retryMaxDelay, MAX_TIMER_SECONDS) : MAX_TIMER_SECONDS;
    const header = response.headers['retry-after'];

    // A number of seconds too large to parse safely is a very long wait, not none
    if ((typeof header === 'string') && /^\s*\d+\s*$/.test(header) && !Number.isSafeInteger(Number(header))) {
        log(`Retry-after of ${header.trim()} seconds exceeds the maximum delay of ${cap}, not retrying`);
        return null;
    }

    const retryAfter = parseRetryAfterHeader(header);

    if (retryAfter > 0) {
        if (retryAfter > cap) {
            log(`Retry-after of ${retryAfter} seconds exceeds the maximum delay of ${cap}, not retrying`);
            return null;
        }

        return retryAfter;
    }

    // Without Retry-After, back off per attempt, but never past the cap
    return Math.min(retryDefaultDelay * (attempt + 1), cap);
}

/**
 * Wait before the next attempt, and say why
 *
 * @param {object} outcome Result of the attempt, as for getRetryDelay
 * @param {number} delay Seconds to wait
 * @param {number} attempt Number of the upcoming retry
 * @param {string} url Request URL
 * @returns {Promise}
 */

function waitForRetry({ response = null, error = null }, delay, attempt, url) {
    const cause = response ? `HTTP ${response.status}` : (error && error.code) || 'transport error';
    log(`Caught ${cause}, retry attempt ${attempt}/${getRetrySettings().retryMaxAttempts} to URL ${url}, waiting ${delay} seconds`);

    return new Promise((resolve) => { setTimeout(resolve, (delay * 1000)); });
}

/**
 * Send an idempotent request, retrying it under the policy above
 *
 * `send` must be safe to call again unchanged. A response is returned as is
 * once it is not retryable (or retries are exhausted); an error that carries a
 * response (axios rejecting a status) is treated the same way and rethrown.
 *
 * @param {function(): Promise<object>} send Sends the request once
 * @param {string} url Request URL, for logging
 * @param {number} [attempt] Retries done so far
 * @returns {Promise<object>} HTTP response
 */

async function retryIdempotent(send, url, attempt = 0) {
    let outcome;

    try {
        outcome = { response: await send() };
    }
    catch (e) {
        outcome = e.response ? { response: e.response, error: e } : { error: e };
    }

    const delay = getRetryDelay(outcome, attempt);

    if (delay === null) {
        if (outcome.error) {
            throw outcome.error;
        }

        return outcome.response;
    }

    await waitForRetry(outcome, delay, attempt + 1, url);
    return retryIdempotent(send, url, attempt + 1);
}

module.exports = {
    getRetrySettings,
    getRetryDelay,
    waitForRetry,
    retryIdempotent,
};
