/**
 * ACME HTTP client
 */

const { createHmac, createSign, constants: { RSA_PKCS1_PADDING } } = require('crypto');
const { getJwk } = require('./crypto');
const { log } = require('./logger');
const axios = require('./axios');
const { getRetryDelay, waitForRetry, retryIdempotent } = require('./retry');

/**
 * ACME HTTP client
 *
 * @class
 * @param {string} directoryUrl ACME directory URL
 * @param {buffer} accountKey PEM encoded account private key
 * @param {object} [opts.externalAccountBinding]
 * @param {string} [opts.externalAccountBinding.kid] External account binding KID
 * @param {string} [opts.externalAccountBinding.hmacKey] External account binding HMAC key
 */

class HttpClient {
    constructor(directoryUrl, accountKey, externalAccountBinding = {}) {
        this.directoryUrl = directoryUrl;
        this.accountKey = accountKey;
        this.externalAccountBinding = externalAccountBinding;

        this.maxBadNonceRetries = 5;
        this.replayNonceMaxAge = 30;
        this.jwk = null;

        this.directoryCache = null;
        this.directoryMaxAge = 86400;
        this.directoryTimestamp = 0;
    }

    /**
     * HTTP request, retried under the retry policy
     *
     * For requests that are safe to send again unchanged: directory, new-nonce,
     * ARI renewal info. Signed requests go through signedRequest, which signs a
     * retry again with a fresh nonce.
     *
     * @param {string} url HTTP URL
     * @param {string} method HTTP method
     * @param {object} [opts] Request options
     * @returns {Promise<object>} HTTP response
     */

    async request(url, method, opts = {}) {
        return retryIdempotent(() => this.send(url, method, opts), url);
    }

    /**
     * HTTP request, sent exactly once
     *
     * @private
     * @param {string} url HTTP URL
     * @param {string} method HTTP method
     * @param {object} [opts] Request options
     * @returns {Promise<object>} HTTP response
     */

    async send(url, method, opts = {}) {
        opts.url = url;
        opts.method = method;
        opts.validateStatus = null;

        // Headers
        if (typeof opts.headers === 'undefined') {
            opts.headers = {};
        }

        opts.headers['Content-Type'] = 'application/jose+json';

        // Request
        log(`HTTP request: ${method} ${url}`);
        const resp = await axios.request(opts);

        log(`RESP ${resp.status} ${method} ${url}`);
        return resp;
    }

    /**
     * Get ACME provider directory
     *
     * https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
     *
     * @returns {Promise<object>} ACME directory contents
     */

    async getDirectory() {
        const now = Math.floor(Date.now() / 1000);
        const age = (now - this.directoryTimestamp);

        if (!this.directoryCache || (age > this.directoryMaxAge)) {
            log(`Refreshing ACME directory, age: ${age}`);
            const resp = await this.request(this.directoryUrl, 'get');

            if (resp.status >= 400) {
                throw new Error(`Attempting to read ACME directory returned error ${resp.status}: ${this.directoryUrl}`);
            }

            if (!resp.data) {
                throw new Error('Attempting to read ACME directory returned no data');
            }

            this.directoryCache = resp.data;
            this.directoryTimestamp = now;
        }

        return this.directoryCache;
    }

    /**
     * Get JSON Web Key
     *
     * @returns {object} JSON Web Key
     */

    getJwk() {
        if (!this.jwk) {
            this.jwk = getJwk(this.accountKey);
        }

        return this.jwk;
    }

    /**
     * Get nonce from directory API endpoint
     *
     * https://datatracker.ietf.org/doc/html/rfc8555#section-7.2
     *
     * @returns {Promise<string>} Nonce
     */

    async getNonce() {
        const url = await this.getResourceUrl('newNonce');
        const resp = await this.request(url, 'head');

        if (!resp.headers['replay-nonce']) {
            throw new Error('Failed to get nonce from ACME provider');
        }

        return resp.headers['replay-nonce'];
    }

    /**
     * Get URL for a directory resource
     *
     * @param {string} resource API resource name
     * @returns {Promise<string>} URL
     */

    async getResourceUrl(resource) {
        const dir = await this.getDirectory();

        if (!dir[resource]) {
            throw new Error(`Unable to locate API resource URL in ACME directory: "${resource}"`);
        }

        return dir[resource];
    }

    /**
     * Get directory meta field
     *
     * @param {string} field Meta field name
     * @returns {Promise<string|null>} Meta field value
     */

    async getMetaField(field) {
        const dir = await this.getDirectory();

        if (('meta' in dir) && (field in dir.meta)) {
            return dir.meta[field];
        }

        return null;
    }

    /**
     * Determine if provider supports ACME Renewal Information (ARI)
     *
     * https://datatracker.ietf.org/doc/html/draft-ietf-acme-ari#section-3
     *
     * @returns {Promise<boolean>} Provider supports ARI
     */

    async hasAriSupport() {
        try {
            await this.getResourceUrl('renewalInfo');
            return true;
        }
        catch (e) {
            return false;
        }
    }

    /**
     * Prepare HTTP request body for signature
     *
     * @param {string} alg JWS algorithm
     * @param {string} url Request URL
     * @param {object} [payload] Request payload
     * @param {object} [opts]
     * @param {string} [opts.nonce] JWS anti-replay nonce
     * @param {string} [opts.kid] JWS KID
     * @returns {object} Signed HTTP request body
     */

    prepareSignedBody(alg, url, payload = null, { nonce = null, kid = null } = {}) {
        const header = { alg, url };

        // Nonce
        if (nonce) {
            log(`Using nonce: ${nonce}`);
            header.nonce = nonce;
        }

        // KID or JWK
        if (kid) {
            header.kid = kid;
        }
        else {
            header.jwk = this.getJwk();
        }

        // Body
        return {
            payload: payload ? Buffer.from(JSON.stringify(payload)).toString('base64url') : '',
            protected: Buffer.from(JSON.stringify(header)).toString('base64url'),
        };
    }

    /**
     * Create JWS HTTP request body using HMAC
     *
     * @param {string} hmacKey HMAC key
     * @param {string} url Request URL
     * @param {object} [payload] Request payload
     * @param {object} [opts]
     * @param {string} [opts.nonce] JWS anti-replay nonce
     * @param {string} [opts.kid] JWS KID
     * @returns {object} Signed HMAC request body
     */

    createSignedHmacBody(hmacKey, url, payload = null, { nonce = null, kid = null } = {}) {
        const result = this.prepareSignedBody('HS256', url, payload, { nonce, kid });

        // Signature
        const signer = createHmac('SHA256', Buffer.from(hmacKey, 'base64')).update(`${result.protected}.${result.payload}`, 'utf8');
        result.signature = signer.digest().toString('base64url');

        return result;
    }

    /**
     * Create JWS HTTP request body using RSA or ECC
     *
     * https://datatracker.ietf.org/doc/html/rfc7515
     *
     * @param {string} url Request URL
     * @param {object} [payload] Request payload
     * @param {object} [opts]
     * @param {string} [opts.nonce] JWS nonce
     * @param {string} [opts.kid] JWS KID
     * @returns {object} JWS request body
     */

    createSignedBody(url, payload = null, { nonce = null, kid = null } = {}) {
        const jwk = this.getJwk();
        let headerAlg = 'RS256';
        let signerAlg = 'SHA256';

        // https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
        if (jwk.crv && (jwk.kty === 'EC')) {
            headerAlg = 'ES256';

            if (jwk.crv === 'P-384') {
                headerAlg = 'ES384';
                signerAlg = 'SHA384';
            }
            else if (jwk.crv === 'P-521') {
                headerAlg = 'ES512';
                signerAlg = 'SHA512';
            }
        }

        // Prepare body and signer
        const result = this.prepareSignedBody(headerAlg, url, payload, { nonce, kid });
        const signer = createSign(signerAlg).update(`${result.protected}.${result.payload}`, 'utf8');

        // Signature
        // https://stackoverflow.com/questions/39554165
        result.signature = signer.sign({
            key: this.accountKey,
            padding: RSA_PKCS1_PADDING,
            dsaEncoding: 'ieee-p1363',
        }, 'base64url');

        return result;
    }

    /**
     * Signed HTTP request
     *
     * https://datatracker.ietf.org/doc/html/rfc8555#section-6.2
     *
     * @param {string} url Request URL
     * @param {object} payload Request payload
     * @param {object} [opts]
     * @param {string} [opts.kid] JWS KID
     * @param {string} [opts.nonce] JWS anti-replay nonce
     * @param {boolean} [opts.includeExternalAccountBinding] Include EAB in request
     * @param {number} [opts.retryAttempt] Internal: rate limit / server error retry counter
     * @param {number} [attempts] Internal: bad nonce retry counter
     * @returns {Promise<object>} HTTP response
     */

    async signedRequest(url, payload, {
        kid = null, nonce = null, includeExternalAccountBinding = false, retryAttempt = 0,
    } = {}, attempts = 0) {
        if (!nonce) {
            nonce = await this.getNonce();
        }

        // External account binding, added to a copy so retries build it from the caller's payload again
        let body = payload;

        if (includeExternalAccountBinding && this.externalAccountBinding) {
            if (this.externalAccountBinding.kid && this.externalAccountBinding.hmacKey) {
                const jwk = this.getJwk();
                const eabKid = this.externalAccountBinding.kid;
                const eabHmacKey = this.externalAccountBinding.hmacKey;

                body = { ...payload, externalAccountBinding: this.createSignedHmacBody(eabHmacKey, url, jwk, { kid: eabKid }) };
            }
        }

        // Sign body and send request
        const data = this.createSignedBody(url, body, { nonce, kid });
        let resp;

        try {
            resp = await this.send(url, 'post', { data });
        }
        catch (e) {
            // Transport failure (send() never rejects on a status): sign again with a fresh nonce, never replay
            const outcome = { error: e };
            const delay = getRetryDelay(outcome, retryAttempt);

            if (delay === null) {
                throw e;
            }

            return this.resignAndRetry(url, payload, { kid, includeExternalAccountBinding, retryAttempt }, attempts, {
                cause: outcome, delay, last: { error: e }, replaySource: null,
            });
        }

        // Retry on bad nonce
        // https://datatracker.ietf.org/doc/html/rfc8555#section-6.5
        if (resp.data && resp.data.type && (resp.status === 400) && (resp.data.type === 'urn:ietf:params:acme:error:badNonce') && (attempts < this.maxBadNonceRetries)) {
            const { nonce: retryNonce, error: nonceError } = await this.getRetryNonce(resp, 0);

            // No nonce to sign with: spend the rate limit / server error budget on getting one
            if (!retryNonce) {
                const nonceDelay = getRetryDelay({ error: nonceError }, retryAttempt);

                if (nonceDelay === null) {
                    return this.giveUpRetry({ response: resp }, nonceError);
                }

                return this.resignAndRetry(url, payload, { kid, includeExternalAccountBinding, retryAttempt }, attempts + 1, {
                    cause: { error: nonceError }, delay: nonceDelay, last: { response: resp }, replaySource: null,
                });
            }

            attempts += 1;

            log(`Caught invalid nonce error, retrying (${attempts}/${this.maxBadNonceRetries}) signed request to: ${url}`);
            return this.signedRequest(url, payload, {
                kid, nonce: retryNonce, includeExternalAccountBinding, retryAttempt,
            }, attempts);
        }

        // Rate limits and server errors: sign again with a fresh nonce, never replay
        const outcome = { response: resp };
        const delay = getRetryDelay(outcome, retryAttempt);

        if (delay !== null) {
            return this.resignAndRetry(url, payload, { kid, includeExternalAccountBinding, retryAttempt }, attempts, {
                cause: outcome, delay, last: { response: resp }, replaySource: resp,
            });
        }

        // Return response
        return resp;
    }

    /**
     * Wait, then sign the request again with a fresh nonce
     *
     * One budget covers everything: each wait spends one of `retryMaxAttempts`,
     * whether it precedes the request itself or another try at getting a nonce.
     * If no nonce can be had once the budget is spent, the caller gets back
     * what it would have had without retrying: the last response, or the
     * original transport error.
     *
     * @private
     * @param {string} url Request URL
     * @param {object} payload Request payload
     * @param {object} opts Signing options and the retries done so far
     * @param {number} attempts Bad nonce retries done so far
     * @param {object} retry Why and how long to wait, and what to hand back
     * @returns {Promise<object>} HTTP response
     */

    async resignAndRetry(url, payload, { kid, includeExternalAccountBinding, retryAttempt }, attempts, {
        cause, delay, last, replaySource,
    }) {
        const nextAttempt = retryAttempt + 1;
        await waitForRetry(cause, delay, nextAttempt, url);

        const { nonce, error: nonceError } = await this.getRetryNonce(replaySource, delay);

        if (nonce) {
            return this.signedRequest(url, payload, {
                kid, nonce, includeExternalAccountBinding, retryAttempt: nextAttempt,
            }, attempts);
        }

        const nonceDelay = getRetryDelay({ error: nonceError }, nextAttempt);

        if (nonceDelay === null) {
            return this.giveUpRetry(last, nonceError);
        }

        return this.resignAndRetry(url, payload, { kid, includeExternalAccountBinding, retryAttempt: nextAttempt }, attempts, {
            cause: { error: nonceError }, delay: nonceDelay, last, replaySource: null,
        });
    }

    /**
     * Hand back the last outcome of a retry that could not get a nonce
     *
     * The nonce failure is kept, non-enumerable so it stays out of logged
     * responses: as `retryNonceError` on the response (apiRequest turns it into
     * the cause of its HttpError), or as the cause of the transport error.
     *
     * @private
     * @param {object} last Last response or transport error
     * @param {Error} nonceError Why no nonce could be had
     * @returns {object} The last response
     */

    giveUpRetry(last, nonceError) {
        const hidden = (target, key, value) => Object.defineProperty(target, key, {
            value, enumerable: false, configurable: true, writable: true,
        });

        if (last.response) {
            hidden(last.response, 'retryNonceError', nonceError);
            return last.response;
        }

        hidden(last.error, 'retryNonceError', nonceError);

        if (typeof last.error.cause === 'undefined') {
            hidden(last.error, 'cause', nonceError);
        }

        throw last.error;
    }

    /**
     * Nonce for signing a retry
     *
     * The response that triggers a retry usually carries a fresh nonce in its
     * Replay-Nonce header; using it saves a new-nonce request. It is only used
     * when the retry follows within `replayNonceMaxAge` seconds, since a CA
     * may expire a nonce while we wait. Otherwise one new nonce is fetched,
     * with a single request: a failure is retried by the caller within the
     * signed request's own budget, so nonce trouble cannot multiply retries.
     *
     * @private
     * @param {object|null} resp Response that triggered the retry
     * @param {number} waited Seconds waited since that response
     * @returns {Promise<{nonce: (string|null), error: (Error|null)}>} Nonce, or why there is none
     */

    async getRetryNonce(resp, waited) {
        const replayNonce = resp && resp.headers && resp.headers['replay-nonce'];

        if (replayNonce && (waited <= this.replayNonceMaxAge)) {
            return { nonce: replayNonce, error: null };
        }

        try {
            // The cached directory, even if stale: refetching it would bring its own retries
            const url = (this.directoryCache && this.directoryCache.newNonce) || await this.getResourceUrl('newNonce');
            const nonceResp = await this.send(url, 'head');

            if (!nonceResp.headers['replay-nonce']) {
                throw new Error(`Failed to get nonce from ACME provider (HTTP ${nonceResp.status})`);
            }

            return { nonce: nonceResp.headers['replay-nonce'], error: null };
        }
        catch (e) {
            log(`Could not get a fresh nonce for the retry: ${e.message}`);
            return { nonce: null, error: e };
        }
    }
}

// Export client
module.exports = HttpClient;
