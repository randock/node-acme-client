/**
 * Retry policy tests
 */

const { randomUUID: uuid } = require('crypto');
const { assert } = require('chai');
const nock = require('nock');
const axios = require('./../src/axios');
const { getRetryDelay, retryIdempotent } = require('./../src/retry');

describe('retry', () => {
    const endpoint = `http://${uuid()}.example.com`;
    let originalSettings;

    beforeEach(() => {
        originalSettings = { ...axios.defaults.acmeSettings };
        axios.defaults.acmeSettings.retryMaxAttempts = 3;
        axios.defaults.acmeSettings.retryDefaultDelay = 0;
        axios.defaults.acmeSettings.retryMaxDelay = null;
    });

    afterEach(() => {
        nock.cleanAll();
        axios.defaults.acmeSettings = originalSettings;
    });

    const response = (status, headers = {}) => ({ status, headers });

    describe('getRetryDelay', () => {
        it('should retry rate limits and server errors', () => {
            assert.strictEqual(getRetryDelay({ response: response(429) }, 0), 0);
            assert.strictEqual(getRetryDelay({ response: response(503) }, 0), 0);
        });

        it('should not retry other statuses', () => {
            [200, 201, 400, 403, 404, 409].forEach((status) => {
                assert.isNull(getRetryDelay({ response: response(status) }, 0), `status ${status}`);
            });
        });

        it('should honour Retry-After', () => {
            assert.strictEqual(getRetryDelay({ response: response(429, { 'retry-after': '7' }) }, 0), 7);
        });

        it('should hand a Retry-After above retryMaxDelay back', () => {
            axios.defaults.acmeSettings.retryMaxDelay = 60;
            assert.isNull(getRetryDelay({ response: response(429, { 'retry-after': '3600' }) }, 0));
            assert.strictEqual(getRetryDelay({ response: response(429, { 'retry-after': '30' }) }, 0), 30);
        });

        it('should back off by retryDefaultDelay per attempt without Retry-After', () => {
            axios.defaults.acmeSettings.retryDefaultDelay = 5;
            assert.strictEqual(getRetryDelay({ response: response(503) }, 0), 5);
            assert.strictEqual(getRetryDelay({ response: response(503) }, 2), 15);
        });

        it('should stop after retryMaxAttempts', () => {
            assert.isNull(getRetryDelay({ response: response(503) }, 3));
        });

        it('should not let retryMaxDelay shorten the own backoff', () => {
            // retryMaxDelay bounds what a server asks for; a cap of 0 must not mean back-to-back retries
            axios.defaults.acmeSettings.retryDefaultDelay = 5;
            axios.defaults.acmeSettings.retryMaxDelay = 0;
            assert.deepStrictEqual([0, 1, 2].map((a) => getRetryDelay({ response: response(503) }, a)), [5, 10, 15]);
            assert.strictEqual(getRetryDelay({ error: { code: 'ECONNRESET' } }, 1), 10);
        });

        it('should keep the own backoff below the timer limit, for responses and transport errors', () => {
            axios.defaults.acmeSettings.retryDefaultDelay = 3e6;
            assert.isBelow(getRetryDelay({ response: response(503) }, 0), 2147484);
            assert.isBelow(getRetryDelay({ error: { code: 'ECONNRESET' } }, 0), 2147484);
        });

        it('should hand back a Retry-After too large to parse, in any spelling', () => {
            axios.defaults.acmeSettings.retryMaxDelay = 120;
            ['99999999999999999999', ' 99999999999999999999 ', '+99999999999999999999', '1e30', ['99999999999999999999']].forEach((header) => {
                assert.isNull(getRetryDelay({ response: response(429, { 'retry-after': header }) }, 0), JSON.stringify(header));
            });
        });

        it('should round a fractional Retry-After up', () => {
            assert.strictEqual(getRetryDelay({ response: response(429, { 'retry-after': '1.5' }) }, 0), 2);
        });

        it('should read numeric strings in the settings', () => {
            axios.defaults.acmeSettings = { retryMaxAttempts: '2', retryDefaultDelay: '7', retryMaxDelay: '120' };
            assert.strictEqual(getRetryDelay({ response: response(503) }, 0), 7);
            assert.isNull(getRetryDelay({ response: response(503) }, 2));
            assert.isNull(getRetryDelay({ response: response(429, { 'retry-after': '121' }) }, 0));
        });

        it('should retry transport failures, except aborted requests', () => {
            assert.strictEqual(getRetryDelay({ error: { code: 'ECONNRESET' } }, 0), 0);
            assert.isNull(getRetryDelay({ error: { code: 'ECONNABORTED' } }, 0));
        });
    });

    describe('http layer', () => {
        it('should not retry anything itself', async () => {
            let calls = 0;

            nock(endpoint).persist().get('/').reply(() => {
                calls += 1;
                return [503, 'unavailable'];
            });

            const resp = await axios.request({ url: endpoint, method: 'get', validateStatus: null });

            assert.strictEqual(resp.status, 503);
            assert.strictEqual(calls, 1);
        });
    });

    describe('retryIdempotent', () => {
        it('should retry a request whose status axios rejects', async () => {
            let calls = 0;

            nock(endpoint).persist().get('/challenge').reply(() => {
                calls += 1;
                return (calls < 2) ? [503, 'unavailable'] : [200, 'key-authz'];
            });

            const resp = await retryIdempotent(() => axios.get(`${endpoint}/challenge`), `${endpoint}/challenge`);

            assert.strictEqual(resp.status, 200);
            assert.strictEqual(calls, 2);
        });

        it('should rethrow a rejected status that is not retryable, without retrying', async () => {
            let calls = 0;

            nock(endpoint).persist().get('/challenge').reply(() => {
                calls += 1;
                return [404, 'not found'];
            });

            await assert.isRejected(retryIdempotent(() => axios.get(`${endpoint}/challenge`), `${endpoint}/challenge`));
            assert.strictEqual(calls, 1);
        });

        it('should retry a transport failure and then give up with the error', async () => {
            const scope = nock(endpoint).get('/challenge').times(4).replyWithError({ code: 'ECONNRESET', message: 'socket hang up' });

            await assert.isRejected(retryIdempotent(() => axios.get(`${endpoint}/challenge`), `${endpoint}/challenge`), /socket hang up/);
            assert.isTrue(scope.isDone(), 'expected 1 attempt plus 3 retries');
        });
    });
});
