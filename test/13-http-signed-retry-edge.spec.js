/**
 * Signed request retries: edge cases from review
 *
 * Missing retry settings, nonce reuse from the response, a failing nonce fetch
 * during a retry, interplay with the bad nonce counter, and that retries keep
 * the KID, JWK and external account binding of the original request.
 */

const { randomUUID: uuid, generateKeyPairSync, randomBytes } = require('crypto');
const { assert } = require('chai');
const nock = require('nock');
const axios = require('./../src/axios');
const HttpClient = require('./../src/http');
const AcmeApi = require('./../src/api');
const HttpError = require('./../src/error/http');

describe('http signed request retries (edge cases)', () => {
    const accountKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });

    let endpoint;
    let nonceRequests;
    let originalSettings;

    const decode = (body) => {
        const jws = (typeof body === 'string') ? JSON.parse(body) : body;
        return {
            header: JSON.parse(Buffer.from(jws.protected, 'base64url').toString()),
            payload: jws.payload ? JSON.parse(Buffer.from(jws.payload, 'base64url').toString()) : null,
        };
    };

    /* Directory plus a new-nonce endpoint; `nonceReply` decides each HEAD */
    const mockServer = (nonceReply = () => [200, '', { 'Replay-Nonce': `nonce-${uuid()}` }]) => {
        nock(endpoint).persist().get('/directory').reply(200, {
            newNonce: `${endpoint}/new-nonce`,
            newOrder: `${endpoint}/new-order`,
            newAccount: `${endpoint}/new-account`,
            renewalInfo: `${endpoint}/renewal-info`,
        });
        nock(endpoint).persist().head('/new-nonce').reply(() => {
            nonceRequests += 1;
            return nonceReply(nonceRequests);
        });
    };

    beforeEach(() => {
        endpoint = `http://${uuid()}.example.com`;
        nonceRequests = 0;
        originalSettings = { ...axios.defaults.acmeSettings };
        axios.defaults.acmeSettings.retryMaxAttempts = 3;
        axios.defaults.acmeSettings.retryDefaultDelay = 0;
        axios.defaults.acmeSettings.retryMaxDelay = 120;
    });

    afterEach(() => {
        nock.cleanAll();
        axios.defaults.acmeSettings = originalSettings;
    });

    it('should not retry at all when the retry settings are missing', async () => {
        axios.defaults.acmeSettings = { httpChallengePort: 80 };
        mockServer();

        let posts = 0;
        nock(endpoint).persist().post('/new-order').reply(() => {
            posts += 1;
            return [503, 'unavailable'];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 503);
        assert.strictEqual(posts, 1);
    });

    it('should not retry an unsigned request when the retry settings are missing', async () => {
        axios.defaults.acmeSettings = {};

        let gets = 0;
        nock(endpoint).persist().get('/plain').reply(() => {
            gets += 1;
            return [503, 'unavailable'];
        });

        const resp = await new HttpClient().request(`${endpoint}/plain`, 'get');

        assert.strictEqual(resp.status, 503);
        assert.strictEqual(gets, 1);
    });

    it('should sign the retry with the Replay-Nonce of the rate limited response', async () => {
        mockServer();
        const nonces = [];

        nock(endpoint).post('/new-order').reply((uri, body) => {
            nonces.push(decode(body).header.nonce);
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Replay-Nonce': 'from-the-429' }];
        });
        nock(endpoint).post('/new-order').reply((uri, body) => {
            nonces.push(decode(body).header.nonce);
            return [201, { status: 'pending' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 201);
        assert.strictEqual(nonces[1], 'from-the-429');
        assert.strictEqual(nonceRequests, 1, 'only the first request should fetch a nonce');
    });

    it('should hand the 429 back, not a nonce error, when no nonce can be had for the retry', async () => {
        // First nonce works, every later new-nonce request fails
        mockServer((n) => ((n === 1) ? [200, '', { 'Replay-Nonce': 'nonce-1' }] : [503, 'unavailable']));

        nock(endpoint).persist().post('/new-order').reply(() => [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '0' }]);

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 429);
        assert.strictEqual(resp.headers['retry-after'], '0');
        assert.instanceOf(resp.retryNonceError, Error);
        assert.notInclude(Object.keys(resp), 'retryNonceError', 'the nonce error must stay out of logged responses');
        // 1 nonce for the request, then 1 per retry of the 3 in the budget: no nested nonce retries
        assert.strictEqual(nonceRequests, 4);
    });

    it('should stay bounded when bad nonces and rate limits alternate', async () => {
        mockServer();
        let posts = 0;

        nock(endpoint).persist().post('/new-order').reply(() => {
            posts += 1;

            if (posts % 2) {
                return [400, { type: 'urn:ietf:params:acme:error:badNonce' }, { 'Replay-Nonce': `replay-${posts}` }];
            }

            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Replay-Nonce': `replay-${posts}` }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        // bad, 429, bad, 429, bad, 429, bad, 429: the fourth 429 exhausts retryMaxAttempts (3)
        assert.strictEqual(resp.status, 429);
        assert.strictEqual(posts, 8);
    });

    it('should not reset the bad nonce budget when a rate limit retry happens in between', async () => {
        mockServer();
        let posts = 0;

        nock(endpoint).persist().post('/new-order').reply(() => {
            posts += 1;

            if (posts === 6) {
                return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Replay-Nonce': `replay-${posts}` }];
            }

            return [400, { type: 'urn:ietf:params:acme:error:badNonce' }, { 'Replay-Nonce': `replay-${posts}` }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        // 5 bad nonces use up the budget, the 429 is retried once, the next bad nonce is final
        assert.strictEqual(resp.status, 400);
        assert.strictEqual(posts, 7);
    });

    it('should fetch a fresh nonce instead of reusing one after a long wait', async () => {
        mockServer();
        const nonces = [];

        nock(endpoint).post('/new-order').reply((uri, body) => {
            nonces.push(decode(body).header.nonce);
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Replay-Nonce': 'possibly-stale' }];
        });
        nock(endpoint).post('/new-order').reply((uri, body) => {
            nonces.push(decode(body).header.nonce);
            return [201, { status: 'pending' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        client.replayNonceMaxAge = -1;
        await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.notStrictEqual(nonces[1], 'possibly-stale');
        assert.strictEqual(nonceRequests, 2);
    });

    it('should survive a network blip that also hits the first retry nonce', async () => {
        // nonce 1 works, nonce 2 hits the same outage, nonce 3 works again
        let heads = 0;
        nock(endpoint).persist().get('/directory').reply(200, { newNonce: `${endpoint}/new-nonce`, newOrder: `${endpoint}/new-order` });
        nock(endpoint).head('/new-nonce').reply(() => { heads += 1; return [200, '', { 'Replay-Nonce': 'n1' }]; });
        nock(endpoint).head('/new-nonce').replyWithError({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' });
        nock(endpoint).head('/new-nonce').reply(() => { heads += 1; return [200, '', { 'Replay-Nonce': 'n3' }]; });

        nock(endpoint).post('/new-order').replyWithError({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' });
        nock(endpoint).post('/new-order').reply(() => [201, { status: 'pending' }]);

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 201);
        assert.strictEqual(heads, 2);
    });

    it('should not give up a server error retry on one failed nonce fetch', async () => {
        nock(endpoint).persist().get('/directory').reply(200, { newNonce: `${endpoint}/new-nonce`, newOrder: `${endpoint}/new-order` });
        nock(endpoint).head('/new-nonce').reply(200, '', { 'Replay-Nonce': 'n1' });
        nock(endpoint).head('/new-nonce').reply(503, 'unavailable');
        nock(endpoint).head('/new-nonce').reply(200, '', { 'Replay-Nonce': 'n3' });

        nock(endpoint).post('/new-order').reply(503, { type: 'urn:ietf:params:acme:error:serverInternal' });
        nock(endpoint).post('/new-order').reply(201, { status: 'pending' });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 201);
    });

    it('should keep the nonce failure on a rethrown transport error, without replacing its cause', async () => {
        mockServer((n) => ((n === 1) ? [200, '', { 'Replay-Nonce': 'nonce-1' }] : [503, 'unavailable']));
        nock(endpoint).persist().post('/new-order').replyWithError({ code: 'ECONNRESET', message: 'socket hang up' });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);

        try {
            await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });
            assert.fail('expected the transport error');
        }
        catch (e) {
            assert.strictEqual(e.code, 'ECONNRESET');
            // axios already sets the socket error as cause; it is kept, the nonce failure rides along
            assert.isDefined(e.cause);
            assert.notMatch(String(e.cause && e.cause.message), /Failed to get nonce/);
            assert.instanceOf(e.retryNonceError, Error);
            assert.match(e.retryNonceError.message, /Failed to get nonce/);
            assert.notInclude(Object.keys(e), 'retryNonceError');
        }
    });

    it('should reuse a Replay-Nonce up to replayNonceMaxAge seconds, and fetch a fresh one after', async () => {
        mockServer();
        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = { headers: { 'replay-nonce': 'from-response' } };

        assert.strictEqual((await client.getRetryNonce(resp, 30)).nonce, 'from-response');
        assert.strictEqual(nonceRequests, 0);

        assert.notStrictEqual((await client.getRetryNonce(resp, 31)).nonce, 'from-response');
        assert.strictEqual(nonceRequests, 1);
    });

    it('should fetch a retry nonce from the cached directory, even when it is stale', async () => {
        let directoryGets = 0;
        nock(endpoint).persist().get('/directory').reply(() => { directoryGets += 1; return [200, { newNonce: `${endpoint}/new-nonce` }]; });
        nock(endpoint).persist().head('/new-nonce').reply(200, '', { 'Replay-Nonce': 'fresh' });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        await client.getDirectory();
        client.directoryTimestamp = 0;

        const { nonce } = await client.getRetryNonce(null, 0);

        assert.strictEqual(nonce, 'fresh');
        assert.strictEqual(directoryGets, 1);
    });

    it('should keep the cause on HttpError', () => {
        const cause = new Error('why');
        const e = new HttpError('message', { status: 503 }, { cause });

        assert.strictEqual(e.cause, cause);
        assert.strictEqual(e.response.status, 503);
    });

    it('should honour retry settings given as strings', async () => {
        axios.defaults.acmeSettings = { retryMaxAttempts: '3', retryDefaultDelay: '0', retryMaxDelay: '120' };
        mockServer();

        let rateLimited = 0;
        nock(endpoint).persist().post('/new-order').reply(() => {
            rateLimited += 1;
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '3600', 'Replay-Nonce': 'n' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 429, 'a Retry-After above the string retryMaxDelay must be handed back');
        assert.strictEqual(rateLimited, 1);

        let unavailable = 0;
        nock(endpoint).persist().get('/plain').reply(() => {
            unavailable += 1;
            return [503, 'unavailable'];
        });

        await client.request(`${endpoint}/plain`, 'get');
        assert.strictEqual(unavailable, 4, 'a string retryMaxAttempts must still allow retries');
    });

    it('should not sleep on any Retry-After when retryMaxDelay is set but invalid', async () => {
        axios.defaults.acmeSettings = { retryMaxAttempts: 3, retryDefaultDelay: 0, retryMaxDelay: 'soon' };
        mockServer();

        let posts = 0;
        nock(endpoint).persist().post('/new-order').reply(() => {
            posts += 1;
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '5', 'Replay-Nonce': 'n' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 429);
        assert.strictEqual(posts, 1);
    });

    it('should carry the nonce failure as the cause of the HttpError', async () => {
        mockServer((n) => ((n === 1) ? [200, '', { 'Replay-Nonce': 'nonce-1' }] : [503, 'unavailable']));
        nock(endpoint).persist().post('/new-order').reply(() => [503, { type: 'urn:ietf:params:acme:error:serverInternal' }]);

        const api = new AcmeApi(new HttpClient(`${endpoint}/directory`, accountKey), `${endpoint}/acct/1`);

        try {
            await api.apiRequest(`${endpoint}/new-order`, {}, [201]);
            assert.fail('expected an HttpError');
        }
        catch (e) {
            assert.instanceOf(e, HttpError);
            assert.strictEqual(e.response.status, 503);
            assert.instanceOf(e.cause, Error);
            assert.match(e.cause.message, /Failed to get nonce/);
        }
    });

    it('should keep the KID on every retry', async () => {
        mockServer();
        const kids = [];

        nock(endpoint).post('/new-order').reply((uri, body) => {
            kids.push(decode(body).header.kid);
            return [503, 'unavailable'];
        });
        nock(endpoint).post('/new-order').reply((uri, body) => {
            kids.push(decode(body).header.kid);
            return [400, { type: 'urn:ietf:params:acme:error:badNonce' }, { 'Replay-Nonce': 'replay' }];
        });
        nock(endpoint).post('/new-order').reply((uri, body) => {
            kids.push(decode(body).header.kid);
            return [201, { status: 'pending' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        await client.signedRequest(`${endpoint}/new-order`, {}, { kid: `${endpoint}/acct/1` });

        assert.deepStrictEqual(kids, [`${endpoint}/acct/1`, `${endpoint}/acct/1`, `${endpoint}/acct/1`]);
    });

    it('should keep the JWK and external account binding on every retry', async () => {
        mockServer();
        const attempts = [];

        const record = (body) => {
            const { header, payload } = decode(body);
            attempts.push({ jwk: !!header.jwk, kid: header.kid, eab: !!(payload && payload.externalAccountBinding) });
        };

        nock(endpoint).post('/new-account').reply((uri, body) => {
            record(body);
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }];
        });
        nock(endpoint).post('/new-account').reply((uri, body) => {
            record(body);
            return [201, { status: 'valid' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey, {
            kid: 'eab-kid',
            hmacKey: randomBytes(32).toString('base64'),
        });
        const payload = { termsOfServiceAgreed: true };
        const resp = await client.signedRequest(`${endpoint}/new-account`, payload, { includeExternalAccountBinding: true });

        assert.strictEqual(resp.status, 201);
        assert.notProperty(payload, 'externalAccountBinding', 'the caller payload must not be mutated');
        assert.deepStrictEqual(attempts, [
            { jwk: true, kid: undefined, eab: true },
            { jwk: true, kid: undefined, eab: true },
        ]);
    });

    it('should report an ARI rate limit as an HttpError with the response', async () => {
        mockServer();

        nock(endpoint).persist().get('/renewal-info/cert-id').reply(() => [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '3600' }]);

        const api = new AcmeApi(new HttpClient(`${endpoint}/directory`, accountKey));

        try {
            await api.getCertRenewalInfo('cert-id');
            assert.fail('expected an HttpError');
        }
        catch (e) {
            assert.instanceOf(e, HttpError);
            assert.strictEqual(e.response.status, 429);
            assert.strictEqual(e.response.headers['retry-after'], '3600');
        }
    });
});
