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
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '1', 'Replay-Nonce': 'from-the-429' }];
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

        nock(endpoint).persist().post('/new-order').reply(() => [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '1' }]);

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.strictEqual(resp.status, 429);
        assert.strictEqual(resp.headers['retry-after'], '1');
    });

    it('should stay bounded when bad nonces and rate limits alternate', async () => {
        mockServer();
        let posts = 0;

        nock(endpoint).persist().post('/new-order').reply(() => {
            posts += 1;

            if (posts % 2) {
                return [400, { type: 'urn:ietf:params:acme:error:badNonce' }, { 'Replay-Nonce': `replay-${posts}` }];
            }

            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '1', 'Replay-Nonce': `replay-${posts}` }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey);
        const resp = await client.signedRequest(`${endpoint}/new-order`, {}, { kid: 'kid-1' });

        assert.oneOf(resp.status, [400, 429]);
        assert.isAtMost(posts, 1 + client.maxBadNonceRetries + axios.defaults.acmeSettings.retryMaxAttempts);
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
            return [429, { type: 'urn:ietf:params:acme:error:rateLimited' }, { 'Retry-After': '1' }];
        });
        nock(endpoint).post('/new-account').reply((uri, body) => {
            record(body);
            return [201, { status: 'valid' }];
        });

        const client = new HttpClient(`${endpoint}/directory`, accountKey, {
            kid: 'eab-kid',
            hmacKey: randomBytes(32).toString('base64'),
        });
        const resp = await client.signedRequest(`${endpoint}/new-account`, { termsOfServiceAgreed: true }, { includeExternalAccountBinding: true });

        assert.strictEqual(resp.status, 201);
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
