/**
 * Axios instance
 */

const axios = require('axios');
const pkg = require('./../package.json');

const { AxiosError } = axios;

/**
 * Defaults
 */

const instance = axios.create();

// Default User-Agent
instance.defaults.headers.common['User-Agent'] = `node-${pkg.name}/${pkg.version}`;

// Default ACME settings
instance.defaults.acmeSettings = {
    httpChallengePort: 80,
    httpsChallengePort: 443,
    tlsAlpnChallengePort: 443,

    retryMaxAttempts: 5,
    retryDefaultDelay: 5,
    retryMaxDelay: null,
};

/**
 * Explicitly set Node as default HTTP adapter
 *
 * https://github.com/axios/axios/issues/1180
 * https://stackoverflow.com/questions/42677387
 */

instance.defaults.adapter = 'http';

// https://github.com/axios/axios/blob/main/lib/core/settle.js
function validateStatus(response) {
    const validator = response.config.retryValidateStatus;

    if (!response.status || !validator || validator(response.status)) {
        return response;
    }

    throw new AxiosError(
        `Request failed with status code ${response.status}`,
        (Math.floor(response.status / 100) === 4) ? AxiosError.ERR_BAD_REQUEST : AxiosError.ERR_BAD_RESPONSE,
        response.config,
        response.request,
        response,
    );
}

// Pass all responses through the error interceptor
instance.interceptors.request.use((config) => {
    if (!('retryValidateStatus' in config)) {
        config.retryValidateStatus = config.validateStatus;
    }

    config.validateStatus = () => false;
    return config;
});

/* Hand every response back as is. Retries are not done here: a signed ACME
   request cannot be sent again unchanged (its nonce is single use), so the
   retry policy lives in retry.js and is applied by HttpClient, which knows
   whether a request has to be signed again. */
instance.interceptors.response.use(null, async (error) => {
    const { config, response } = error;

    // Transport failure, or not one of our requests: nothing to validate
    if (!config || !response) {
        return Promise.reject(error);
    }

    return validateStatus(response);
});

/**
 * Export instance
 */

module.exports = instance;
