class HttpError extends Error {
    constructor(message, response, options = undefined) {
        super(message, options);
        this.response = response;

        // Error options arrived in Node 16.9; keep the cause on older versions too
        if (options && ('cause' in options) && (typeof this.cause === 'undefined')) {
            Object.defineProperty(this, 'cause', {
                value: options.cause, enumerable: false, configurable: true, writable: true,
            });
        }
    }
}

module.exports = HttpError;
