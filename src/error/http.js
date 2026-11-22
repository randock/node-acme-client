class HttpError extends Error {
    constructor(message, response, options = undefined) {
        super(message, options);
        this.response = response;
    }
}

module.exports = HttpError;
