#pragma once

namespace intellBoxSDK {

enum class HTTPResponseCode {
    /// No HTTP response received.
    HTTP_RESPONSE_CODE_UNDEFINED = 0,
    /// HTTP Success with reponse payload.
    SUCCESS_OK = 200,
    /// HTTP Succcess with no response payload.
    SUCCESS_NO_CONTENT = 204,
    /// HTTP code for invalid request by user.
    BAD_REQUEST = 400,
    /// HTTP code for internal error by server which didn't fulfill the request.
    SERVER_INTERNAL_ERROR = 500
};

}  // namespace intellBoxSDK
