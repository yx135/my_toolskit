#pragma once

#include <chrono>
#include <string>

#include "IntellBoxCommon/Utils/HttpClient/HttpResponseCodes.h"

namespace intellBoxSDK {

/// Minimal interface for making Http POST requests.
class HttpPostInterface {
public:
    /// Virtual destructor to assure proper cleanup of derived types.
    virtual ~HttpPostInterface() = default;

    /**
     * Adds a HTTP Header to the CURL handle
     *
     * @param header The HTTP header to add to the POST request.
     * @returns @c true if the addition was successful @c false otherwise.
     */
    virtual bool addHTTPHeader(const std::string& header) = 0;

    /**
     * Perform an HTTP Post request returning the response body as a string. This method blocks for the duration
     * of the request.
     *
     * @param url The URL to send the POST to.
     * @param data The POST data to send in the request.
     * @param timeout The maximum amount of time (in seconds) to wait for the request to complete.
     * @param[out] body A string to receive the body of the request if there is one.
     * @return A HttpStatus indicating the disposition of the Post request.
     */
    virtual HTTPResponseCode doPost(
        const std::string& url,
        const std::string& data,
        std::chrono::seconds timeout,
        std::string& body) = 0;
};

}  // namespace intellBoxSDK
