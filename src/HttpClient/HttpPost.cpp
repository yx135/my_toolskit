
#include <iostream>
#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/HttpClient/HttpPost.h"

namespace intellBoxSDK {

std::unique_ptr<HttpPost> HttpPost::create() {
    std::unique_ptr<HttpPost> httpPost(new HttpPost());
    if (httpPost->m_curl.isValid()) {
        return httpPost;
    }
    return nullptr;
}

bool HttpPost::addHTTPHeader(const std::string& header) {
    return m_curl.addHTTPHeader(header);
}

HTTPResponseCode HttpPost::doPost(
    const std::string& url,
    const std::string& data,
    std::chrono::seconds timeout,
    std::string& body) {
    std::lock_guard<std::mutex> lock(m_mutex);
    body.clear();

    if (!m_curl.setTransferTimeout(static_cast<long>(timeout.count())) || !m_curl.setURL(url) ||
        !m_curl.setPostData(data) || !m_curl.setWriteCallback(staticWriteCallbackLocked, &body)) {
        return HTTPResponseCode::HTTP_RESPONSE_CODE_UNDEFINED;
    }

    auto curlHandle = m_curl.getCurlHandle();
    auto result = curl_easy_perform(curlHandle);

    if (result != CURLE_OK) {
        LOG_INFO("[HttpPost:{0}]result:{1}", __LINE__, result);
        body.clear();
        return HTTPResponseCode::HTTP_RESPONSE_CODE_UNDEFINED;
    }

    long responseCode = 0;
    result = curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &responseCode);
    if (result != CURLE_OK) {
        // ACSDK_ERROR(LX("doPostFailed")
        //                 .d("reason", "curl_easy_getinfoFailed")
        //                 .d("property", "CURLINFO_RESPONSE_CODE")
        //                 .d("result", result)
        //                 .d("error", curl_easy_strerror(result)));
        body.clear();
        return HTTPResponseCode::HTTP_RESPONSE_CODE_UNDEFINED;
    } else {
        // ACSDK_DEBUG(LX("doPostSucceeded").d("code", responseCode));
        return static_cast<HTTPResponseCode>(responseCode);
    }
}

size_t HttpPost::staticWriteCallbackLocked(char* ptr, size_t size, size_t nmemb, void* userdata) {
    if (!userdata) {
        // ACSDK_ERROR(LX("staticWriteCallbackFailed").d("reason", "nullUserData"));
        return 0;
    }

    size_t count = size * nmemb;
    auto body = static_cast<std::string*>(userdata);
    body->append(ptr, count);
    return count;
}

}  // namespace intellBoxSDK
