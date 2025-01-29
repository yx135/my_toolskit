#pragma once

#include <map>
#include <set>
#include <memory>
#include <cstring>
#include <functional>
#include <curl/curl.h>
#include "IntellBoxCommon/SDKInterfaces/Error.h"
#include "nlohmann/json.hpp"

namespace intellBoxSDK {

using Json = nlohmann::json;

struct DataBuf {
    char* payload;
    size_t size;
};

class HTTPSClient {
public:
    struct ClientCA;
    struct SSLSwitch;
    enum class HTTP_VER;
    enum class SSL_VER;

    ~HTTPSClient();

    static std::shared_ptr<HTTPSClient> create(Json rootNode);

    void clearPut();
    void clearHeader();
    void disableTrace();
    void enableTrace(bool traceLog = true);

    struct curl_slist* headerAppend(const std::string& header);
    Error headerAppend(const std::set<std::string>& header);
    Error connectRemote(const std::string ip, uint16_t port);

    Error customPut(const char* data, size_t size);
    Error customPut(const std::string data);
    Error customHeader(struct curl_slist* headers);
	 Error customSSL(const char* data, size_t size);

    Error setURL(const std::string& url);
    Error setSSLVer(SSL_VER ver);
    Error setHTTPVer(const HTTP_VER& ver);
    Error setCipherList(std::vector<std::string>& cipher);
    // Error setClientExchangeKeyAlgorithmes();
    Error setAppLayerProtoNegotiation(bool enable = true);
    Error setServerCA(const std::string& caFile, const std::string& caPath = "");
    Error setClientCA(const ClientCA& clientCA);
    Error setCASwitch(SSLSwitch sw);
    Error confSSL(const std::string& serverCA, const ClientCA& clientCA, const SSLSwitch sw);

    std::string Get();
    Error Post(const std::string& data);
    Error Put();

    std::string getPostInfo();
    std::string getDebugInfo();
    std::string getHeaderInfo();
    int getResponseCode(std::string& reason);
    std::string getHeaderData(const std::string& key);
    std::string getSSLInfo();
    std::string getCURLVer();
    std::string getCURLSSLVer();
    std::string getCURLZlibVer();

private:
    enum class OptType;
    typedef void (*CVCallback)(void);

    HTTPSClient();
    Error initialize(Json rootNode);
    Error getVer(const std::string index, std::string& ver);
    Error setPutOpt(bool enable = true);

    Error callbackOpt();
    Error registerCallback(
        std::pair<CURLoption, CURLoption> opt[],
        std::vector<CVCallback>& callback,
        std::vector<DataBuf>& buffer);

    friend size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata);
    friend size_t readCallback(char* buffer, size_t size, size_t nitems, void* userdata);
    friend size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata);
    friend int debugCallback(CURL* handle, curl_infotype type, char* data, size_t size, void* userptr);
    friend CURLcode sslCallback(CURL* curl, void* ssl_ctx, void* userptr);

    void resetCURL();
    void resetBuf();
    size_t parseHeader();

    template <class T>
    int setOpt(CURLoption opt, T val);

    CURL* m_curl;
    struct curl_slist* m_list;

    std::string m_schema;
    static bool m_traceLog;
    std::vector<DataBuf> m_dataBuf;
    std::vector<CVCallback> m_callbackFunc;
    std::map<SSL_VER, long> m_sslMap;
    std::map<HTTP_VER, long> m_httpMap;
    std::map<std::string, std::string> m_headerMap;
};

enum class HTTPSClient::HTTP_VER { V_NONE, V_1_0, V_1_1, V_2_0, V_2TLS, V_2, V_3 };
enum class HTTPSClient::SSL_VER {
    V_DEFAULT,
    V_TLSv1,
    V_SSLv2,
    V_SSLv3,
    V_TLSv1_0,
    V_TLSv1_1,
    V_TLSv1_2,
    V_TLSv1_3,
    V_LAST
};

struct HTTPSClient::ClientCA {
    std::string crtType;
    std::string cert;
    std::string keyType;
    std::string key;
    std::string passwd;
};

struct HTTPSClient::SSLSwitch {
    uint8_t verifyHost : 2;
    bool verifyPeer;
    bool verifyStatus;
};

}  // namespace intellBoxSDK
