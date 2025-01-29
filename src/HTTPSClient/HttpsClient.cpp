#include "IntellBoxCommon/Utils/HTTPSClient/HttpsClient.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include <unistd.h>
#include <cstdio>

namespace intellBoxSDK {

#define WRITE_SIZE 4096
#define READ_SIZE WRITE_SIZE
#define CLIENT_CA_TYPE_INDEX "clientCAType"
#define CLIENT_CA_INDEX "clientCA"
#define CLIENT_KEY_TYPE_INDEX "clientKeyType"
#define CLIENT_KEY_INDEX "clientKey"
#define CLIENT_CA_PASSWD_INDEX "clientKeyPasswd"
#define SERVER_CA_INDEX "serverCA"
#define VERIFY_HOST_INDEX "verifyHost"
#define VERIFY_PEER_INDEX "verifyPeer"
#define VERIFY_STATUS_INDEX "verifyStatus"
#define PREV_PUT_VERSION "7.12.1"

bool HTTPSClient::m_traceLog = false;
using HTTP_VER = HTTPSClient::HTTP_VER;
static std::map<std::string, HTTP_VER> verMap = {{"none", HTTP_VER::V_NONE},
                                                 {"1.0", HTTP_VER::V_1_0},
                                                 {"1.1", HTTP_VER::V_1_1},
                                                 {"2.0", HTTP_VER::V_2_0},
                                                 {"2TLS", HTTP_VER::V_2TLS},
                                                 {"2", HTTP_VER::V_2},
                                                 {"3", HTTP_VER::V_3}};
const std::string CRLF = "\r\n";
const std::string SS = ": ";

enum class HTTPSClient::OptType { READ, WRITE, DEBUG, SSL, HEADER };

typedef int (*DebugCallback)(CURL*, curl_infotype, char*, size_t, void*);
typedef size_t (*DataCallback)(char*, size_t, size_t, void*);
typedef CURLcode (*SSLCallback)(CURL*, void*, void*);

static FILE* debugFd = stderr;
static bool isDigital(const std::string& str) {
    for (auto strInfo : str) {
        if ((strInfo > '9' || strInfo < '0')) {
            return false;
        }
    }
    return true;
}

static void dump(const char text, FILE* stream, char* ptr, size_t size, void* userptr) {
    if (stream == nullptr) {
        stream = stderr;
    }

    size_t i, c;
    unsigned int width = 0x10;
    fputc(text, stream);
    for (i = 0; i < size; i += width) {
        for (c = 0; (c < width) && (i + c < size); c++) {
            char x = (ptr[i + c] >= 0x20 && ptr[i + c] < 0x80)
                         ? ptr[i + c]
                         : ptr[i + c] != 0x0D ? ptr[i + c] == 0x0A ? ' ' : '\t' : ' ';
            fputc(x, stream);
            if (x == '>') {
                fputc('\n', stream);
            }
        }
    }
    fputc('\n', stream);
}

int debugCallback(CURL* handle, curl_infotype type, char* data, size_t size, void* userptr) {
    char text;
    (void)handle; /* prevent compiler warning */
    (void)userptr;

    switch (type) {
        case CURLINFO_HEADER_OUT:
        case CURLINFO_DATA_OUT:
            text = '>';
            break;
        case CURLINFO_HEADER_IN:
        case CURLINFO_DATA_IN:
            text = '<';
            break;
        case CURLINFO_SSL_DATA_OUT:
        case CURLINFO_SSL_DATA_IN:
        default:
            return -1;
    }

    if (HTTPSClient::m_traceLog) {
        struct DataBuf* mem = (struct DataBuf*)userptr;
        mem->payload = (char*)realloc(mem->payload, mem->size + size + 1);
        if (mem->payload == NULL) {
            LOG_ERROR("[{0}][{1}] Debug data size too large.", __FUNCTION__, __LINE__);
            return -1;
        }
        memcpy(&mem->payload[mem->size], data, size);

        mem->size += size;
        mem->payload[mem->size] = '\0';

        if (debugFd == nullptr || debugFd == stderr) {
            debugFd = fopen("/dev/null", "w");
        }
    }

    dump(text, debugFd, data, size, userptr);
    return 0;
}

size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t realSize = size * nmemb;
    struct DataBuf* mem = (struct DataBuf*)userdata;
    mem->payload = (char*)realloc(mem->payload, mem->size + realSize + 1);
    if (mem->payload == NULL) {
        return 0;
    }

    memcpy(&mem->payload[mem->size], ptr, realSize);
    mem->size += realSize;
    mem->payload[mem->size] = 0;
    return realSize;
}

size_t readCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    struct DataBuf* mem = (struct DataBuf*)userdata;
    size_t readSize = size * nitems, dataIndex = 0;
    if (readSize <= mem->size) {
        memcpy(buffer, &mem->payload[dataIndex], readSize);
        mem->size -= readSize;
        return readSize;
    }

    memcpy(buffer, &mem->payload[dataIndex], mem->size);
    dataIndex = mem->size;
    mem->size = 0;
    return dataIndex;
}

size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t realSize = size * nitems;
    struct DataBuf* mem = (struct DataBuf*)userdata;
    mem->payload = (char*)realloc(mem->payload, mem->size + realSize + 1);
    if (mem->payload == NULL) {
        return 0;
    }

    memcpy(&mem->payload[mem->size], buffer, realSize);
    mem->size += realSize;
    mem->payload[mem->size] = 0;
    return realSize;
}

CURLcode sslCallback(CURL* curl, void* ssl_ctx, void* userptr) {
	 LOG_INFO("[{0}][{1}] ", __FUNCTION__, __LINE__);
    return CURLcode::CURLE_OK;
}

std::string HTTPSClient::getCURLVer() {
    const std::string verIndex = "libcurl";

    std::string ver = curl_version();
    int verLen = ver.find(verIndex) + verIndex.length();
    int len = ver.find(" ") - verLen - 1;
    return ver.substr(verLen + 1, len);
}

std::string HTTPSClient::getCURLSSLVer() {
    std::string ver;
    if (Error::SUCCESS != getVer("OpenSSL", ver)) {
        return "";
    }
    return ver;
}

std::string HTTPSClient::getCURLZlibVer() {
    std::string ver;
    if (Error::SUCCESS != getVer("zlib", ver)) {
        return "";
    }
    return ver;
}

void HTTPSClient::clearPut() {
    auto readBuf = m_dataBuf[static_cast<int>(OptType::READ)];
    if (readBuf.payload != nullptr) {
        delete[] readBuf.payload;
        readBuf.payload = nullptr;
        readBuf.size = 0;
    }
}

void HTTPSClient::clearHeader() {
    curl_slist_free_all(m_list);
    m_list = nullptr;
}

struct curl_slist* HTTPSClient::headerAppend(const std::string& header) {
    return m_list = curl_slist_append(m_list, header.c_str());
}

Error HTTPSClient::headerAppend(const std::set<std::string>& header) {
    clearHeader();

    for (auto info : header) {
        auto retVal = headerAppend(info);
        if (retVal == nullptr) {
            LOG_ERROR("[{0}][{1}] Append {2} header failed", __FUNCTION__, __LINE__, info);
            return Error::GENERAL_FAIL;
        }
    }
    if (Error::SUCCESS != customHeader(m_list)) {
        LOG_ERROR("[{0}][{1}] Custom header failed.", __FUNCTION__, __LINE__);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::customHeader(struct curl_slist* headers) {
    auto retVal = setOpt(CURLOPT_HTTPHEADER, headers);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set HTTP header failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::customPut(const char* data, size_t size) {
    auto& readBuf = m_dataBuf[static_cast<int>(OptType::READ)];
    readBuf.payload = (char*)realloc(readBuf.payload, readBuf.size + size);
    if (readBuf.payload == NULL) {
        LOG_ERROR("[{0}][{1}] Put data size too large.", __FUNCTION__, __LINE__);
        return Error::NO_ENOUGH_SPACE;
    }

    memcpy(&readBuf.payload[readBuf.size], data, size);
    readBuf.size += size;
    auto retVal = setOpt(CURLOPT_INFILESIZE_LARGE, size);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set file size failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::customPut(const std::string data) {
    return customPut(data.c_str(), data.length());
}

void HTTPSClient::resetCURL() {
    curl_easy_reset(m_curl);
}

Error HTTPSClient::connectRemote(const std::string ip, uint16_t port) {
    std::string hostInfo = "::";
    hostInfo.append(ip + ":" + std::to_string(port));

    struct curl_slist* connect_to = NULL;
    connect_to = curl_slist_append(NULL, hostInfo.c_str());

    auto retVal = setOpt(CURLOPT_CONNECT_TO, connect_to);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Connect {2}:{3} failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

void HTTPSClient::disableTrace() {
    auto retVal = setOpt(CURLOPT_VERBOSE, 0L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_DEBUG("[{0}][{1}] Disable verbose failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
    }
}

Error HTTPSClient::setURL(const std::string& url) {
    std::string schema = m_schema + "://";
    schema.append(url);

    // provide the DNS-over-HTTPS URL
    // setOpt(client->CURLOPT_DOH_URL, "");

    auto retVal = setOpt(CURLOPT_URL, schema.c_str());
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set url failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::setSSLVer(SSL_VER ver) {
    if (m_sslMap.find(ver) == m_sslMap.end()) {
        LOG_ERROR("[{0}][{1}] Invalid ssl version.", __FUNCTION__, __LINE__);
        return Error::INVALID_PARA;
    }

    auto retVal = setOpt(CURLOPT_SSLVERSION, m_sslMap[ver]);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set ssl version failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::setCipherList(std::vector<std::string>& cipher) {
    std::string cipherList;
    size_t cipherSize = cipher.size();
    if (cipherSize == 0) {
        LOG_ERROR("[{0}][{1}] Please configure valid cipher list.", __FUNCTION__, __LINE__);
        return Error::INVALID_PARA;
    }

    for (auto data : cipher) {
        cipherList.append(data);
        if (--cipherSize > 0) {
            cipherList.append(":");
        }
    }

    auto retVal = setOpt(CURLOPT_SSL_CIPHER_LIST, cipherList.c_str());  //"RC4-SHA:SHA1+DES:TLSv1:DEFAULT");
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set cipher list failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

#if 0
Error HTTPSClient::setClientExchangeKeyAlgorithmes() {
    // define the client's key exchange algorithms in the ssl handshake
    auto retVal = setOpt(CURLOPT_SSL_EC_CURVES, "X25519");
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR(
            "[{0}][{1}] Set client's key exchange algorithms failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}
#endif

Error HTTPSClient::setAppLayerProtoNegotiation(bool enable) {
    // enable Application Layer Protocol Negotiation in the ssl handshake
    auto retVal = setOpt(CURLOPT_SSL_ENABLE_ALPN, enable ? 1L : 0L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR(
            "[{0}][{1}] Operate application layer protocol negotiation failed. retVal: {2}",
            __FUNCTION__,
            __LINE__,
            retVal);
        return Error::GENERAL_FAIL;
    }

    return Error::SUCCESS;
}

Error HTTPSClient::setServerCA(const std::string& caFile, const std::string& caPath) {
    if (caPath.empty() && access(caFile.c_str(), F_OK)) {
        LOG_ERROR("[{0}][{1}] Not found {2}", __FUNCTION__, __LINE__, caFile);
        return Error::GENERAL_FAIL;
    }

    std::string abCAFile;
    if (!caPath.empty()) {
        abCAFile.append(caPath + "/" + caFile.substr(caFile.find_last_of("/") + 1));
        if (access(abCAFile.c_str(), F_OK)) {
            LOG_ERROR("[{0}][{1}] Not found {2}", __FUNCTION__, __LINE__, abCAFile);
        }
    }

    if (abCAFile.empty()) {
        abCAFile = caFile;
    }

    // configure ca file and path
    auto retVal = setOpt(CURLOPT_CAINFO, abCAFile.c_str());
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set CA file failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }

    retVal = setOpt(CURLOPT_CAPATH, caPath.c_str());
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set CA absolute PATH failed. ret", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }

    return Error::SUCCESS;
}

Error HTTPSClient::setClientCA(const ClientCA& clientCA) {
    int retVal = 0;
    if (!clientCA.crtType.empty()) {
        retVal = setOpt(CURLOPT_SSLCERTTYPE, clientCA.crtType.c_str());
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set client cert type failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::INITIAL_FAIL;
        }
    }

    if (!clientCA.cert.empty() && !access(clientCA.cert.c_str(), F_OK)) {
        // client cert
        retVal = setOpt(CURLOPT_SSLCERT, clientCA.cert.c_str());
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set client cert failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::INITIAL_FAIL;
        }
    }

    // SSL client certificate from memory blob, format is "PEM" or "P12" for openssl.
    // struct curl_blob stblob;
    // retVal = setOpt(CURLOPT_SSLCERT_BLOB, &stblob);

    if (!clientCA.keyType.empty()) {
        // private key file for TLS and SSL client cert
        retVal = setOpt(CURLOPT_SSLKEYTYPE, clientCA.keyType.c_str());
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set client key type failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::INITIAL_FAIL;
        }
    }

    if (!clientCA.key.empty() && !access(clientCA.key.c_str(), F_OK)) {
        // type of the private key file, support formats are "PEM", "DER" and "ENG", "ENG"
        // enables to load the private key from a crypto enagin.
        retVal = setOpt(CURLOPT_SSLKEY, clientCA.key.c_str());
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set client key failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::INITIAL_FAIL;
        }

        // passphrase to private key, used as the password required to use the CURLOPT_SSLKE or
        // CURLOPT_SSH_PRIVATE_KEYFILE private key. to load private key.
        if (clientCA.passwd.empty()) {
            LOG_ERROR("[{0}][{1}] Use client key before configure passwd.", __FUNCTION__, __LINE__);
            return Error::INITIAL_FAIL;
        }
        retVal = setOpt(CURLOPT_KEYPASSWD, clientCA.passwd.c_str());
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set client key password failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::INITIAL_FAIL;
        }
    }

    return Error::SUCCESS;
}

Error HTTPSClient::setCASwitch(SSLSwitch sw) {
    // verify the certificate's name against host. value 0, 1, 2.
    auto retVal = setOpt(CURLOPT_SSL_VERIFYHOST, sw.verifyHost);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Verify certificate's name operate failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }

    // verfiy the peer's SSL certificate.
    retVal = setOpt(CURLOPT_SSL_VERIFYPEER, sw.verifyPeer ? 1L : 0L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Verify peer's certificate operate failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }

    // verfiy the certificate's status
    retVal = setOpt(CURLOPT_SSL_VERIFYSTATUS, sw.verifyStatus ? 1L : 0L);  // setOpt(CURLOPT_SSL_VERIFYSTATUS, 0L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Verify certificate's status operate failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

std::string HTTPSClient::Get() {
    resetBuf();

    auto retVal = setOpt(CURLOPT_HTTPGET, 1L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set GET command failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return "";
    }

    retVal = curl_easy_perform(m_curl);
    if (CURLcode::CURLE_OK != retVal) {
        if (CURLcode::CURLE_OPERATION_TIMEDOUT == retVal) {
            LOG_ERROR("[{0}][{1}] Get request timeout.", __FUNCTION__, __LINE__);
        } else {
            LOG_ERROR("[{0}][{1}] Excute GET command failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        }
        return "";
    }
    auto writeBuf = m_dataBuf[static_cast<int>(OptType::WRITE)];
    return std::string(writeBuf.payload, writeBuf.size);
}

Error HTTPSClient::Post(const std::string& data) {
    resetBuf();

    auto retVal = setPutOpt(false);
    if (Error::SUCCESS != retVal) {
        return retVal;
    }

    auto curlRet = setOpt(CURLOPT_HTTPGET, 0L);
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Set GET command failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::GENERAL_FAIL;
    }

    curlRet = setOpt(CURLOPT_POST, 1L);
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Set POST command failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::GENERAL_FAIL;
    }

    curlRet = setOpt(CURLOPT_POSTFIELDS, data.c_str());
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Set POST data failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::GENERAL_FAIL;
    }
    curlRet = setOpt(CURLOPT_POSTFIELDSIZE, data.length());
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Set POST data length failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::GENERAL_FAIL;
    }

    curlRet = curl_easy_perform(m_curl);
    if (CURLcode::CURLE_OK != curlRet) {
        if (CURLcode::CURLE_OPERATION_TIMEDOUT == curlRet) {
            LOG_ERROR("[{0}][{1}] POST request timeout.", __FUNCTION__, __LINE__);
            return Error::TIMEOUT;
        }

        LOG_ERROR("[{0}][{1}] Excute POST command failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::setPutOpt(bool enable) {
    int retVal = CURLcode::CURLE_OK;
    if (std::string(PREV_PUT_VERSION).compare(LIBCURL_VERSION) > 0) {
        retVal = setOpt(CURLOPT_UPLOAD, enable);
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set UPLOAD command failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::GENERAL_FAIL;
        }
    } else {
        retVal = setOpt(CURLOPT_PUT, enable);
        if (CURLcode::CURLE_OK != retVal) {
            LOG_ERROR("[{0}][{1}] Set PUT command failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return Error::GENERAL_FAIL;
        }
    }
    return Error::SUCCESS;
}

Error HTTPSClient::Put() {
    resetBuf();

    auto retVal = setPutOpt();
    if (Error::SUCCESS != retVal) {
        return retVal;
    }

    int curlRet = curl_easy_perform(m_curl);

    auto& readBuf = m_dataBuf[static_cast<int>(OptType::READ)];
    if (readBuf.payload != nullptr) {
        delete[] readBuf.payload;
        readBuf.payload = nullptr;
        readBuf.size = 0;
    }

    if (CURLcode::CURLE_OK != curlRet) {
        if (CURLcode::CURLE_OPERATION_TIMEDOUT == curlRet) {
            LOG_ERROR("[{0}][{1}] PUT request timeout.", __FUNCTION__, __LINE__);
            return Error::TIMEOUT;
        }

        LOG_ERROR("[{0}][{1}] Excute PUT command failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::GENERAL_FAIL;
    }
    return Error::SUCCESS;
}

std::string HTTPSClient::getPostInfo() {
    auto writeBuf = m_dataBuf[static_cast<int>(OptType::WRITE)];
    return writeBuf.size > 0 ? std::string(writeBuf.payload, writeBuf.size) : "";
}

std::string HTTPSClient::getDebugInfo() {
    auto debugBuf = m_dataBuf[static_cast<int>(OptType::DEBUG)];
    return debugBuf.size > 0 ? std::string(debugBuf.payload, debugBuf.size) : "";
}

std::string HTTPSClient::getHeaderInfo() {
    auto headerBuf = m_dataBuf[static_cast<int>(OptType::HEADER)];
    return headerBuf.size > 0 ? std::string(headerBuf.payload, headerBuf.size - CRLF.length() * 2) : "";
}

size_t HTTPSClient::parseHeader() {
    auto& headerBuf = m_dataBuf[static_cast<int>(OptType::HEADER)];
    if (headerBuf.size == 0) {
        LOG_ERROR("[{0}][{1}] No recv operate response.", __FUNCTION__, __LINE__);
        return -1;
    }

    std::string headerResponse(headerBuf.payload, headerBuf.size);
    size_t offset = 0, startIndex;
    while ((startIndex = headerResponse.find_first_of(CRLF, offset)) != std::string::npos) {
        auto headerKeyContainer = headerResponse.substr(offset, startIndex);
        if (0 != headerKeyContainer.compare(CRLF)) {
            auto ssIndex = headerKeyContainer.find_first_of(SS), endIndex = headerKeyContainer.find_first_of(CRLF),
                 startIndex = ssIndex + SS.length();
            m_headerMap.insert(std::make_pair(
                headerKeyContainer.substr(0, ssIndex),
                headerKeyContainer.substr(ssIndex + SS.length(), endIndex - startIndex)));
        }
        offset = startIndex + CRLF.length();
    }
    return m_headerMap.size();
}

int HTTPSClient::getResponseCode(std::string& reason) {
    auto& headerBuf = m_dataBuf[static_cast<int>(OptType::HEADER)];
    if (headerBuf.size == 0) {
        LOG_ERROR("[{0}][{1}] No recv operate response.", __FUNCTION__, __LINE__);
        return -1;
    }

    std::string headerResponse(headerBuf.payload, headerBuf.size);
    size_t startIndex = headerResponse.find_first_of(' ') + 1,
           endIndex = headerResponse.find_first_of(' ', startIndex + 1);
    reason = headerResponse.substr(endIndex + 1, headerResponse.find_first_of(CRLF) - endIndex);
    auto retVal = headerResponse.substr(startIndex, endIndex - startIndex);
    return isDigital(retVal) ? std::stoi(retVal) : -1;
}

std::string HTTPSClient::getHeaderData(const std::string& key) {
    auto& headerBuf = m_dataBuf[static_cast<int>(OptType::HEADER)];
    if (headerBuf.size == 0) {
        LOG_ERROR("[{0}][{1}] No recv operate response.", __FUNCTION__, __LINE__);
        return "";
    }

    if (m_headerMap.size() == 0) {
        parseHeader();
    }

    auto it = m_headerMap.find(key);
    if (it == m_headerMap.end()) {
        LOG_ERROR("[{0}[{1}] Not found key: {2}", __FUNCTION__, __LINE__, key);
        return "";
    }
    return it->second;
}

std::string HTTPSClient::getSSLInfo() {
    auto& sslBuf = m_dataBuf[static_cast<int>(OptType::SSL)];
    return sslBuf.size > 0 ? std::string(sslBuf.payload, sslBuf.size) : "";
}

Error HTTPSClient::customSSL(const char* data, size_t size) {
    auto& sslBuf = m_dataBuf[static_cast<int>(OptType::SSL)];
    sslBuf.payload = (char*)realloc(sslBuf.payload, sslBuf.size + size);
    if (sslBuf.payload == NULL) {
        LOG_ERROR("[{0}][{1}] SSL data size too large.", __FUNCTION__, __LINE__);
        return Error::NO_ENOUGH_SPACE;
    }

    memcpy(&sslBuf.payload[sslBuf.size], data, size);
    sslBuf.size += size;
    return Error::SUCCESS;
}

Error HTTPSClient::setHTTPVer(const HTTP_VER& ver) {
    auto curlVer = m_httpMap.find(ver);
    if (curlVer == m_httpMap.end()) {
        LOG_ERROR("[{0}][{1}] Unsupport HTTP version.", __FUNCTION__, __LINE__);
        return Error::NO_SUCH_RECORD;
    }

    int retVal = setOpt(CURLOPT_HTTP_VERSION, curlVer->second);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set HTTP version failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

Error HTTPSClient::confSSL(const std::string& serverCA, const ClientCA& clientCA, const SSLSwitch sw) {
    // retVal = setOpt(CURLOPT_SSL_EC_CURVES, "");
    // identifier for the crypto engine for your private key.
    // retVal = setOpt(CURLOPT_SSLENGINE, "dynamic");

    // payload using SSL/TLS for the transfer
    int optCode = setOpt(CURLOPT_USE_SSL, CURLUSESSL_ALL);
    if (CURLcode::CURLE_OK != optCode) {
        LOG_ERROR("[{0}][{1}] Set payload using SSL/TLS failed.", __FUNCTION__, __LINE__, optCode);
        return Error::INITIAL_FAIL;
    }

    auto caPathIndex = serverCA.find_last_of("/");
    Error retVal = setServerCA(serverCA, serverCA.substr(0, caPathIndex));
    if (Error::SUCCESS != retVal) {
        return retVal;
    }

    retVal = setClientCA(clientCA);
    if (Error::SUCCESS != retVal) {
        return retVal;
    }

    retVal = setCASwitch(sw);
    if (Error::SUCCESS != retVal) {
        return retVal;
    }
    return Error::SUCCESS;
}

HTTPSClient::~HTTPSClient() {
    curl_easy_cleanup(m_curl);

    for (auto data : m_dataBuf) {
        if (data.payload != nullptr) {
            delete[] data.payload;
        }
    }

    if (debugFd != stderr) {
        fclose(debugFd);
    }
}

HTTPSClient::HTTPSClient() : m_list(nullptr), m_schema("http") {
    m_dataBuf.resize(static_cast<int>(OptType::HEADER) + 1);
    for (auto& data : m_dataBuf) {
        data.payload = nullptr;
        data.size = 0;
    };

    m_callbackFunc.resize(m_dataBuf.size());
    m_callbackFunc[static_cast<int>(OptType::READ)] = reinterpret_cast<CVCallback>(readCallback);
    m_callbackFunc[static_cast<int>(OptType::WRITE)] = reinterpret_cast<CVCallback>(writeCallback);
    m_callbackFunc[static_cast<int>(OptType::DEBUG)] = reinterpret_cast<CVCallback>(debugCallback);
    m_callbackFunc[static_cast<int>(OptType::SSL)] = reinterpret_cast<CVCallback>(sslCallback);
    m_callbackFunc[static_cast<int>(OptType::HEADER)] = reinterpret_cast<CVCallback>(headerCallback);

    m_httpMap[HTTP_VER::V_NONE] = CURL_HTTP_VERSION_NONE;
    m_httpMap[HTTP_VER::V_1_0] = CURL_HTTP_VERSION_1_0;
    m_httpMap[HTTP_VER::V_1_1] = CURL_HTTP_VERSION_1_1;
    m_httpMap[HTTP_VER::V_2_0] = CURL_HTTP_VERSION_2_0;
    m_httpMap[HTTP_VER::V_2TLS] = CURL_HTTP_VERSION_2TLS;
    m_httpMap[HTTP_VER::V_2] = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
    m_httpMap[HTTP_VER::V_3] = CURL_HTTP_VERSION_2;

    m_sslMap[SSL_VER::V_DEFAULT] = CURL_SSLVERSION_DEFAULT;
    m_sslMap[SSL_VER::V_TLSv1] = CURL_SSLVERSION_TLSv1;
    m_sslMap[SSL_VER::V_SSLv2] = CURL_SSLVERSION_SSLv2;
    m_sslMap[SSL_VER::V_SSLv3] = CURL_SSLVERSION_SSLv3;
    m_sslMap[SSL_VER::V_TLSv1_0] = CURL_SSLVERSION_TLSv1_0;
    m_sslMap[SSL_VER::V_TLSv1_1] = CURL_SSLVERSION_TLSv1_1;
    m_sslMap[SSL_VER::V_TLSv1_2] = CURL_SSLVERSION_TLSv1_2;
    m_sslMap[SSL_VER::V_TLSv1_3] = CURL_SSLVERSION_TLSv1_3;
    m_sslMap[SSL_VER::V_LAST] = CURL_SSLVERSION_LAST;
}

Error HTTPSClient::getVer(const std::string index, std::string& ver) {
    std::string verAll = curl_version();
    auto fdIndex = verAll.find(index);
    if (fdIndex == verAll.npos) {
        LOG_ERROR("[{0}][{1}] Not Found {2}", __FUNCTION__, __LINE__, index);
        return Error::NO_SUCH_RECORD;
    }

    int verLen = fdIndex + index.length();
    verAll = verAll.substr(verLen + 1, verAll.npos);
    int len = verAll.find(" ");
    ver = verAll.substr(0, len);
    return Error::SUCCESS;
}

std::shared_ptr<HTTPSClient> HTTPSClient::create(Json rootNode) {
    auto handle = std::shared_ptr<HTTPSClient>(new HTTPSClient());
    if (handle != nullptr) {
        if (Error::SUCCESS == handle->initialize(rootNode)) {
            return handle;
        }
    }
    return nullptr;
}

Error HTTPSClient::initialize(Json rootNode) {
    m_curl = curl_easy_init();
    if (m_curl == nullptr) {
        LOG_ERROR("[{0}][{1}] Initialize curl easy failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    // make connection get closed at once after use.
    auto curlRet = setOpt(CURLOPT_FORBID_REUSE, 0L);
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Set forbid reuse. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::INITIAL_FAIL;
    }

    curlRet = setOpt(CURLOPT_HEADER, 0L);
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Discard data header failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::INITIAL_FAIL;
    }

    auto retVal = callbackOpt();
    if (Error::SUCCESS != retVal) {
        return Error::INITIAL_FAIL;
    }

    if (rootNode.count("HttpClient") == 0) {
        LOG_ERROR("[{0}][{1}] HttpClient configure not found.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    auto httpNode = rootNode["HttpClient"];
    curlRet = setOpt(CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);
    if (CURLcode::CURLE_OK != curlRet) {
        LOG_ERROR("[{0}][{1}] Set curl support protocol set failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
        return Error::INITIAL_FAIL;
    }

    if (httpNode.count("timeout") != 0) {
        long timeout = httpNode["timeout"];
        curlRet = setOpt(CURLOPT_TIMEOUT, timeout);
        if (CURLcode::CURLE_OK != curlRet) {
            LOG_ERROR("[{0}][{1}] Set server response timeout failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
            return Error::INITIAL_FAIL;
        }
        curlRet = setOpt(CURLOPT_SERVER_RESPONSE_TIMEOUT, timeout);
        if (CURLcode::CURLE_OK != curlRet) {
            LOG_ERROR("[{0}][{1}] Set server response timeout failed. retVal: {2}", __FUNCTION__, __LINE__, curlRet);
            return Error::INITIAL_FAIL;
        }
    }

    if (httpNode.count("httpVer") == 0 || httpNode.count("curlVer") == 0) {
        LOG_ERROR("[{0}][{1}] Not found configure.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    if (httpNode.count("httpVer") > 0) {
        auto it = verMap.find(httpNode["httpVer"]);
        if (verMap.end() == it) {
            std::string verList;
            int verCount = verMap.size();
            for (auto ver : verMap) {
                verList.append(ver.first);
                if ((--verCount - 1) == 0) {
                    break;
                }
                verList.append(":");
            }
            LOG_ERROR(
                "[{0}][{1}] Unsupport version: {2}, support version list: {3}",
                __FUNCTION__,
                __LINE__,
                httpNode["httpVer"],
                verList);
            return Error::INITIAL_FAIL;
        }
    }

    const std::string verType = httpNode["httpVer"];
    if (Error::SUCCESS != setHTTPVer(verMap[verType])) {
        return Error::INITIAL_FAIL;
    }

    std::string runCurlVer = getCURLVer(), libCurlVer = httpNode["curlVer"];
    if (0 > runCurlVer.compare(libCurlVer)) {
        LOG_ERROR(
            "[{0}][{1}] curl version too old. runlib: {2}, require: >= {3}",
            __FUNCTION__,
            __LINE__,
            runCurlVer,
            libCurlVer);
        return Error::INITIAL_FAIL;
    }

    if (httpNode.count("SSL") > 0) {
        auto sslNode = httpNode["SSL"];
        if (sslNode.count("opensslVer") == 0) {
            LOG_ERROR("[{0}][{1}] Not found configure.", __FUNCTION__, __LINE__);
            return Error::INITIAL_FAIL;
        }

        std::string runSSLVer = getCURLSSLVer(), libSSLVer = sslNode["opensslVer"];
        if (0 > runSSLVer.compare(libSSLVer)) {
            LOG_ERROR(
                "[{0}][{1}] ssl version too old. runlib: {2}, require: >= {3}",
                __FUNCTION__,
                __LINE__,
                runSSLVer,
                libSSLVer);
            return Error::INITIAL_FAIL;
        }

        if (sslNode.count(SERVER_CA_INDEX) == 0) {
            LOG_ERROR("[{0}][{1}] Not found server ca file.", __FUNCTION__, __LINE__);
            return Error::INITIAL_FAIL;
        }
        ClientCA clientCA = {
            .crtType = sslNode.count(CLIENT_CA_TYPE_INDEX) > 0 ? sslNode[CLIENT_CA_TYPE_INDEX] : "",
            .cert = sslNode.count(CLIENT_CA_INDEX) > 0 ? sslNode[CLIENT_CA_INDEX] : "",
            .keyType = sslNode.count(CLIENT_KEY_TYPE_INDEX) > 0 ? sslNode[CLIENT_KEY_TYPE_INDEX] : "",
            .key = sslNode.count(CLIENT_KEY_INDEX) > 0 ? sslNode[CLIENT_KEY_INDEX] : "",
            .passwd = sslNode.count(CLIENT_CA_PASSWD_INDEX) > 0 ? sslNode[CLIENT_CA_PASSWD_INDEX] : ""};
        uint8_t verifyHost =
            sslNode.count(VERIFY_HOST_INDEX) > 0 ? static_cast<uint8_t>(sslNode[VERIFY_HOST_INDEX]) : 2;
        SSLSwitch sw = {
            .verifyHost = verifyHost,
            .verifyPeer = sslNode.count(VERIFY_PEER_INDEX) > 0 ? static_cast<bool>(sslNode[VERIFY_PEER_INDEX]) : false,
            .verifyStatus =
                sslNode.count(VERIFY_STATUS_INDEX) > 0 ? static_cast<bool>(sslNode[VERIFY_STATUS_INDEX]) : false};
        retVal = confSSL(sslNode[SERVER_CA_INDEX], clientCA, sw);
        if (Error::SUCCESS != retVal) {
            LOG_ERROR("[{0}][{1}] Configure ssl failed.", __FUNCTION__, __LINE__);
            return Error::INITIAL_FAIL;
        }

        m_schema = "https";
    }
    return Error::SUCCESS;
}

void HTTPSClient::enableTrace(bool traceLog) {
    m_traceLog = traceLog;

    auto retVal = setOpt(CURLOPT_VERBOSE, 1L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_DEBUG("[{0}][{1}] Enable verbose failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
    }

    retVal = setOpt(CURLOPT_FOLLOWLOCATION, 1L);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_DEBUG("[{0}][{1}] Follow location failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
    }
}

Error HTTPSClient::callbackOpt() {
    std::pair<CURLoption, CURLoption> opts[] = {{CURLOPT_READFUNCTION, CURLOPT_READDATA},
                                                {CURLOPT_WRITEFUNCTION, CURLOPT_WRITEDATA},
                                                {CURLOPT_DEBUGFUNCTION, CURLOPT_DEBUGDATA},
                                                {CURLOPT_SSL_CTX_FUNCTION, CURLOPT_SSL_CTX_DATA},
                                                {CURLOPT_HEADERFUNCTION, CURLOPT_HEADERDATA}};

    return registerCallback(opts, m_callbackFunc, m_dataBuf);
}

void HTTPSClient::resetBuf() {
    int size = m_dataBuf.size();
    for (int i = 1; i < size; i++) {
        if (m_dataBuf[i].payload != nullptr) {
            delete[] m_dataBuf[i].payload;
            m_dataBuf[i].payload = nullptr;
            m_dataBuf[i].size = 0;
        }
    }
    m_headerMap.clear();
}

Error HTTPSClient::registerCallback(
    std::pair<CURLoption, CURLoption> opt[],
    std::vector<CVCallback>& callback,
    std::vector<DataBuf>& buffer) {
    static size_t checkIndex = 0;
    auto retVal = setOpt(opt[checkIndex].first, callback[checkIndex]);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set callback failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        checkIndex = 0;
        return Error::GENERAL_FAIL;
    }

    retVal = setOpt(opt[checkIndex].second, &buffer[checkIndex]);
    if (CURLcode::CURLE_OK != retVal) {
        LOG_ERROR("[{0}][{1}] Set data failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        checkIndex = 0;
        return Error::GENERAL_FAIL;
    }

    if (++checkIndex < buffer.size()) {
        return registerCallback(opt, callback, buffer);
    }
    checkIndex = 0;

    return Error::SUCCESS;
}

template <class T>
int HTTPSClient::setOpt(CURLoption opt, T val) {
    return curl_easy_setopt(m_curl, opt, val);
}
template int HTTPSClient::setOpt(CURLoption opt, long);
template int HTTPSClient::setOpt(CURLoption opt, const char*);

}  // namespace intellBoxSDK
