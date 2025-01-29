#include "Algorithms/Algorithms.h"
#include "Logger/Logger.h"

namespace my_toolskit {

#define DEFAULT_LEN 4096000
const char base64Data[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

Algorithms::Algorithms() {
}
Algorithms::~Algorithms() {
}

Error Algorithms::compressByGZip(const std::string& in, std::string& out) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    strm.next_in = reinterpret_cast<z_const Bytef*>(const_cast<char*>(in.c_str()));
    strm.avail_in = in.length();
    Bytef* data = new Bytef[DEFAULT_LEN];
    strm.next_out = data;
    strm.avail_out = DEFAULT_LEN;
    bzero(strm.next_out, DEFAULT_LEN);

    auto retVal =
        deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (retVal != Z_OK) {
        LOG_ERROR("[{0}][{1}] deflateInit2 failed, retMsg:[{2}]", __FUNCTION__, __LINE__, zError(retVal));
        delete[] data;
        return Error::INITIAL_FAIL;
    }

    retVal = deflate(&strm, Z_FINISH);
    if (retVal == Z_STREAM_ERROR) {
        LOG_ERROR("[{0}][{1}] deflate failed, retMsg:[{2}]", __FUNCTION__, __LINE__, zError(retVal));
        delete[] data;
        return Error::GENERAL_FAIL;
    }
    retVal = deflateEnd(&strm);
    if (retVal != Z_OK) {
        LOG_ERROR("[{0}][{1}] deflateEnd failed. retMsg: {2}", __FUNCTION__, __LINE__, zError(retVal));
        return Error::GENERAL_FAIL;
    }
    char* payload = reinterpret_cast<char*>(data);
    out = std::string(payload, strm.total_out);
    delete[] data;
    return Error::SUCCESS;
}

Error Algorithms::decompressByGZip(const std::string& in, std::string& out) {
    if (in.empty()) {
        return Error::INVALID_PARA;
    }
    out.clear();
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    strm.next_in = reinterpret_cast<z_const Bytef*>(const_cast<char*>(in.c_str()));
    strm.avail_in = in.length();
    Bytef* data = new Bytef[DEFAULT_LEN];
    strm.next_out = data;
    strm.avail_out = DEFAULT_LEN;
    bzero(strm.next_out, DEFAULT_LEN);

    auto retVal = inflateInit2(&strm, MAX_WBITS + 32);
    if (retVal != Z_OK) {
        LOG_ERROR("[{0}][{1}] inflateInit2 failed, retMsg:[{2}]", __FUNCTION__, __LINE__, zError(retVal));
        delete[] data;
        return Error::INITIAL_FAIL;
    }

    retVal = inflate(&strm, Z_FINISH);
    if (retVal == Z_STREAM_ERROR) {
        LOG_ERROR("[{0}][{1}] inflate failed, retMsg:[{2}]", __FUNCTION__, __LINE__, zError(retVal));
        delete[] data;
        return Error::GENERAL_FAIL;
    }

    char* payload = reinterpret_cast<char*>(data);
    out = std::string(payload, strm.total_out);
    retVal = inflateEnd(&strm);

    if (retVal != Z_OK) {
        LOG_ERROR("[{0}][{1}] inflateEnd failed. retMsg: {2}", __FUNCTION__, __LINE__, zError(retVal));
        return Error::GENERAL_FAIL;
    }
    delete[] data;
    return Error::SUCCESS;
}

std::string Algorithms::base64Encode(const std::string& data) {
    std::vector<uint8_t> s2v;
    uint8_t* payload = reinterpret_cast<uint8_t*>(const_cast<char*>(data.c_str()));
    s2v.insert(s2v.begin(), payload, payload + data.length());
    return base64Encode(s2v);
}

std::string Algorithms::base64Encode(const std::vector<uint8_t>& data) {
    std::string encodeData;
    uint32_t i = 0, len = data.size();
    for (; i < len; i += 3) {
        if (i + 3 > len) {
            break;
        }
        encodeData += base64Data[data[i] >> 2];
        encodeData += base64Data[((data[i] & 0x03) << 4) | (data[i + 1] >> 4)];
        encodeData += base64Data[((data[i + 1] << 2) & 0x3c) | (data[i + 2] >> 6)];
        encodeData += base64Data[data[i + 2] & 0x3F];
    }

    if (i < len) {
        encodeData += base64Data[data[i] >> 2];
        encodeData += (len - i) == 1 ? base64Data[(data[i] & 0x03) << 4]
                                     : base64Data[((data[i] & 0x03) << 4) | (data[i + 1] >> 4)];
        encodeData += (len - i) == 1 ? '=' : base64Data[(data[i + 1] << 2) & 0x3c];
        encodeData += '=';
    }

    return encodeData;
}

std::vector<uint8_t> Algorithms::base64Decode(const std::string& data) {
    std::vector<uint8_t> decodeData;
    std::string encodeData = std::string(base64Data);
    uint32_t i, len = data.length();

    if (len != 0 && len % 4 != 0) {
        LOG_ERROR("[{0}][{1}] input parameters failed.", __FUNCTION__, __LINE__);
        return {};
    }

    for (i = 0; i < len; i += 4) {
        decodeData.push_back((encodeData.find(data[i]) << 2) | (encodeData.find(data[i + 1]) >> 4 & 0x03));

        if (data[i + 2] != '=') {
            decodeData.push_back((encodeData.find(data[i + 1]) << 4) | ((encodeData.find(data[i + 2]) >> 2) & 0x0f));
        }

        if (data[i + 3] != '=') {
            decodeData.push_back(((encodeData.find(data[i + 2]) & 0x03) << 6) | encodeData.find(data[i + 3]));
        }
    }

    return decodeData;
}

std::string Algorithms::base64Decode(const std::string& data, bool) {
    std::vector<uint8_t> payload = base64Decode(data);
    return std::string(reinterpret_cast<char*>(const_cast<uint8_t*>(payload.data())), payload.size());
}

}  // namespace my_toolskit
