#include "IntellBoxCommon/Utils/OpenSSL/OpenSSL.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/err.h>

namespace intellBoxSDK {

#define READ_BUF 4096
#define SIGN_BUF 65536
#define SSL_SIG_LENGTH 36
#define BIG_PRIME_RATIO 64
#define DES_CIPHER_BYTES 8
#define BASE64_MULTI 3

#define CaculateSum(x, y)                                                                               \
    MACFunc<x##_CTX> funcSet = {.InitFunc = y##_Init, .UpdateFunc = y##_Update, .FinalFuc = y##_Final}; \
    x##_CTX c;                                                                                          \
    return macCommon(data, funcSet, c, x##_DIGEST_LENGTH);

#define MK(x) EVP_des_##x

using DC = OpenSSL::DESCipher;

template <class T>
struct OpenSSL::MACFunc {
    typedef int (*Init)(T* c);
    typedef int (*Update)(T* c, const void* data, size_t len);
    typedef int (*Final)(unsigned char* md, T* c);

    Init InitFunc;
    Update UpdateFunc;
    Final FinalFuc;
};

template <class T>
struct OpenSSL::SVInfo {
    SVInfo();
    SVInfo(T handle, bool RSAFlag = false);

    typedef int (*SignSize)(T const handle);
    typedef int (*AlgoTypeMap)(T handle, int type);
    typedef int (
        *SignFunc)(int type, const unsigned char* m, int m_len, unsigned char* sigret, unsigned int* siglen, T handle);
    typedef int (
        *VerifyFunc)(int type, const unsigned char* m, int m_len, const unsigned char* sigret, int siglen, T handle);

    T handle;
    union {
        SignSize calcSize;
        AlgoTypeMap algoTypeMap;
    } getSize;
    union {
        SignFunc sign;
        VerifyFunc verify;
    } func;
    bool RSAFlag;
};

template <class T>
OpenSSL::SVInfo<T>::SVInfo() : RSAFlag(false) {
}

template <class T>
OpenSSL::SVInfo<T>::SVInfo(T handle, bool RSAFlag) {
    this->handle = handle;
    this->RSAFlag = RSAFlag;
}

template <class T>
struct OpenSSL::GetKeyInfo {
    typedef const BIGNUM* (*GetKey)(T d);
    GetKeyInfo();
    GetKeyInfo(T handle, GetKey getKey);
    T handle;
    GetKey getKey;
};

template <class T>
OpenSSL::GetKeyInfo<T>::GetKeyInfo() {
}

template <class T>
OpenSSL::GetKeyInfo<T>::GetKeyInfo(T handle, GetKey getKey) {
    this->handle = handle;
    this->getKey = getKey;
}

enum class OpenSSL::MACType { MD5, SHA, SHA256, SHA512 };
static const std::map<int, std::string> checkDHParam = {
    {DH_CHECK_P_NOT_PRIME, "The parameter p is not prime."},
    {DH_CHECK_P_NOT_PRIME, "The parameter p is not safe prime and no q value is present."},
    {DH_UNABLE_TO_CHECK_GENERATOR, "The generator g cannot be checked for suitability."},
    {DH_NOT_SUITABLE_GENERATOR, "The generator g is not suitable."},
    {DH_CHECK_Q_NOT_PRIME, "The parameter q is not prime."},
    {DH_CHECK_INVALID_Q_VALUE, "The parameter q is invalid."},
    {DH_CHECK_INVALID_J_VALUE, "The parameter j is invalid."}};

void OpenSSL::RSAFree() {
    if (nullptr != m_r) {
        RSA_free(m_r), m_r = nullptr;
    }

    if (nullptr != m_bn) {
        BN_free(m_bn), m_bn = nullptr;
    }
}

void OpenSSL::DSAFree() {
    if (nullptr != m_dsa) {
        DSA_free(m_dsa), m_dsa = nullptr;
    }
}

void OpenSSL::DHFree() {
    if (nullptr != m_dh) {
        DH_free(m_dh), m_dh = nullptr;
    }
}

void OpenSSL::ECCFree() {
    if (nullptr != m_ec) {
        EC_KEY_free(m_ec), m_ec = nullptr;
    }
}

void OpenSSL::DESFree() {
    if (nullptr != m_ctx) {
        EVP_CIPHER_CTX_free(m_ctx), m_ctx = nullptr;
    }
}

void OpenSSL::Base64Free() {
    if (nullptr != m_base64) {
        EVP_ENCODE_CTX_free(m_base64), m_base64 = nullptr;
    }
}

OpenSSL::OpenSSL() :
        m_r(nullptr),
        m_bn(nullptr),
        m_dsa(nullptr),
        m_dh(nullptr),
        m_ec(nullptr),
        m_ctx(nullptr),
        m_base64(nullptr),
        m_key(nullptr),
        m_eccKey(nullptr),
        m_cipher(nullptr) {
    m_cipherMap = {{DC::CBC, MK(cbc)},
                   {DC::ECB, MK(ecb)},
                   {DC::CFB, MK(cfb)},
                   {DC::CFB1, MK(cfb1)},
                   {DC::CFB8, MK(cfb8)},
                   {DC::CFB64, MK(cfb64)},
                   {DC::OFB, MK(ofb)},

                   {DC::EDE, MK(ede)},
                   {DC::EDE_CBC, MK(ede_cbc)},
                   {DC::EDE_CFB, MK(ede_cfb)},
                   {DC::EDE_CFB64, MK(ede_cfb64)},
                   {DC::EDE_ECB, MK(ede_ecb)},
                   {DC::EDE_OFB, MK(ede_ofb)},

                   {DC::EDE3, MK(ede3)},
                   {DC::EDE3_CBC, MK(ede3_cbc)},
                   {DC::EDE3_CFB, MK(ede3_cfb)},
                   {DC::EDE3_CFB1, MK(ede3_cfb1)},
                   {DC::EDE3_CFB8, MK(ede3_cfb8)},
                   {DC::EDE3_CFB64, MK(ede3_cfb64)},
                   {DC::EDE3_ECB, MK(ede3_ecb)},
                   {DC::EDE3_OFB, MK(ede3_ofb)},
                   {DC::EDE3_WRAP, MK(ede3_wrap)}};
}

OpenSSL::~OpenSSL() {
    RSAFree();
    DSAFree();
    DHFree();
    ECCFree();
    Base64Free();

    if (nullptr != m_key) {
        BN_free(m_key);
    }
}

const char u2s[] = "0123456789abcdef";
std::string OpenSSL::uint2str(const uint8_t data[], uint8_t len) {
    if (data == nullptr) {
        return {};
    }
    std::string str;
    for (int i = 0; i < len; i++) {
        str += u2s[data[i] >> 4];
        str += u2s[data[i] & 0x0F];
    }
    return str;
}

template <class T, class T1>
std::string OpenSSL::macCommon(const std::string& data, T func, T1& handle, int mdLen) {
    std::vector<uint8_t> md(mdLen);

    auto retVal = func.InitFunc(&handle);
    if (0 == retVal) {
        LOG_ERROR("[{0}][{1}] Initialize md5 interface failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return "";
    }

    if (0 == access(data.c_str(), F_OK)) {
        int fd = open(data.c_str(), O_RDONLY, 0666);
        if (-1 == fd) {
            LOG_ERROR("[{0}][{1}] Open {2} failed.", __FUNCTION__, __LINE__, data);
            return "";
        }

        size_t readLen = 0;
        uint8_t readBuf[READ_BUF] = {0};
        while (true) {
            readLen = read(fd, readBuf, sizeof(readBuf));
            if (0 >= readLen) {
                break;
            }

            retVal = func.UpdateFunc(&handle, readBuf, readLen);
            if (0 == retVal) {
                LOG_ERROR("[{0}][{1}] Update MD5 data failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
                close(fd);
                return "";
            }

            if (readLen < sizeof(readBuf)) {
                break;
            }
        }
        close(fd);
    } else {
        retVal = func.UpdateFunc(&handle, reinterpret_cast<const uint8_t*>(data.c_str()), data.length());
        if (0 == retVal) {
            LOG_ERROR("[{0}][{1}] Update MD5 data failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return "";
        }
    }

    retVal = func.FinalFuc(md.data(), &handle);
    if (0 == retVal) {
        LOG_ERROR("[{0}][{1}] Calculate MD5 failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return "";
    }

    OPENSSL_cleanse(&handle, sizeof(handle));
    return uint2str(md.data(), strlen(reinterpret_cast<char*>(md.data())));
}

std::string OpenSSL::md5(const std::string& data){CaculateSum(MD5, MD5)}

std::string OpenSSL::sha(const std::string& data) {
    CaculateSum(SHA, SHA1);
}

std::string OpenSSL::sha256(const std::string& data) {
    CaculateSum(SHA256, SHA256);
}

std::string OpenSSL::sha512(const std::string& data) {
    CaculateSum(SHA512, SHA512);
}

Error OpenSSL::RSAInit(const std::string& key) {
    return Error::SUCCESS;
}

Error OpenSSL::RSAInit(int bits, BN_ULONG word, BN_GENCB* callback) {
    if (nullptr != m_bn) {
        BN_free(m_bn);
        m_bn = nullptr;
    }

    if (nullptr != m_r) {
        RSA_free(m_r);
        m_r = nullptr;
    }

    m_bn = BN_new();
    if (nullptr == m_bn) {
        LOG_ERROR("[{0}][{1}] Big num create failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    int retVal = BN_set_word(m_bn, word);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Set word failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        BN_free(m_bn), m_bn = nullptr;
        return Error::INITIAL_FAIL;
    }

    m_r = RSA_new();
    if (nullptr == m_r) {
        LOG_ERROR("[{0}][{1}] Create RSA failed.", __FUNCTION__, __LINE__);
        BN_free(m_bn), m_bn = nullptr;
        return Error::INITIAL_FAIL;
    }

    retVal = RSA_generate_key_ex(m_r, bits, m_bn, callback);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Generate key failed by RSA. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        BN_free(m_bn), m_bn = nullptr;
        RSA_free(m_r), m_r = nullptr;
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

template <class T>
std::vector<uint8_t> OpenSSL::RSACommon(std::vector<uint8_t>& data, int padType, T callback, bool decrypt) {
    if (nullptr == m_r) {
        LOG_ERROR("[{0}][{1}] RSA handle invalid.", __FUNCTION__, __LINE__);
        return {};
    }

    int rsaSize = RSA_size(m_r);
    switch (padType) {
        case RSA_SSLV23_PADDING:
        case RSA_PKCS1_PADDING: {
            rsaSize -= 11;
            break;
        }
        case RSA_X931_PADDING: {
            rsaSize -= 2;
            break;
        }
        case RSA_PKCS1_OAEP_PADDING: {
            rsaSize = rsaSize - 2 * SHA_DIGEST_LENGTH - 2;
            break;
        }
        case RSA_NO_PADDING: {
            break;
        }
        default: {
            LOG_ERROR("[{0}][{1}] Unsupport pad type. type: {2}", __FUNCTION__, __LINE__, padType);
            return {};
        }
    }

    std::vector<uint8_t> outData(data.size() * 2);
    if (decrypt) {
        rsaSize = data.size();
    }

    rsaSize = callback(rsaSize, data.data(), outData.data(), m_r, padType);
    if (rsaSize > 0) {
        outData.resize(rsaSize);
    }

    return outData;
}

std::vector<uint8_t> OpenSSL::RSAEncrypt(std::vector<uint8_t>& data, int padType, bool privEnc) {
    return RSACommon(data, padType, privEnc ? RSA_private_encrypt : RSA_public_encrypt);
}

std::vector<uint8_t> OpenSSL::RSADecrypt(std::vector<uint8_t>& data, int padType, bool privDec) {
    return RSACommon(data, padType, privDec ? RSA_private_decrypt : RSA_public_decrypt, true);
}

template <class T>
std::vector<uint8_t> OpenSSL::sign(T signInfo, std::vector<uint8_t>& data, int algoType) {
    auto handle = signInfo.handle;
    if (nullptr == handle) {
        LOG_ERROR("[{0}][{1}] Sign handle invalid.", __FUNCTION__, __LINE__);
        return {};
    }

    uint32_t signLen = 0;
    std::vector<uint8_t> signData(SIGN_BUF);

    uint32_t dataLen =
        signInfo.RSAFlag ? signInfo.getSize.algoTypeMap(handle, algoType) : signInfo.getSize.calcSize(handle);
    int retVal = signInfo.func.sign(algoType, data.data(), dataLen, signData.data(), &signLen, handle);
    if (1 != retVal) {
        LOG_ERROR(
            "[{0}][{1}] Sign digest failed. retVal: {2}, msg: {3}",
            __FUNCTION__,
            __LINE__,
            retVal,
            ERR_error_string(retVal, NULL));
        return {};
    }
    signData.resize(signLen);
    return signData;
}

template <class T>
bool OpenSSL::verify(T signInfo, std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType) {
    auto handle = signInfo.handle;
    if (nullptr == handle) {
        LOG_ERROR("[{0}][{1}] Verify handle invalid.", __FUNCTION__, __LINE__);
        return false;
    }

    uint32_t dataLen =
        signInfo.RSAFlag ? signInfo.getSize.algoTypeMap(handle, algoType) : signInfo.getSize.calcSize(handle);
    int retVal = signInfo.func.verify(algoType, data.data(), dataLen, sign.data(), sign.size(), handle);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Verify digest failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return false;
    }
    return true;
}

template <class T>
const BIGNUM* OpenSSL::getKey(T getKeyInfo) {
    std::unique_lock<std::mutex> lock(m_processMutex);
    if (nullptr != m_key) {
        BN_free(m_key);
    }

    const BIGNUM* cp = getKeyInfo.getKey(getKeyInfo.handle);
    if (nullptr == cp) {
        LOG_ERROR("[{0}][{1}] Invalid key.", __FUNCTION__, __LINE__);
        return nullptr;
    }

    m_key = BN_dup(cp);
    if (nullptr == m_key) {
        LOG_ERROR("[{0}][{1}] Duplicate BN failed.", __FUNCTION__, __LINE__);
        return nullptr;
    }

    return m_key;
}

uint32_t algoTypeMap(RSA* handle, int algoType) {
    uint32_t dataLen = RSA_size(handle) - RSA_PKCS1_PADDING_SIZE;
    switch (algoType) {
        case NID_md5: {
            dataLen -= 18;
            break;
        }
        case NID_sha:
        case NID_sha1: {
            dataLen -= 15;
            break;
        }
        case NID_md5_sha1: {
            dataLen = SSL_SIG_LENGTH;
            break;
        }
        default: {
            break;
        }
    }
    return dataLen;
}

std::vector<uint8_t> OpenSSL::RSASign(std::vector<uint8_t>& data, int algoType) {
    SVInfo<RSA*> signInfo(m_r, true);
    signInfo.getSize.algoTypeMap = reinterpret_cast<decltype(signInfo.getSize.algoTypeMap)>(algoTypeMap);
    signInfo.func.sign = reinterpret_cast<decltype(signInfo.func.sign)>(RSA_sign);

    return sign(signInfo, data, algoType);
}

bool OpenSSL::RSAVerify(std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType) {
    SVInfo<RSA*> verifyInfo(m_r, true);
    verifyInfo.getSize.algoTypeMap = reinterpret_cast<decltype(verifyInfo.getSize.algoTypeMap)>(algoTypeMap);
    verifyInfo.func.verify = reinterpret_cast<decltype(verifyInfo.func.verify)>(RSA_verify);

    return verify(verifyInfo, data, sign, algoType);
}

Error OpenSSL::DSAInit(const std::string& key) {
    return Error::SUCCESS;
}

Error OpenSSL::DSAInit(
    int bits,
    const uint8_t* seed,
    int seedLen,
    int* counterRet,
    unsigned long* hRet,
    BN_GENCB* callback) {
    if (bits % BIG_PRIME_RATIO != 0) {
        LOG_ERROR("[{0}][{1}] Param bits must be times 64.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    if (nullptr != m_dsa) {
        DSA_free(m_dsa), m_dsa = nullptr;
    }

    m_dsa = DSA_new();
    if (nullptr == m_dsa) {
        LOG_ERROR("[{0}][{1}] Create DSA struct failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    int retVal = DSA_generate_parameters_ex(m_dsa, bits, seed, seedLen, counterRet, hRet, callback);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Generate DSA parameters failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }

    retVal = DSA_generate_key(m_dsa);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Generate DSA key failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        DSA_free(m_dsa), m_dsa = nullptr;
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

const BIGNUM* OpenSSL::getDSAPubKey() {
    GetKeyInfo<DSA*> keyInfo(m_dsa, reinterpret_cast<GetKeyInfo<DSA*>::GetKey>(DSA_get0_pub_key));
    return getKey(keyInfo);
}

const BIGNUM* OpenSSL::getDSAPrivKey() {
    GetKeyInfo<DSA*> keyInfo(m_dsa, reinterpret_cast<GetKeyInfo<DSA*>::GetKey>(DSA_get0_priv_key));
    return getKey(keyInfo);
}

std::vector<uint8_t> OpenSSL::DSASign(std::vector<uint8_t>& data, int algoType) {
    SVInfo<DSA*> signInfo(m_dsa);
    signInfo.getSize.calcSize = reinterpret_cast<decltype(signInfo.getSize.calcSize)>(DSA_size);
    signInfo.func.sign = DSA_sign;

    return sign(signInfo, data, algoType);
}

bool OpenSSL::DSAVerify(std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType) {
    SVInfo<DSA*> verifyInfo(m_dsa);
    verifyInfo.getSize.calcSize = reinterpret_cast<decltype(verifyInfo.getSize.calcSize)>(DSA_size);
    verifyInfo.func.verify = DSA_verify;

    return verify(verifyInfo, data, sign, algoType);
}

Error OpenSSL::DHInit(const std::string& key) {
    return Error::SUCCESS;
}

Error OpenSSL::DHInit(int primeLen, int generator, BN_GENCB* callback) {
    if (nullptr != m_dh) {
        DH_free(m_dh), m_dh = nullptr;
    }

    m_dh = DH_new();
    if (nullptr == m_dh) {
        LOG_ERROR("[{0}][{1}] Create DH struct failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    int retVal = DH_generate_parameters_ex(m_dh, primeLen, generator, callback);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Generate DH parameters failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        DH_free(m_dh), m_dh = nullptr;
        return Error::INITIAL_FAIL;
    }

    int checkFlag = 0;
    retVal = DH_check(m_dh, &checkFlag);
    if (1 != retVal) {
        for (auto info : checkDHParam) {
            if (info.first & checkFlag) {
                LOG_ERROR("[{0}][{1}] {2}", __FUNCTION__, __LINE__, info.second);
            }
        }
        DH_free(m_dh), m_dh = nullptr;
        return Error::INITIAL_FAIL;
    }

    retVal = DH_generate_key(m_dh);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Generate DH key failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

const BIGNUM* OpenSSL::getDHPubKey() {
    GetKeyInfo<DH*> keyInfo(m_dh, reinterpret_cast<GetKeyInfo<DH*>::GetKey>(DH_get0_pub_key));
    return getKey(keyInfo);
}

const BIGNUM* OpenSSL::getDHPrivKey() {
    GetKeyInfo<DH*> keyInfo(m_dh, reinterpret_cast<GetKeyInfo<DH*>::GetKey>(DH_get0_priv_key));
    return getKey(keyInfo);
}

std::vector<uint8_t> OpenSSL::computeKey(const BIGNUM* key) {
    std::unique_lock<std::mutex> lock(m_processMutex);

    int dhSize = DH_size(m_dh);
    m_computeKey.resize(dhSize);
    auto retVal = DH_compute_key(m_computeKey.data(), key, m_dh);
    if (-1 == retVal) {
        LOG_ERROR("[{0}][{1}] DH compute key failed.", __FUNCTION__, __LINE__);
        return {};
    }
    return m_computeKey;
}

Error OpenSSL::ECCInit(const std::string& key) {
    return Error::SUCCESS;
}

Error OpenSSL::ECCInit(int index) {
    if (nullptr != m_ec) {
        EC_KEY_free(m_ec);
    }

    m_ec = EC_KEY_new();
    if (nullptr == m_ec) {
        LOG_ERROR("[{0}][{1}] Create ECC struct failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    int btSize = EC_get_builtin_curves(NULL, 0);
    if (btSize == 0) {
        LOG_ERROR("[{0}][{1}] Not found valid builtin curves.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    EC_builtin_curve* btCurve = new EC_builtin_curve[btSize];
    if (nullptr == btCurve) {
        LOG_ERROR("[{0}][{1}] Not enough space.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }
    EC_get_builtin_curves(btCurve, btSize);

    EC_GROUP* gp = nullptr;
    int nid = index;
    if (0 == nid) {
        gp = EC_GROUP_new_by_curve_name(btCurve[btSize - 1].nid);
    } else if (btSize >= nid && nid >= 0) {
        gp = EC_GROUP_new_by_curve_name(btCurve[nid - 1].nid);
    } else {
        LOG_ERROR(
            "[{0}][{1}] Nid index out of range. index should less than or equal to {2}.",
            __FUNCTION__,
            __LINE__,
            btSize);
        delete[] btCurve;
        return Error::INITIAL_FAIL;
    }
    delete[] btCurve;

    if (nullptr == gp) {
        LOG_ERROR("[{0}][{1}] Get EC group struct failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    auto retVal = EC_KEY_set_group(m_ec, gp);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Set EC group failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return Error::INITIAL_FAIL;
    }

    retVal = EC_KEY_generate_key(m_ec);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Generate EC key failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        EC_KEY_free(m_ec), m_ec = nullptr;
        return Error::INITIAL_FAIL;
    }

    retVal = EC_KEY_check_key(m_ec);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Check EC key wrong. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        EC_KEY_free(m_ec), m_ec = nullptr;
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

const EC_POINT* OpenSSL::getECCPubKey() {
    std::unique_lock<std::mutex> lock(m_processMutex);
    if (nullptr != m_eccKey) {
        EC_POINT_free(m_eccKey);
    }

    if (nullptr == m_ec) {
        LOG_ERROR("[{0}][{1}] EC handle invalid.", __FUNCTION__, __LINE__);
        return nullptr;
    }

    const EC_POINT* cp = EC_KEY_get0_public_key(m_ec);
    if (nullptr == cp) {
        LOG_ERROR("[{0}][{1}] Invalid EC public key.", __FUNCTION__, __LINE__);
        return nullptr;
    }
    const EC_GROUP* gp = EC_KEY_get0_group(m_ec);
    if (nullptr == gp) {
        LOG_ERROR("[{0}][{1}] Invalid EC group.", __FUNCTION__, __LINE__);
        return nullptr;
    }

    m_eccKey = EC_POINT_dup(cp, gp);
    if (nullptr == m_eccKey) {
        LOG_ERROR("[{0}][{1}] Duplicate ECC failed.", __FUNCTION__, __LINE__);
        return nullptr;
    }

    return m_eccKey;
}

const BIGNUM* OpenSSL::getECCPrivKey() {
    GetKeyInfo<EC_KEY*> keyInfo(m_ec, reinterpret_cast<GetKeyInfo<EC_KEY*>::GetKey>(EC_KEY_get0_private_key));
    return getKey(keyInfo);
}

std::vector<uint8_t> OpenSSL::ECCSign(std::vector<uint8_t>& data, int algoType) {
    SVInfo<EC_KEY*> signInfo(m_ec);
    signInfo.getSize.calcSize = reinterpret_cast<decltype(signInfo.getSize.calcSize)>(ECDSA_size);
    signInfo.func.sign = ECDSA_sign;

    return sign(signInfo, data, algoType);
}

bool OpenSSL::ECCVerify(std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType) {
    SVInfo<EC_KEY*> verifyInfo(m_ec);
    verifyInfo.getSize.calcSize = reinterpret_cast<decltype(verifyInfo.getSize.calcSize)>(ECDSA_size);
    verifyInfo.func.verify = ECDSA_verify;

    return verify(verifyInfo, data, sign, algoType);
}

std::vector<uint8_t> OpenSSL::computeKey(const EC_POINT* key, size_t outLen, ECCCompute callback) {
    std::unique_lock<std::mutex> lock(m_processMutex);

    m_computeKey.resize(outLen);
    auto retVal = ECDH_compute_key(m_computeKey.data(), outLen, key, m_ec, callback);
    if (-1 == retVal) {
        LOG_ERROR("[{0}][{1}] ECC compute key failed.", __FUNCTION__, __LINE__);
        return {};
    }
    return m_computeKey;
}

Error OpenSSL::DSA2DH() {
    static DH* dh = nullptr;
    dh = DSA_dup_DH(m_dsa);
    if (nullptr == dh) {
        LOG_ERROR("[{0}][{1}] Convert DSA to DH failed.", __FUNCTION__, __LINE__);
        return Error::GENERAL_FAIL;
    }

    if (nullptr != m_dh) {
        DH_free(m_dh);
    }
    m_dh = dh;
    return Error::SUCCESS;
}

Error OpenSSL::DESInit(DESCipher cipher, std::vector<uint8_t>& key, std::vector<uint8_t>& iv, DESPaddingType type) {
    if (nullptr != m_ctx) {
        EVP_CIPHER_CTX_free(m_ctx), m_ctx = nullptr;
    }

    m_ctx = EVP_CIPHER_CTX_new();
    if (nullptr == m_ctx) {
        LOG_ERROR("[{0}][{1}] Create cipher context failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }

    auto retVal = EVP_CIPHER_CTX_init(m_ctx);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] Cipher initialize failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        EVP_CIPHER_CTX_free(m_ctx), m_ctx = nullptr;
        return Error::INITIAL_FAIL;
    }

    auto cipherMap = m_cipherMap.find(cipher);
    if (cipherMap == m_cipherMap.end()) {
        LOG_ERROR("[{0}][{1}] Cipher not support.", __FUNCTION__, __LINE__);
        EVP_CIPHER_CTX_free(m_ctx), m_ctx = nullptr;
        return Error::INITIAL_FAIL;
    }
    m_cipher = m_cipherMap[cipher]();
    if (nullptr == m_cipher) {
        LOG_ERROR("[{0}][{1}] Create cipher object failed.", __FUNCTION__, __LINE__);
        EVP_CIPHER_CTX_free(m_ctx), m_ctx = nullptr;
        return Error::INITIAL_FAIL;
    }

    m_desKey = key, m_desIV = iv, m_paddingType = type;
    return Error::SUCCESS;
}

struct OpenSSL::DESInfo {
    typedef int (
        *EVP_Init)(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key, const unsigned char* iv);
    typedef int (*EVP_Update)(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl);
    typedef int (*EVP_Final)(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl);
    EVP_Init evpInit;
    EVP_Update evpUpdate;
    EVP_Final evpFinal;
};

struct OpenSSL::Base64Info {
    typedef void (*Init)(EVP_ENCODE_CTX* ctx);
    typedef int (*Update)(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl);
    typedef void (*EncodeFinal)(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl);
    typedef int (*DecodeFinal)(EVP_ENCODE_CTX* ctx, unsigned char* out, int* outl);

    Init init;
    Update update;
    union {
        EncodeFinal encFinal;
        DecodeFinal decFinal;
    } finals;
};

std::vector<uint8_t> OpenSSL::DESOption(DESInfo desInfo, std::vector<uint8_t>& data, bool encrypt) {
    auto retVal = desInfo.evpInit(m_ctx, m_cipher, m_desKey.data(), m_desIV.data());
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] DES encrypt initialize failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return {};
    }

    retVal = EVP_CIPHER_CTX_set_padding(m_ctx, static_cast<int>(m_paddingType));
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] DES set padding failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return {};
    }

    int dataSize = data.size(), encSize = dataSize, updateSize = (dataSize / DES_CIPHER_BYTES) * DES_CIPHER_BYTES;
    if (encrypt) {
        if (0 != (dataSize % DES_CIPHER_BYTES)) {
            encSize += 8;
        }
    } else {
        updateSize -= DES_CIPHER_BYTES;
    }

    std::vector<uint8_t> encData(encSize);

    int convertSize = 0, len = 0;
    do {
        retVal = desInfo.evpUpdate(m_ctx, &encData[convertSize], &len, &data[convertSize], dataSize);
        if (1 != retVal) {
            LOG_ERROR("[{0}][{1}] EVP update failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return {};
        }
        convertSize += len;
    } while (convertSize != 0 && convertSize < updateSize);

    retVal = desInfo.evpFinal(m_ctx, &encData[convertSize], &len);
    if (1 != retVal) {
        LOG_ERROR("[{0}][{1}] EVP final failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return {};
    }
    convertSize += len;
    encData.resize(convertSize);

    return encData;
}

std::vector<uint8_t> OpenSSL::DESEncrypt(std::vector<uint8_t>& data) {
    DESInfo desInfo = {.evpInit = EVP_EncryptInit, .evpUpdate = EVP_EncryptUpdate, .evpFinal = EVP_EncryptFinal};
    return DESOption(desInfo, data);
}

std::vector<uint8_t> OpenSSL::Base64Option(Base64Info info, std::vector<uint8_t>& data, bool encode) {
    int encLen = 0, convertSize = 0;
    std::vector<uint8_t> buf(data.size() * BASE64_MULTI);

    info.init(m_base64);

    auto retVal = info.update(m_base64, buf.data(), &encLen, data.data(), data.size());
    if (-1 == retVal) {
        LOG_ERROR("[{0}][{1}] Update failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
        return {};
    }
    convertSize += encLen;

    if (encode) {
        info.finals.encFinal(m_base64, &buf[convertSize], &encLen);
    } else {
        retVal = info.finals.decFinal(m_base64, &buf[convertSize], &encLen);
        if (1 != retVal) {
            LOG_ERROR("[{0}][{1}] Final failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
            return {};
        }
    }

    convertSize += encLen;
    buf.resize(convertSize);

    return buf;
}

Error OpenSSL::Base64Init() {
    Base64Free();

    m_base64 = EVP_ENCODE_CTX_new();
    if (nullptr == m_base64) {
        LOG_ERROR("[{0}][{1}] Create base64 context failed.", __FUNCTION__, __LINE__);
        return Error::INITIAL_FAIL;
    }
    return Error::SUCCESS;
}

std::vector<uint8_t> OpenSSL::Base64Encode(std::vector<uint8_t>& data) {
    Base64Info info = {.init = EVP_EncodeInit, .update = EVP_EncodeUpdate};
    info.finals.encFinal = EVP_EncodeFinal;
    return Base64Option(info, data);
}

std::vector<uint8_t> OpenSSL::Base64Decode(std::vector<uint8_t>& data) {
    Base64Info info = {.init = EVP_DecodeInit, .update = EVP_DecodeUpdate};
    info.finals.decFinal = EVP_DecodeFinal;
    return Base64Option(info, data, false);
}

std::vector<uint8_t> OpenSSL::DESDecrypt(std::vector<uint8_t>& data) {
    DESInfo desInfo = {
        .evpInit = EVP_DecryptInit,
        .evpUpdate = EVP_DecryptUpdate,
        .evpFinal = EVP_DecryptFinal,
    };
    return DESOption(desInfo, data, false);
}

#if 0
std::string OpenSSL::md5ByEVP(const std::string& data){
	const EVP_MD* md = EVP_md5();

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	auto retVal = EVP_DigestInit(ctx, md);
	if(1 != retVal){
		LOG_ERROR("[{0}][{1}] Digest initialize failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
		EVP_MD_CTX_free(ctx);
		return "";
	}

	retVal = EVP_DigestUpdate(ctx, data.data(), data.length());
	if(1 != retVal){
		LOG_ERROR("[{0}][{1}] Digest update failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
		EVP_MD_CTX_free(ctx);
		return "";
	}

	uint32_t mdLen = 0;
	uint8_t mdData[READ_BUF] = {0};
	retVal = EVP_DigestFinal(ctx, mdData, &mdLen);
   EVP_MD_CTX_free(ctx);

	if(1 != retVal){
		LOG_ERROR("[{0}][{1}] Digest final failed. retVal: {2}", __FUNCTION__, __LINE__, retVal);
		return "";
	}
   return uint2str(mdData, strlen(reinterpret_cast<char*>(mdData)));
}
#endif

}  // namespace intellBoxSDK
