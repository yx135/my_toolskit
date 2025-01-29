#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <map>

#include "IntellBoxCommon/SDKInterfaces/Error.h"

#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <openssl/x509.h>

namespace intellBoxSDK {

class OpenSSL {
public:
    typedef void* (*ECCCompute)(const void* in, size_t inlen, void* out, size_t* outlen);

    enum class DESCipher;
    enum class DESPaddingType;

    OpenSSL();
    ~OpenSSL();
    std::string md5(const std::string& data);
    // std::string md5ByEVP(const std::string& data);
    std::string sha(const std::string& data);
    std::string sha256(const std::string& data);
    std::string sha512(const std::string& data);

    Error RSAInit(const std::string& key);
    Error RSAInit(int bits, BN_ULONG word, BN_GENCB* callback);
    std::vector<uint8_t> RSAEncrypt(std::vector<uint8_t>& data, int padType, bool privEnc = false);
    std::vector<uint8_t> RSADecrypt(std::vector<uint8_t>& data, int padType, bool privDec = false);
    std::vector<uint8_t> RSASign(std::vector<uint8_t>& data, int algoType);
    bool RSAVerify(std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType);

    Error DSAInit(const std::string& key);
    Error DSAInit(int bits, const uint8_t* seed, int seedLen, int* counterRet, unsigned long* hRet, BN_GENCB* callback);
    const BIGNUM* getDSAPubKey();
    const BIGNUM* getDSAPrivKey();
    std::vector<uint8_t> DSASign(std::vector<uint8_t>& data, int algoType);
    bool DSAVerify(std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType);

    Error DHInit(const std::string& key);
    Error DHInit(int primeLen, int generator, BN_GENCB* callback);
    const BIGNUM* getDHPubKey();
    const BIGNUM* getDHPrivKey();
    std::vector<uint8_t> computeKey(const BIGNUM* key);

    Error ECCInit(const std::string& key);
    Error ECCInit(int index = 0);
    const EC_POINT* getECCPubKey();
    const BIGNUM* getECCPrivKey();
    std::vector<uint8_t> ECCSign(std::vector<uint8_t>& data, int algoType);
    bool ECCVerify(std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType);
    std::vector<uint8_t> computeKey(const EC_POINT* key, size_t outLen, ECCCompute callback);

    Error DESInit(DESCipher cipher, std::vector<uint8_t>& key, std::vector<uint8_t>& iv, DESPaddingType type);
    std::vector<uint8_t> DESEncrypt(std::vector<uint8_t>& data);
    std::vector<uint8_t> DESDecrypt(std::vector<uint8_t>& data);

    Error Base64Init();
    std::vector<uint8_t> Base64Encode(std::vector<uint8_t>& data);
    std::vector<uint8_t> Base64Decode(std::vector<uint8_t>& data);

private:
    typedef const EVP_CIPHER* (*CipherFunc)(void);

    template <class T>
    struct MACFunc;
    template <class T>
    struct SVInfo;
    template <class T>
    struct GetKeyInfo;

    enum class MACType;
    struct DESInfo;
    struct Base64Info;

    template <class T, class T1>
    std::string macCommon(const std::string& data, T func, T1& handle, int mdLen);
    template <class T>
    std::vector<uint8_t> RSACommon(std::vector<uint8_t>& data, int padType, T callback, bool decrypt = false);
    template <class T>
    std::vector<uint8_t> sign(T signInfo, std::vector<uint8_t>& data, int algoType);
    template <class T>
    bool verify(T signInfo, std::vector<uint8_t>& data, std::vector<uint8_t>& sign, int algoType);
    template <class T>
    const BIGNUM* getKey(T getKeyInfo);

    Error DSA2DH();
    std::string uint2str(const uint8_t data[], uint8_t len);
    std::vector<uint8_t> DESOption(DESInfo desInfo, std::vector<uint8_t>& data, bool encrypt = true);
    std::vector<uint8_t> Base64Option(Base64Info info, std::vector<uint8_t>& data, bool encode = true);

    friend uint32_t algoTypeMap(RSA* handle, int algoType);

    void RSAFree();
    void DSAFree();
    void DHFree();
    void ECCFree();
    void DESFree();
    void Base64Free();

    RSA* m_r;
    BIGNUM* m_bn;
    DSA* m_dsa;
    DH* m_dh;
    EC_KEY* m_ec;
    EVP_CIPHER_CTX* m_ctx;
    EVP_ENCODE_CTX* m_base64;

    BIGNUM* m_key;
    EC_POINT* m_eccKey;
    const EVP_CIPHER* m_cipher;
    DESPaddingType m_paddingType;
    std::vector<uint8_t> m_desKey;
    std::vector<uint8_t> m_desIV;

    std::mutex m_processMutex;
    std::vector<uint8_t> m_computeKey;
    std::map<DESCipher, CipherFunc> m_cipherMap;
};

enum class OpenSSL::DESCipher {
    CBC,
    ECB,
    CFB,
    CFB1,
    CFB8,
    CFB64,
    OFB,

    EDE,
    EDE_CBC,
    EDE_CFB,
    EDE_CFB64,
    EDE_ECB,
    EDE_OFB,

    EDE3,
    EDE3_CBC,
    EDE3_CFB,
    EDE3_CFB1,
    EDE3_CFB8,
    EDE3_CFB64,
    EDE3_ECB,
    EDE3_OFB,
    EDE3_WRAP
};

enum class OpenSSL::DESPaddingType { NONE, PKCS7, ISO7816_4, ANSI923, ISO10126, ZERO };

}  // namespace intellBoxSDK
