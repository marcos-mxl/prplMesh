/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2017, Broadband Forum
 * Copyright (c) 2019 Arnout Vandecappelle (Essensium/Mind)
 * Copyright (c) 2019 Tomer Eliyahu (Intel)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <mapf/common/encryption.h>
#include <mapf/common/logger.h>

#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace mapf {
namespace encryption {

/**
 * Diffie-Hellman group 5, see RFC3523
 */
static const uint8_t dh1536_p[] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
    0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
    0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
    0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
    0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
    0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
    0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
    0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
    0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};
static const uint8_t dh1536_g[] = {0x02};

static bool generate_random_bytestream(uint8_t *buf, unsigned len)
{
    std::ifstream urandom("/dev/urandom");
    urandom.read(reinterpret_cast<char *>(buf), len);
    return urandom.good();
}

//PLATFORM_GENERATE_DH_KEY_PAIR
diffie_hellman::diffie_hellman() : m_pubkey(nullptr), m_privkey(nullptr)
{
    MAPF_DBG("Generating DH keypair");

    DH *dh = DH_new();
    if (dh == nullptr) {
        MAPF_ERR("Failed to allocate DH");
        return;
    }

    if (!generate_random_bytestream(m_nonce, sizeof(m_nonce))) {
        MAPF_ERR("Failed to generate nonce");
        return;
    }

    // Convert binary to BIGNUM format
    if (NULL == (dh->p = BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL))) {
        MAPF_ERR("Failed BN_bin2bn");
        DH_free(dh);
        return;
    }
    if (NULL == (dh->g = BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL))) {
        MAPF_ERR("Failed BN_bin2bn");
        DH_free(dh);
        return;
    }

    // Obtain key pair
    if (0 == DH_generate_key(dh)) {
        MAPF_ERR("Failed to generate DH key");
        DH_free(dh);
        return;
    }

    m_privkey_length = BN_num_bytes(dh->priv_key);
    m_privkey = new uint8_t[m_privkey_length];
    BN_bn2bin(dh->priv_key, m_privkey);

    m_pubkey_length = BN_num_bytes(dh->priv_key);
    m_pubkey = new uint8_t[m_pubkey_length];
    BN_bn2bin(dh->pub_key, m_pubkey);

    DH_free(dh);
}

diffie_hellman::~diffie_hellman()
{
    delete m_pubkey;
    delete m_privkey;
}

// PLATFORM_COMPUTE_DH_SHARED_SECRET
bool diffie_hellman::compute_key(uint8_t *key, unsigned &key_length, const uint8_t *remote_pubkey,
                                 unsigned remote_pubkey_length) const
{
    MAPF_DBG("Computing DH shared key");

    DH *dh = DH_new();
    if (dh == nullptr) {
        MAPF_ERR("Failed to allocate DH");
        return false;
    }
    // Convert binary to BIGNUM format
    if (NULL == (dh->p = BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL))) {
        MAPF_ERR("Failed BN_bin2bn");
        DH_free(dh);
        return false;
    }
    if (NULL == (dh->g = BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL))) {
        MAPF_ERR("Failed BN_bin2bn");
        DH_free(dh);
        return false;
    }
    BIGNUM *pub_key = BN_bin2bn(remote_pubkey, remote_pubkey_length, NULL);
    if (pub_key == nullptr) {
        MAPF_ERR("Failed to set DH remote_pub_key");
        return false;
    }
    if (NULL == (dh->priv_key = BN_bin2bn(m_privkey, m_privkey_length, NULL)))
    {
        BN_clear_free(pub_key);
        DH_free(dh);
        return false;
    }
    
    // Compute the shared secret and save it in the output buffer
    if ((int)key_length < DH_size(dh)) {
        MAPF_ERR("Output buffer for DH shared key to small: ")
            << key_length << " < " << DH_size(dh);
        BN_clear_free(pub_key);
        return false;
    }
    int ret = DH_compute_key(key, pub_key, dh);
    if (ret < 0) {
        MAPF_ERR("Failed to compute DH shared key");
        return false;
    }
    key_length = (unsigned)ret;
    BN_clear_free(pub_key);
    DH_free(dh);
    return true;
}

bool create_iv(uint8_t *iv, unsigned iv_length)
{
    return generate_random_bytestream(iv, iv_length);
}

class sha256 {
public:
    sha256();
    ~sha256();

    bool update(const uint8_t *message, size_t message_length);

    /**
     * @brief Calculate and return the sha256 digest
     * @param[out] digest Output buffer, must be 32 bytes
     * @return
     */
    bool digest(uint8_t *digest);

private:
    EVP_MD_CTX *m_ctx;
    EVP_MD_CTX  ctx_aux;
};

sha256::sha256()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    m_ctx = EVP_MD_CTX_new();
#else
    m_ctx = &ctx_aux;
    EVP_MD_CTX_init(m_ctx);
#endif
    if (!EVP_DigestInit_ex(m_ctx, EVP_sha256(), NULL)) {
        MAPF_ERR("Failed to create sha256");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_MD_CTX_free(m_ctx);
#endif
        m_ctx = nullptr;
    }
}

sha256::~sha256()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(m_ctx);
#endif
}

bool sha256::update(const uint8_t *message, size_t message_length)
{
    if (m_ctx == nullptr) {
        return false;
    }
    return EVP_DigestUpdate(m_ctx, message, message_length);
}

bool sha256::digest(uint8_t *digest)
{
    if (m_ctx == nullptr) {
        return false;
    }
    unsigned int digest_length = 32;
    return EVP_DigestFinal(m_ctx, digest, &digest_length);
}

class hmac {
public:
    hmac(const uint8_t *key, unsigned key_length);
    ~hmac();

    bool update(const uint8_t *message, size_t message_length);

    /**
     * @brief Calculate and return the hmac digest
     * @param[out] digest Output buffer, must be 32 bytes
     * @return
     */
    bool digest(uint8_t *digest);

private:
    HMAC_CTX *m_ctx;
    HMAC_CTX  ctx_aux;
};

hmac::hmac(const uint8_t *key, unsigned key_length)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    m_ctx = HMAC_CTX_new();
#else
    m_ctx = &ctx_aux;
    HMAC_CTX_init(m_ctx);
#endif
    if (!HMAC_Init_ex(m_ctx, key, key_length, EVP_sha256(), NULL)) {
        MAPF_ERR("Failed to create hmac");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        HMAC_CTX_free(m_ctx);
#endif
        m_ctx = nullptr;
    }
}

hmac::~hmac()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(m_ctx);
#endif
}

bool hmac::update(const uint8_t *message, size_t message_length)
{
    if (m_ctx == nullptr) {
        return false;
    }
    return HMAC_Update(m_ctx, message, message_length);
}

bool hmac::digest(uint8_t *digest)
{
    if (m_ctx == nullptr) {
        return false;
    }
    unsigned int digest_length = 32;
    return HMAC_Final(m_ctx, digest, &digest_length);
}

bool aes_encrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint32_t data_len)
{
    EVP_CIPHER_CTX *ctx;

    int clen, len;
    uint8_t buf[128];

    ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return false;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    clen = data_len;
    if (EVP_EncryptUpdate(ctx, data, &clen, data, data_len) != 1 || clen != (int)data_len) {
        return false;
    }

    len = sizeof(buf);
    if (EVP_EncryptFinal_ex(ctx, buf, &len) != 1 || len != 0) {
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool aes_decrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint32_t data_len)
{
    EVP_CIPHER_CTX *ctx;

    int plen, len;
    uint8_t buf[128];

    ctx = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return false;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    plen = data_len;
    if (EVP_DecryptUpdate(ctx, data, &plen, data, data_len) != 1 || plen != (int)data_len) {
        return false;
    }

    len = sizeof(buf);
    if (EVP_DecryptFinal_ex(ctx, buf, &len) != 1 || len != 0) {
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool wps_calculate_keys(const diffie_hellman &dh, const uint8_t *remote_pubkey,
                        unsigned remote_pubkey_length, const uint8_t *m1_nonce, const uint8_t *mac,
                        const uint8_t *m2_nonce, uint8_t *authkey, uint8_t *keywrapkey)
{
    uint8_t shared_secret[192];
    unsigned shared_secret_length = sizeof(shared_secret);

    dh.compute_key(shared_secret, shared_secret_length, remote_pubkey, remote_pubkey_length);
    // Zero pad the remaining part
    // std::fill(shared_secret + shared_secret_length, shared_secret + sizeof(shared_secret), 0);

    sha256 sha;
    sha.update(shared_secret, shared_secret_length);

    uint8_t key[32];
    sha.digest(key);

    hmac hmac_kdk(key, sizeof(key));
    hmac_kdk.update(m1_nonce, 16);
    hmac_kdk.update(mac, 6);
    hmac_kdk.update(m2_nonce, 16);

    uint8_t kdk[32];
    hmac_kdk.digest(kdk);

    // Finally, take "kdk" and using a function provided in the "Wi-Fi
    // simple configuration" standard, obtain THREE KEYS that we will use
    // later ("authkey", "keywrapkey" and "emsk")
    union {
        struct {
            uint8_t authkey[32];
            uint8_t keywrapkey[16];
            uint8_t emsk[32];
        } keys;
        uint8_t buf[3][32];
    } keys;

    // This is the key derivation function used in the WPS standard to obtain a
    // final hash that is later used for encryption.
    //
    // The output is stored in the memory buffer pointed by 'res', which must be
    // "SHA256_MAC_LEN" bytes long (ie. 're_len' must always be "SHA256_MAC_LEN",
    // even if it is an input argument)
    //
    union {
        uint32_t i;
        uint8_t buf[4];
    } kdf_iter, kdf_key_length;

    kdf_key_length.i = htonl(sizeof(keys.keys) * 8);

    std::string personalization_string("Wi-Fi Easy and Secure Key Derivation");
    for (unsigned iter = 1; iter < sizeof(keys) / 32; iter++) {
        kdf_iter.i = htonl(iter);

        hmac hmac_iter(kdk, sizeof(kdk));
        hmac_iter.update(kdf_iter.buf, sizeof(kdf_iter.buf));
        hmac_iter.update(reinterpret_cast<const uint8_t *>(personalization_string.data()),
                         personalization_string.length());
        hmac_iter.update(kdf_key_length.buf, sizeof(kdf_key_length.buf));
        static_assert(sizeof(keys.buf[1]) == 32, "Correct size");
        hmac_iter.digest(keys.buf[iter - 1]);
    }
    std::copy(keys.keys.authkey, keys.keys.authkey + sizeof(keys.keys.authkey), authkey);
    std::copy(keys.keys.keywrapkey, keys.keys.keywrapkey + sizeof(keys.keys.keywrapkey),
              keywrapkey);
    return true;
}

bool kwa_compute(const uint8_t *authkey, uint8_t *data, uint32_t data_len, uint8_t *kwa)
{
    uint8_t hmac_[32];
    hmac hmac_kwa(authkey, 32);
    if (!hmac_kwa.update(data, data_len))
        return false;
    if (!hmac_kwa.digest(hmac_))
        return false;
    std::copy_n(hmac_, 8, kwa);
    return true;
}

// bbf reference code

////////////////////////////////////////////////////////////////////////////////
// Platform API: Interface related functions to be used by platform-independent
// files (functions declarations are  found in "../interfaces/platform.h)
////////////////////////////////////////////////////////////////////////////////

INT8U PLATFORM_GET_RANDOM_BYTES(INT8U *p, INT16U len)
{
    FILE   *fd;
    INT32U  rc;

    fd = fopen("/dev/urandom", "rb");

    if (NULL == fd)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("[PLATFORM] Cannot open /dev/urandom\n");
        return 0;
    }

    rc = fread(p, 1, len, fd);

    fclose(fd);

    if (len != rc)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("[PLATFORM] Could not obtain enough random bytes\n");
        return 0;
    }
    else
    {
        return 1;
    }
}

INT8U PLATFORM_GENERATE_DH_KEY_PAIR(INT8U **priv, INT16U *priv_len, INT8U **pub, INT16U *pub_len)
{
    DH *dh;

    if (
         NULL == priv     ||
         NULL == priv_len ||
         NULL == pub      ||
         NULL == pub_len
       )
    {
        return 0;
    }

    if (NULL == (dh = DH_new()))
    {
        return 0;
    }

    // Convert binary to BIGNUM format
    //
    if (NULL == (dh->p = BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL)))
    {
        DH_free(dh);
        return 0;
    }
    if (NULL == (dh->g = BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL)))
    {
        DH_free(dh);
        return 0;
    }

    // Obtain key pair
    //
    if (0 == DH_generate_key(dh))
    {
        DH_free(dh);
        return 0;
    }

    *priv_len = BN_num_bytes(dh->priv_key);
    *priv     = (INT8U *)malloc(*priv_len);
    BN_bn2bin(dh->priv_key, *priv);

    *pub_len = BN_num_bytes(dh->pub_key);
    *pub     = (INT8U *)malloc(*pub_len);
    BN_bn2bin(dh->pub_key, *pub);

    DH_free(dh);
      // NOTE: This internally frees "dh->p" and "dh->q", thus no need for us
      // to do anything else.

    return 1;
}

INT8U PLATFORM_COMPUTE_DH_SHARED_SECRET(INT8U **shared_secret, INT16U *shared_secret_len, INT8U *remote_pub, INT16U remote_pub_len, INT8U *local_priv, INT8U local_priv_len)
{
    BIGNUM *pub_key;

    size_t rlen;
    int    keylen;

    DH *dh;

    if (
         NULL == shared_secret     ||
         NULL == shared_secret_len ||
         NULL == remote_pub        ||
         NULL == local_priv
       )
    {
        return 0;
    }

    if (NULL == (dh = DH_new()))
    {
        return 0;
    }

    // Convert binary to BIGNUM format
    //
    if (NULL == (dh->p = BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL)))
    {
        DH_free(dh);
        return 0;
    }
    if (NULL == (dh->g = BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL)))
    {
        DH_free(dh);
        return 0;
    }
    if (NULL == (pub_key = BN_bin2bn(remote_pub, remote_pub_len, NULL)))
    {
        DH_free(dh);
        return 0;
    }
    if (NULL == (dh->priv_key = BN_bin2bn(local_priv, local_priv_len, NULL)))
    {
        BN_clear_free(pub_key);
        DH_free(dh);
        return 0;
    }

    // Allocate output buffer
    //
    rlen            = DH_size(dh);
    *shared_secret  = (INT8U*)malloc(rlen);

    // Compute the shared secret and save it in the output buffer
    //
    keylen = DH_compute_key(*shared_secret, pub_key, dh);
    if (keylen < 0)
    {
        *shared_secret_len = 0;
        free(*shared_secret);
        *shared_secret = NULL;
        BN_clear_free(pub_key);
        DH_free(dh);

        return 0;
    }
    else
    {
        *shared_secret_len = (INT16U)keylen;
    }

    BN_clear_free(pub_key);
    DH_free(dh);

    return 1;
}

INT8U PLATFORM_SHA256(INT8U num_elem, INT8U **addr, INT32U *len, INT8U *digest)
{
    INT8U res;
    unsigned int  mac_len;
    EVP_MD_CTX   *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return 0;
    }
#else
    EVP_MD_CTX  ctx_aux;
    ctx = &ctx_aux;

    EVP_MD_CTX_init(ctx);
#endif

    res = 1;

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    {
        res = 0;
    }

    if (1 == res)
    {
        size_t i;

        for (i = 0; i < num_elem; i++)
        {
            if (!EVP_DigestUpdate(ctx, addr[i], len[i]))
            {
                res = 0;
                break;
            }
        }
    }

    if (1 == res)
    {
        if (!EVP_DigestFinal(ctx, digest, &mac_len))
        {
            res = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif

    return res;
}

INT8U PLATFORM_HMAC_SHA256(INT8U *key, INT32U keylen, INT8U num_elem, INT8U **addr, INT32U *len, INT8U *hmac)
{
    HMAC_CTX *ctx;
    size_t    i;

    unsigned int mdlen = 32;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = HMAC_CTX_new();
    if (!ctx)
    {
        return 0;
    }
#else
    HMAC_CTX  ctx_aux;
    ctx = &ctx_aux;

    HMAC_CTX_init(ctx);
#endif

    HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);

    for (i = 0; i < num_elem; i++)
    {
        HMAC_Update(ctx, addr[i], len[i]);
    }

    HMAC_Final(ctx, hmac, &mdlen);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 1;
}

INT8U PLATFORM_AES_ENCRYPT(INT8U *key, INT8U *iv, INT8U *data, INT32U data_len)
{
    EVP_CIPHER_CTX ctx;

    int clen, len;
    INT8U buf[AES_BLOCK_SIZE];

    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
    {
        return 0;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    clen = data_len;
    if (EVP_EncryptUpdate(&ctx, data, &clen, data, data_len) != 1 || clen != (int) data_len)
    {
        return 0;
    }

    len = sizeof(buf);
    if (EVP_EncryptFinal_ex(&ctx, buf, &len) != 1 || len != 0)
    {
        return 0;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);

    return 1;
}

INT8U PLATFORM_AES_DECRYPT(INT8U *key, INT8U *iv, INT8U *data, INT32U data_len)
{
    EVP_CIPHER_CTX ctx;

    int plen, len;
    INT8U buf[AES_BLOCK_SIZE];

    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
    {
        return 0;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    plen = data_len;
    if (EVP_DecryptUpdate(&ctx, data, &plen, data, data_len) != 1 || plen != (int) data_len)
    {
        return 0;
    }

    len = sizeof(buf);
    if (EVP_DecryptFinal_ex(&ctx, buf, &len) != 1 || len != 0)
    {
        return 0;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);

    return 1;
}

} // namespace encryption
} // namespace mapf
