/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Arnout Vandecappelle (Essensium/Mind)
 * Copyright (c) 2019 Tomer Eliyahu (Intel)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#include <cstdint>

namespace mapf {

/**
 * @brief Wrapper functions for performing encryption
 */
namespace encryption {

///
/// @brief Diffie-Hellman key exchange
///
class diffie_hellman {
public:
    /**
     * @brief Generate a keypair suitable for Diffie-Hellman key exchange
     */
    diffie_hellman();

    ~diffie_hellman();

    /**
     * @brief Compute the shared secret key
     *
     * Diffie-Hellman generates a shared secret key based on a local private key
     * (contained in this object) and a remote public key.
     *
     * @param[out] key The derived shared secret key
     * @param[in,out] key_length Length of @a key buffer, updated to actual length on output
     * @param[in] remote_pubkey The public key of the peer
     * @param[in] remote_pubkey_length Length of @a remote_pubkey.
     * @return true if successful, false if not.
     */
    bool compute_key(uint8_t *key, unsigned &key_length, const uint8_t *remote_pubkey,
                     unsigned remote_pubkey_length) const;

    /**
     * @brief Get the public key
     */
    const uint8_t *pubkey() const { return m_pubkey; }

    /**
     * @brief Get the length of pubkey().
     */
    unsigned pubkey_length() const { return m_pubkey_length; }

    /**
     * @brief Get the nonce
     */
    const uint8_t *nonce() const { return m_nonce; }

    /**
     * @brief Get the length of nonce().
     */
    unsigned nonce_length() const { return sizeof(m_nonce); }

private:
    /**
     * If keypair generation failed in the constructor, this will be @a nullptr.
     */
    uint8_t *m_pubkey = nullptr;
    unsigned m_pubkey_length;
    uint8_t *m_privkey = nullptr;
    unsigned m_privkey_length;
    uint8_t m_nonce[16];
};

/**
 * @brief Create an initialization vector - a random byte stream used for generating the WSC authkey
 *        and keywrapkey which are used for encrypting the WSC M2 config_data according to the WSC
 *        specification v2.0.6.
 * 
 * @param[in/out] iv buffer of generated initialization vector
 * @param[in] iv_length length of initialization buffer
 * @return true on success
 * @return false on failure
 */
bool create_iv(uint8_t *iv, unsigned iv_length);

/**
 * @brief Compute KWA (Key Wrap Attribute)
 *        KWA = 1st 64 Bits of HMAC(authkey, DataToEncrypt)
 *        See section 7.5 in WiFi Simple configuration technical specification v2.0.6
 * 
 * @param[in] authkey 32 bytes authkey, calculated using wps_calculate_keys()
 * @param[in] data ConfigData before encryption
 * @param[in] data_len ConfigData length in bytes
 * @param[out] kwa 8 bytes calculated Key Wrap attribute (64 bits of HMAC(ConfigData))
 * @return true on success
 * @return false on failure
 */
bool kwa_compute(const uint8_t *key, uint8_t *data, uint32_t data_len, uint8_t *kwa);

/**
 * @brief AES encryption
 *
 * @param[in] key 32 byte KeyWrapKey calculated according to WSC v2.0.6 specification
 * @param[in] iv random 128bit input vector
 * @param[in/out] plaintext bytestream, aligned to 16 bytes boundary
 * @param[in] data_len plaintext buffer length
 * @return true on success
 * @return false on error
 */
bool aes_encrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint32_t data_len);

/**
 * @brief AES decryption
 *
 * @param[in] key 32 byte KeyWrapKey calculated according to WSC v2.0.6 specification
 * @param[in] iv random 128bit input vector
 * @param[in/out] cyphertext bytestream, aligned to 16 bytes boundary
 * @param[in] data_len cyphertext buffer length
 * @return true on success
 * @return false on error
 */
bool aes_decrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, uint32_t data_len);

/**
 * @brief Calculate WPS secret authkey and KeyWrapKey based on remote and local public keys
 *        generated with diffie-hellman key exchange, WSC M1 and M2 nonces, and M1 MAC address.
 *        The authkey used for the Key Wrap Algorithm to generate the KWA, used for the Key Wrap
 *        Authenticator attribute of the M2 WSC TLV.
 *        The keywrapkey is used for AES encryption/decryption of M2 WSC encrypted settings.
 *
 * @param[in] dh diffie helman instance containing the local public key
 * @param[in] remote_pubkey remote public key (from M1 or M2 WSC TLV)
 * @param[in] remote_pubkey_length remote public key length
 * @param[in] m1_nonce WSC M1 TLV enrollee nonce attribute
 * @param[in] mac WSC M1 TLV mac attribute
 * @param[in] m2_nonce WSC M2 TLV registrar nonce attribute
 * @param[out] authkey calculated 256 bit authentication key
 * @param[out] keywrapkey calculated 128 bit keywrapkey
 * @return true on success, false on error
 */
bool wps_calculate_keys(const diffie_hellman &dh, const uint8_t *remote_pubkey,
                        unsigned remote_pubkey_length, const uint8_t *m1_nonce, const uint8_t *mac,
                        const uint8_t *m2_nonce, uint8_t *authkey, uint8_t *keywrapkey);

// BBF CODE

#define INT8U unsigned char
#define INT16U unsigned short int
#define INT32U unsigned int
#define INT8S signed char
#define INT16S signed short int
#define INT32S signed int
#define PLATFORM_PRINTF_DEBUG_WARNING(x) LOG(DEBUG) << x
#define SHA256_MAC_LEN 32
#define AES_BLOCK_SIZE 16

// Fill the buffer of length 'len' pointed by 'p' with random bytes.
//
// Return "0" if there was a problem, "1" otherwise
//
INT8U PLATFORM_GET_RANDOM_BYTES(INT8U *p, INT16U len);


// Return a Diffie Hellman pair of private and public keys (and its lengths) in
// the output arguments "priv", "priv_len", "pub" and "pub_len".
//
// Both "priv" and "pub" must be deallocated by the caller when they are no
// longer needed (using "PLATFORM_FREE()")
//
// The keys are obtained using the DH group specified in RFC3523 "section 2"
// (ie. the "1536-bit MODP Group" where "g = 2" and "p = 2^1536 - 2^1472 - 1 +
// 2^64 * { [2^1406 pi] + 741804 }")
//
// Return "0" if there was a problem, "1" otherwise
//
INT8U PLATFORM_GENERATE_DH_KEY_PAIR(INT8U **priv, INT16U *priv_len, INT8U **pub, INT16U *pub_len);

// Return the Diffie Hell shared secret (in output argument "shared_secret"
// which is "shared_secret_len" bytes long) associated to a remote public key
// ("remote_pub", which is "remote_pub_len" bytes long") and a local private
// key ("local_priv", which is "local_priv_len" bytes long).
//
// "shared_secret" must be deallocated by the caller once it is no longer needed
// (using "PLATFORM_FREE()")
//
// Return "0" if there was a problem, "1" otherwise
//
INT8U PLATFORM_COMPUTE_DH_SHARED_SECRET(INT8U **shared_secret, INT16U *shared_secret_len, INT8U *remote_pub, INT16U remote_pub_len, INT8U *local_priv, INT8U local_priv_len);

// Return the SHA256 digest of the provided input.
//
// The provided input is the result of concatenating 'num_elem' elements
// (addr[0], addr[1], ..., addr[num_elem-1] of size len[0], len[1], ...,
// len[num_elem-1])
//
// The digest is returned in the 'digest' output argument which must point to
// a preallocated buffer of "SHA256_MAC_LEN" bytes.
//
INT8U PLATFORM_SHA256(INT8U num_elem, INT8U **addr, INT32U *len, INT8U *digest);


// Return the HMAC_SHA256 digest of the provided input using the provided 'key'
// (which is 'keylen' bytes long).
//
// The provided input is the result of concatenating 'num_elem' elements
// (addr[0], addr[1], ..., addr[num_elem-1] of size len[0], len[1], ...,
// len[num_elem-1])
//
// The digest is returned in the 'hmac' output argument which must point to
// a preallocated buffer of "SHA256_MAC_LEN" bytes.
//
INT8U PLATFORM_HMAC_SHA256(INT8U *key, INT32U keylen, INT8U num_elem, INT8U **addr, INT32U *len, INT8U *hmac);

// Encrypt the provided 'data' (which is a pointer to buffer of size
// n*AES_BLOCK_SIZE) using the AES 128 CBC algorithm with the provided
// "initialization vector" ('iv', which is also a pointer to a buffer of
// AES_BLOCK_SIZE bytes).
//
// The result is written to THE SAME 'data' buffer and has the same length as
// the input (plain) data.
//
// Note that you might have to "pad" the data buffer (so that its length is a
// multiple of AES_BLOCK_SIZE) in most cases.
//
// Return "0" if there was a problem, "1" otherwise
//
INT8U PLATFORM_AES_ENCRYPT(INT8U *key, INT8U *iv, INT8U *data, INT32U data_len);

// Works exactly like "PLATFORM_AES_ENCRYPT", but now the 'data' buffer
// originally contains encrypted data and after the call it contains
// unencrypted data.
INT8U PLATFORM_AES_DECRYPT(INT8U *key, INT8U *iv, INT8U *data, INT32U data_len);


} // namespace encryption
} // namespace mapf
#endif // ENCRYPTION_H_
