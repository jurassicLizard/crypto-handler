//
// MIT License
//
// Copyright (c) 2025 Salem B.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#include  "jlizard/byte_array.h"

#include "jlizard/CryptoHandler.h"
#include "openssl/hmac.h"
#include <cstring>
#include <stdexcept>
#include <cassert>
#include <iostream>
#include <sstream>
#include <openssl/err.h>
#include <openssl/provider.h>


using namespace jlizard;

CryptoHandler::CryptoHandler(const EVP_CIPHER *cipher) : m_cipher(cipher){

        printf("running in cipher mode \n");
        printf("using : %s\n",EVP_CIPHER_get0_name(cipher));

        if(!cipher) {
            throw std::runtime_error("passed a null cipher this is fatal");
        }

        m_bIsLegacy = strncmp(EVP_CIPHER_get0_name(cipher),"DES",3) == 0;

        if(m_bIsLegacy)
        {
            m_legacy_provider = OSSL_PROVIDER_load(nullptr,"legacy");
            if (!m_legacy_provider) {
                throw std::runtime_error("Unable to initialize legacy provider");
            }
        }

        //start initializations
        /* Create and initialise the context */
        m_cipher_ctx.reset(EVP_CIPHER_CTX_new());
        if(!m_cipher_ctx)
        {
            openssl_handle_errors();
        }




}

CryptoHandler::CryptoHandler(const EVP_MD * digest) : m_digest(digest) {
    printf("running in digest mode \n");
    printf("using : %s\n",EVP_MD_get0_name(digest));

    m_digest_ctx.reset(EVP_MD_CTX_new());
    if (!m_digest_ctx)
    {
        openssl_handle_errors();
    }

}

CryptoHandler::~CryptoHandler() {
    /* Clean up */

    if(m_bIsLegacy)
    {
        OSSL_PROVIDER_unload(m_legacy_provider);  // Unload the legacy provider

    }
}

void CryptoHandler::openssl_handle_errors() {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("OpenSSL error");
}

int CryptoHandler::encrypt_(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, const unsigned char *iv,
                           unsigned char *ciphertext_out, const bool bAllowPadding,
                           const unsigned char *aad, const int aad_len ,
                           unsigned char *tag_out, const int tag_len)
 {

    expect_cipher_mode_handler();

    int len;

    // Reset context for reuse
    if(1 != EVP_CIPHER_CTX_reset(m_cipher_ctx.get()))
        openssl_handle_errors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(m_cipher_ctx.get(), m_cipher, nullptr, key, iv))
         openssl_handle_errors();
    /*
     * disable padding if we need to or if we are in gcm mode
     */
    if(!bAllowPadding || (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE)) {
        if(1 != EVP_CIPHER_CTX_set_padding(m_cipher_ctx.get(),0))
            openssl_handle_errors();
    }

    // Process AAD data if we're in GCM mode and have AAD data
    if (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE && aad != nullptr && aad_len > 0) {
        int aad_update_len;
        if (1 != EVP_EncryptUpdate(m_cipher_ctx.get(), nullptr, &aad_update_len, aad, aad_len))
            openssl_handle_errors();
    }


    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(m_cipher_ctx.get(), ciphertext_out, &len, plaintext, plaintext_len))
        openssl_handle_errors();
    int ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(m_cipher_ctx.get(), ciphertext_out + len, &len))
        openssl_handle_errors();
    ciphertext_len += len;

    // Get the tag if we're in GCM mode and tag_out is provided
    if (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE && tag_out != nullptr && tag_len > 0) {
        if (1 != EVP_CIPHER_CTX_ctrl(m_cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_len, tag_out))
            openssl_handle_errors();
    }

    return ciphertext_len;


}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::encrypt(
    const ByteArray& plaintext_bytes,
    const ByteArray& key,
    const ByteArray& iv,
    ByteArray& tag_out,
    const ByteArray& aad,
    const bool bAllowPadding)
{
    // Pre-allocate ciphertext buffer with sufficient space
    int block_size = EVP_CIPHER_block_size(m_cipher);
    ByteArray ciphertext_bytes(plaintext_bytes.size() + block_size,0x00);

    // Handle AAD - pass nullptr if empty
    const unsigned char* aad_ptr =  !aad.empty() ?
                const_cast<ByteArray&>(aad).data() : nullptr;
    const auto aad_size = aad.size();

    // Handle tag - pass nullptr to openssl api if empty or not in GCM mode
    unsigned char* tag_ptr = !tag_out.empty() ? tag_out.data() : nullptr;
    const auto tag_size = tag_out.size();
    // In GCM mode, verify tag_out is properly sized
    if (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE && (tag_size < 12 || tag_size > 16)) {
        return std::unexpected(CryptoHandlerError::with_msg("Expected Tag buffer to be between 12 and 16 bytes for GCM mode"));
    }


    int encrypted_length = encrypt_(
    const_cast<ByteArray&>(plaintext_bytes).data(),
    plaintext_bytes.size(),
    const_cast<ByteArray&>(key).data(),
    const_cast<ByteArray&>(iv).data(),
    ciphertext_bytes.data(),
    bAllowPadding,aad_ptr,
    aad_size,
    tag_ptr,
    tag_size);

    if (encrypted_length < 0)
    {
        ciphertext_bytes.clear();
        return std::unexpected(CryptoHandlerError::with_msg("Openssl error"));
    }

    //resize array to actual encrypted size and return that size
    ciphertext_bytes.resize(encrypted_length,true,false);

    return ciphertext_bytes;

}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::encrypt(const ByteArray& plaintext_bytes, const ByteArray& key, const ByteArray& iv, ByteArray& tag_out, const bool bAllowPadding)
{
    const ByteArray aad{};
    return encrypt(plaintext_bytes,key,iv,tag_out,aad,bAllowPadding);
}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::encrypt(const ByteArray& plaintext_bytes, const ByteArray& key, const ByteArray& iv, const bool bAllowPadding)
{
    ByteArray tag_out{};
    const ByteArray aad{};
    return encrypt(plaintext_bytes,key,iv,tag_out,aad,bAllowPadding);
}


std::expected<ByteArray, CryptoHandlerError> CryptoHandler::decrypt(
    const ByteArray& ciphertext_bytes,
    const ByteArray& key,
    const ByteArray& iv,
    const ByteArray& tag,
    const ByteArray& aad,
    const bool bAllowPadding
)
{
    // Pre-allocate plaintext buffer with sufficient space
    int block_size = EVP_CIPHER_block_size(m_cipher);
    ByteArray plaintext_bytes(ciphertext_bytes.size() + block_size, 0x00);

    // Handle AAD - pass nullptr if not provided
    const unsigned char* aad_ptr = nullptr;
    size_t aad_size = 0;
    if (!aad.empty()) {
        aad_ptr = const_cast<ByteArray&>(aad).data();
        aad_size = aad.size();
    }

    // Handle tag - pass nullptr if not provided
    const unsigned char* tag_ptr = nullptr;
    size_t tag_size = 0;
    if (!tag.empty()) {
        tag_ptr = const_cast<ByteArray&>(tag).data();
        tag_size = tag.size();
    }

    // In GCM mode, verify tag is properly sized
    if (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE) {
        if (tag_ptr == nullptr) {
            return std::unexpected(CryptoHandlerError::with_msg("Tag is required for GCM mode"));
        }
        if (tag.size() < 12) {
            return std::unexpected(CryptoHandlerError::with_msg("Tag too small for GCM mode"));
        }
    }


    // The const_cast is unfortunate but necessary due to OpenSSL's API
    int decrypted_length = decrypt_(
        const_cast<ByteArray&>(ciphertext_bytes).data(),
        ciphertext_bytes.size(),
        const_cast<ByteArray&>(key).data(),
        const_cast<ByteArray&>(iv).data(),
        plaintext_bytes.data(),
        bAllowPadding,
        aad_ptr,
        aad_size,
        tag_ptr,
        tag_size
    );

    // Handle decryption result
    if (decrypted_length < 0) {
        plaintext_bytes.clear();  // Clear output on error
        return std::unexpected(CryptoHandlerError::with_msg("OpenSSL error"));  // Return the error code
    }

    // Resize plaintext to actual decrypted length
    plaintext_bytes.resize(decrypted_length,true,false);

    return plaintext_bytes;
}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::decrypt(const ByteArray& ciphertext_bytes, const ByteArray& key, const ByteArray& iv, bool bAllowPadding)
{
    const ByteArray tag{};
    const ByteArray aad{};
    return decrypt(ciphertext_bytes,key,iv,tag,aad,bAllowPadding);
}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::decrypt(const ByteArray& ciphertext_bytes, const ByteArray& key, const ByteArray& iv, const ByteArray& tag, bool bAllowPadding)
{
    const ByteArray aad{};
    return decrypt(ciphertext_bytes,key,iv,tag,aad,bAllowPadding);
}


int CryptoHandler::decrypt_(const unsigned char *ciphertext, const int ciphertext_len,
                           const unsigned char *key, const unsigned char *iv,
                           unsigned char *plaintext_out, const bool bAllowPadding,
                           const unsigned char *aad, const int aad_len,
                           const unsigned char *tag, const int tag_len)
{
    expect_cipher_mode_handler();

    int len;

    // Reset context for reuse
    if(1 != EVP_CIPHER_CTX_reset(m_cipher_ctx.get()))
        openssl_handle_errors();


    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(m_cipher_ctx.get(), m_cipher, nullptr, key, iv))
        openssl_handle_errors();

    /*
     * disable padding if we need to or if we are in gcm mode
     */
    if(!bAllowPadding || (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE)) {
        if(1 != EVP_CIPHER_CTX_set_padding(m_cipher_ctx.get(),0))
            openssl_handle_errors();
    }

    // Set the tag if we're in GCM mode - MUST be done before processing ciphertext
    if (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE && tag != nullptr && tag_len > 0) {
        if (1 != EVP_CIPHER_CTX_ctrl(m_cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag))
            openssl_handle_errors();
    }

    // Process AAD data if we're in GCM mode and have AAD data
    if (EVP_CIPHER_mode(m_cipher) == EVP_CIPH_GCM_MODE && aad != nullptr && aad_len > 0) {
        int aad_update_len;
        if (1 != EVP_DecryptUpdate(m_cipher_ctx.get(), nullptr, &aad_update_len, aad, aad_len))
            openssl_handle_errors();
    }
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(m_cipher_ctx.get(), plaintext_out, &len, ciphertext, ciphertext_len))
        openssl_handle_errors();
    int plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(m_cipher_ctx.get(), plaintext_out + len, &len))
        openssl_handle_errors();
    plaintext_len += len;

    return plaintext_len;
}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::calculate_digest(const ByteArray& message)
{
    // Check if the digest_type is properly initialized
    expect_digest_mode_handler();

    // Reset context for reuse
    if(1 != EVP_MD_CTX_reset(m_digest_ctx.get()))
        openssl_handle_errors();

    // Initialize the digest operation
    if (1 != EVP_DigestInit_ex(m_digest_ctx.get(), m_digest, nullptr)) {
        openssl_handle_errors();
    }

    // Update with the message
    if (1 != EVP_DigestUpdate(m_digest_ctx.get(), const_cast<ByteArray&>(message).data(), message.size())) {
        openssl_handle_errors();
    }

    // Resize the output buffer to hold the digest
    unsigned int digest_len = EVP_MD_size(m_digest);
    const unsigned int expected_digest_len = digest_len;
    // Prepare output buffer
    ByteArray digest_output(expected_digest_len,0x00);

    // Finalize the digest calculation
    if (1 != EVP_DigestFinal_ex(m_digest_ctx.get(), digest_output.data(), &digest_len)) {
        openssl_handle_errors();
    }

    if (digest_len != expected_digest_len)
    {
        return std::unexpected(CryptoHandlerError::with_msg("OpenSSL error"));
    }

    // No need for explicit cleanup - unique_ptr will handle it

    return digest_output;
}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::calculate_digest_truncated(
    const ByteArray& message, const size_t show_bits)
{
    auto digest_res = calculate_digest(message);
    if (digest_res)
    {
        if ((show_bits/8) < digest_res.value().size()) {
            digest_res.value().resize(show_bits/8,true,false);
        }else
        {
            return std::unexpected(CryptoHandlerError::with_msg("requested more bytes than digest provides"));
        }
    }

    return digest_res;

}

std::expected<ByteArray, CryptoHandlerError> CryptoHandler::calculate_cbc_mac(const ByteArray& plaintext_bytes,
                                                                              const ByteArray& key) {

    expect_cipher_mode_handler(); //AES256-CBC-MAC so we are using the cipher mode here

    const int block_size_bytes = EVP_CIPHER_get_block_size(m_cipher); //check for nullptr done in expect clause above
    ByteArray mac_bytes(block_size_bytes,0x00);

    const ByteArray iv(block_size_bytes,0);
    auto enc_res = encrypt(plaintext_bytes,key,iv,false).value(); //no cipher padding because we need the last cipher block as is

    if (enc_res.size() >= static_cast<size_t>(block_size_bytes))
    {
        mac_bytes = ByteArray(enc_res.end() - block_size_bytes, enc_res.end());

    }else
    {
        return std::unexpected(CryptoHandlerError::with_msg("Fatal : expected cipher text block to be at least one block size long"));
    }

    return mac_bytes;

}

ByteArray CryptoHandler::calculate_hmac(const ByteArray& message, const ByteArray& key)
{
    expect_digest_mode_handler();
    ByteArray hmac_out(EVP_MAX_MD_SIZE,0x00);

    unsigned int digest_length = 0;

    if (nullptr == HMAC(m_digest,const_cast<ByteArray&>(key).data(),
        key.size(),
        const_cast<ByteArray&>(message).data(),
        message.size(),
        hmac_out.data(),&digest_length))
    {
        hmac_out.clear();
        openssl_handle_errors();
    }


    hmac_out.resize(digest_length,true,false);

    return hmac_out;

}


std::expected<ByteArray, CryptoHandlerError> CryptoHandler::calculate_gmac(const ByteArray& aad_data,
                                                                           const ByteArray& key,
                                                                           const ByteArray& iv)
{
    expect_cipher_mode_handler();

    // Validate we're using a GCM mode cipher
    if (EVP_CIPHER_mode(m_cipher) != EVP_CIPH_GCM_MODE) {
        return std::unexpected(CryptoHandlerError::with_msg("GMAC calculation requires GCM mode cipher"));
    }

    // Check size limits
    if (aad_data.size() >= INT_MAX) {
        return std::unexpected(CryptoHandlerError::with_msg("AAD data size exceeds INT_MAX"));
    }

    // Initialize encryption operation with key and IV
    if (1 != EVP_EncryptInit_ex(m_cipher_ctx.get(), m_cipher, nullptr, const_cast<ByteArray&>(key).data(), const_cast<ByteArray&>(iv).data())) {
        openssl_handle_errors();
    }

    // Process AAD data
    int len;
    if (1 != EVP_EncryptUpdate(m_cipher_ctx.get(), nullptr, &len, const_cast<ByteArray&>(aad_data).data(), static_cast<int>(aad_data.size()))) {
        openssl_handle_errors();
    }

    // Finalize encryption (with no ciphertext output since we're only doing GMAC)
    if (1 != EVP_EncryptFinal_ex(m_cipher_ctx.get(), nullptr, &len)) {
        openssl_handle_errors();
    }

    // Get the authentication tag (GMAC)
    ByteArray gmac_bytes(16,0x00); // Standard GCM tag size is 16 bytes
    if (1 != EVP_CIPHER_CTX_ctrl(m_cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG,
                               gmac_bytes.size(), gmac_bytes.data())) {
        openssl_handle_errors();
    }

    return gmac_bytes;
}




void CryptoHandler::expect_cipher_mode_handler() const
{
    if (m_cipher == nullptr || m_cipher_ctx == nullptr)
    {
        throw std::runtime_error("Cannot run in cipher mode, ciphers not properly initialized. Are we running in digest mode ?");
    }
}

void CryptoHandler::expect_cipher_in_gcm_mode() const
{
    if (m_cipher == nullptr || (EVP_CIPHER_mode(m_cipher) != EVP_CIPH_GCM_MODE)) {
        throw std::runtime_error("Expected a cipher in gcm mode for this operation");
    }
}

void CryptoHandler::expect_digest_mode_handler() const
{
    // Check if the digest_type is properly initialized
    if ( (m_digest == nullptr) || (m_digest_ctx == nullptr) ) {
        throw std::runtime_error("Cannot calculate digest, digest type not properly initialized.");
    }
}





