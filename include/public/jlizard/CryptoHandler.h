/*
 * MIT License
 * 
 * Copyright (c) 2025 Salem B.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 */
#ifndef CRYPTO_ENG_CRYPTOHANDLER_H
#define CRYPTO_ENG_CRYPTOHANDLER_H

#include <expected>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <memory>
#include <vector>

namespace jlizard
{
    class ByteArray;
}
using namespace jlizard;

struct CryptoHandlerError {
    int err_code = -1;
    std::string err_message;

    static CryptoHandlerError with_msg(const std::string& err_msg) {return CryptoHandlerError{-1, err_msg};}
    static CryptoHandlerError with_code(const int err_code) {return  CryptoHandlerError{err_code,"Runtime Error"};}
};

class CryptoHandler{
public:
    explicit CryptoHandler(const EVP_CIPHER * cipher);
    explicit CryptoHandler(const EVP_MD * digest);
    ~CryptoHandler();
    CryptoHandler(const CryptoHandler&) = delete;
    CryptoHandler& operator=(const CryptoHandler&) = delete;


private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> m_cipher_ctx{nullptr, EVP_CIPHER_CTX_free};
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> m_digest_ctx{nullptr,EVP_MD_CTX_free};
    const EVP_CIPHER* m_cipher{nullptr}; //statically managed via openssl
    const EVP_MD* m_digest{nullptr};
    OSSL_PROVIDER* m_legacy_provider{nullptr};
    bool m_bIsLegacy{false};
private:
    /**
     * @deprecated this must be used as part of the std::expected design pattern
     * with error propagation
     */
    static void openssl_handle_errors(void) ;
    void expect_cipher_mode_handler() const;
    void expect_digest_mode_handler() const;
    int encrypt_(const unsigned char* plaintext,const int plaintext_len,
               const unsigned char *key, const unsigned char* iv,
               unsigned char* ciphertext_out,
               const bool bAllowPadding = true);
    int decrypt_(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
        const unsigned char *iv, unsigned char *plaintext_out,const bool bAllowPadding = true);


public:
    std::expected<ByteArray,CryptoHandlerError> encrypt(const ByteArray& plaintext_bytes, const ByteArray& key, const ByteArray& iv, const bool bAllowPadding);

    std::expected<ByteArray,CryptoHandlerError> decrypt(const ByteArray& ciphertext_bytes,
                                             const ByteArray& key,
                                             const ByteArray& iv,
                                             const bool bAllowPadding = true);
    std::expected<ByteArray, CryptoHandlerError> calculate_digest(const ByteArray& message);
    void calculate_digest(const std::vector<unsigned char>& message,
                         std::vector<unsigned char>& digest_output);
    std::expected<ByteArray, CryptoHandlerError> calculate_digest_truncated(
        const ByteArray& message, const size_t show_bits = 8);
    std::expected<ByteArray, CryptoHandlerError> calculate_cbc_mac(const ByteArray& plaintext_bytes,
                                                                   const ByteArray& key);
    ByteArray calculate_hmac(const ByteArray& message,
                             const ByteArray& key);
    std::expected<ByteArray, CryptoHandlerError> calculate_gmac(const ByteArray& aad_data, const ByteArray& key,
                                                                const ByteArray& iv);
};


#endif //CRYPTO_ENG_CRYPTOHANDLER_H
