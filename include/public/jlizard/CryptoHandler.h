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
#ifndef CRYPTO_ENG_CRYPTOHANDLER_H
#define CRYPTO_ENG_CRYPTOHANDLER_H

#include <expected>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <memory>
#include <vector>

namespace jlizard
{
    class ByteArray;
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
        CryptoHandler(CryptoHandler&&) = delete;
        CryptoHandler& operator=(CryptoHandler&&) = delete;


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
        void expect_cipher_in_gcm_mode() const;

        int encrypt_(const unsigned char* plaintext,const int plaintext_len,
                   const unsigned char *key, const unsigned char* iv,
                   unsigned char* ciphertext_out,
                   const bool bAllowPadding = true,
                   const unsigned char *aad = nullptr, const int aad_len = 0,
                    unsigned char *tag_out = nullptr, const int tag_len = 0);

        int decrypt_(const unsigned char *ciphertext, const int ciphertext_len,
                               const unsigned char *key, const unsigned char *iv,
                               unsigned char *plaintext_out, const bool bAllowPadding,
                               const unsigned char *aad = nullptr, const int aad_len = 0,
                               const unsigned char *tag = nullptr, const int tag_len = 0);


    public:
        /**
         * @brief Encrypts data using the configured cipher
         *
         * Encrypts the provided plaintext using the configured cipher with the specified key and IV.
         * Supports both standard block cipher modes (CBC, CTR, etc.) and authenticated encryption
         * modes (GCM).
         *
         * @param plaintext_bytes The data to be encrypted
         * @param key The encryption key (must match the expected key length for the cipher)
         * @param iv The initialization vector (must match the expected IV length for the cipher)
         * @param tag_out Output parameter that will receive the authentication tag when using GCM mode.
         *                Must be pre-allocated with sufficient size (16 bytes recommended).
         *                Ignored in non-GCM modes
         * @param aad Additional Authenticated Data for GCM mode. This data is authenticated but
         *            not encrypted. Ignored in non-GCM modes
         * @param bAllowPadding If true, applies padding according to the cipher's default scheme.
         *                      If false, plaintext must be a multiple of the block size
         *                      (except for stream ciphers and GCM mode)
         *
         * @return On success, returns the encrypted data as a ByteArray.
         *         On failure, returns a CryptoHandlerError with an error message
         *
         * @note In GCM mode, both the tag_out and the returned ciphertext are required for decryption
         * @note Tag size of 16 bytes (128 bits) is recommended for GCM mode
         * @note IV size should be 12 bytes (96 bits) for GCM mode for optimal security and performance
         */
        std::expected<ByteArray, CryptoHandlerError> encrypt(
            const ByteArray& plaintext_bytes,
            const ByteArray& key,
            const ByteArray& iv,
            ByteArray& tag_out,
            const ByteArray& aad,
            bool bAllowPadding = true);
        /**
         * @brief Simplified version of encrypt that doesn't return authentication tags.
         *
         * @details This is a convenience overload that calls the full version while ignoring
         * values for tag_out and aad parameters. Use this version when you don't need
         * authenticated encryption features (non-GCM modes).
         *
         * @param plaintext_bytes The data to be encrypted
         * @param key The encryption key
         * @param iv The initialization vector
         * @param bAllowPadding Whether padding should be applied (defaults to true)
         * @return std::expected<ByteArray, CryptoHandlerError> The encrypted data or an error
         *
         * @see encrypt(const ByteArray&, const ByteArray&, const ByteArray&, bool, std::optional<ByteArray>&, std::optional<const ByteArray>&)
         */
        std::expected<ByteArray, CryptoHandlerError> encrypt(
        const ByteArray& plaintext_bytes,
        const ByteArray& key,
        const ByteArray& iv,
        const bool bAllowPadding = true);

            /**
         * @brief Simplified version of encrypt that only returns authentication tags but
         * doesn't make use of the aad data.
         *
         * @details This is a convenience overload that calls the full version while ignoring
         * values for aad parameters. Use this version when intending to use authenticated encryption
         * modes (GCM), authentication tags are output to tag_out
         *
         * @param plaintext_bytes The data to be encrypted
         * @param key The encryption key
         * @param iv The initialization vector
         * @param tag_out Output parameter that will receive the authentication tag when using GCM mode.
         *                Must be pre-allocated with sufficient size (16 bytes recommended).
         *                Ignored in non-GCM modes
         * @param bAllowPadding Whether padding should be applied (defaults to true)
         * @return std::expected<ByteArray, CryptoHandlerError> The encrypted data or an error
         *
         * @see encrypt(const ByteArray&, const ByteArray&, const ByteArray&, bool, std::optional<ByteArray>&, std::optional<const ByteArray>&)
         */
        std::expected<ByteArray, CryptoHandlerError> encrypt(const ByteArray& plaintext_bytes,
            const ByteArray& key,
            const ByteArray& iv,
            ByteArray& tag_out,
            const bool bAllowPadding = false);
         /**
         * @brief Decrypts data using the configured cipher
         *
         * Decrypts the provided ciphertext using the configured cipher with the specified key and IV.
         * Supports both standard block cipher modes (CBC, CTR, etc.) and authenticated encryption
         * modes (GCM).
         *
         * @param ciphertext_bytes The encrypted data to be decrypted
         * @param key The decryption key (must match the expected key length for the cipher)
         * @param iv The initialization vector (must match the expected IV length for the cipher)
         * @param tag The authentication tag when using GCM mode. Required for successful
         *            authenticated decryption in GCM mode. Ignored in non-GCM modes
         * @param aad Additional Authenticated Data for GCM mode. This must match the AAD used
         *            during encryption. Ignored in non-GCM modes
         * @param bAllowPadding If true, removes padding according to the cipher's default scheme.
         *                      If false, expects the plaintext to have no padding
         *                      (except for stream ciphers and GCM mode)
         *
         * @return On success, returns the decrypted plaintext as a ByteArray.
         *         On failure, returns a CryptoHandlerError with an error message
         *
         * @note In GCM mode, authentication failure will result in an error
         * @note For GCM mode, the tag size should be 16 bytes (128 bits) for maximum security
         * @note IV size should be 12 bytes (96 bits) for GCM mode for optimal security and performance
         * @note If authentication fails in GCM mode, the plaintext is not returned regardless of any
         *       partial decryption that may have occurred
         */
        std::expected<ByteArray, CryptoHandlerError> decrypt(
            const ByteArray& ciphertext_bytes,
            const ByteArray& key,
            const ByteArray& iv,
            const ByteArray& tag,
            const ByteArray& aad,
            bool bAllowPadding = true
        );
        /**
         * @brief Simplified version of decrypt that doesn't use authentication tags or AAD
         *
         * @details This is a convenience overload that calls the full version while omitting
         * tag and aad parameters. Use this version for non-authenticated encryption modes
         * (non-GCM modes) where authentication tags and AAD are not needed.
         *
         * @param ciphertext_bytes The encrypted data to be decrypted
         * @param key The decryption key (must match the expected key length for the cipher)
         * @param iv The initialization vector (must match the expected IV length for the cipher)
         * @param bAllowPadding If true, removes padding according to the cipher's default scheme.
         *                      If false, expects the plaintext to have no padding
         *                      (except for stream ciphers)
         *
         * @return On success, returns the decrypted plaintext as a ByteArray.
         *         On failure, returns a CryptoHandlerError with an error message
         *
         * @see decrypt(const ByteArray&, const ByteArray&, const ByteArray&, const ByteArray&, const ByteArray&, bool)
         */
        std::expected<ByteArray, CryptoHandlerError> decrypt(
            const ByteArray& ciphertext_bytes,
            const ByteArray& key,
            const ByteArray& iv,
            bool bAllowPadding = true);

        /**
         * @brief Simplified version of decrypt that uses authentication tags but no AAD
         *
         * @details This is a convenience overload that calls the full version while omitting
         * the aad parameter. Use this version for authenticated encryption modes (GCM)
         * where you need to verify authentication tags but don't have additional authenticated data.
         *
         * @param ciphertext_bytes The encrypted data to be decrypted
         * @param key The decryption key (must match the expected key length for the cipher)
         * @param iv The initialization vector (must match the expected IV length for the cipher)
         * @param tag The authentication tag when using GCM mode. Required for successful
         *            authenticated decryption in GCM mode. Ignored in non-GCM modes
         * @param bAllowPadding If true, removes padding according to the cipher's default scheme.
         *                      If false, expects the plaintext to have no padding
         *                      (except for stream ciphers and GCM mode where this boolean is effectively false
         *                      and has no effect)
         *
         * @return On success, returns the decrypted plaintext as a ByteArray.
         *         On failure, returns a CryptoHandlerError with an error message
         *
         * @note In GCM mode, authentication failure will result in an error
         * @see decrypt(const ByteArray&, const ByteArray&, const ByteArray&, const ByteArray&, const ByteArray&, bool)
         */
        std::expected<ByteArray, CryptoHandlerError> decrypt(
            const ByteArray& ciphertext_bytes,
            const ByteArray& key,
            const ByteArray& iv,
            const ByteArray& tag,
            bool bAllowPadding = true);

        std::expected<ByteArray, CryptoHandlerError> calculate_digest(const ByteArray& message);
        std::expected<ByteArray, CryptoHandlerError> calculate_digest_truncated(
            const ByteArray& message, const size_t show_bits = 8);
        std::expected<ByteArray, CryptoHandlerError> calculate_cbc_mac(const ByteArray& plaintext_bytes,
                                                                       const ByteArray& key);
        ByteArray calculate_hmac(const ByteArray& message,
                                 const ByteArray& key);
        std::expected<ByteArray, CryptoHandlerError> calculate_gmac(const ByteArray& aad_data, const ByteArray& key,
                                                                    const ByteArray& iv);
    };
}




#endif //CRYPTO_ENG_CRYPTOHANDLER_H
