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

#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <cassert>
#include <string>
#include <iostream>
#include <iomanip>

using namespace jlizard;



// Test AES-CBC Encryption/Decryption
void test_aes_cbc_encryption() {
    CryptoHandler handler(EVP_aes_256_cbc());

    ByteArray plaintext = {'T', 'e', 's', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    ByteArray key(32, 0x42); // 256-bit key filled with 0x42
    ByteArray iv(16, 0x24);  // 128-bit IV filled with 0x24

    auto encrypted = handler.encrypt(plaintext, key, iv, true);
    assert(encrypted.has_value());

    auto decrypted = handler.decrypt(encrypted.value(), key, iv, true);
    assert(decrypted.has_value());
    assert(plaintext == decrypted.value());

    // Proper cleanup
    plaintext.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    encrypted.value().secure_wipe();
    decrypted.value().secure_wipe();

    std::cout << "AES-CBC encryption/decryption test passed" << std::endl;
}

// Test AES-CBC Encryption without padding
void test_aes_cbc_encryption_no_padding() {
    CryptoHandler handler(EVP_aes_256_cbc());

    // Block-aligned data (16 bytes for AES)
    ByteArray plaintext(16, 'A');
    ByteArray key(32, 0x42);
    ByteArray iv(16, 0x24);

    auto encrypted = handler.encrypt(plaintext, key, iv, false); // No padding
    assert(encrypted.has_value());

    auto decrypted = handler.decrypt(encrypted.value(), key, iv, false);
    assert(decrypted.has_value());
    assert(plaintext == decrypted.value());

    // Proper cleanup
    plaintext.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    encrypted.value().secure_wipe();
    decrypted.value().secure_wipe();

    std::cout << "AES-CBC encryption/decryption without padding test passed" << std::endl;
}

// Test encryption/decryption with wrong key
void test_aes_cbc_wrong_key() {
    CryptoHandler handler(EVP_aes_256_cbc());

    ByteArray plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'D', 'a', 't', 'a'};
    ByteArray correct_key(32, 0x42);
    ByteArray wrong_key(32, 0x43); // Different key
    ByteArray iv(16, 0x24);

    auto encrypted = handler.encrypt(plaintext, correct_key, iv, true);
    assert(encrypted.has_value());
    std::expected<ByteArray,CryptoHandlerError> decrypted;
    bool exception_thrown = false;
    try
    {
        decrypted = handler.decrypt(encrypted.value(), wrong_key, iv, true);

    } catch (std::exception&)
    {
        exception_thrown = true;
    }

    assert(exception_thrown);

    // Proper cleanup
    plaintext.secure_wipe();
    correct_key.secure_wipe();
    wrong_key.secure_wipe();
    iv.secure_wipe();
    encrypted.value().secure_wipe();
    if (decrypted.has_value()) decrypted.value().secure_wipe();

    std::cout << "AES-CBC wrong key test passed" << std::endl;
}

// Test SHA-256 digest with known value
void test_sha256_digest() {
    CryptoHandler handler(EVP_sha256());

    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    ByteArray message = {'a', 'b', 'c'};
    std::string expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    ByteArray expected(expected_hex);

    auto digest = handler.calculate_digest(message);
    assert(digest.has_value());
    assert(expected == digest.value());

    // Cleanup
    message.secure_wipe();
    expected.secure_wipe();
    digest.value().secure_wipe();

    std::cout << "SHA-256 digest test passed" << std::endl;
}

// Test truncated digest
void test_sha256_digest_truncated() {
    CryptoHandler handler(EVP_sha256());

    ByteArray message = {'a', 'b', 'c'};

    // Truncate to 128 bits (16 bytes)
    auto truncated = handler.calculate_digest_truncated(message, 128);
    assert(truncated.has_value());
    assert(truncated.value().size() == 16);

    // Cleanup
    message.secure_wipe();
    truncated.value().secure_wipe();

    std::cout << "SHA-256 truncated digest test passed" << std::endl;
}

// Test truncation with requested size too large
void test_digest_truncation_too_large() {
    CryptoHandler handler(EVP_sha256());

    ByteArray message = {'t', 'e', 's', 't'};

    // SHA-256 is 256 bits, try to get 512 bits
    auto truncated = handler.calculate_digest_truncated(message, 512);

    // Should fail
    assert(!truncated.has_value());

    // Cleanup
    message.secure_wipe();

    std::cout << "Digest truncation too large test passed" << std::endl;
}

// Test HMAC-SHA256
void test_hmac_sha256() {
    CryptoHandler handler(EVP_sha256());

    // HMAC test vector
    ByteArray key = {};  // Empty key
    ByteArray message = {};  // Empty message
    std::string expected_hex = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
    ByteArray expected(expected_hex);

    ByteArray hmac = handler.calculate_hmac(message, key);
    assert(hmac.size() == 32); // SHA-256 produces 32 bytes
    assert(hmac == expected);

    // Cleanup
    message.secure_wipe();
    key.secure_wipe();
    hmac.secure_wipe();
    expected.secure_wipe();

    std::cout << "HMAC-SHA256 test passed" << std::endl;
}

// Test CBC-MAC
void test_cbc_mac() {
    CryptoHandler handler(EVP_aes_256_cbc());

    ByteArray message(32, 'A'); // 32 bytes of 'A'
    ByteArray key(32, 0x42);    // 256-bit key

    auto mac = handler.calculate_cbc_mac(message, key);
    assert(mac.has_value());
    assert(mac.value().size() == 16); // AES block size is 16 bytes

    // Cleanup
    message.secure_wipe();
    key.secure_wipe();
    mac.value().secure_wipe();

    std::cout << "CBC-MAC test passed" << std::endl;
}

// Test GMAC
void test_gmac() {
    CryptoHandler handler(EVP_aes_256_gcm());

    ByteArray aad = {'A', 'd', 'd', 'i', 't', 'i', 'o', 'n', 'a', 'l', ' ', 'D', 'a', 't', 'a'};
    ByteArray key(32, 0x42); // 256-bit key
    ByteArray iv(12, 0x24);  // 96-bit IV (recommended for GCM)

    auto gmac = handler.calculate_gmac(aad, key, iv);
    assert(gmac.has_value());
    assert(gmac.value().size() == 16); // GCM tag size is 16 bytes

    // Cleanup
    aad.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    gmac.value().secure_wipe();

    std::cout << "GMAC test passed" << std::endl;
}

// Test using GMAC with wrong cipher mode
void test_wrong_cipher_mode() {
    CryptoHandler handler(EVP_aes_256_cbc());

    ByteArray aad = {'D', 'a', 't', 'a'};
    ByteArray key(32, 0x42);
    ByteArray iv(16, 0x24);

    auto gmac = handler.calculate_gmac(aad, key, iv);
    assert(!gmac.has_value()); // Should fail because CBC is not GCM

    // Cleanup
    aad.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();

    std::cout << "Wrong cipher mode test passed" << std::endl;
}

// Test mode mismatch exception
void test_mode_mismatch() {
    bool exception_caught = false;

    try {
        CryptoHandler handler(EVP_aes_256_cbc());
        ByteArray message = {'t', 'e', 's', 't'};

        // This should throw - using cipher handler for digest
        auto h = handler.calculate_digest(message);

        message.secure_wipe();
    }
    catch (const std::exception&) {
        exception_caught = true;
    }

    assert(exception_caught);

    std::cout << "Mode mismatch exception test passed" << std::endl;
}

// Test HMAC against RFC 4231 Test Case 1
void test_hmac_rfc4231_tc1() {
    CryptoHandler handler(EVP_sha256());

    // Test Case 1 from RFC 4231
    ByteArray key("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    ByteArray message("4869205468657265"); // "Hi There"
    std::string expected_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    ByteArray expected(expected_hex);

    ByteArray hmac = handler.calculate_hmac(message, key);
    assert(hmac == expected);

    // Cleanup
    key.secure_wipe();
    message.secure_wipe();
    expected.secure_wipe();
    hmac.secure_wipe();

    std::cout << "HMAC RFC 4231 Test Case 1 passed" << std::endl;
}

// Test encrypt/decrypt with AES-GCM
void test_aes_gcm() {
    //FIXME gcm encryption is wrong
    CryptoHandler handler(EVP_aes_256_gcm());

    ByteArray plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    ByteArray key(32, 0x42);
    ByteArray iv(12, 0x24); // 96-bit IV for GCM

    // AAD using a realistic example of protocol metadata
    std::optional<const ByteArray> aad = ByteArray{
        0x01, 0x02, // Protocol version (1.2)
        0x00, 0x00, 0x00, 0x01, // Message ID
        0x00, 0x05, // Sender ID length
        'A', 'l', 'i', 'c', 'e', // Sender ID "Alice"
        0x00, 0x03, // Content type length
        'M', 'S', 'G' // Content type "MSG"
    };


    std::optional<ByteArray> tag_out = ByteArray(16,0x00);
    auto encrypted = handler.encrypt(plaintext, key, iv,tag_out,aad);
    assert(encrypted.has_value());

    if (!tag_out.has_value())
    {
        throw std::runtime_error("Expected to get a tag from gcm encryption but got none");
    }
    std::optional<const ByteArray> tag = tag_out;
    auto decrypted = handler.decrypt(encrypted.value(), key, iv,tag,aad);
    assert(decrypted.has_value());
    assert(plaintext == decrypted.value());

    // Cleanup
    plaintext.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    encrypted.value().secure_wipe();
    decrypted.value().secure_wipe();

    std::cout << "AES-GCM encryption/decryption test passed" << std::endl;
}


void test_aes_gcm_missing_tag() {
    CryptoHandler handler(EVP_aes_256_gcm());

    ByteArray plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    ByteArray key(32, 0x42);
    ByteArray iv(12, 0x24); // 96-bit IV for GCM

    // Encrypt with tag
    std::optional<ByteArray> tag_out = ByteArray(16, 0x00);
    auto no_aad = std::optional<const ByteArray>(std::nullopt);
    auto encrypted = handler.encrypt(plaintext, key, iv, tag_out, no_aad);
    assert(encrypted.has_value());
    assert(tag_out.has_value());

    // Try to decrypt without providing the tag
    std::optional<const ByteArray> no_tag = std::nullopt;
    auto decrypted = handler.decrypt(encrypted.value(), key, iv, no_tag, no_aad);

    // Should fail with an error
    assert(!decrypted.has_value());
    // Verify the error message mentions the tag requirement
    assert(decrypted.error().err_message.find("Tag is required") != std::string::npos);

    std::cout << "AES-GCM missing tag test passed" << std::endl;
}

void test_aes_gcm_small_tag() {
    CryptoHandler handler(EVP_aes_256_gcm());

    ByteArray plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    ByteArray key(32, 0x42);
    ByteArray iv(12, 0x24); // 96-bit IV for GCM

    // Encrypt with proper tag size
    std::optional<ByteArray> tag_out = ByteArray(16, 0x00);
    auto no_aad = std::optional<const ByteArray>(std::nullopt);
    auto encrypted = handler.encrypt(plaintext, key, iv, tag_out, no_aad);
    assert(encrypted.has_value());
    assert(tag_out.has_value());

    // Create a small tag (only 8 bytes) by copying part of the original tag
    ByteArray small_tag(tag_out->begin(), tag_out->begin() + 8);
    std::optional<const ByteArray> small_tag_opt = small_tag;

    // Try to decrypt with the small tag
    auto decrypted = handler.decrypt(encrypted.value(), key, iv, small_tag_opt, no_aad);

    // Should fail with an error about tag size
    assert(!decrypted.has_value());
    assert(decrypted.error().err_message.find("Tag too small") != std::string::npos);

    std::cout << "AES-GCM small tag test passed" << std::endl;
}

void test_aes_gcm_empty_tag_buffer() {
    CryptoHandler handler(EVP_aes_256_gcm());

    ByteArray plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    ByteArray key(32, 0x42);
    ByteArray iv(12, 0x24); // 96-bit IV for GCM

    // Try to encrypt with an empty tag buffer
    std::optional<ByteArray> empty_tag = ByteArray();
    auto no_aad = std::optional<const ByteArray>(std::nullopt);
    auto encrypted = handler.encrypt(plaintext, key, iv, empty_tag, no_aad);

    // Should fail with an error about tag size
    assert(!encrypted.has_value());
    assert(encrypted.error().err_message.find("Tag buffer too small") != std::string::npos);

    std::cout << "AES-GCM empty tag buffer test passed" << std::endl;
}

void test_aes_gcm_large_tag_buffer() {
    CryptoHandler handler(EVP_aes_256_gcm());

    ByteArray plaintext = {'S', 'e', 'c', 'r', 'e', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    ByteArray key(32, 0x42);
    ByteArray iv(12, 0x24); // 96-bit IV for GCM

    // Encrypt with a larger than needed tag buffer (24 bytes)
    std::optional<ByteArray> large_tag = ByteArray(24, 0x00);
    auto no_aad = std::optional<const ByteArray>(std::nullopt);
    auto encrypted = handler.encrypt(plaintext, key, iv, large_tag, no_aad);

    // Should work fine, with the tag being 16 bytes
    assert(encrypted.has_value());
    assert(large_tag.has_value());
    // The tag buffer should still be 24 bytes, but only the first 16 are meaningful
    assert(large_tag->size() == 24);

    // Now try to decrypt with this tag
    std::optional<const ByteArray> tag_for_decrypt = *large_tag;
    auto decrypted = handler.decrypt(encrypted.value(), key, iv, tag_for_decrypt, no_aad);

    // Should work, but might require fixing the implementation to handle larger tag buffers
    assert(decrypted.has_value());
    assert(plaintext == decrypted.value());

    std::cout << "AES-GCM large tag buffer test passed" << std::endl;
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Run the tests
    test_aes_cbc_encryption();
    test_aes_cbc_encryption_no_padding();
    test_aes_cbc_wrong_key();
    test_sha256_digest();
    test_sha256_digest_truncated();
    test_digest_truncation_too_large();
    test_hmac_sha256();
    test_hmac_rfc4231_tc1();
    test_cbc_mac();
    test_gmac();
    test_wrong_cipher_mode();
    test_mode_mismatch();
    test_aes_gcm();

    // Clean up OpenSSL
    EVP_cleanup();

    std::cout << "All tests passed!" << std::endl;
    return 0;
}