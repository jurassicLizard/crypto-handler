# CryptoHandler

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

CryptoHandler is a modern C++23 library that simplifies cryptographic operations with a user-friendly interface. By abstracting away the complexities of OpenSSL's C-style API, it enables developers to quickly perform secure, high-level cryptographic operations with minimal boilerplate.

Designed with performance, safety, and code clarity in mind, this library is ideal for applications requiring robust cryptographic functionality without needing in-depth expertise in OpenSSL internals.


<!-- TOC -->
* [CryptoHandler](#cryptohandler)
  * [Overview](#overview)
  * [Key Features](#key-features)
  * [Requirements](#requirements)
  * [Installation](#installation)
    * [Option 1: Build from source](#option-1-build-from-source)
    * [Option 2: Include via CMake FetchContent](#option-2-include-via-cmake-fetchcontent)
  * [Usage Examples](#usage-examples)
    * [Symmetric Encryption/Decryption (General)](#symmetric-encryptiondecryption-general)
    * [Symmetric Encryption/Decryption (GCM)](#symmetric-encryptiondecryption-gcm)
    * [Calculating Message Digests](#calculating-message-digests)
    * [HMAC Calculation](#hmac-calculation)
    * [CBC-MAC Calculation](#cbc-mac-calculation)
    * [GMAC Calculation](#gmac-calculation)
  * [Security Considerations](#security-considerations)
    * [⚠️ **SECURITY ADVISORIES**](#-security-advisories)
    * [Security Best Practices](#security-best-practices)
  * [Advanced Usage](#advanced-usage)
    * [Tips on Padding Options](#tips-on-padding-options)
    * [Error Handling](#error-handling)
  * [Testing & Development](#testing--development)
    * [Prerequisites for Testing](#prerequisites-for-testing)
    * [Building and Running Tests](#building-and-running-tests)
    * [Test Coverage](#test-coverage)
  * [Project Information](#project-information)
    * [Future Plans](#future-plans)
    * [Changelog](#changelog)
    * [License](#license)
<!-- TOC -->


## Key Features

- **Modern C++ Abstractions**: Provides a high-level interface around OpenSSL's cryptographic operations using type-safe C++23 constructs, making it easier to use.
- **Memory Safety**: Leverages RAII principles and smart pointers for automatic resource management, reducing manual memory management risks.
- **Error Handling**: Implements `std::expected` for robust and exception-free error reporting.
- **Abstracted Cryptographic Operations**:
  - **Symmetric Encryption/Decryption**: Clean and simplified APIs for encrypting and decrypting with symmetric ciphers, including AES (CBC, GCM, CTR).
  - **Message Digests**: Easily calculate cryptographic hash values with optional truncation (e.g., SHA-256).
  - **MAC Algorithms**: Provides HMAC, CBC-MAC, and GMAC functionality for keyed message authentication.
  - **Legacy Cipher Support**: Offers transparent handling of legacy ciphers via OpenSSL provider configurations.
- **ByteArray Utility**: Includes seamless integration with the custom ByteArray library ([ByteArray Ops (byte-ao)](https://github.com/jurassiclizard/byte-ao)), allowing efficient manipulation of binary data (e.g., concatenations, secure memory wiping).
- **Reduced Boilerplate**: Minimizes repetitive error-handling code, resource cleanup, and buffer management by abstracting these complexities.

## Requirements

- C++23 compatible compiler
- OpenSSL (1.1.1 minimum - more recent versions recommended) (older openSSL implementations are vulnerable and insecure and are not recommended for use)
- CMake build system

## Installation
### Option 1: Build from source
``` bash
git clone https://github.com/jurassiclizard/crypto-handler.git
cd crypto-handler
mkdir build && cd build
cmake ..
make
```
### Option 2: Include via CMake FetchContent

Add CryptoHandler to your CMake project using FetchContent:

``` cmake
include(FetchContent)

FetchContent_Declare(
  crypto-handler
  GIT_REPOSITORY https://github.com/jurassiclizard/crypto-handler.git
  GIT_TAG master  # or specify a tag/commit hash
)
FetchContent_MakeAvailable(crypto-handler)

# Link against the library in your target
target_link_libraries(your_target PRIVATE jlizard::crypto-handler)
```

## Usage Examples

### Symmetric Encryption/Decryption (General)

```cpp
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>


int main() {
    // Create a CryptoHandler for AES-256-CBC
    jlizard::CryptoHandler handler(EVP_aes_256_cbc());
    
    // Prepare data, key and IV as ByteArray objects (handles buffer management)
    
     jlizard::ByteArray plaintext = ByteArray::create_from_string("Hello World!");
    
    // Alternatively use an initializer list () (same as create_from_string used above)
    // jlizard::ByteArray plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    // random bytes
    // jlizard::ByteArray plaintext = {0x7a, 0xbc, 0x1f, 0x3d, 0x82, 0xe5, 0x9c, 0x4b, 0xf3, 0x6d, 0xa2, 0x58};

    jlizard::ByteArray key(32, 0x42);  // 256-bit key
    jlizard::ByteArray iv(16, 0x24);   // 128-bit IV
    
    // Encrypt with std::expected error handling
    // both encrypt and decrypt return a value of type std::expected<ByteArray,CryptoHandlerError>
    auto encrypted = handler.encrypt(plaintext, key, iv, true);
    if (!encrypted) {
        std::cerr << "Encryption failed: " << encrypted.error().err_message << std::endl;
        return 1;
    }
    
    // Decrypt with std::expected error handling
    auto decrypted = handler.decrypt(encrypted.value(), key, iv, true);
    if (!decrypted) {
        std::cerr << "Decryption failed: " << decrypted.error().err_message << std::endl;
        return 1;
    }
    
    // Use the decrypted value safely
    std::cout << "Decrypted: ";
    std::cout << decrypted.value().as_hex_string() << std::endl;
    
    // Proper cleanup of sensitive data
    // Note: For maximum security, consider using OpenSSL_cleanse directly on the underlying buffer:
    // OpenSSL_cleanse(buffer.data(), buffer.size())
    plaintext.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    encrypted.value().secure_wipe();
    decrypted.value().secure_wipe();
    
    return 0;
}
``` 

### Symmetric Encryption/Decryption (GCM)

GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both confidentiality and integrity protection. Here's how to use it with CryptoHandler:

```cpp
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>

int main() {
    // Create a CryptoHandler for AES-256-GCM
    jlizard::CryptoHandler handler(EVP_aes_256_gcm());
    
    // Prepare data, key and IV
    jlizard::ByteArray plaintext = jlizard::ByteArray::create_from_string("Secret message");
    jlizard::ByteArray key(32, 0x42);  // 256-bit key
    jlizard::ByteArray iv(12, 0x24);   // 96-bit IV (recommended for GCM)
    
    // Optional authenticated data that won't be encrypted but will be authenticated
    jlizard::ByteArray aad = jlizard::ByteArray::create_from_string("Additional data");
    
    // This will store the authentication tag
    jlizard::ByteArray tag;
    
    // Encrypt with GCM (note: padding parameter is ignored in GCM mode)
    auto encrypted = handler.encrypt(plaintext, key, iv, tag, aad, false);
    // Or use simplified overload for GCM mode
    // auto encrypted = handler.encrypt(plaintext, key, iv, tag, aad);
    if (!encrypted) {
        std::cerr << "Encryption failed: " << encrypted.error().err_message << std::endl;
        return 1;
    }
    
    std::cout << "Encryption successful, tag size: " << tag.size() << " bytes\n";
    std::cout << "Tag: ";
    std::cout << tag.as_hex_string() << std::endl;

      
    // Decrypt with GCM, providing tag and AAD for authentication
    auto decrypted = handler.decrypt(encrypted.value(), key, iv, tag, aad, false);
    if (!decrypted) {
        std::cerr << "Decryption failed: " << decrypted.error().err_message << std::endl;
        return 1;
    }
    
    std::cout << "Decrypted message: ";
    std::cout << decrypted.value().as_hex_string() << std::endl;
    
    // Proper cleanup of sensitive data
    plaintext.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    aad.secure_wipe();
    tag.secure_wipe();
    encrypted.value().secure_wipe();
    decrypted.value().secure_wipe();
    
    return 0;
}
```



### Calculating Message Digests

```cpp 
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>

int main() {
    // Create a CryptoHandler for SHA-256
    jlizard::CryptoHandler handler(EVP_sha256());
    
    // ByteArray handles data buffer management
    jlizard::ByteArray message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    
    // Calculate digest with std::expected error handling
    auto digest = handler.calculate_digest(message);
    if (!digest) {
        std::cerr << "Digest calculation failed: " << digest.error().err_message << std::endl;
        return 1;
    }
    
    // Result is already in a managed buffer
    std::cout << "SHA-256: ";
    std::cout << digest.value().as_hex_string() << std::endl;
    
    // You can also calculate a truncated digest
    auto truncated = handler.calculate_digest_truncated(message, 128); // 128 bits
    if (!truncated) {
        std::cerr << "Truncated digest failed: " << truncated.error().err_message << std::endl;
        return 1;
    }
    
    std::cout << "Truncated SHA-256 (128 bits): ";
    std::cout << truncated.value().as_hex_string() << std::endl;
    
    // Proper cleanup of sensitive data
    // Note: For maximum security, consider using OpenSSL_cleanse directly on the underlying buffer:
    // OpenSSL_cleanse(buffer.data(), buffer.size())
    message.secure_wipe();
    digest.value().secure_wipe();
    truncated.value().secure_wipe();
    
    return 0;
}
``` 

### HMAC Calculation

```cpp
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>

int main() {
    // Create a CryptoHandler for SHA-256
    jlizard::CryptoHandler handler(EVP_sha256());
    
    // ByteArray manages buffers for message and key
    jlizard::ByteArray message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    jlizard::ByteArray key = {'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    
    // Calculate HMAC (returns ByteArray directly, not std::expected)
    jlizard::ByteArray hmac = handler.calculate_hmac(message, key);
    
    // Display the result
    std::cout << "HMAC-SHA256: ";
    std::cout << hmac.as_hex_string() << std::endl;
      
    
    // Proper cleanup of sensitive data
    // Note: For maximum security, consider using OpenSSL_cleanse directly on the underlying buffer:
    // OpenSSL_cleanse(buffer.data(), buffer.size())
    message.secure_wipe();
    key.secure_wipe();
    hmac.secure_wipe();
    
    return 0;
}
``` 

### CBC-MAC Calculation

```cpp
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>

int main() {
    // Create a CryptoHandler for AES-256-CBC
    jlizard::CryptoHandler handler(EVP_aes_256_cbc());
    
    // ByteArray handles buffer management
    jlizard::ByteArray message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    jlizard::ByteArray key(32, 0x42);  // 256-bit key
    
    // Calculate CBC-MAC with std::expected error handling
    auto mac = handler.calculate_cbc_mac(message, key);
    if (!mac) {
        std::cerr << "CBC-MAC calculation failed: " << mac.error().err_message << std::endl;
        return 1;
    }
    
    // Display the result
    std::cout << "CBC-MAC: ";
    std::cout << mac.value().as_hex_string() << std::endl;
    
    // Proper cleanup of sensitive data
    // Note: For maximum security, consider using OpenSSL_cleanse directly on the underlying buffer:
    // OpenSSL_cleanse(buffer.data(), buffer.size())
    message.secure_wipe();
    key.secure_wipe();
    mac.value().secure_wipe();
    
    return 0;
}
``` 

### GMAC Calculation

```cpp
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>

int main() {
    // Create a CryptoHandler for AES-256-GCM
    jlizard::CryptoHandler handler(EVP_aes_256_gcm());
    
    // ByteArray manages all data buffers
    jlizard::ByteArray aad = {'A', 'd', 'd', 'i', 't', 'i', 'o', 'n', 'a', 'l', ' ', 'D', 'a', 't', 'a'};
    jlizard::ByteArray key(32, 0x42);  // 256-bit key
    jlizard::ByteArray iv(12, 0x24);   // 96-bit IV (recommended for GCM)
    
    // Calculate GMAC with std::expected error handling
    auto gmac = handler.calculate_gmac(aad, key, iv);
    if (!gmac) {
        std::cerr << "GMAC calculation failed: " << gmac.error().err_message << std::endl;
        return 1;
    }
    
    // Display the result
    std::cout << "GMAC: ";
    std::cout << gmac.value().as_hex_string() << std::endl;
    
    // Proper cleanup of sensitive data
    // Note: For maximum security, consider using OpenSSL_cleanse directly on the underlying buffer:
    // OpenSSL_cleanse(buffer.data(), buffer.size())
    aad.secure_wipe();
    key.secure_wipe();
    iv.secure_wipe();
    gmac.value().secure_wipe();
    
    return 0;
}
``` 
## Security Considerations

### ⚠️ **SECURITY ADVISORIES**

> ⚠️ **IMPORTANT NOTICE**:
> Cryptographic implementations require precise implementation details
> and must undergo thorough security audits before deployment in production environments.
> This library has **NOT** yet been formally audited. Use at your own risk.

> ⚠️ **SECURITY ADVISORY**: CBC mode encryption requires additional authentication mechanisms.
> Without proper authentication, CBC is vulnerable to padding oracle attacks and other cryptographic threats.
> For most applications, authenticated encryption modes such as GCM are strongly recommended.

> ⚠️ **MEMORY SECURITY NOTE**: This library does not automatically purge sensitive data from memory.
> While ByteArray provides a secure_erase method, we recommend using OpenSSL_cleanse()
> which has undergone extensive security review and provides more reliable and deterministic memory clearing.



### Security Best Practices

When using this library, please consider the following security recommendations:

- **Key Management**:
  - Never use hardcoded or predictable keys/IVs in production
  - Generate cryptographically secure random values for keys, IVs, and nonces
  - Keep keys protected using proper key management techniques

- **Algorithm Selection**:
  - Always use authenticated encryption (like AES-GCM) for data protection
  - Prefer modern, well-reviewed cryptographic algorithms

- **Implementation Security**:
  - Securely erase sensitive data using OpenSSL_cleanse() after use
  - Update OpenSSL regularly to receive security patches
  - Enable compiler security flags when building your application
  - Consider timing attacks when implementing security-sensitive code

- **Verification**:
  - Test cryptographic operations with known test vectors
  - Verify authenticated encryption with tampered data to confirm detection

## Advanced Usage

### Tips on Padding Options

1. For GCM mode:
   The padding parameter is ignored since GCM operates on full blocks internally.
   all of these calls are equivalent for GCM:

    ```cpp
       handler.encrypt(plaintext, key,iv) // Padding enabled(but ignored)
       handler.encrypt(plaintext, key, iv, true); // Padding enabled (but ignored)
       handler.encrypt(plaintext, key, iv, false); // Padding disabled (but ignored)
    ```
2. For CBC mode:
- WITH padding (recommended for most use cases):
  Both of the these calls are equivalent for CBC
  ```cpp
  // Alternative 1 (padding enabled implicitly)
  handler.encrypt(plaintext, key,iv);
  // Alternative 2 (explicit enabling for more readability)
  handler.encrypt(plaintext, key, iv, true);
  ```
  This handles messages of any length automatically.

- WITHOUT padding (only for special cases):
  `handler.encrypt(plaintext, key, iv, false);`

  > NOTE : Only disable padding when your data is guaranteed to be a multiple of the block size
  > (16 bytes for AES). Otherwise, encryption will fail.


Choose the appropriate mode based on your security requirements:
- GCM: When you need authentication and integrity protection (recommended)
- CBC: For legacy systems, but always pair with a MAC for integrity protection
- CTR: very tricky to get right due to special care for nonce handling
- OFB: same as CTR should be avoided in favor of CBC or GCM


### Error Handling

CryptoHandler uses C++20's `std::expected` for most operations, providing clear error reporting:
```cpp
auto result = handler.encrypt(plaintext, key, iv, true);
if (!result) {
    // Handle error
    std::cerr << "Error: " << result.error().err_message << std::endl;
} else {
    // Use result.value()
    auto encrypted_data = result.value();
}
```

## Testing & Development

CryptoHandler includes a comprehensive test suite to verify functionality and correctness. The tests cover various cryptographic operations and error handling scenarios.

### Prerequisites for Testing

CTest from CMake is used for testing; therefore, no special configuration is required. The same [Requirements](#requirements) apply as those for the installation


### Building and Running Tests

```bash
# Clone the repository
git clone https://github.com/jurassiclizard/crypto-handler.git 
cd crypto-handler
# Create a build directory and build
mkdir build && cd build
# Configure with testing enabled
cmake .. -DBUILD_TESTING=ON
# Build the project and tests
make
# Run all tests
ctest
# Or run the test executable directly for more detailed output
./tests/crypto_handler_tests
``` 

### Test Coverage

The test suite includes:

- Encryption/decryption with various ciphers and modes
- Verification of authenticated encryption (GCM)
- Error cases such as:
  - Invalid keys and IVs
  - Data tampering detection
  - Incompatible algorithm parameters
- Message digest calculations
- MAC operations (HMAC, CBC-MAC, GMAC)
- Memory wiping functionality


## Project Information
### Future Plans

- Asymmetric cryptography support (RSA, ECDSA)
- Key derivation functions (PBKDF2, HKDF)
- Better documentation and examples
- Comprehensive test suite
- Performance optimizations
- CMake package configuration
- RAII cleansing of data

### Changelog
Changes between version increments are documented under [Changelog](CHANGELOG.md)

### License

This project is licensed under the MIT License - see the license notice at the top of source files for details.
```
