# CryptoHandler

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

<!-- TOC -->
* [CryptoHandler](#cryptohandler)
  * [⚠️ **SECURITY ADVISORIES**](#-security-advisories)
  * [Security Best Practices](#security-best-practices)
  * [Status: Work In Progress](#status-work-in-progress)
  * [Key Features](#key-features)
  * [Abstracted Cryptographic Operations](#abstracted-cryptographic-operations)
  * [Requirements](#requirements)
  * [Installation](#installation)
    * [Option 1: Build from source](#option-1-build-from-source)
    * [Option 2: Include via CMake FetchContent](#option-2-include-via-cmake-fetchcontent)
  * [Usage Examples](#usage-examples)
    * [Symmetric Encryption/Decryption](#symmetric-encryptiondecryption)
    * [Calculating Message Digests](#calculating-message-digests)
    * [HMAC Calculation](#hmac-calculation)
    * [CBC-MAC Calculation](#cbc-mac-calculation)
    * [GMAC Calculation](#gmac-calculation)
  * [Error Handling](#error-handling)
  * [Future Plans](#future-plans)
  * [Contributing](#contributing)
  * [License](#license)
<!-- TOC -->

## ⚠️ **SECURITY ADVISORIES**

> ⚠️ **IMPORTANT NOTICE**: This code is provided for educational purposes only.
> Cryptographic implementations require precise implementation details
> and must undergo thorough security audits before deployment in production environments.
> This library has not been formally audited. Use at your own risk.

> ⚠️ **SECURITY ADVISORY**: CBC mode encryption requires additional authentication mechanisms.
> Without proper authentication, CBC is vulnerable to padding oracle attacks and other cryptographic threats.
> For most applications, authenticated encryption modes such as GCM are strongly recommended.

> ⚠️ **MEMORY SECURITY NOTE**: This library does not automatically purge sensitive data from memory.
> While ByteArray provides a secure_erase method, we recommend using OpenSSL_cleanse()
> which has undergone extensive security review and provides more reliable and deterministic memory clearing.


## Security Best Practices

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

## Status: Work In Progress

CryptoHandler is a high-level C++23 library that provides a clean interface to OpenSSL cryptographic operations. It simplifies usage of common cryptographic primitives by abstracting away the complexities of OpenSSL's C-style API.

## Key Features

- **Modern C++ Abstractions**: Wraps OpenSSL's C-style buffer APIs with type-safe C++23 interfaces
- **Memory Safety**: Automatic resource management using RAII principles and smart pointers
- **Error Handling**: Uses `std::expected` for robust error reporting without exceptions
- **ByteArray Utility**: Simplified handling of binary data buffers that integrates seamlessly with OpenSSL
- **Reduced Boilerplate**: Eliminates repetitive error handling and buffer management code

## Abstracted Cryptographic Operations

- **Symmetric Encryption/Decryption**: Clean interface to cipher operations
- **Message Digests**: Simplified hashing with optional truncation
- **MAC Algorithms**: HMAC, CBC-MAC, and GMAC implementations
- **Legacy Support**: Transparent handling of legacy ciphers via OpenSSL providers


## Requirements

- C++23 compatible compiler
- OpenSSL (1.1.1 minimum - more recent versions recommended) (older openSSL implementations are vulnerable and insecure use a more recent version)
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
  GIT_TAG main  # or specify a tag/commit hash
)
FetchContent_MakeAvailable(crypto-handler)

# Link against the library in your target
target_link_libraries(your_target PRIVATE jlizard::crypto-handler)
```

## Usage Examples

### Symmetric Encryption/Decryption

```cpp
#include "jlizard/CryptoHandler.h"
#include "jlizard/byte_array.h"
#include <openssl/evp.h>
#include <iostream>

int main() {
    // Create a CryptoHandler for AES-256-CBC
    jlizard::CryptoHandler handler(EVP_aes_256_cbc());
    
    // Prepare data, key and IV as ByteArray objects (handles buffer management)
    jlizard::ByteArray plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    jlizard::ByteArray key(32, 0x42);  // 256-bit key
    jlizard::ByteArray iv(16, 0x24);   // 128-bit IV
    
    // Encrypt with std::expected error handling
    auto encrypted = handler.encrypt(plaintext, key, iv, true);
    if (!encrypted) {
        std::cerr << "Encryption failed: " << encrypted.error().what() << std::endl;
        return 1;
    }
    
    // Decrypt with std::expected error handling
    auto decrypted = handler.decrypt(encrypted.value(), key, iv, true);
    if (!decrypted) {
        std::cerr << "Decryption failed: " << decrypted.error().what() << std::endl;
        return 1;
    }
    
    // Use the decrypted value safely
    std::cout << "Decrypted: ";
    for (char c : decrypted.value()) {
        std::cout << c;
    }
    std::cout << std::endl;
    
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
        std::cerr << "Digest calculation failed: " << digest.error().what() << std::endl;
        return 1;
    }
    
    // Result is already in a managed buffer
    std::cout << "SHA-256: ";
    for (auto byte : digest.value()) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;
    
    // You can also calculate a truncated digest
    auto truncated = handler.calculate_digest_truncated(message, 128); // 128 bits
    if (!truncated) {
        std::cerr << "Truncated digest failed: " << truncated.error().what() << std::endl;
        return 1;
    }
    
    std::cout << "Truncated SHA-256 (128 bits): ";
    for (auto byte : truncated.value()) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;
    
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
    for (auto byte : hmac) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;
    
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
        std::cerr << "CBC-MAC calculation failed: " << mac.error().what() << std::endl;
        return 1;
    }
    
    // Display the result
    std::cout << "CBC-MAC: ";
    for (auto byte : mac.value()) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;
    
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
```
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
        std::cerr << "GMAC calculation failed: " << gmac.error().what() << std::endl;
        return 1;
    }
    
    // Display the result
    std::cout << "GMAC: ";
    for (auto byte : gmac.value()) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;
    
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

## Error Handling

CryptoHandler uses C++20's `std::expected` for most operations, providing clear error reporting:
```cpp
auto result = handler.encrypt(plaintext, key, iv, true);
if (!result) {
    // Handle error
    std::cerr << "Error: " << result.error().what() << std::endl;
} else {
    // Use result.value()
    auto encrypted_data = result.value();
}
``` 

## Future Plans

- Asymmetric cryptography support (RSA, ECDSA)
- Key derivation functions (PBKDF2, HKDF)
- Better documentation and examples
- Comprehensive test suite
- Performance optimizations
- CMake package configuration
- RAII cleansing of data

## Contributing

This project is currently in active development. 

## License

This project is licensed under the MIT License - see the license notice at the top of source files for details.
```
