# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Changed
- Removed redundant calculate_digest signature. Kept only signature in active use, old function was not used
  and doesnot adhere to error propagation methodology applied for other functions
- Updated Readme.md with reference to ByteArray library
- Reorganize structure of readme

## [0.1.0-alpha.1] - 2025-05-26

### Added
- Initial implementation of CryptoHandler class with support for:
    - AES encryption in CBC and GCM modes
    - SHA-256 message digest functionality
    - HMAC generation with SHA-256
    - CBC-MAC authentication
    - GMAC authentication for GCM mode
- Comprehensive set of unit tests:
    - AES-CBC encryption/decryption with and without padding
    - AES-GCM authenticated encryption
    - SHA-256 digest calculation and truncation
    - HMAC-SHA256 verification against RFC 4231 test vectors
    - CBC-MAC and GMAC authentication
    - Error handling for mismatched modes and wrong keys
- New edge case tests for AES-GCM:
    - Behavior when tag is missing during decryption
    - Handling of tags smaller than required 16 bytes
    - Validation of empty tag buffers
    - Support for oversized tag buffers
- Proper error handling and reporting through std::expected
- Comprehensive validation of cryptographic parameters
- Support for legacy crypto algorithms through providers

### Security
- Secure memory handling with ByteArray class that wipes sensitive data
- Proper IV handling for CBC and GCM modes
- Complete tag validation for authenticated encryption
- Implementation follows cryptographic best practices
- OpenSSL-based cryptographic operations