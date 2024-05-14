> English | [中文](README.md)

# super_license
super_license is an open source project used for security hardening, providing an authorized use method for software.

## mcode
ref:
- [How to add License function to software](https://www.duidaima.com/Group/Topic/ASP.NET/15393)
- [TrueLicense](https://github.com/JCXTB/TrueLicense)

## design
1. The security basis of license is digital signature
1. Use rsa to encrypt the license content. In fact, it is okay to use aes here, or even without encryption, because the license client always needs to parse the license content.

     > Common scenarios are public key for encryption and private key for decryption. The reason why rsa supports reverse operation: RSA D/E is interchangeable. In fact, it is openssl RSA_private_encrypt(The RSA_private_encrypt is deprecated in OpenSSL 3.x, some people recommend using [EVP_PKEY_verify_recover]( https://github.com/openssl/openssl/discussions/23733) instead).

## schema
See `LicenseV1` and `AuthV1` in `pkg/license/licensev1.go`

## example
See `pkg/license/licensev1_authv1.go` and `pkg/license/licensev1_demo.go`

## license
[Apache License 2.0](https://github.com/apache/.github/blob/main/LICENSE)