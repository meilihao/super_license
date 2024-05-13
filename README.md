# super_license

## mcode
ref:
- [如何给软件添加License功能](https://www.duidaima.com/Group/Topic/ASP.NET/15393)
- [TrueLicense](https://github.com/JCXTB/TrueLicense)

## design
1. license的安全基础是数字签名
1. 使用rsa来加密license内容, 其实这里使用aes也是没问题的, 甚至不加密也行, 因为license client始终要解析license内容的.

    > 常用场景是公钥加密, 私钥解密. rsa支持反向操作的原因: RSA D/E 可互换. 其实就是openssl RSA_private_encrypt(The RSA_private_encrypt is deprecated in OpenSSL 3.x, 有人推荐用[EVP_PKEY_verify_recover](https://github.com/openssl/openssl/discussions/23733)代替).

## schema
见`pkg/license/licensev1.go`的`LicenseV1`和`AuthV1`