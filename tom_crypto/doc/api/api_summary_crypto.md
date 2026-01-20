# TomBase API Reference: Crypto Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Classes](#classes)
  - [TomJwtTokenException](#tomjwttokenexception)
  - [TomJwtConfiguration](#tomjwtconfiguration)
  - [TomServerJwtToken](#tomserverjwttoken)
  - [TomClientJwtToken](#tomclientjwttoken)
  - [TomPasswordHasher](#tompasswordhasher)
  - [RsaKeyHelper](#rsakeyhelper)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The Crypto module provides cryptographic utilities including JWT token generation and verification, password hashing with PBKDF2, and RSA key management for encryption and signing.

---

## Class Hierarchy

```
Object
├── TomException
│   └── TomJwtTokenException
├── TomJwtConfiguration
├── TomServerJwtToken
├── TomClientJwtToken
├── TomPasswordHasher
└── RsaKeyHelper
```

---

## Classes

### TomJwtTokenException

Exception thrown when JWT token operations fail.

**Extends:** `TomException`

#### Constructors

```dart
TomJwtTokenException(
  String key,
  String defaultUserMessage, {
  Map<String, Object?>? parameters,
  Object? stack,
  Object? rootException,
  bool autoLog = false,
  String? uuid,
  TomServerCallError? serverCallError,
})
```

---

### TomJwtConfiguration

Configuration for JWT token signing and encryption.

**Extends:** `Object`

#### Constructors

```dart
TomJwtConfiguration(
  JWTKey key,
  JWTAlgorithm algorithm,
  RSAPrivateKey rsaPrivateKey,
  RSAPublicKey rsaPublicKey, [
  bool isDummy = true,
])
```

#### Static Properties

| Property | Type | Description |
|----------|------|-------------|
| `hmacKey` | `SecretKey` | HMAC secret key for HS algorithms |
| `rsaPrivKey` | `RSAPrivateKey` | RSA private key for RS algorithms |
| `rsaPubKey` | `RSAPublicKey` | RSA public key for encryption |
| `defaultSignConfiguration` | `TomJwtConfiguration` | Default signing configuration |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `rsaPrivateKey` | `RSAPrivateKey` | RSA private key for decryption |
| `rsaPublicKey` | `RSAPublicKey` | RSA public key for encryption |
| `isDummy` | `bool` | Whether this is a development configuration |
| `key` | `JWTKey` | Secret key for HMAC signing |
| `algorithm` | `JWTAlgorithm` | Signing algorithm |

#### Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `encrypt(String s)` | `String` | Encrypts a string using RSA |
| `decrypt(String s)` | `String` | Decrypts a string using RSA |

---

### TomServerJwtToken

Server-side JWT token generator.

**Extends:** `Object`

#### Constructors

```dart
TomServerJwtToken(
  Map<String, Object?> publicData, {
  Map<String, Object?> encryptedData = const {},
  Duration expiresIn = const Duration(hours: 24),
  Duration notBefore = Duration.zero,
  bool noIssueAt = false,
  TomJwtConfiguration? signingConfiguration,
})
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `signingConfiguration` | `TomJwtConfiguration` | Configuration for signing |
| `publicData` | `Map<String, Object?>` | Public payload data |
| `encryptedData` | `Map<String, Object?>` | Encrypted payload data |
| `expiresIn` | `Duration` | Token expiration duration |
| `notBefore` | `Duration` | Token validity start delay |
| `noIssueAt` | `bool` | Whether to omit issue timestamp |

#### Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `getJWT(String issuer)` | `String` | Generates the JWT string |

---

### TomClientJwtToken

Client-side JWT token parser.

**Extends:** `Object`

#### Constructors

```dart
TomClientJwtToken(
  String tokenString, {
  bool decrypt = true,
  TomJwtConfiguration? signingConfiguration,
})
```

#### Static Properties

| Property | Type | Description |
|----------|------|-------------|
| `globalSettingShowContentInToString` | `bool?` | Whether to show content in toString |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `decrypt` | `bool` | Whether to decrypt secret data |
| `signingConfiguration` | `TomJwtConfiguration` | Configuration for verification |
| `token` | `JWT` | Parsed JWT object |
| `tokenString` | `String` | Original token string |
| `secretData` | `Map<String, dynamic>?` | Decrypted secret payload |
| `issuer` | `String?` | Token issuer |
| `subject` | `String?` | Token subject |
| `jwtId` | `String?` | JWT ID |
| `audience` | `Audience?` | Token audience |
| `payload` | `Map<String, dynamic>?` | Public payload data |

---

### TomPasswordHasher

Password hashing utilities using PBKDF2.

**Extends:** `Object`

#### Static Properties

| Property | Type | Description |
|----------|------|-------------|
| `globalSettingDefaultSaltLength` | `int?` | Default salt length |
| `globalSettingDefaultHashSpec` | `String?` | Default hash specification |

#### Static Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `verifyPassword(String password, String dbHash, String dbHashSpec)` | `bool` | Verifies a password against stored hash |
| `hashPassword(String password)` | `(String, String)` | Hashes a password, returns (hash, spec) |
| `generateSalt(int length)` | `String` | Generates a random salt |
| `buildKeyDerivator([String? specs, String? salt])` | `KeyDerivator` | Builds a key derivator |
| `toHexString(Uint8List list)` | `String` | Converts bytes to hex string |
| `toUint8List(String hexString)` | `Uint8List` | Converts hex string to bytes |

---

### RsaKeyHelper

Helper class for RSA key generation, parsing, and encoding.

**Extends:** `Object`

#### Static Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `computeRSAKeyPair(SecureRandom secureRandom)` | `Future<AsymmetricKeyPair<PublicKey, PrivateKey>>` | Generates an RSA key pair |
| `getSecureRandom()` | `SecureRandom` | Creates a secure random generator |
| `parsePublicKeyFromPem(String pemString)` | `RSAPublicKey` | Parses public key from PEM |
| `parsePrivateKeyFromPem(String pemString)` | `RSAPrivateKey` | Parses private key from PEM |
| `sign(String plainText, RSAPrivateKey privateKey)` | `String` | Signs text with private key |
| `rsaEncrypt(RSAPublicKey myPublic, Uint8List dataToEncrypt)` | `Uint8List` | Encrypts data with public key |
| `rsaDecrypt(RSAPrivateKey myPrivate, Uint8List cipherText)` | `Uint8List` | Decrypts data with private key |
| `createUint8ListFromString(String s)` | `Uint8List` | Converts string to bytes |
| `decodePEM(String pem)` | `List<int>` | Decodes PEM to bytes |
| `removePemHeaderAndFooter(String pem)` | `String` | Removes PEM headers/footers |
| `encodePrivateKeyToPemPKCS1(RSAPrivateKey privateKey)` | `String` | Encodes private key to PEM |
| `encodePublicKeyToPemPKCS1(RSAPublicKey publicKey)` | `String` | Encodes public key to PEM |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
|----------|------|-------------|
| `tomRsaHashIdentifier` | `String?` | RSA hash identifier |

### Functions

| Function | Return Type | Description |
|----------|-------------|-------------|
| `rsaEncrypt(RSAPublicKey myPublic, Uint8List dataToEncrypt)` | `Uint8List` | Encrypts data using RSA |
| `rsaDecrypt(RSAPrivateKey myPrivate, Uint8List cipherText)` | `Uint8List` | Decrypts data using RSA |
| `rsaSign(RSAPrivateKey privateKey, Uint8List dataToSign)` | `Uint8List` | Signs data with RSA |
| `rsaVerify(RSAPublicKey publicKey, Uint8List signedData, Uint8List signature)` | `bool` | Verifies RSA signature |
| `getRsaKeyPair(SecureRandom secureRandom)` | `AsymmetricKeyPair<PublicKey, PrivateKey>` | Generates RSA key pair |
