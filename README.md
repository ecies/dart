Elliptic Curve Integrated Encryption Scheme for secp256k1 in Dart.

This is the Dart version of [eciespy](https://github.com/ecies/py)

## Usage
Encrypt a message

```dart
import 'package:eciesdart/eciesdart.dart';

final keyPair = Ecies.generateEcKeyPairBytes();
final message = "Welcome to ECIES";
var messageBytes = utf8.encode(message);
final cipherText = Ecies.encrypt(keyPair.publicKey, messageBytes);

final decryptedBytes = Ecies.decrypt(keyPair.privateKey, cipherText);
final decryptedMessage = utf8.decode(decryptedBytes);

print(decryptedMessage);
```

Encrypt using an [AsymmetricKeyPair<ECPublicKey, ECPrivateKey>]

```dart
import 'package:eciesdart/eciesdart.dart';

final keyPair = Ecies.generateEcKeyPair();
final message = "Welcome to ECIES";
var messageBytes = utf8.encode(message);
final publicKey = keyPair.publicKey.Q!.getEncoded(false);
final privateKey = bigIntToBytes(keyPair.privateKey.d!);
final cipherText = Ecies.encrypt(publicKey, messageBytes);

final decryptedBytes = Ecies.decrypt(privateKey, cipherText);
final decryptedMessage = utf8.decode(decryptedBytes);

print(decryptedMessage);
```
