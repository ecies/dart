import 'dart:convert';

import 'package:eciesdart/eciesdart.dart';
import 'package:test/test.dart';
import 'dart:io';

void main() {
  group('ECIES interoperability with js', () {
    test('JS encryption with dart decryption', () async {
      final message = 'New York just had a 4.8 earthquake';
      final keyPair = generateEcKeyPairBytes();
      final messageBytes = utf8.encode(message);
      final encodedMessage = base64Encode(messageBytes);
      final encodedPublicKey = base64Encode(keyPair.publicKey);
      final encodedEncryptionResult = await Process.run('node', [
        'test/node/dist/bin/index.js',
        'encrypt',
        encodedPublicKey,
        encodedMessage
      ]).then((result) {
        return result.stdout;
      });
      final nodeEncryptedResult = base64Decode(encodedEncryptionResult);

      final decryptedResult = decrypt(keyPair.privateKey, nodeEncryptedResult);
      final decryptedMessage = utf8.decode(decryptedResult);
      assert(decryptedMessage == message);
    });

    test('Dart encryption with js decryption', () async {
      final message = 'It is the first earthquake of this magnitude since 1884';
      final keyPair = generateEcKeyPairBytes();
      final messageBytes = utf8.encode(message);
      final encryptedResult = encrypt(keyPair.publicKey, messageBytes);

      final encodedPrivateKey = base64Encode(keyPair.privateKey);
      final encodedCipherText = base64Encode(encryptedResult);

      final encodedEncryptionResult = await Process.run('node', [
        'test/node/dist/bin/index.js',
        'decrypt',
        encodedPrivateKey,
        encodedCipherText
      ]).then((result) {
        return result.stdout;
      });
      final nodeDecryptedResult = base64Decode(encodedEncryptionResult);
      final decryptedMessage = utf8.decode(nodeDecryptedResult);
      assert(decryptedMessage == message);
    });
  });
}
