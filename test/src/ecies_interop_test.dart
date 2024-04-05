import 'dart:convert';

import 'package:eciesdart/eciesdart.dart';
import 'package:test/test.dart';
import 'dart:io';

void main() {
  test('ECIES interop test', () async {
    final message = 'test message';
    final keyPair = Ecies.generateEcKeyPairBytes();
    final messageBytes = utf8.encode(message);
    final encodedMessage = base64Encode(messageBytes);
    final encodedPublicKey = base64Encode(keyPair.publicKey);
    final encodedEncryptionResult = await Process.run('node', [
      'test/node/dist/bin/index.js',
      'encrypt',
      encodedPublicKey,
      encodedMessage
    ]).then((result) {
      print(result.stderr);
      return result.stdout;
    });
    final nodeEncryptedResult = base64Decode(encodedEncryptionResult);

    final decryptedResult =
        Ecies.decrypt(keyPair.privateKey, nodeEncryptedResult);
    final decryptedMessage = utf8.decode(decryptedResult);
    assert(decryptedMessage == message);
  });
}
