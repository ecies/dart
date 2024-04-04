import 'dart:convert';

import 'package:eciesdart/eciesdart.dart';
import 'package:test/test.dart';
import 'package:collection/collection.dart';
import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;

void main() {
  group('ECIES', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('bip32 compatibility', () {
      final mnemonic = bip39.generateMnemonic(strength: 256);
      final seed = bip39.mnemonicToSeed(mnemonic);
      final hdWallet = BIP32.fromSeed(seed);
      final message = "This is a test message";
      var messageBytes = utf8.encode(message);

      final cipherText = Ecies.encrypt(hdWallet.publicKey, messageBytes);
      assert(cipherText != messageBytes);

      final decryptedMessage = Ecies.decrypt(hdWallet.privateKey!, cipherText);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });

    test('Key generation', () {
      final keyPair = Ecies.generateEcKeyPair();
      final message = "This is a different test message";
      var messageBytes = utf8.encode(message);
      final publicKey = keyPair.publicKey.Q!.getEncoded(false);
      final privateKey = bigIntToBytes(keyPair.privateKey.d!);
      final cipherText = Ecies.encrypt(publicKey, messageBytes);
      assert(!ListEquality().equals(cipherText, messageBytes));

      final decryptedMessage = Ecies.decrypt(privateKey, cipherText);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });

    test('Generate key pair bytes', () {
      final keyPair = Ecies.generateEcKeyPairBytes();
      final message = "BigInts can be very big";
      var messageBytes = utf8.encode(message);
      final cipherText = Ecies.encrypt(keyPair.publicKey, messageBytes);
      assert(!ListEquality().equals(cipherText, messageBytes));

      final decryptedMessage = Ecies.decrypt(keyPair.privateKey, cipherText);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });
  });
}
