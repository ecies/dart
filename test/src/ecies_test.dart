import 'dart:convert';

import 'package:eciesdart/eciesdart.dart';
import 'package:test/test.dart';
import 'package:collection/collection.dart';
import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;

void main() {
  group('ECIES encryption and decryption', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('is compatible with BIP32 keys', () {
      final mnemonic = bip39.generateMnemonic(strength: 256);
      final seed = bip39.mnemonicToSeed(mnemonic);
      final hdWallet = BIP32.fromSeed(seed);
      final message = "This is a test message";
      var messageBytes = utf8.encode(message);

      final cipherText = encrypt(hdWallet.publicKey, messageBytes);
      assert(cipherText != messageBytes);

      final decryptedMessage = decrypt(hdWallet.privateKey!, cipherText);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });

    test('using ECPublicKey and ECPrivateKey', () {
      final keyPair = generateEcKeyPair();
      final message = "This is a different test message";
      var messageBytes = utf8.encode(message);
      final publicKey = keyPair.publicKey.Q!.getEncoded(false);
      final privateKey = bigIntToBytes(keyPair.privateKey.d!);
      final cipherText = encrypt(publicKey, messageBytes);
      assert(!ListEquality().equals(cipherText, messageBytes));

      final decryptedMessage = decrypt(privateKey, cipherText);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });

    test('using key pair bytes', () {
      final keyPair = generateEcKeyPairBytes();
      final message = "BigInts can be very big";
      var messageBytes = utf8.encode(message);
      final cipherText = encrypt(keyPair.publicKey, messageBytes);
      assert(!ListEquality().equals(cipherText, messageBytes));

      final decryptedMessage = decrypt(keyPair.privateKey, cipherText);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });

    test('with 12 byte iv', () {
      final keyPair = generateEcKeyPairBytes();
      final message = "This is a small message";
      var messageBytes = utf8.encode(message);
      final cipherText = encrypt(keyPair.publicKey, messageBytes, ivLength: 12);
      assert(!ListEquality().equals(cipherText, messageBytes));

      final decryptedMessage =
          decrypt(keyPair.privateKey, cipherText, ivLength: 12);
      assert(ListEquality().equals(decryptedMessage, messageBytes));
      assert(utf8.decode(decryptedMessage) == message);
    });

    test('throws for an invalid iv ivLength', () {
      final keyPair = generateEcKeyPairBytes();
      expect(
          () => encrypt(keyPair.publicKey, utf8.encode("nevermind"),
              ivLength: 13),
          throwsA(isA<ArgumentError>()));
    });
  });
}
