import 'package:eciesdart/src/ecies2.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;

void main() {
  group('Test encryption', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () {
      final mnemonic = bip39.generateMnemonic(strength: 256);
      final seed = bip39.mnemonicToSeed(mnemonic);
      final hdWallet = BIP32.fromSeed(seed);
      final message = "This is a test message";
      // final publicKey = decodeBigInt(hdWallet.publicKey);
      final cipherText =
          Ecies.encrypt(HEX.encode(hdWallet.publicKey.toList()), message);
      assert(cipherText != message);

      final decryptedMessage =
          Ecies.decrypt(HEX.encode(hdWallet.privateKey!.toList()), cipherText);
      assert(decryptedMessage == message);
    });
  });
}
