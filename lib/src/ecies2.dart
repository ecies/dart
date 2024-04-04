import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:eciesdart/src/bigint.dart';
import 'package:pointycastle/export.dart';
import 'package:hex/hex.dart';

class Ecies {
  static final int _uncompressedPublicKeySize = 65;
  // 16 bits to match the js implementation https://github.com/ecies/js/blob/f7f0923362beea9e0c4e05c2bcf5bceb1980f9e5/src/config.ts#L19
  static final int _aesIvLength = 16;
  static final int _aesTagLength = 16;
  static final int _aesIvPlusTagLength = _aesIvLength + _aesTagLength;
  // 32 bytes for 256 bit encryption
  static final int _secretKeyLength = 32;
  static final _sGen = Random.secure();
  static final _seed =
      Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
  static final _secureRandom = SecureRandom('Fortuna')
    ..seed(KeyParameter(_seed));

  /// Encrypt a [message].
  ///
  /// Encrypte a [message] given a [publicKey] as hex encoded version of an ASN.1 BigInt
  static String encrypt(String publicKey, String message) {
    final publicKeyBytes = HEX.decode(publicKey);
    final encrypted =
        _encryptBytes(Uint8List.fromList(publicKeyBytes), utf8.encode(message));
    return HEX.encode(encrypted);
  }

  /// Decrypt a [message].
  ///
  /// Decrypt a [message] given a [privateKey] as hex encoded version of an ASN.1 BigInt
  static String decrypt(String privateKeyHex, String ciphertext) {
    final privateKey = HEX.decode(privateKeyHex);
    final cipherBytes = HEX.decode(ciphertext);
    return utf8.decode(_decryptBytes(
        Uint8List.fromList(privateKey), Uint8List.fromList(cipherBytes)));
  }

  static Uint8List _encryptBytes(Uint8List publicKeyBytes, Uint8List message) {
    // Create an ephemeral key pair
    final ecSpec = ECKeyGeneratorParameters(ECCurve_secp256k1());
    final ephemeralKeyPair = _generateEphemeralKey(ecSpec);
    ECPrivateKey ephemeralPrivKey = ephemeralKeyPair.privateKey as ECPrivateKey;
    ECPublicKey ephemeralPubKey = ephemeralKeyPair.publicKey as ECPublicKey;
    // Generate receiver PK
    ECPublicKey publicKey =
        _getEcPublicKey(ecSpec.domainParameters, publicKeyBytes);

    // Derive shared secret
    final uncompressed = ephemeralPubKey.Q!.getEncoded(false);
    final multiply = publicKey.Q! * ephemeralPrivKey.d;
    final aesKey = _hkdf(uncompressed, multiply!.getEncoded(false));

    // AES encryption
    return _aesEncrypt(message, ephemeralPubKey, aesKey);
  }

  static Uint8List _decryptBytes(
      Uint8List privateKeyBytes, Uint8List cipherBytes) {
    final keyParams = ECCurve_secp256k1();
    final ecSpec = ECKeyGeneratorParameters(keyParams);

    // Generate receiver private key
    final d = byteToBigInt(privateKeyBytes);
    ECPrivateKey privateKey = ECPrivateKey(d, ecSpec.domainParameters);

    // Get sender public key
    final senderPubKeyBytes =
        cipherBytes.sublist(0, _uncompressedPublicKeySize);

    final Q = ecSpec.domainParameters.curve.decodePoint(senderPubKeyBytes);
    final senderPubKey = ECPublicKey(Q, ecSpec.domainParameters);

    // Decapsulate
    final uncompressed = senderPubKey.Q!.getEncoded(false);
    final multiply = senderPubKey.Q! * privateKey.d;
    final aesKey = _hkdf(uncompressed, multiply!.getEncoded(false));

    // AES decryption
    return _aesDecrypt(cipherBytes, aesKey);
  }

  /// Encrypt a [message] using AES-256-GCM.
  ///
  /// Encrypt a [message] and return a buffer in the following format [...iv, ...cipherText, ...tag]
  /// where iv 16 bytes and the tag is 16 bytes.
  static Uint8List _aesEncrypt(
      Uint8List message, ECPublicKey ephemeralPubKey, Uint8List aesKey) {
    final cipher = GCMBlockCipher(AESEngine());
    final iv = _secureRandom.nextBytes(_aesIvLength);
    final parameters = AEADParameters(
        KeyParameter(aesKey), _aesTagLength * 8, iv, Uint8List(0));

    cipher.init(true, parameters);

    final ephemeralPkUncompressed = ephemeralPubKey.Q!.getEncoded(false);
    final cipherTextAndTag = cipher.process(message);

    final result = Uint8List.fromList(
        [...ephemeralPkUncompressed, ...iv, ...cipherTextAndTag]);
    return result;
  }

  /// Decrypt  [inputBytes] using AES-256-GCM.
  ///
  /// Decrypt [inputBytes] where inputBytes is assumed to have the following format
  /// [...iv, ...cipherText, ...tag] where iv 16 bytes and the tag is 16 bytes.
  static Uint8List _aesDecrypt(Uint8List inputBytes, Uint8List aesKey) {
    final ivCipherTextAndTag = inputBytes.sublist(_uncompressedPublicKeySize);
    final iv = ivCipherTextAndTag.sublist(0, _aesIvLength);
    final cipherTextAndTag = ivCipherTextAndTag.sublist(_aesIvLength);

    final aesgcmBlockCipher = GCMBlockCipher(AESEngine());
    final parametersWithIV = AEADParameters(
        KeyParameter(aesKey), _aesTagLength * 8, iv, Uint8List(0));
    aesgcmBlockCipher.init(false, parametersWithIV);
    final plainText = aesgcmBlockCipher.process(cipherTextAndTag);

    return plainText;
  }

  static AsymmetricKeyPair<PublicKey, PrivateKey> _generateEphemeralKey(
      ECKeyGeneratorParameters ecSpec) {
    final keyGenerator = ECKeyGenerator()
      ..init(ParametersWithRandom(ecSpec, _secureRandom));
    return keyGenerator.generateKeyPair();
  }

  static ECPublicKey _getEcPublicKey(
      ECDomainParameters params, List<int> senderPubKeyBytes) {
    var Q = params.curve.decodePoint(senderPubKeyBytes);
    return ECPublicKey(Q, params);
  }

  static Uint8List _hkdf(Uint8List uncompressed, Uint8List multiply) {
    final initialKeyMaterial =
        Uint8List.fromList([...uncompressed, ...multiply]);
    final hkdf = KeyDerivator("SHA-256/HKDF");
    hkdf.init(HkdfParameters(initialKeyMaterial, _secretKeyLength, null));
    return hkdf.process(Uint8List(_secretKeyLength));
  }
}
