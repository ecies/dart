// import 'dart:math';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:eciesdart/src/bigint.dart';
import 'package:pointycastle/export.dart';
import 'package:hex/hex.dart';

class Ecies {
  static final String curveName = "secp256k1";
  static final int uncompressedPublicKeySize = 65;
  static final int aesIvLength = 12;
  static final int aesTagLength = 12;
  static final int aesIvPlusTagLength = aesIvLength + aesTagLength;
  static final int secretKeyLength = 32;
  static final _sGen = Random.secure();
  static final _seed =
      Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
  static final secureRandom = SecureRandom('Fortuna')
    ..seed(KeyParameter(_seed)); // Using Fortuna instead of SecureRandom

  // static AsymmetricKeyPair<PublicKey, PrivateKey> _generateEcKeyPair() {
  //   final keyParams = ECCurve_secp256k1();
  //   final ecSpec = ECKeyGeneratorParameters(keyParams);
  //   final keyGenerator = ECKeyGenerator()
  //     ..init(ParametersWithRandom(ecSpec, secureRandom));
  //   return keyGenerator.generateKeyPair();
  // }

  /// Hex encoding of a BigInt asn1 encoding
  static String encrypt(String publicKeyHex, String message) {
    final publicKey = HEX.decode(publicKeyHex);
    final encrypted =
        _encryptBytes(Uint8List.fromList(publicKey), utf8.encode(message));
    return HEX.encode(encrypted);
  }

  static String decrypt(String privateKeyHex, String ciphertext) {
    final privateKey = HEX.decode(privateKeyHex);
    final cipherBytes = HEX.decode(ciphertext);
    return utf8.decode(_decryptBytes(
        Uint8List.fromList(privateKey), Uint8List.fromList(cipherBytes)));
  }

  static Uint8List _encryptBytes(Uint8List publicKeyBytes, Uint8List message) {
    // Create an ephemeral key pair
    final keyParams = ECCurve_secp256k1();
    final ecSpec = ECKeyGeneratorParameters(keyParams);
    final pair = _generateEphemeralKey(ecSpec);
    ECPrivateKey ephemeralPrivKey = pair.privateKey as ECPrivateKey;
    ECPublicKey ephemeralPubKey = pair.publicKey as ECPublicKey;

    // Generate receiver PK
    ECPublicKey publicKey =
        getEcPublicKey(ecSpec.domainParameters, publicKeyBytes);

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
    final senderPubKeyBytes = cipherBytes.sublist(0, uncompressedPublicKeySize);

    final Q = ecSpec.domainParameters.curve.decodePoint(senderPubKeyBytes);
    final senderPubKey = ECPublicKey(Q, ecSpec.domainParameters);

    // Decapsulate
    final uncompressed = senderPubKey.Q!.getEncoded(false);
    final multiply = senderPubKey.Q! * d;
    final aesKey = _hkdf(uncompressed, multiply!.getEncoded(false));

    // AES decryption
    return _aesDecrypt(cipherBytes, aesKey);
  }

  static AsymmetricKeyPair<PublicKey, PrivateKey> _generateEphemeralKey(
      ECKeyGeneratorParameters ecSpec) {
    final keyGenerator = ECKeyGenerator()
      ..init(ParametersWithRandom(ecSpec, secureRandom));
    return keyGenerator.generateKeyPair();
  }

  static ECPublicKey getEcPublicKey(
      ECDomainParameters params, List<int> senderPubKeyBytes) {
    var Q = params.curve.decodePoint(senderPubKeyBytes);
    return ECPublicKey(Q, params);
  }

  static Uint8List _hkdf(Uint8List uncompressed, Uint8List multiply) {
    final initialKeyMaterial =
        Uint8List.fromList([...uncompressed, ...multiply]);
    final hkdf = KeyDerivator("SHA-256/HKDF");
    hkdf.init(HkdfParameters(initialKeyMaterial, secretKeyLength, null));
    return hkdf.process(Uint8List(secretKeyLength));
  }

  static Uint8List _aesEncrypt(
      Uint8List message, ECPublicKey ephemeralPubKey, Uint8List aesKey) {
    final cipher = GCMBlockCipher(AESEngine());
    final nonce = secureRandom.nextBytes(aesIvLength);
    final parametersWithIV = ParametersWithIV(KeyParameter(aesKey), nonce);
    cipher.init(true, parametersWithIV);

    final outputSize = cipher.getOutputSize(message.length);
    var encrypted = Uint8List(outputSize);
    var pos = cipher.processBytes(message, 0, message.length, encrypted, 0);
    pos += cipher.doFinal(encrypted, pos);

    final tag = encrypted.sublist(encrypted.length - nonce.length);
    encrypted = encrypted.sublist(0, encrypted.length - tag.length);

    final ephemeralPkUncompressed = ephemeralPubKey.Q!.getEncoded(false);

    print("ephemeralPubKey ${base64Encode(ephemeralPkUncompressed)}");
    print("nonce ${base64Encode(nonce)}");
    print("tag ${base64Encode(tag)}");
    print("key ${base64Encode(aesKey)}");
    print("encrypted ${base64Encode(encrypted)}");

    final result = Uint8List.fromList(
        [...ephemeralPkUncompressed, ...nonce, ...tag, ...encrypted]);
    print("aesEncrypt output ${base64Encode(result)}");
    return result;
  }

  static Uint8List _aesDecrypt(Uint8List inputBytes, Uint8List aesKey) {
    final encrypted = inputBytes.sublist(uncompressedPublicKeySize);
    final nonce = encrypted.sublist(0, aesIvLength);
    final tag = encrypted.sublist(aesIvLength, aesIvPlusTagLength);
    final ciphered = encrypted.sublist(aesIvPlusTagLength);

    print("aesDecrypt input ${base64Encode(inputBytes)}");
    print("nonce ${base64Encode(nonce)}");
    print("tag ${base64Encode(tag)}");
    print("key ${base64Encode(aesKey)}");
    print(
        "encrypted ${base64Encode(encrypted.sublist(0, encrypted.length - tag.length))}");

    final aesgcmBlockCipher = GCMBlockCipher(AESEngine());
    final parametersWithIV = ParametersWithIV(KeyParameter(aesKey), nonce);
    aesgcmBlockCipher.init(false, parametersWithIV);

    final outputSize =
        aesgcmBlockCipher.getOutputSize(ciphered.length + tag.length);
    final decrypted = Uint8List(outputSize);
    var pos = aesgcmBlockCipher.processBytes(
        ciphered, 0, ciphered.length, decrypted, 0);
    pos += aesgcmBlockCipher.processBytes(tag, 0, tag.length, decrypted, pos);
    print("decrypted ${utf8.decode(decrypted)}");
    aesgcmBlockCipher.doFinal(decrypted, pos);
    return decrypted;
  }
}
