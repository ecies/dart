import 'dart:math';
import 'dart:typed_data';
import 'package:eciesdart/src/bigint.dart';
import 'package:pointycastle/export.dart';

typedef KeyPairBytes = ({Uint8List publicKey, Uint8List privateKey});

class Ecies {
  static final int _uncompressedPublicKeySize = 65;
  // 16 bits to match the js implementation https://github.com/ecies/js/blob/f7f0923362beea9e0c4e05c2bcf5bceb1980f9e5/src/config.ts#L19
  static final int aesIvLength = 16;
  static final int _aesTagLength = 16;
  // 32 bytes for 256 bit encryption
  static final int _secretKeyLength = 32;
  static final _sGen = Random.secure();
  static final _seed =
      Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
  static final _secureRandom = SecureRandom('Fortuna')
    ..seed(KeyParameter(_seed));

  /// Encrypt a [message].
  ///
  /// Encrypt a [message] given a [publicKey] ASN.1 BigInt and return a buffer with the
  /// format [...iv, ...cipherText, ...tag]
  static Uint8List encrypt(Uint8List publicKey, Uint8List message) {
    final ecSpec = ECKeyGeneratorParameters(ECCurve_secp256k1());
    final ephemeralKeyPair = Ecies._generateEphemeralKey(ecSpec);
    ECPrivateKey ephemeralPrivKey = ephemeralKeyPair.privateKey as ECPrivateKey;
    ECPublicKey ephemeralPubKey = ephemeralKeyPair.publicKey as ECPublicKey;
    // Generate receiver PK
    ECPublicKey publicKey2 =
        Ecies._getEcPublicKey(ecSpec.domainParameters, publicKey);

    // Derive shared secret
    final uncompressed = ephemeralPubKey.Q!.getEncoded(false);
    final multiply = publicKey2.Q! * ephemeralPrivKey.d;
    final aesKey = Ecies._hkdf(uncompressed, multiply!.getEncoded(false));
    return Ecies._aesEncrypt(message, ephemeralPubKey, aesKey);
  }

  /// Decrypt  [cipherText].
  ///
  /// Decrypt [cipherText] with the format [...iv, ...cipherText, ...tag] with a
  /// [privateKey] ASN.1 BigInt
  static Uint8List decrypt(Uint8List privateKey, Uint8List cipherText) {
    final keyParams = ECCurve_secp256k1();
    final ecSpec = ECKeyGeneratorParameters(keyParams);

    // Generate receiver private key
    final d = byteToBigInt(privateKey);
    ECPrivateKey privateKey2 = ECPrivateKey(d, ecSpec.domainParameters);

    // Get sender public key
    final senderPubKeyBytes =
        cipherText.sublist(0, Ecies._uncompressedPublicKeySize);

    final Q = ecSpec.domainParameters.curve.decodePoint(senderPubKeyBytes);
    final senderPubKey = ECPublicKey(Q, ecSpec.domainParameters);

    // Decapsulate
    final uncompressed = senderPubKey.Q!.getEncoded(false);
    final multiply = senderPubKey.Q! * privateKey2.d;
    final aesKey = Ecies._hkdf(uncompressed, multiply!.getEncoded(false));
    return Ecies._aesDecrypt(cipherText, aesKey);
  }

  /// Generate an EC key pair.
  ///
  /// Generate an EC key pair using the secp256k1 curve.
  static AsymmetricKeyPair<ECPublicKey, ECPrivateKey> generateEcKeyPair() {
    final keyParams = ECCurve_secp256k1();
    final ecSpec = ECKeyGeneratorParameters(keyParams);
    final keyGenerator = ECKeyGenerator()
      ..init(ParametersWithRandom(ecSpec, _secureRandom));
    final pair = keyGenerator.generateKeyPair();
    final publicKey = pair.publicKey as ECPublicKey;
    final privateKey = pair.privateKey as ECPrivateKey;
    return AsymmetricKeyPair(publicKey, privateKey);
  }

  /// Generate an EC key pair.
  ///
  /// Generate an EC key pair using the secp256k1 curve and retrn the ASN.1
  /// representation of the [BigInt]s
  static KeyPairBytes generateEcKeyPairBytes() {
    final pair = generateEcKeyPair();
    return (
      publicKey: pair.publicKey.Q!.getEncoded(false),
      privateKey: bigIntToBytes(pair.privateKey.d!)
    );
  }

  /// Encrypt a [message] using AES-256-GCM.
  ///
  /// Encrypt a [message] and return a buffer in the following format [...iv, ...cipherText, ...tag]
  /// where iv 16 bytes and the tag is 16 bytes.
  static Uint8List _aesEncrypt(
      Uint8List message, ECPublicKey ephemeralPubKey, Uint8List aesKey) {
    final cipher = GCMBlockCipher(AESEngine());
    final iv = _secureRandom.nextBytes(aesIvLength);
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
    final iv = ivCipherTextAndTag.sublist(0, aesIvLength);
    final cipherTextAndTag = ivCipherTextAndTag.sublist(aesIvLength);

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
