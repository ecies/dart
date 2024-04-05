import 'dart:math';
import 'dart:typed_data';
import 'package:eciesdart/src/bigint.dart';
import 'package:pointycastle/export.dart';

typedef KeyPairBytes = ({Uint8List publicKey, Uint8List privateKey});

const int _uncompressedPublicKeySize = 65;
// 16 bits to match the js implementation https://github.com/ecies/js/blob/f7f0923362beea9e0c4e05c2bcf5bceb1980f9e5/src/config.ts#L19
const int aesIvLength = 16;
const int _aesTagLength = 16;
// 32 bytes for 256 bit encryption
const int _secretKeyLength = 32;
final _sGen = Random.secure();
final _seed = Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
final _secureRandom = SecureRandom('Fortuna')..seed(KeyParameter(_seed));

/// Encrypt [message].
///
/// Encrypt [message] given a [publicKey] ASN.1 BigInt and return a buffer with the
/// format
/// ```
/// [
/// ...uncompressedPublicKey, // 65 bytes
/// ...iv,                    // 12 or 16 bytes,
/// ...cipherText,            // variable length
/// ...tag                    // 16 bytes
/// ]
/// ```
/// Optionally, you can specify the [ivLength] as either 12 or 16 bytes.
Uint8List encrypt(Uint8List publicKey, Uint8List message,
    {int ivLength = aesIvLength}) {
  validateIVLength(ivLength);
  final ecSpec = ECKeyGeneratorParameters(ECCurve_secp256k1());
  final ephemeralKeyPair = _generateEphemeralKey(ecSpec);
  ECPrivateKey ephemeralPrivKey = ephemeralKeyPair.privateKey as ECPrivateKey;
  ECPublicKey ephemeralPubKey = ephemeralKeyPair.publicKey as ECPublicKey;
  // Generate receiver PK
  ECPublicKey ecPublicKey = _getEcPublicKey(ecSpec.domainParameters, publicKey);

  // Derive shared secret
  final uncompressed = ephemeralPubKey.Q!.getEncoded(false);
  final multiply = ecPublicKey.Q! * ephemeralPrivKey.d;
  final aesKey = _hkdf(uncompressed, multiply!.getEncoded(false));
  return _aesEncrypt(message, ephemeralPubKey, aesKey, ivLength: ivLength);
}

/// Decrypt [message].
///
/// Decrypt [message] given a [privateKey] ASN.1 BigInt. The input buffer must have the
/// following format
/// ```
/// [
/// ...uncompressedPublicKey, // 65 bytes
/// ...iv,                    // 12 or 16 bytes,
/// ...cipherText,            // variable length
/// ...tag                    // 16 bytes
/// ]
/// ```
/// The [ivLength] must match the length used for encryption and defaults to 16 bytes.
Uint8List decrypt(Uint8List privateKey, Uint8List message,
    {int ivLength = aesIvLength}) {
  validateIVLength(ivLength);
  final keyParams = ECCurve_secp256k1();
  final ecSpec = ECKeyGeneratorParameters(keyParams);

  // Generate receiver private key
  final receiverSK = bytesToBigInt(privateKey);
  ECPrivateKey ecPrivateKey = ECPrivateKey(receiverSK, ecSpec.domainParameters);

  final senderPK = message.sublist(0, _uncompressedPublicKeySize);
  final Q = ecSpec.domainParameters.curve.decodePoint(senderPK);
  final senderPK2 = ECPublicKey(Q, ecSpec.domainParameters);

  // Decapsulate
  final uncompressed = senderPK2.Q!.getEncoded(false);
  final multiply = senderPK2.Q! * ecPrivateKey.d;
  final aesKey = _hkdf(uncompressed, multiply!.getEncoded(false));

  return _aesDecrypt(message, aesKey, ivLength: ivLength);
}

/// Generate an EC key pair.
///
/// Generate an EC key pair using the secp256k1 curve.
AsymmetricKeyPair<ECPublicKey, ECPrivateKey> generateEcKeyPair() {
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
/// Generate an EC key pair using the secp256k1 curve and return the ASN.1
/// representation of the [BigInt]s
KeyPairBytes generateEcKeyPairBytes() {
  final pair = generateEcKeyPair();
  return (
    publicKey: pair.publicKey.Q!.getEncoded(false),
    privateKey: bigIntToBytes(pair.privateKey.d!)
  );
}

/// Encrypt a [message] using AES-256-GCM.
///
/// Encrypt a [message] and return a buffer in the following format
/// ```
/// [
/// ...uncompressedPublicKey, // 65 bytes
/// ...iv,                    // 12 or 16 bytes,
/// ...cipherText,            // variable length
/// ...tag                    // 16 bytes
/// ]
/// ```
Uint8List _aesEncrypt(
    Uint8List message, ECPublicKey ephemeralPubKey, Uint8List aesKey,
    {required int ivLength}) {
  final iv = _secureRandom.nextBytes(ivLength);
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
    true,
    AEADParameters(
      KeyParameter(aesKey),
      _aesTagLength * 8,
      iv,
      Uint8List(0),
    ),
  );

  final ephemeralPkUncompressed = ephemeralPubKey.Q!.getEncoded(false);
  final cipherTextAndTag = cipher.process(message);
  final cipherTextLength = cipherTextAndTag.length - _aesTagLength;
  final tag = cipherTextAndTag.sublist(cipherTextLength);
  final cipherText = cipherTextAndTag.sublist(0, cipherTextLength);

  final result = Uint8List.fromList(
      [...ephemeralPkUncompressed, ...iv, ...tag, ...cipherText]);
  return result;
}

/// Decrypt  [inputBytes] using AES-256-GCM.
///
/// Decrypt [inputBytes] with the following format
/// ```
/// [
/// ...uncompressedPublicKey, // 65 bytes
/// ...iv,                    // 12 or 16 bytes,
/// ...cipherText,            // variable length
/// ...tag                    // 16 bytes
/// ]
/// ```
Uint8List _aesDecrypt(Uint8List inputBytes, Uint8List aesKey,
    {required int ivLength}) {
  final ivTagAndCipherText = inputBytes.sublist(_uncompressedPublicKeySize);
  final iv = ivTagAndCipherText.sublist(0, ivLength);
  final tagAndCipherText = ivTagAndCipherText.sublist(ivLength);
  final tag = tagAndCipherText.sublist(0, _aesTagLength);
  final cipherText = tagAndCipherText.sublist(_aesTagLength);
  final cipherTextAndTag = Uint8List.fromList([...cipherText, ...tag]);
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
    false,
    AEADParameters(
      KeyParameter(aesKey),
      _aesTagLength * 8,
      iv,
      Uint8List(0),
    ),
  );
  final plainText = cipher.process(cipherTextAndTag);
  return plainText;
}

AsymmetricKeyPair<PublicKey, PrivateKey> _generateEphemeralKey(
    ECKeyGeneratorParameters ecSpec) {
  final keyGenerator = ECKeyGenerator()
    ..init(ParametersWithRandom(ecSpec, _secureRandom));
  return keyGenerator.generateKeyPair();
}

ECPublicKey _getEcPublicKey(
    ECDomainParameters params, List<int> senderPubKeyBytes) {
  var Q = params.curve.decodePoint(senderPubKeyBytes);
  return ECPublicKey(Q, params);
}

Uint8List _hkdf(Uint8List uncompressed, Uint8List multiply) {
  final initialKeyMaterial = Uint8List.fromList([...uncompressed, ...multiply]);
  final hkdf = KeyDerivator("SHA-256/HKDF");
  hkdf.init(HkdfParameters(initialKeyMaterial, _secretKeyLength));
  return hkdf.process(Uint8List(0));
}

void validateIVLength(int ivLength) {
  if (ivLength != 12 && ivLength != 16) {
    throw ArgumentError('IV length must be 12 or 16 bytes');
  }
}
