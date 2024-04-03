import 'dart:typed_data';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/export.dart';

class ECKeyPair {
  dynamic publicKey;
  dynamic privateKey;
  ECKeyPair(this.publicKey, this.privateKey);
}

class Ecies {
  static const String curveName = 'secp256k1';
  static const int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
  static const int AES_IV_LENGTH = 16;
  static const int AES_TAG_LENGTH = 16;
  static const int AES_IV_PLUS_TAG_LENGTH = AES_IV_LENGTH + AES_TAG_LENGTH;
  static const int SECRET_KEY_LENGTH = 32;
  static final secureRandom =
      SecureRandom('Fortuna'); // Using Fortuna instead of SecureRandom

  static ECKeyPair generateEcKeyPair() {
    final keyParams = ECKeyGeneratorParameters(ECDomainParameters(curveName));
    final keyGenerator = KeyGenerator('EC')
      ..init(ParametersWithRandom(keyParams, secureRandom));
    final keyPair = keyGenerator.generateKeyPair();
    final publicKey = keyPair.publicKey as ECPublicKey;
    final privateKey = keyPair.privateKey as ECPrivateKey;
    return ECKeyPair(publicKey, privateKey);
  }

  static Uint8List hkdf(Uint8List uncompressed, Uint8List multiply) {
    final master = Uint8List.fromList([...uncompressed, ...multiply]);
    final hkdfParams = HkdfParameters(master, null, null);
    final hkdf = HKDFKeyDerivator(SHA256Digest());
    hkdf.init(hkdfParams);
    final aesKey = Uint8List(SECRET_KEY_LENGTH);
    hkdf.process(aesKey);
    return aesKey;
  }

  static Uint8List aesEncrypt(
      Uint8List message, ECPublicKey ephemeralPubKey, Uint8List aesKey) {
    final cipher = GCMBlockCipher(AESEngine());
    final nonce = secureRandom.nextBytes(AES_IV_LENGTH);
    final parametersWithIV = ParametersWithIV(KeyParameter(aesKey), nonce);
    cipher.init(true, parametersWithIV);

    final outputSize = cipher.getOutputSize(message.length);
    final encrypted = Uint8List(outputSize);
    var pos = cipher.processBytes(message, 0, message.length, encrypted, 0);
    pos += cipher.doFinal(encrypted, pos);

    final tag = encrypted.sublist(encrypted.length - nonce.length);
    final ephemeralPkUncompressed = encodeECPublicKey(ephemeralPubKey);
    return Uint8List.fromList([
      ...ephemeralPkUncompressed,
      ...nonce,
      ...tag,
      ...encrypted.sublist(0, encrypted.length - tag.length)
    ]);
  }

  static Uint8List aesDecrypt(
      Uint8List inputBytes, ECSignaturePrivateKey receiverPrivKey) {
    final encrypted = inputBytes.sublist(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    final nonce = encrypted.sublist(0, AES_IV_LENGTH);
    final tag = encrypted.sublist(AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH);
    final ciphered = encrypted.sublist(AES_IV_PLUS_TAG_LENGTH);

    final cipher = GCMBlockCipher(AESFastEngine());
    final parametersWithIV =
        AEADParameters(null, AES_TAG_LENGTH * 8, nonce, null);
    cipher.init(false, parametersWithIV);

    final outputSize = cipher.getOutputSize(ciphered.length + tag.length);
    final decrypted = Uint8List(outputSize);
    var pos = cipher.processBytes(ciphered, 0, ciphered.length, decrypted, 0);
    pos += cipher.processBytes(tag, 0, tag.length, decrypted, pos);
    pos += cipher.doFinal(decrypted, pos);

    return decrypted.sublist(0, pos);
  }

  static Uint8List encodeECPublicKey(ECPublicKey publicKey) {
    final encodedPoint = publicKey.Q.getEncoded(false);
    return encodedPoint;
  }

  static ECPublicKey decodeECPublicKey(Uint8List encodedPoint) {
    final curve = ECCurve_secp256k1();
    final point = ECPoint(curve.curve, encodedPoint);
    final params = ECParameters(curve);
    return ECPublicKey(point, params);
  }

  static Uint8List encrypt(Uint8List publicKeyBytes, Uint8List message) {
    final ephemeralKeyPair = generateEcKeyPair();
    final ephemeralPrivKey =
        ephemeralKeyPair.privateKey as ECSignaturePrivateKey;
    final ephemeralPubKey = ephemeralKeyPair.publicKey as ECSignaturePublicKey;

    final publicKey = decodeECPublicKey(publicKeyBytes);

    final uncompressed = encodeECPublicKey(ephemeralPubKey.Q);
    final multiply = publicKey.Q * ephemeralPrivKey.d;
    final aesKey = hkdf(uncompressed, encodeECPublicKey(multiply));

    return aesEncrypt(message, ephemeralPubKey, aesKey);
  }

  static Uint8List decrypt(Uint8List privateKeyBytes, Uint8List cipherBytes) {
    final curve = ECCurve_secp256k1();
    final receiverPrivKey =
        ECSignaturePrivateKey(privateKeyBytes, ECParameters(curve));

    final senderPubKeyByte =
        cipherBytes.sublist(0, UNCOMPRESSED_PUBLIC_KEY_SIZE);
    final senderPubKey = decodeECPublicKey(senderPubKeyByte);

    final multiply = senderPubKey.Q * receiverPrivKey.d;
    final uncompressed = encodeECPublicKey(senderPubKey.Q);
    final aesKey = hkdf(uncompressed, encodeECPublicKey(multiply));

    return aesDecrypt(cipherBytes, aesKey);
  }
}
