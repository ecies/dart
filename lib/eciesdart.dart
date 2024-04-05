/// ECIES encryption in Dart.
///
/// This library provides functions to encrypt and decrypt messages using the ECIES
/// encryption scheme with the secp256k1 curve.
///
/// Encrypted buffers have the following format
/// ```
/// [
/// ...uncompressedPublicKey, // 65 bytes
/// ...iv,                    // 12 or 16 bytes,
/// ...cipherText,            // variable length
/// ...tag                    // 16 bytes
/// ]
/// ```
library;

export 'src/ecies.dart';
export 'src/bigint.dart';
