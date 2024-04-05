import 'dart:typed_data';
import 'package:hex/hex.dart';

/// Convert [bytes] from ANS.1 format to a [BigInt].
BigInt bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.from(0);
  for (int i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

/// Convert [bigInt] to a [Uint8List] in ASN.1 format.
Uint8List bigIntToBytes(BigInt bigInt) {
  return Uint8List.fromList(
      HEX.decode(bigInt.toRadixString(16).padLeft(32, "0")));
}
