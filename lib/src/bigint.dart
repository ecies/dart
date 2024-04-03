import 'dart:typed_data';
import 'package:hex/hex.dart';

BigInt byteToBigInt(Uint8List bigIntBytes) {
  BigInt result = BigInt.from(0);
  for (int i = 0; i < bigIntBytes.length; i++) {
    result += BigInt.from(bigIntBytes[bigIntBytes.length - i - 1]) << (8 * i);
  }
  return result;
}

/// Convert a bigint to a byte array
Uint8List bigIntToBytes(BigInt bigInt) {
  return Uint8List.fromList(
      HEX.decode(bigInt.toRadixString(16).padLeft(32, "0")));
}
