import 'package:flutter_test/flutter_test.dart';
import 'package:veilid/veilid.dart';

// Renaming either side of the @DefaultAsset/assetName pair still compiles, and only
// fails when the first FFI call runs.
void testNativeAssetResolves() {
  expect(Veilid.instance.veilidVersionString(), isNotEmpty);
  expect(Veilid.instance.veilidFeatures(), isNotEmpty);
  expect(Veilid.instance.validCryptoKinds(), isNotEmpty);
  expect(Veilid.instance.now().value, greaterThan(BigInt.zero));
}
