import 'package:flutter_test/flutter_test.dart';

import 'test_encoding.dart';
import 'test_native_asset.dart';
import 'test_timestamp.dart';
import 'test_value_subkey_range.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {});
  tearDown(() {});

  group('native asset', () {
    test('test FFI entry points resolve', testNativeAssetResolves);
  });

  group('encoding', () {
    test('test encoding known vectors', testEncodingKnownVectors);
    test('test encode/decode garbage', testEncodeDecodeGarbage);
    test('test encode/decode garbage with pad', testEncodeDecodeGarbagePad);
  });

  group('Timestamp', () {
    test('human form matches veilid-core', testTimestampHumanForm);
    test('machine form round trips', testTimestampMachineForm);
    test(
      'duration human form matches veilid-core',
      testTimestampDurationHumanForm,
    );
    test('duration machine form round trips', testTimestampDurationMachineForm);
  });

  group('ValueSubkeyRange', () {
    test('test ValueSubkeyRange', testValueSubkeyRange);
    test('test List<ValueSubkeyRange>', testValueSubkeyRangeList);
  });
}
