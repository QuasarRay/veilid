import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:veilid/veilid.dart';

/// Every key path through the nested objects of [json].
Set<String> _keyPaths(Object? json, [String prefix = '']) => switch (json) {
  final Map<String, dynamic> map => {
    for (final MapEntry(:key, :value) in map.entries) ...{
      '$prefix$key',
      ..._keyPaths(value, '$prefix$key.'),
    },
  },
  _ => {},
};

// A key core sends that a Dart round trip drops is a config field the Dart
// classes lack, and a changeConfig from Dart resets it to core's default
void testDefaultConfigRoundTrip() {
  final coreJson = jsonDecode(Veilid.instance.defaultVeilidConfig());
  final dartJson = jsonDecode(jsonEncode(VeilidConfig.fromJson(coreJson)));
  expect(_keyPaths(coreJson).difference(_keyPaths(dartJson)), isEmpty);
}

void testAutoDetectStateRoundTrip() {
  final off = VeilidConfigAppLifecycle.fromJson({
    'preferForeground': true,
    'autoDetectState': false,
  });
  expect(off.autoDetectState, isFalse);
  expect(off.toJson()['autoDetectState'], isFalse);

  // Left out, it takes core's default
  expect(
    VeilidConfigAppLifecycle.fromJson({'preferForeground': true})
        .autoDetectState,
    isTrue,
  );
}
