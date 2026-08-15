// Builds veilid-flutter/rust as the code asset lib/veilid_ffi.dart resolves against.
// `assetName` below and that file's @DefaultAsset must move together.

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }
    await RustBuilder(
      assetName: 'veilid_ffi.dart',
      cratePath: 'rust',
      buildMode: _buildMode(input),
      features: _features(input),
    ).run(input: input, output: output);
  });
}

// linkingEnabled is false only for debug builds, and it sits in the hashed config
// subtree, so the two modes get separate hook output directories.
BuildMode _buildMode(BuildInput input) =>
    input.config.linkingEnabled ? BuildMode.release : BuildMode.debug;

// Hooks run under a fixed environment allowlist, so features cannot come from the
// environment; the root app declares them under `hooks: user_defines: veilid:`.
List<String> _features(BuildInput input) {
  final features = input.userDefines['features'];
  if (features is! List) {
    return const <String>[];
  }
  return features.cast<String>();
}
