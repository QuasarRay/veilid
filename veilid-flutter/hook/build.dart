// Builds veilid-flutter/rust as the code asset lib/veilid_ffi.dart resolves against.
// `assetName` below and that file's @DefaultAsset must move together.

import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

/// Cargo features a consuming app selects for this build, read from
/// `.dart_tool/veilid_build_config.json` under that app.
///
/// `.dart_tool` is gitignored in every Dart project, so a test run can select a
/// feature set without touching a tracked file, and an ordinary app build -
/// which never writes one - gets the default. It has to be a file rather than an
/// environment variable or a `--define`: hooks run under a fixed environment
/// allowlist, and user-defines reach a hook only from the workspace pubspec,
/// which the app shares with its own release builds.
const _configFileName = 'veilid_build_config.json';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }
    final selection = _featureSelection(input, output);
    await RustBuilder(
      assetName: 'veilid_ffi.dart',
      cratePath: 'rust',
      buildMode: _buildMode(input),
      features: selection.features,
      enableDefaultFeatures: selection.defaultFeatures,
    ).run(input: input, output: output);
  });
}

// linkingEnabled is false only for debug builds, and it sits in the hashed config
// subtree, so the two modes get separate hook output directories.
BuildMode _buildMode(BuildInput input) =>
    input.config.linkingEnabled ? BuildMode.release : BuildMode.debug;

typedef _FeatureSelection = ({List<String> features, bool defaultFeatures});

/// The config file wins over pubspec user-defines, which stay supported for an
/// app that wants one fixed feature set for every build.
_FeatureSelection _featureSelection(BuildInput input, BuildOutputBuilder output) {
  final configFile = _configFile(input);
  if (configFile != null) {
    // Declared whether or not it exists, so writing one re-runs this hook rather
    // than serving the previous build's library
    output.dependencies.add(configFile.uri);
    final fromFile = _readConfig(configFile);
    if (fromFile != null) {
      return fromFile;
    }
  }
  return (features: _userDefineFeatures(input), defaultFeatures: true);
}

/// Where the consuming app would put its config, derived from the hook's own
/// output directory because that is the only path a hook is handed inside it.
File? _configFile(BuildInput input) {
  final segments = input.outputDirectoryShared.pathSegments;
  final dartTool = segments.lastIndexOf('.dart_tool');
  if (dartTool < 0) {
    return null;
  }
  return File.fromUri(
    input.outputDirectoryShared.replace(
      pathSegments: [...segments.take(dartTool + 1), _configFileName],
    ),
  );
}

/// Null when there is no usable config, so the caller falls back rather than
/// building something the app did not ask for
_FeatureSelection? _readConfig(File configFile) {
  if (!configFile.existsSync()) {
    return null;
  }
  final Object? decoded;
  try {
    decoded = jsonDecode(configFile.readAsStringSync());
  } on FormatException catch (e) {
    throw StateError('$_configFileName is not valid JSON: $e');
  }
  if (decoded is! Map<String, Object?>) {
    throw StateError('$_configFileName must hold a JSON object');
  }
  final features = decoded['features'];
  final defaultFeatures = decoded['default_features'];
  return (
    features: features is List ? features.cast<String>() : const <String>[],
    // Absent means the ordinary build; a feature set that conflicts with the
    // defaults has to say so, the way mock-api does against stats
    defaultFeatures: defaultFeatures is bool ? defaultFeatures : true,
  );
}

List<String> _userDefineFeatures(BuildInput input) {
  final features = input.userDefines['features'];
  if (features is! List) {
    return const <String>[];
  }
  return features.cast<String>();
}
