import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

import 'package:veilid/src/hook_helpers/prebuilt.dart';

// Native-assets build hook for veilid. Delivers libveilid_flutter as a
// DynamicLoadingBundled CodeAsset (loaded by lib/veilid_ffi.dart's DynamicLibrary
// loader — no @Native). Waterfall:
//   1. reuse a cached, verified prebuilt   (inside fetchPrebuilt)
//   2. download + SHA-256 verify a published prebuilt
//   3. compile veilid-flutter/rust from source (RustBuilder)
// The prebuilt tiers fire only when lib/src/hook_helpers/checksums.dart is
// populated (published package) and `source_only` is not set; a working-tree /
// path-override consumer has empty checksums and therefore builds from source.
void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    if (!_boolDefine(input, 'source_only')) {
      final prebuilt =
          await fetchPrebuilt(input: input, source: _artifactSource(input));
      if (prebuilt != null) {
        output.assets.code.add(CodeAsset(
          package: input.packageName,
          name: 'veilid_flutter',
          linkMode: DynamicLoadingBundled(),
          file: prebuilt.uri,
        ));
        output.dependencies.add(prebuilt.uri);
        stderr.writeln('veilid build hook: bundled prebuilt ${prebuilt.path}');
        return;
      }
    }

    stderr.writeln('veilid build hook: compiling veilid-flutter/rust from source');
    await const RustBuilder(
      assetName: 'veilid_flutter',
      cratePath: 'rust',
      buildMode: BuildMode.debug,
    ).run(input: input, output: output);
  });
}

// Pluggable artifact source. The `artifact_base` user-define overrides the host
// (e.g. a file:// directory for testing, or an alternate mirror).
ArtifactSource _artifactSource(BuildInput input) {
  final override = input.userDefines['artifact_base'];
  if (override is String && override.isNotEmpty) {
    return HttpArtifactSource(Uri.parse(override));
  }
  // TODO(veilid): confirm the GitLab generic package registry path/host.
  return HttpArtifactSource(Uri.parse(
      'https://gitlab.com/api/v4/projects/veilid%2Fveilid/packages/generic/veilid-flutter/'));
}

bool _boolDefine(BuildInput input, String key) {
  final v = input.userDefines[key];
  return v == true || v == 'true' || v == 1;
}
