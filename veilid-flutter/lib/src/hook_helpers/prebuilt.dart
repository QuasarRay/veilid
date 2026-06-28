// ignore_for_file: public_member_api_docs

import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';

import 'checksums.dart';

/// A swappable source of prebuilt `veilid_flutter` binaries. GitLab is the
/// default, but the deployment backend is intentionally pluggable.
abstract interface class ArtifactSource {
  /// Absolute URL of [fileName] for [version] + [rustTriple].
  Uri urlFor({
    required String version,
    required String rustTriple,
    required String fileName,
  });
}

/// Layout: `<base>/<version>/<triple>/<file>`. Works for https or file URLs.
class HttpArtifactSource implements ArtifactSource {
  HttpArtifactSource(Uri base)
      : base = base.path.endsWith('/') ? base : base.replace(path: '${base.path}/');
  final Uri base;

  @override
  Uri urlFor({
    required String version,
    required String rustTriple,
    required String fileName,
  }) =>
      base.resolve('$version/$rustTriple/$fileName');
}

/// Maps a Dart target to the Rust target triple (mirrors native_toolchain_rust).
String? rustTripleFor(CodeConfig code) {
  final os = code.targetOS;
  final arch = code.targetArchitecture;
  if (os == OS.macOS) {
    if (arch == Architecture.arm64) return 'aarch64-apple-darwin';
    if (arch == Architecture.x64) return 'x86_64-apple-darwin';
  } else if (os == OS.iOS) {
    final sim = code.iOS.targetSdk == IOSSdk.iPhoneSimulator;
    if (arch == Architecture.arm64) {
      return sim ? 'aarch64-apple-ios-sim' : 'aarch64-apple-ios';
    }
    if (arch == Architecture.x64) return 'x86_64-apple-ios';
  } else if (os == OS.android) {
    if (arch == Architecture.arm) return 'armv7-linux-androideabi';
    if (arch == Architecture.arm64) return 'aarch64-linux-android';
    if (arch == Architecture.x64) return 'x86_64-linux-android';
  } else if (os == OS.linux) {
    if (arch == Architecture.arm64) return 'aarch64-unknown-linux-gnu';
    if (arch == Architecture.x64) return 'x86_64-unknown-linux-gnu';
  } else if (os == OS.windows) {
    if (arch == Architecture.arm64) return 'aarch64-pc-windows-msvc';
    if (arch == Architecture.x64) return 'x86_64-pc-windows-msvc';
  }
  return null;
}

/// Canonical bundled file name per OS, so the Apple framework comes out as
/// `veilid_flutter.framework/veilid_flutter` (same as the RustBuilder output).
String bundledFileName(OS os) {
  if (os == OS.windows) return 'veilid_flutter.dll';
  if (os == OS.macOS || os == OS.iOS) return 'libveilid_flutter.dylib';
  return 'libveilid_flutter.so';
}

/// Returns the verified prebuilt [File] for this target, or `null` when no
/// pinned checksum exists for it (=> caller compiles from source). Throws on a
/// checksum mismatch or a failed download.
Future<File?> fetchPrebuilt({
  required BuildInput input,
  required ArtifactSource source,
}) async {
  if (kPrebuiltVersion.isEmpty) return null;
  final code = input.config.code;
  final triple = rustTripleFor(code);
  if (triple == null) return null;
  final expected = kPrebuiltSha256[triple];
  if (expected == null) return null;

  final fileName = bundledFileName(code.targetOS);
  final cached =
      File.fromUri(input.outputDirectoryShared.resolve('$triple/$fileName'));
  if (cached.existsSync() && await _sha256(cached) == expected) return cached;

  final url = source.urlFor(
      version: kPrebuiltVersion, rustTriple: triple, fileName: fileName);
  final bytes = await _download(url);
  cached.parent.createSync(recursive: true);
  await cached.writeAsBytes(bytes);
  final got = await _sha256(cached);
  if (got != expected) {
    cached.deleteSync();
    throw Exception(
        'veilid prebuilt checksum mismatch for $triple: expected $expected, '
        'got $got (url: $url)');
  }
  return cached;
}

Future<String> _sha256(File f) async =>
    sha256.convert(await f.readAsBytes()).toString();

Future<Uint8List> _download(Uri url) async {
  if (url.scheme == 'file') {
    return File.fromUri(url).readAsBytes();
  }
  final client = HttpClient()..findProxy = HttpClient.findProxyFromEnvironment;
  try {
    final resp = await (await client.getUrl(url)).close();
    if (resp.statusCode != 200) {
      throw Exception('veilid prebuilt download failed ${resp.statusCode}: $url');
    }
    final b = BytesBuilder(copy: false);
    await for (final chunk in resp) {
      b.add(chunk);
    }
    return b.takeBytes();
  } finally {
    client.close(force: true);
  }
}
