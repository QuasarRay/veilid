import 'dart:convert';

import 'package:path_provider/path_provider.dart';

import 'veilid.dart';

/// Build a [VeilidConfig] from veilid-core's defaults, overriding the
/// program/storage/network fields most callers need to set.
///
/// Off the web the stores go under [storageDirectory], or under the
/// application support directory when it is null. An embedder that starts a
/// node off the main isolate passes it: path_provider is a platform-channel
/// call, and such an isolate has no messenger bound to make one.
/// [bootstrap] is comma-separated, and empty keeps the default.
/// [bootstrapKeys] is comma-separated, empty for none, and null keeps the
/// default. [bootstrapRecords] (whose lines hold commas of their own) and
/// [bootstrapProtocols] are lists, and null keeps the default.
Future<VeilidConfig> getDefaultVeilidConfig({
  required bool isWeb,
  required String programName,
  String bootstrap = '',
  String? bootstrapKeys,
  List<String>? bootstrapRecords,
  List<VeilidConfigBootstrapProtocol>? bootstrapProtocols,
  String namespace = '',
  String deviceEncryptionKeyPassword = '',
  String? newDeviceEncryptionKeyPassword,
  String networkKeyPassword = '',
  String? storageDirectory,
}) async {
  final defaultConfigStr = Veilid.instance.defaultVeilidConfig();
  final defaultConfig = VeilidConfig.fromJson(jsonDecode(defaultConfigStr));
  // Resolved once, and not at all on web or when the caller supplied it
  final storageDir = isWeb
      ? ''
      : storageDirectory ??
            (await getApplicationSupportDirectory()).absolute.path;
  return defaultConfig.copyWith(
    programName: programName,
    namespace: namespace,
    storage: defaultConfig.storage.copyWith(directory: storageDir),
    protectedStore: defaultConfig.protectedStore.copyWith(
      deviceEncryptionKeyPassword: deviceEncryptionKeyPassword,
      newDeviceEncryptionKeyPassword: newDeviceEncryptionKeyPassword,
    ),
    network: defaultConfig.network.copyWith(
      networkKeyPassword: networkKeyPassword,
      routingTable: defaultConfig.network.routingTable.copyWith(
        bootstrap: bootstrap.isNotEmpty
            ? bootstrap.split(',')
            : defaultConfig.network.routingTable.bootstrap,
        bootstrapKeys: bootstrapKeys != null
            ? bootstrapKeys.isNotEmpty
                  ? bootstrapKeys.split(',').map(PublicKey.fromString).toList()
                  : []
            : defaultConfig.network.routingTable.bootstrapKeys,
        bootstrapRecords:
            bootstrapRecords ??
            defaultConfig.network.routingTable.bootstrapRecords,
        bootstrapProtocols:
            bootstrapProtocols ??
            defaultConfig.network.routingTable.bootstrapProtocols,
      ),
    ),
  );
}
