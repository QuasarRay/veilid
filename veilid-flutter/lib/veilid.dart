import 'dart:async';
import 'dart:typed_data';

import 'package:equatable/equatable.dart';
import 'package:freezed_annotation/freezed_annotation.dart';

//////////////////////////////////////////////////////////

import 'routing_context.dart';
import 'veilid_config.dart';
import 'veilid_crypto.dart';
import 'veilid_dht_transaction.dart';
import 'veilid_state.dart';
import 'veilid_stub.dart'
    if (dart.library.io) 'veilid_ffi.dart'
    if (dart.library.js) 'veilid_js.dart';
import 'veilid_table_db.dart';
import 'veilid_timestamp.dart';
import 'veilid_types.dart';

export 'default_config.dart';
export 'routing_context.dart';
export 'value_subkey_range.dart';
export 'veilid.dart';
export 'veilid_api_exception.dart';
export 'veilid_config.dart';
export 'veilid_crypto.dart';
export 'veilid_dht_transaction.dart';
export 'veilid_encoding.dart';
export 'veilid_state.dart';
export 'veilid_table_db.dart';
export 'veilid_timestamp.dart';
export 'veilid_types.dart';

//////////////////////////////////////
/// VeilidVersion

@immutable
class VeilidVersion extends Equatable {
  final int major;

  final int minor;

  final int patch;

  const VeilidVersion(this.major, this.minor, this.patch);

  @override
  List<Object> get props => [major, minor, patch];
}

//////////////////////////////////////
/// Veilid singleton factory

abstract class Veilid {
  static Veilid instance = getVeilid();

  void initializeVeilidCore(Map<String, dynamic> platformConfigJson);
  void changeLogLevel(String layer, String directives);
  @Deprecated("'ignore' syntax was confusing, migrate to changeLogLevel")
  void changeLogIgnore(String layer, List<String> changes);
  Future<Stream<VeilidUpdate>> startupVeilidCore(VeilidConfig config);
  Future<VeilidState> getVeilidState();
  Future<bool> isShutdown();
  Future<void> attach();
  Future<void> detach();
  Future<void> shutdownVeilidCore();

  // Crypto
  List<CryptoKind> validCryptoKinds();
  Future<VeilidCryptoSystem> getCryptoSystem(CryptoKind kind);
  Future<List<PublicKey>?> verifySignatures(
    List<PublicKey> publicKeys,
    Uint8List data,
    List<Signature> signatures,
  );
  Future<List<Signature>> generateSignatures(
    Uint8List data,
    List<KeyPair> keyPairs,
  );
  Future<KeyPair> generateKeyPair(CryptoKind kind);

  // Routing context
  Future<VeilidRoutingContext> routingContext();
  Future<VeilidRoutingContext> safeRoutingContext({
    Stability stability = Stability.lowLatency,
    Sequencing sequencing = Sequencing.preferOrdered,
  }) async {
    final rc = await routingContext();
    final originalSafety = await rc.safety() as SafetySelectionSafe;
    final safetySpec = originalSafety.safetySpec.copyWith(
      stability: stability,
      sequencing: sequencing,
    );
    return rc.withSafety(
      SafetySelectionSafe(safetySpec: safetySpec),
      closeSelf: true,
    );
  }

  Future<VeilidRoutingContext> unsafeRoutingContext({
    Sequencing sequencing = Sequencing.preferOrdered,
  }) async => (await routingContext()).withSafety(
    SafetySelectionUnsafe(sequencing: sequencing),
  );

  // DHT operations
  Future<MemberId> generateMemberId(PublicKey writerKey);
  Future<RecordKey> getDHTRecordKey(
    DHTSchema schema,
    PublicKey owner,
    SharedSecret? encryptionKey,
  );
  Future<VeilidDHTTransaction> transactDHTRecords(
    List<RecordKey> recordKeys, {
    TransactDHTRecordsOptions? options,
  });

  // Private route allocation
  Future<RouteBlob> newPrivateRoute();
  Future<RouteBlob> newCustomPrivateRoute(PrivateSpec privateSpec);

  Future<RouteId> importRemotePrivateRoute(Uint8List blob);
  Future<void> releasePrivateRoute(RouteId routeId);

  // App calls
  Future<void> appCallReply(String callId, Uint8List message);

  // TableStore
  Future<VeilidTableDB> openTableDB(String name, int columnCount);
  Future<bool> deleteTableDB(String name);

  // Misc
  Timestamp now();
  String veilidVersionString();
  VeilidVersion veilidVersion();
  String defaultVeilidConfig();
  Future<String> debug(String command);

  /// Return the features that were enabled when veilid-core was built.
  List<String> veilidFeatures();
}
