import 'dart:async';
import 'dart:typed_data';

import 'veilid.dart';

//////////////////////////////////////
/// VeilidRoutingContext

abstract class VeilidRoutingContext {
  void close();

  // Modifiers
  VeilidRoutingContext withDefaultSafety({bool closeSelf = false});
  VeilidRoutingContext withSafety(
    SafetySelection safetySelection, {
    bool closeSelf = false,
  });
  VeilidRoutingContext withSequencing(
    Sequencing sequencing, {
    bool closeSelf = false,
  });
  Future<SafetySelection> safety();

  // App call/message
  Future<Uint8List> appCall(Target target, Uint8List request);
  Future<void> appMessage(Target target, Uint8List message);

  // DHT Operations
  Future<DHTRecordDescriptor> createDHTRecord(
    CryptoKind kind,
    DHTSchema schema, {
    KeyPair? owner,
  });
  Future<DHTRecordDescriptor> openDHTRecord(RecordKey key, {KeyPair? writer});
  Future<void> closeDHTRecord(RecordKey key);
  Future<void> deleteDHTRecord(RecordKey key);
  Future<ValueData?> getDHTValue(
    RecordKey key,
    int subkey, {
    bool forceRefresh = false,
  });
  Future<ValueData?> setDHTValue(
    RecordKey key,
    int subkey,
    Uint8List data, {
    SetDHTValueOptions? options,
  });
  Future<bool> watchDHTValues(
    RecordKey key, {
    List<ValueSubkeyRange>? subkeys,
    Timestamp? expiration,
    int? count,
  });
  Future<bool> cancelDHTWatch(RecordKey key, {List<ValueSubkeyRange>? subkeys});
  Future<DHTRecordReport> inspectDHTRecord(
    RecordKey key, {
    List<ValueSubkeyRange>? subkeys,
    DHTReportScope scope = DHTReportScope.local,
  });
}
