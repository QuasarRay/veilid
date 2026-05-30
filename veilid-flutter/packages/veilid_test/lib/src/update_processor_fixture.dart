import 'dart:async';

import 'package:async_tools/async_tools.dart';
import 'package:veilid/veilid.dart';

import 'veilid_fixture.dart';

class UpdateProcessorFixture implements VeilidProcessorInterface {
  static final _fixtureMutex = Mutex();

  VeilidFixture veilidFixture;

  @override
  ProcessorConnectionState processorConnectionState =
      ProcessorConnectionState(
    attachment: VeilidStateAttachment(
      state: AttachmentState.detached,
      publicInternetReady: false,
      localNetworkReady: false,
      uptime: TimestampDuration(value: BigInt.zero),
      attachedUptime: null,
      reliablePeerCount: BigInt.zero,
      livePeerCount: BigInt.zero,
      estimatedNetworkSize: BigInt.zero,
      medianLatency: null,
      overAttachedNodes: BigInt.zero,
    ),
    network: VeilidStateNetwork(
      started: false,
      bpsDown: BigInt.zero,
      bpsUp: BigInt.zero,
      peers: [],
    ),
  );

  final _connectionStateController =
      StreamController<ProcessorConnectionState>.broadcast(sync: true);

  StreamSubscription<VeilidUpdate>? _updateSubscription;

  @override
  Stream<ProcessorConnectionState> streamProcessorConnectionState() =>
      _connectionStateController.stream;

  UpdateProcessorFixture({required this.veilidFixture});

  /// Test-side implementation of [VeilidProcessorInterface.retry]. Mirrors
  /// veilidchat's `processorRetry`: blocks until the harness sees
  /// publicInternetReady, then runs [closure], retrying on transient
  /// DHT failures (`notAvailable` / `tryAgain`).
  @override
  Future<T> retry<T>(
    Future<T> Function() closure, {
    Duration? timeout,
  }) async {
    final deadline = timeout == null ? null : DateTime.now().add(timeout);
    while (true) {
      if (deadline != null && DateTime.now().isAfter(deadline)) {
        throw TimeoutException('UpdateProcessorFixture.retry timeout');
      }
      if (!processorConnectionState.isPublicInternetReady) {
        var stream = veilidFixture.updateStream
            .where(
              (u) => u is VeilidUpdateAttachment && u.publicInternetReady,
            );
        if (deadline != null) {
          stream = stream.timeout(deadline.difference(DateTime.now()));
        }
        try {
          await stream.first;
        } on TimeoutException {
          throw TimeoutException(
            'UpdateProcessorFixture.retry timeout while '
            'waiting for publicInternetReady',
          );
        }
      }
      try {
        return await closure();
      } on VeilidAPIExceptionTryAgain {
        // veilid_support's DHTExceptionNotAvailable lives outside the
        // veilid package, so we can't catch it explicitly here without a
        // dependency cycle. The inner dhtRetryLoop already absorbs
        // short-term notAvailable failures, so anything that escapes is
        // a genuine signal — let it propagate so the test fails loudly.
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
    }
  }

  Future<void> setUp() async {
    await _fixtureMutex.acquire();
    _updateSubscription = veilidFixture.updateStream.listen((update) {
      if (update is VeilidUpdateNetwork) {
        processorConnectionState = processorConnectionState.copyWith(
          network: VeilidStateNetwork(
            started: update.started,
            bpsDown: update.bpsDown,
            bpsUp: update.bpsUp,
            peers: update.peers,
          ),
        );
        _connectionStateController.add(processorConnectionState);
      } else if (update is VeilidUpdateAttachment) {
        processorConnectionState = processorConnectionState.copyWith(
          attachment: VeilidStateAttachment(
            state: update.state,
            publicInternetReady: update.publicInternetReady,
            localNetworkReady: update.localNetworkReady,
            uptime: update.uptime,
            attachedUptime: update.attachedUptime,
            reliablePeerCount: update.reliablePeerCount,
            livePeerCount: update.livePeerCount,
            estimatedNetworkSize: update.estimatedNetworkSize,
            medianLatency: update.medianLatency,
            overAttachedNodes: update.overAttachedNodes,
          ),
        );
        _connectionStateController.add(processorConnectionState);
      }
    });

    // Seed from current state so consumers don't wait on the next
    // attachment update push if attach() already completed.
    final state = await Veilid.instance.getVeilidState();
    processorConnectionState = processorConnectionState.copyWith(
      attachment: state.attachment,
      network: state.network,
    );
    _connectionStateController.add(processorConnectionState);
  }

  Future<void> tearDown() async {
    assert(_fixtureMutex.isLocked, 'should not tearDown without setUp');
    await _updateSubscription?.cancel();
    _updateSubscription = null;
    await _connectionStateController.close();
    _fixtureMutex.release();
  }
}
