import 'processor_connection_state.dart';

/// Abstraction over a network-aware retry policy and Veilid attachment
/// state.
///
/// Production app code implements this against the live Veilid attachment
/// state (see veilidchat's `VeilidProcessorRepository`). Integration-test
/// harnesses provide their own implementation backed by their fixture-side
/// connection-state stream so code under test doesn't depend on the
/// singletons the production app stands up.
abstract class VeilidProcessorInterface {
  /// Run [closure], retrying it through transient network unavailability
  /// and DHT `tryAgain`/`notAvailable` failures. Throws `TimeoutException`
  /// if [timeout] elapses before either a successful run or a clean
  /// terminating exception. Other exceptions propagate.
  Future<T> retry<T>(
    Future<T> Function() closure, {
    Duration? timeout,
  });

  /// Latest snapshot of the Veilid attachment + network state.
  ProcessorConnectionState get processorConnectionState;

  /// Stream of [ProcessorConnectionState] updates as Veilid attachment /
  /// network state changes. Each implementation decides whether to emit on
  /// every update or only on changes; consumers should treat values as
  /// snapshots of the current state.
  Stream<ProcessorConnectionState> streamProcessorConnectionState();
}
