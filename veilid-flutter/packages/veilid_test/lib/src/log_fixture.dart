import 'package:veilid/veilid.dart';

/// Test logging fixture that formats messages with timestamps and level.
///
/// Uses the LOG_LEVEL dart-define to filter output. Provides both
/// direct logging methods (trace/debug/info/warn/error) and a
/// [processVeilidLog] method for use with the VeilidLog update stream.
/// Global accessor for the log fixture singleton
LogFixture get log => LogFixture.instance;

class LogFixture {
  // ignore: do_not_use_environment
  static const _logLevelStr =
      String.fromEnvironment('LOG_LEVEL', defaultValue: 'info');

  static final LogFixture instance = LogFixture._();

  late final VeilidConfigLogLevel _maxLevel;

  LogFixture._() {
    _maxLevel = VeilidConfigLogLevel.fromJson(_logLevelStr);
  }

  String _timestamp() {
    final dt = DateTime.now();
    return '${dt.hour.toString().padLeft(2, '0')}:'
        '${dt.minute.toString().padLeft(2, '0')}:'
        '${dt.second.toString().padLeft(2, '0')}.'
        '${dt.millisecond.toString().padLeft(3, '0')}';
  }

  bool _shouldLog(VeilidConfigLogLevel level) =>
      level.index <= _maxLevel.index;

  void _log(VeilidConfigLogLevel level, String message) {
    if (_shouldLog(level)) {
      // ignore: avoid_print
      print('${_timestamp()} ${level.name.toUpperCase()} [test] $message');
    }
  }

  /// Process a VeilidLog update from the Veilid core update stream.
  void processVeilidLog(VeilidLog log) {
    final level = switch (log.logLevel) {
      VeilidLogLevel.error => VeilidConfigLogLevel.error,
      VeilidLogLevel.warn => VeilidConfigLogLevel.warn,
      VeilidLogLevel.info => VeilidConfigLogLevel.info,
      VeilidLogLevel.debug => VeilidConfigLogLevel.debug,
      VeilidLogLevel.trace => VeilidConfigLogLevel.trace,
    };
    _log(level, log.message);
  }

  void error(String message) => _log(VeilidConfigLogLevel.error, message);
  void warn(String message) => _log(VeilidConfigLogLevel.warn, message);
  void info(String message) => _log(VeilidConfigLogLevel.info, message);
  void debug(String message) => _log(VeilidConfigLogLevel.debug, message);
  void trace(String message) => _log(VeilidConfigLogLevel.trace, message);
}
