import 'package:equatable/equatable.dart';
import 'package:fixnum/fixnum.dart';
import 'package:meta/meta.dart';

//////////////////////////////////////
/// Timestamp
@immutable
class Timestamp extends Equatable implements Comparable<Timestamp> {
  final BigInt value;

  const Timestamp({required this.value});

  factory Timestamp.zero() => Timestamp(value: BigInt.zero);

  factory Timestamp.fromInt64(Int64 i64) => Timestamp(
    value:
        (BigInt.from((i64 >> 32).toUnsigned(32).toInt()) << 32) |
        BigInt.from(i64.toUnsigned(32).toInt()),
  );

  factory Timestamp.fromString(String s) => Timestamp(value: BigInt.parse(s));

  factory Timestamp.fromJson(dynamic json) =>
      Timestamp.fromString(json as String);

  @override
  List<Object> get props => [value];

  @override
  int compareTo(Timestamp other) => value.compareTo(other.value);

  bool operator <(Timestamp other) => compareTo(other) < 0;

  bool operator <=(Timestamp other) => compareTo(other) <= 0;

  bool operator >(Timestamp other) => compareTo(other) > 0;

  bool operator >=(Timestamp other) => compareTo(other) >= 0;

  @override
  String toString() => value.toString();

  String toJson() => toString();

  Int64 toInt64() => Int64.fromInts(
    (value >> 32).toUnsigned(32).toInt(),
    value.toUnsigned(32).toInt(),
  );

  TimestampDuration diff(Timestamp other) =>
      TimestampDuration(value: value - other.value);

  Timestamp offset(TimestampDuration dur) =>
      Timestamp(value: value + dur.value);
}

@immutable
class TimestampDuration extends Equatable
    implements Comparable<TimestampDuration> {
  final BigInt value;

  const TimestampDuration({required this.value});

  factory TimestampDuration.fromInt64(Int64 i64) => TimestampDuration(
    value:
        (BigInt.from((i64 >> 32).toUnsigned(32).toInt()) << 32) |
        BigInt.from(i64.toUnsigned(32).toInt()),
  );

  factory TimestampDuration.fromMillis(int millis) =>
      TimestampDuration(value: BigInt.from(millis) * BigInt.from(1000));

  factory TimestampDuration.fromDuration(Duration d) => TimestampDuration(
    value:
        BigInt.from(d.inSeconds) * BigInt.from(1000000) +
        BigInt.from(d.inMicroseconds % 1000000),
  );

  factory TimestampDuration.fromString(String s) =>
      TimestampDuration(value: BigInt.parse(s));

  factory TimestampDuration.fromJson(dynamic json) =>
      TimestampDuration.fromString(json as String);

  @override
  List<Object> get props => [value];

  @override
  int compareTo(TimestampDuration other) => value.compareTo(other.value);

  bool operator <(TimestampDuration other) => compareTo(other) < 0;

  bool operator <=(TimestampDuration other) => compareTo(other) <= 0;

  bool operator >(TimestampDuration other) => compareTo(other) > 0;

  bool operator >=(TimestampDuration other) => compareTo(other) >= 0;

  @override
  String toString() {
    final biDay = BigInt.from(1000000) * BigInt.from(60 * 60 * 24);
    final biHour = BigInt.from(1000000) * BigInt.from(60 * 60);
    final biMin = BigInt.from(1000000) * BigInt.from(60);
    final biSec = BigInt.from(1000000);
    final biMsec = BigInt.from(1000);

    final days = (value ~/ biDay).toInt();
    final dvalue = value % biDay;
    final hours = (dvalue ~/ biHour).toInt();
    final hvalue = dvalue % biHour;
    final mins = (hvalue ~/ biMin).toInt();
    final mvalue = hvalue % biMin;
    final secs = (mvalue ~/ biSec).toInt();
    final svalue = mvalue % biSec;
    final msecs = (svalue ~/ biMsec).toInt();
    final uvalue = svalue % biMsec;

    if (days == 0 && hours == 0 && mins == 0 && secs == 0) {
      // microseconds format
      return '$msecs.${uvalue.toString().padLeft(3, '0')}ms';
    }
    var out = '';
    if (days != 0) {
      out += '${days}d';
    }
    if (hours != 0) {
      out += '${hours}h';
    }
    if (mins != 0) {
      out += '${mins}m';
    }
    return '$out$secs.${msecs.toString().padLeft(3, '0')}s';
  }

  String toJson() => value.toString();

  Int64 toInt64() => Int64.fromInts(
    (value >> 32).toUnsigned(32).toInt(),
    value.toUnsigned(32).toInt(),
  );

  double toMillis() => value / BigInt.from(1000);

  double toSecs() => value / BigInt.from(1000000);

  BigInt toMicros() => value;
}
