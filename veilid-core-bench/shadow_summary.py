#!/usr/bin/env python3
"""
Aggregate Shadow benchmark results across all nodes.
Usage: python shadow_summary.py [shadow.data]
"""

import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def percentile(sorted_vals, p):
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = p / 100.0 * (len(sorted_vals) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return sorted_vals[lower]
    frac = rank - lower
    return round(sorted_vals[lower] + frac * (sorted_vals[upper] - sorted_vals[lower]))


def compute_stats(times, timeout_count=0):
    times.sort()
    n = len(times)
    if n == 0:
        return {
            "count": 0,
            "timeout_count": timeout_count,
            "min_us": 0,
            "max_us": 0,
            "mean_us": 0,
            "median_us": 0,
            "p5_us": 0,
            "p95_us": 0,
        }
    return {
        "count": n,
        "timeout_count": timeout_count,
        "min_us": times[0],
        "max_us": times[-1],
        "mean_us": round(sum(times) / n),
        "median_us": percentile(times, 50),
        "p5_us": percentile(times, 5),
        "p95_us": percentile(times, 95),
    }


def classify_node(node_id):
    if node_id.startswith("bootstrap"):
        return "bootstrap"
    for cls in ("vslow", "slow", "fast", "med"):
        if f"-{cls}-" in node_id:
            return cls
    return "other"


def format_us(us):
    if us >= 1_000_000:
        return f"{us / 1_000_000:.2f}s"
    if us >= 1_000:
        return f"{us / 1_000:.1f}ms"
    return f"{us}µs"


def print_group(group_name, node_count, benchmarks):
    print(f"\n--- {group_name} ({node_count} nodes) ---\n")
    print(
        f"  {'benchmark':<30} {'n':>6} {'t/o':>5} {'median':>12} {'mean':>12}"
        f" {'p5':>12} {'p95':>12} {'min':>12} {'max':>12}"
    )
    print(f"  {'-' * 113}")

    for name, stats in benchmarks:
        print(
            f"  {name:<30} {stats['count']:>6} {stats['timeout_count']:>5}"
            f" {format_us(stats['median_us']):>12}"
            f" {format_us(stats['mean_us']):>12}"
            f" {format_us(stats['p5_us']):>12}"
            f" {format_us(stats['p95_us']):>12}"
            f" {format_us(stats['min_us']):>12}"
            f" {format_us(stats['max_us']):>12}"
        )


def main():
    data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("shadow.data")

    if not data_dir.exists():
        print(f"Error: '{data_dir}' not found", file=sys.stderr)
        sys.exit(1)

    hosts_dir = data_dir / "hosts"
    if not hosts_dir.exists():
        print(f"Error: '{hosts_dir}' not found", file=sys.stderr)
        sys.exit(1)

    # Collect all results
    all_times = defaultdict(list)  # benchmark_name -> [durations] (successful only)
    all_timeouts = defaultdict(int)  # benchmark_name -> timeout count
    by_class = defaultdict(lambda: defaultdict(list))  # class -> name -> [durations]
    by_class_timeouts = defaultdict(lambda: defaultdict(int))  # class -> name -> timeout count
    node_counts = defaultdict(int)
    total_nodes = 0

    for results_file in sorted(hosts_dir.glob("*/results.json")):
        try:
            report = json.loads(results_file.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: skipping {results_file}: {e}", file=sys.stderr)
            continue

        node_id = report.get("node_id", results_file.parent.name)
        cls = classify_node(node_id)
        node_counts[cls] += 1
        total_nodes += 1

        for entry in report.get("results", []):
            name = entry["name"]
            if entry.get("timed_out", False):
                all_timeouts[name] += 1
                by_class_timeouts[cls][name] += 1
                # Ensure name appears in times dicts even if all timed out
                _ = all_times[name]
                _ = by_class[cls][name]
            else:
                duration = entry["duration_us"]
                all_times[name].append(duration)
                by_class[cls][name].append(duration)

    if total_nodes == 0:
        print("Error: no results found", file=sys.stderr)
        sys.exit(1)

    # Print header
    print("=== Shadow Benchmark Summary ===")
    print(f"Data: {data_dir}")
    print(f"Nodes: {total_nodes}")
    for cls in ("bootstrap", "fast", "med", "slow", "vslow", "other"):
        if cls in node_counts:
            print(f"  {cls}: {node_counts[cls]}")

    # Overall
    overall = [
        (name, compute_stats(list(times), all_timeouts.get(name, 0)))
        for name, times in sorted(all_times.items())
    ]
    print_group("all nodes", total_nodes, overall)

    # Per class
    summary_json = {
        "data_dir": str(data_dir),
        "total_nodes": total_nodes,
        "groups": [
            {
                "group": "all nodes",
                "node_count": total_nodes,
                "benchmarks": [{"name": n, "stats": s} for n, s in overall],
            }
        ],
    }

    for cls in ("bootstrap", "fast", "med", "slow", "vslow", "other"):
        if cls not in by_class:
            continue
        entries = by_class[cls]
        count = node_counts[cls]
        cls_timeouts = by_class_timeouts.get(cls, {})
        benchmarks = [
            (name, compute_stats(list(times), cls_timeouts.get(name, 0)))
            for name, times in sorted(entries.items())
        ]
        print_group(cls, count, benchmarks)
        summary_json["groups"].append(
            {
                "group": cls,
                "node_count": count,
                "benchmarks": [{"name": n, "stats": s} for n, s in benchmarks],
            }
        )

    # Save JSON
    output_path = data_dir / "summary.json"
    output_path.write_text(json.dumps(summary_json, indent=2))
    print(f"\nSummary saved to {output_path}")


if __name__ == "__main__":
    main()
