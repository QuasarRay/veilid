use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Serialize)]
pub struct BenchmarkReport {
    pub node_id: String,
    pub timestamp: String,
    pub results: Vec<BenchmarkEntry>,
    pub summary: Vec<BenchmarkSummary>,
}

#[derive(Serialize)]
pub struct BenchmarkEntry {
    pub name: String,
    pub category: String,
    pub iteration: usize,
    pub duration_us: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throughput_mbps: Option<f64>,
    pub timed_out: bool,
}

#[derive(Serialize)]
pub struct BenchmarkSummary {
    pub name: String,
    pub count: usize,
    pub timeout_count: usize,
    pub min_us: u128,
    pub max_us: u128,
    pub median_us: u128,
    pub mean_us: u128,
    pub p5_us: u128,
    pub p95_us: u128,
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = p / 100.0 * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let frac = rank - lower as f64;
        let lo = sorted[lower] as f64;
        let hi = sorted[upper] as f64;
        (lo + frac * (hi - lo)).round() as u128
    }
}

impl BenchmarkSummary {
    fn compute(name: &str, times: &mut Vec<u128>, timeout_count: usize) -> Self {
        times.sort();
        let count = times.len();
        if count == 0 {
            return Self {
                name: name.to_string(),
                count: 0,
                timeout_count,
                min_us: 0,
                max_us: 0,
                median_us: 0,
                mean_us: 0,
                p5_us: 0,
                p95_us: 0,
            };
        }
        let min_us = times[0];
        let max_us = times[count - 1];
        let mean_us = times.iter().sum::<u128>() / count as u128;
        let median_us = percentile(times, 50.0);
        let p5_us = percentile(times, 5.0);
        let p95_us = percentile(times, 95.0);

        Self {
            name: name.to_string(),
            count,
            timeout_count,
            min_us,
            max_us,
            median_us,
            mean_us,
            p5_us,
            p95_us,
        }
    }
}

impl BenchmarkReport {
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            results: Vec::new(),
            summary: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &str, category: &str, result: &super::benchmarks::BenchmarkResult) {
        let throughput_mbps = if result.timed_out {
            None
        } else {
            result.bytes.map(|b| {
                let duration_secs = result.duration_us as f64 / 1_000_000.0;
                if duration_secs > 0.0 {
                    (b as f64 / 1_000_000.0) / duration_secs
                } else {
                    0.0
                }
            })
        };

        self.results.push(BenchmarkEntry {
            name: name.to_string(),
            category: category.to_string(),
            iteration: result.iteration,
            duration_us: result.duration_us,
            bytes: result.bytes,
            throughput_mbps,
            timed_out: result.timed_out,
        });
    }

    fn compute_summary(&mut self) {
        let mut grouped: BTreeMap<String, Vec<u128>> = BTreeMap::new();
        let mut timeout_counts: BTreeMap<String, usize> = BTreeMap::new();
        for entry in &self.results {
            if entry.timed_out {
                *timeout_counts.entry(entry.name.clone()).or_default() += 1;
            } else {
                grouped
                    .entry(entry.name.clone())
                    .or_default()
                    .push(entry.duration_us);
            }
            // Ensure every name appears in grouped even if all timed out
            grouped.entry(entry.name.clone()).or_default();
        }

        self.summary = grouped
            .iter_mut()
            .map(|(name, times)| {
                let tc = timeout_counts.get(name).copied().unwrap_or(0);
                BenchmarkSummary::compute(name, times, tc)
            })
            .collect();
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn print_summary(&mut self) {
        self.compute_summary();

        println!("\n=== Benchmark Summary ===");
        println!("Node: {}", self.node_id);
        println!("Time: {}", self.timestamp);
        println!("Results: {} entries\n", self.results.len());
        println!(
            "  {:<30} {:>5} {:>4} {:>12} {:>12} {:>12} {:>12} {:>12}",
            "name", "n", "t/o", "median", "mean", "p5", "p95", "min..max"
        );
        println!("  {}", "-".repeat(101));

        for s in &self.summary {
            println!(
                "  {:<30} {:>5} {:>4} {:>10}µs {:>10}µs {:>10}µs {:>10}µs {:>10}..{}µs",
                s.name,
                s.count,
                s.timeout_count,
                s.median_us,
                s.mean_us,
                s.p5_us,
                s.p95_us,
                s.min_us,
                s.max_us
            );
        }
    }
}
