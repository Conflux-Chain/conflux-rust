use anyhow::{Context, Result};
use cfx_replay_data_executor::replay_exec::{
    EpochExecReport, ReplayExecConfig, ReplayExecReport, ReplayExecutor,
};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(name = "cfx-replay-exec")]
struct Cli {
    /// A single packet file, or a directory of `.cfxpack` containers that are
    /// replayed in epoch order through one cumulative executor.
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[arg(long, default_value_t = false)]
    verbose_epochs: bool,
    #[arg(long, default_value_t = 20)]
    max_mismatches: usize,
    /// The replay is only considered anomalous when this many epochs in a row
    /// disagree with their on-chain commitments. Isolated mismatches are
    /// tolerated: a block that an honest node later blamed carries deferred
    /// roots that the network itself rejected, so the correct replay legitimately
    /// disagrees with it for a short stretch before the chain self-corrects.
    #[arg(long, default_value_t = 20)]
    anomaly_streak: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = ReplayExecConfig {
        config_path: cli.config.clone(),
    };
    let mut executor = ReplayExecutor::new(config)?;

    if cli.input.is_dir() {
        run_packed_dir(&mut executor, &cli)
    } else {
        let packet = std::fs::read(&cli.input)
            .with_context(|| format!("read packet {}", cli.input.display()))?;
        let report = executor.execute_packet(&packet)?;
        print_single_report(&report);
        report_mismatches(&report.epochs, &cli, &mut 0);
        let mut streak = StreakTracker::default();
        for epoch in &report.epochs {
            streak.observe(epoch.pivot_height, epoch_matched(epoch));
        }
        finish_verdict(&streak, cli.anomaly_streak)
    }
}

/// Tracks the longest run of consecutive epochs whose replayed result disagrees
/// with the on-chain commitment. A short run is expected around a block that was
/// honestly blamed; only a long run signals a real replay divergence.
#[derive(Default)]
struct StreakTracker {
    current: usize,
    current_start: u64,
    longest: usize,
    longest_start: u64,
    longest_end: u64,
    total_mismatches: usize,
}

impl StreakTracker {
    fn observe(&mut self, height: u64, matched: bool) {
        if matched {
            self.current = 0;
            return;
        }
        self.total_mismatches += 1;
        if self.current == 0 {
            self.current_start = height;
        }
        self.current += 1;
        if self.current > self.longest {
            self.longest = self.current;
            self.longest_start = self.current_start;
            self.longest_end = height;
        }
    }
}

fn epoch_matched(epoch: &EpochExecReport) -> bool {
    epoch.receipts_root_prefix_match
        && epoch.logs_bloom_prefix_match
        && epoch.state_root_prefix_match
}

/// Succeed unless some run of consecutive mismatches reaches the anomaly
/// threshold, in which case the replay genuinely diverged.
fn finish_verdict(streak: &StreakTracker, anomaly_streak: usize) -> Result<()> {
    if streak.total_mismatches == 0 {
        println!("verification ok: all epochs match");
    } else {
        println!(
            "verification: {} isolated mismatching epoch(s), longest consecutive run = {} (heights {}..={}), tolerance = {}",
            streak.total_mismatches,
            streak.longest,
            streak.longest_start,
            streak.longest_end,
            anomaly_streak,
        );
    }
    anyhow::ensure!(
        streak.longest < anomaly_streak,
        "replay anomaly: {} consecutive epochs disagree with chain (heights {}..={}), \
         exceeding tolerance of {}",
        streak.longest,
        streak.longest_start,
        streak.longest_end,
        anomaly_streak,
    );
    Ok(())
}

/// Aggregated counters across every packet in a directory run.
#[derive(Default)]
struct Totals {
    epoch_count: usize,
    block_count: usize,
    transaction_count: usize,
    receipts_root_prefix_matches: usize,
    logs_bloom_prefix_matches: usize,
    state_root_prefix_matches: usize,
}

fn run_packed_dir(executor: &mut ReplayExecutor, cli: &Cli) -> Result<()> {
    let mut files = std::fs::read_dir(&cli.input)
        .with_context(|| format!("read dir {}", cli.input.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().map(|ext| ext == "cfxpack").unwrap_or(false))
        .collect::<Vec<_>>();
    // Files are named `<prefix>_<start_epoch>_<end_epoch>.cfxpack`; epoch order
    // is required so the cumulative executor sees a contiguous chain.
    files.sort_by_key(|path| container_start_epoch(path).unwrap_or(u64::MAX));
    anyhow::ensure!(!files.is_empty(), "no .cfxpack files in {}", cli.input.display());

    let mut totals = Totals::default();
    let mut printed_mismatches = 0usize;
    let mut groups_done = 0usize;
    let mut streak = StreakTracker::default();
    // Report progress on a wall-clock cadence (once a minute) rather than per
    // a fixed group count, so progress is visible regardless of throughput.
    let started = Instant::now();
    let mut last_log = Instant::now();
    for path in &files {
        let data = std::fs::read(path)
            .with_context(|| format!("read container {}", path.display()))?;
        let entries = parse_container_directory(&data)
            .with_context(|| format!("parse container {}", path.display()))?;
        for (start_epoch, _epoch_count, offset, length) in entries {
            let payload = &data[offset..offset + length];
            let report = executor.execute_packet(payload).with_context(|| {
                format!("execute group starting at epoch {start_epoch}")
            })?;
            accumulate(&mut totals, &report);
            report_mismatches(&report.epochs, cli, &mut printed_mismatches);
            for epoch in &report.epochs {
                streak.observe(epoch.pivot_height, epoch_matched(epoch));
            }
            groups_done += 1;
            if last_log.elapsed() >= Duration::from_secs(60) {
                eprintln!(
                    "replay progress t={}s groups={} epochs={} blocks={} txs={} state_match={}/{} longest_mismatch_run={}",
                    started.elapsed().as_secs(),
                    groups_done,
                    totals.epoch_count,
                    totals.block_count,
                    totals.transaction_count,
                    totals.state_root_prefix_matches,
                    totals.epoch_count,
                    streak.longest,
                );
                last_log = Instant::now();
            }
        }
    }

    println!(
        "executed packed dir: files={}, epochs={}, blocks={}, txs={}, receipt_matches={}, log_matches={}, state_matches={}",
        files.len(),
        totals.epoch_count,
        totals.block_count,
        totals.transaction_count,
        totals.receipts_root_prefix_matches,
        totals.logs_bloom_prefix_matches,
        totals.state_root_prefix_matches,
    );
    finish_verdict(&streak, cli.anomaly_streak)
}

fn accumulate(totals: &mut Totals, report: &ReplayExecReport) {
    totals.epoch_count += report.epoch_count;
    totals.block_count += report.block_count;
    totals.transaction_count += report.transaction_count;
    totals.receipts_root_prefix_matches += report.receipts_root_prefix_matches;
    totals.logs_bloom_prefix_matches += report.logs_bloom_prefix_matches;
    totals.state_root_prefix_matches += report.state_root_prefix_matches;
}

fn print_single_report(report: &ReplayExecReport) {
    println!(
        "executed packet: epochs={}, blocks={}, txs={}, receipt_matches={}, log_matches={}, state_matches={}",
        report.epoch_count,
        report.block_count,
        report.transaction_count,
        report.receipts_root_prefix_matches,
        report.logs_bloom_prefix_matches,
        report.state_root_prefix_matches,
    );
}

fn report_mismatches(epochs: &[EpochExecReport], cli: &Cli, printed: &mut usize) {
    for epoch in epochs {
        let matched = epoch.receipts_root_prefix_match
            && epoch.logs_bloom_prefix_match
            && epoch.state_root_prefix_match;
        if !cli.verbose_epochs && matched {
            continue;
        }
        if !cli.verbose_epochs {
            if *printed >= cli.max_mismatches {
                continue;
            }
            *printed += 1;
        }
        println!(
            "epoch height={} deferred_height={} pivot={:?} blocks={} txs={} receipts_prefix_match={} logs_prefix_match={} state_prefix_match={} computed_receipts={:?} expected_receipts_prefix={:?} computed_logs={:?} expected_logs_prefix={:?} computed_state={:?} expected_state_prefix={:?}",
            epoch.pivot_height,
            epoch.deferred_height,
            epoch.pivot_hash,
            epoch.block_count,
            epoch.transaction_count,
            epoch.receipts_root_prefix_match,
            epoch.logs_bloom_prefix_match,
            epoch.state_root_prefix_match,
            epoch.computed_receipts_root,
            epoch.expected_receipts_root_prefix,
            epoch.computed_logs_bloom_hash,
            epoch.expected_logs_bloom_hash_prefix,
            epoch.computed_state_root,
            epoch.expected_state_root_prefix,
        );
    }
}


const CONTAINER_MAGIC: &[u8; 8] = b"CFXPACK1";
const CONTAINER_HEADER_LEN: usize = 24;
const CONTAINER_DIR_ENTRY_LEN: usize = 32;

/// Parse a `.cfxpack` container directory, returning `(start_epoch, epoch_count,
/// payload_offset, payload_length)` per 2000-epoch group, in file order.
fn parse_container_directory(data: &[u8]) -> Result<Vec<(u64, u64, usize, usize)>> {
    anyhow::ensure!(
        data.len() >= CONTAINER_HEADER_LEN && &data[0..8] == CONTAINER_MAGIC,
        "not a cfxpack container"
    );
    let group_count = u32::from_le_bytes(data[12..16].try_into()?) as usize;
    let mut entries = Vec::with_capacity(group_count);
    let mut pos = CONTAINER_HEADER_LEN;
    for _ in 0..group_count {
        anyhow::ensure!(pos + CONTAINER_DIR_ENTRY_LEN <= data.len(), "truncated directory");
        let start_epoch = u64::from_le_bytes(data[pos..pos + 8].try_into()?);
        let epoch_count = u64::from_le_bytes(data[pos + 8..pos + 16].try_into()?);
        let offset = u64::from_le_bytes(data[pos + 16..pos + 24].try_into()?) as usize;
        let length = u64::from_le_bytes(data[pos + 24..pos + 32].try_into()?) as usize;
        anyhow::ensure!(offset + length <= data.len(), "payload out of bounds");
        entries.push((start_epoch, epoch_count, offset, length));
        pos += CONTAINER_DIR_ENTRY_LEN;
    }
    Ok(entries)
}

fn container_start_epoch(path: &Path) -> Option<u64> {
    let stem = path.file_stem()?.to_str()?;
    // `<prefix>_<start>_<end>` -> second-to-last underscore field
    let mut parts = stem.rsplit('_');
    let _end = parts.next()?;
    parts.next()?.parse().ok()
}
