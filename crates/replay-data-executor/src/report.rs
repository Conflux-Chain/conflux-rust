//! Replay reporting: per-epoch mismatch printing, cross-packet aggregation, the
//! consecutive-mismatch verdict, and the periodic progress line.

use crate::consensus::{EpochReport, RunReport};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// Tracks the longest run of consecutive epochs whose replayed result disagrees
/// with the on-chain commitment. A short run is expected around a block that was
/// honestly blamed; only a long run signals a real replay divergence.
#[derive(Default)]
pub(crate) struct StreakTracker {
    current: usize,
    current_start: u64,
    longest: usize,
    longest_start: u64,
    longest_end: u64,
    total_mismatches: usize,
}

impl StreakTracker {
    pub(crate) fn observe(&mut self, height: u64, matched: bool) {
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

    /// True while an unresolved run of consecutive mismatches is in flight (the
    /// last observed epoch did not match). Lets the driver defer checkpointing
    /// so trie state is only ever persisted at a fully-clean boundary, never in
    /// the middle of a blame run or an incipient real divergence.
    pub(crate) fn in_mismatch_run(&self) -> bool {
        self.current > 0
    }
}

pub(crate) fn epoch_matched(epoch: &EpochReport) -> bool {
    epoch.receipts_root_prefix_match
        && epoch.logs_bloom_prefix_match
        && epoch.state_root_prefix_match
}

/// Succeed unless some run of consecutive mismatches reaches the anomaly
/// threshold, in which case the replay genuinely diverged.
pub(crate) fn finish_verdict(streak: &StreakTracker, anomaly_streak: usize) -> anyhow::Result<()> {
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
pub(crate) struct Totals {
    pub(crate) epoch_count: usize,
    pub(crate) block_count: usize,
    pub(crate) transaction_count: usize,
    pub(crate) receipts_root_prefix_matches: usize,
    pub(crate) logs_bloom_prefix_matches: usize,
    pub(crate) state_root_prefix_matches: usize,
}

pub(crate) fn accumulate(totals: &mut Totals, report: &RunReport) {
    totals.epoch_count += report.epoch_count;
    totals.block_count += report.block_count;
    totals.transaction_count += report.transaction_count;
    totals.receipts_root_prefix_matches += report.receipts_root_prefix_matches;
    totals.logs_bloom_prefix_matches += report.logs_bloom_prefix_matches;
    totals.state_root_prefix_matches += report.state_root_prefix_matches;
}

pub(crate) fn print_single_report(report: &RunReport) {
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

pub(crate) fn report_mismatches(
    epochs: &[EpochReport], verbose_epochs: bool, max_mismatches: usize, printed: &mut usize,
) {
    for epoch in epochs {
        let matched = epoch.receipts_root_prefix_match
            && epoch.logs_bloom_prefix_match
            && epoch.state_root_prefix_match;
        if !verbose_epochs && matched {
            continue;
        }
        if !verbose_epochs {
            if *printed >= max_mismatches {
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

fn format_block_date(timestamp: u64) -> String {
    if timestamp == 0 {
        return "?".to_string();
    }
    let dt = OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!("{}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

/// Emits the one-line `replay progress …` heartbeat at most once a minute.
pub(crate) struct ProgressLogger {
    started: Instant,
    last_log: Instant,
}

impl ProgressLogger {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self { started: now, last_log: now }
    }

    pub(crate) fn maybe_log(
        &mut self, end_epoch: u64, last_block_ts: u64, groups_done: usize,
        totals: &Totals, streak: &StreakTracker,
    ) {
        if self.last_log.elapsed() < Duration::from_secs(60) {
            return;
        }
        eprintln!(
            "replay progress t={}s height={} block_date={} groups={} epochs={} blocks={} txs={} state_match={}/{} longest_mismatch_run={}",
            self.started.elapsed().as_secs(),
            end_epoch,
            format_block_date(last_block_ts),
            groups_done,
            totals.epoch_count,
            totals.block_count,
            totals.transaction_count,
            totals.state_root_prefix_matches,
            totals.epoch_count,
            streak.longest,
        );
        self.last_log = Instant::now();
    }
}
