//! Replay reporting: per-epoch mismatch printing, cross-packet aggregation, the
//! consecutive-mismatch verdict, and the periodic progress line.

use crate::consensus::{EpochReport, RunReport};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// Tracks the longest run of consecutive epochs whose replayed result disagrees
/// with the on-chain commitment. With blame labelling, flagged pivots and
/// fold-verified pivots are treated as matched for streak purposes.
#[derive(Default)]
pub(crate) struct StreakTracker {
    current: usize,
    current_start: u64,
    longest: usize,
    longest_start: u64,
    longest_end: u64,
    total_mismatches: usize,
    pub(crate) blamed_skipped: usize,
    pub(crate) fold_verified: usize,
    /// The last observed epoch was blamed-skipped: its "match" is vacuous, so
    /// it is not a sound checkpoint boundary — restore treats the resume
    /// height as a verified anchor and would prune commitments a later
    /// voucher's fold still needs.
    last_was_blamed: bool,
}

impl StreakTracker {
    pub(crate) fn observe(&mut self, epoch: &EpochReport) {
        if epoch.blamed_skipped {
            self.blamed_skipped += 1;
        }
        if epoch.fold_verified {
            self.fold_verified += 1;
        }
        self.last_was_blamed = epoch.blamed_skipped;
        if epoch_matched(epoch) {
            self.current = 0;
            return;
        }
        self.total_mismatches += 1;
        if self.current == 0 {
            self.current_start = epoch.pivot_height;
        }
        self.current += 1;
        if self.current > self.longest {
            self.longest = self.current;
            self.longest_start = self.current_start;
            self.longest_end = epoch.pivot_height;
        }
    }

    /// True while an unresolved run of consecutive mismatches is in flight (the
    /// last observed epoch did not match) or the last pivot was blamed-skipped.
    /// Lets the driver defer checkpointing so trie state is only persisted at a
    /// fully-verified boundary (direct- or fold-verified pivot).
    pub(crate) fn in_unverified_run(&self) -> bool {
        self.current > 0 || self.last_was_blamed
    }

    pub(crate) fn longest_run(&self) -> usize {
        self.longest
    }
}

pub(crate) fn epoch_matched(epoch: &EpochReport) -> bool {
    epoch.receipts_root_prefix_match
        && epoch.logs_bloom_prefix_match
        && epoch.state_root_prefix_match
}

/// Succeed unless some run of consecutive mismatches exceeds the anomaly
/// threshold, in which case the replay genuinely diverged. With default
/// `anomaly_streak=0`, any unexplained mismatch is a failure.
pub(crate) fn finish_verdict(streak: &StreakTracker, anomaly_streak: usize) -> anyhow::Result<()> {
    if streak.total_mismatches == 0 {
        println!(
            "verification ok: all epochs match (blamed_skipped={} fold_verified={})",
            streak.blamed_skipped,
            streak.fold_verified,
        );
    } else {
        println!(
            "verification: {} mismatching epoch(s), longest consecutive run = {} (heights {}..={}), tolerance = {}, blamed_skipped={}, fold_verified={}",
            streak.total_mismatches,
            streak.longest,
            streak.longest_start,
            streak.longest_end,
            anomaly_streak,
            streak.blamed_skipped,
            streak.fold_verified,
        );
    }
    anyhow::ensure!(
        streak.longest <= anomaly_streak,
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
    pub(crate) blamed_skipped: usize,
    pub(crate) fold_verified: usize,
}

pub(crate) fn accumulate(totals: &mut Totals, report: &RunReport) {
    totals.epoch_count += report.epoch_count;
    totals.block_count += report.block_count;
    totals.transaction_count += report.transaction_count;
    totals.receipts_root_prefix_matches += report.receipts_root_prefix_matches;
    totals.logs_bloom_prefix_matches += report.logs_bloom_prefix_matches;
    totals.state_root_prefix_matches += report.state_root_prefix_matches;
    totals.blamed_skipped += report.blamed_skipped;
    totals.fold_verified += report.fold_verified;
}

pub(crate) fn print_single_report(report: &RunReport) {
    println!(
        "executed packet: epochs={}, blocks={}, txs={}, receipt_matches={}, log_matches={}, state_matches={}, blamed_skipped={}, fold_verified={}",
        report.epoch_count,
        report.block_count,
        report.transaction_count,
        report.receipts_root_prefix_matches,
        report.logs_bloom_prefix_matches,
        report.state_root_prefix_matches,
        report.blamed_skipped,
        report.fold_verified,
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
            "epoch height={} deferred_height={} pivot={:?} blocks={} txs={} receipts_prefix_match={} logs_prefix_match={} state_prefix_match={} blamed_skipped={} fold_verified={} computed_receipts={:?} expected_receipts_prefix={:?} computed_logs={:?} expected_logs_prefix={:?} computed_state={:?} expected_state_prefix={:?}",
            epoch.pivot_height,
            epoch.deferred_height,
            epoch.pivot_hash,
            epoch.block_count,
            epoch.transaction_count,
            epoch.receipts_root_prefix_match,
            epoch.logs_bloom_prefix_match,
            epoch.state_root_prefix_match,
            epoch.blamed_skipped,
            epoch.fold_verified,
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
            "replay progress t={}s height={} block_date={} groups={} epochs={} blocks={} txs={} state_match={}/{} longest_mismatch_run={} blamed_skipped={} fold_verified={}",
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
            streak.blamed_skipped,
            streak.fold_verified,
        );
        self.last_log = Instant::now();
    }
}
