//! Drive the [`Replayer`](crate::consensus::Replayer) over an input source — a
//! single packet file, or a directory of `.cfxpack` containers replayed in
//! epoch order — handling resume, checkpoint cadence, and the final verdict.
//!
//! This is the node/sync slot of the original node: it only decides *what to
//! feed and when to persist/stop*. It is decoupled from the CLI and takes a
//! plain [`DriverConfig`], so it can be driven from a test or another tool.

#[cfg(feature = "backend-minimal-mpt")]
use crate::checkpoint::Checkpoint;
use crate::consensus::{Config, Replayer};
use crate::report::{
    accumulate, epoch_matched, finish_verdict, print_single_report, report_mismatches,
    ProgressLogger, StreakTracker, Totals,
};
use anyhow::{Context, Result};
use cfxpack::container;
use std::path::PathBuf;
use std::time::Instant;

/// Everything the driver needs, mapped from whatever front-end (CLI, test) is
/// driving it. Holds no clap types.
pub struct DriverConfig {
    pub input: PathBuf,
    pub config_path: PathBuf,
    pub verbose_epochs: bool,
    pub max_mismatches: usize,
    pub anomaly_streak: usize,
    pub checkpoint: Option<PathBuf>,
    pub checkpoint_every_groups: u64,
    pub checkpoint_every_seconds: Option<u64>,
    pub stop_after_checkpoint: bool,
}

/// Build the replayer, resuming from a checkpoint when one is configured and
/// present. Returns the replayer and the committed height it starts at (0 for a
/// fresh genesis run). Kept separate from [`run`] so the caller can build before
/// arming a profiler, excluding the one-off resume cost from the sample.
#[cfg(feature = "backend-minimal-mpt")]
pub fn build(cfg: &DriverConfig) -> Result<(Replayer, u64)> {
    let config = Config {
        config_path: cfg.config_path.clone(),
    };
    if let Some(path) = &cfg.checkpoint {
        if let Some(ckpt) = Checkpoint::load(path)? {
            let height = ckpt.height();
            eprintln!(
                "resuming from checkpoint {} at height {}",
                path.display(),
                height,
            );
            let replayer = Replayer::restore(config, ckpt)?;
            return Ok((replayer, height));
        }
        eprintln!("no checkpoint at {} yet; starting from genesis", path.display());
    }
    Ok((Replayer::new(config)?, 0))
}

/// Without the minimal-mpt backend there is no latest-only state to snapshot, so
/// checkpointing is unsupported; reject it rather than silently ignore.
#[cfg(not(feature = "backend-minimal-mpt"))]
pub fn build(cfg: &DriverConfig) -> Result<(Replayer, u64)> {
    anyhow::ensure!(
        cfg.checkpoint.is_none(),
        "--checkpoint requires the backend-minimal-mpt build",
    );
    let config = Config {
        config_path: cfg.config_path.clone(),
    };
    Ok((Replayer::new(config)?, 0))
}

/// Replay `cfg.input` (file or container directory) through `replayer` and
/// produce the verdict.
pub fn run(replayer: &mut Replayer, cfg: &DriverConfig, resume_height: u64) -> Result<()> {
    if cfg.input.is_dir() {
        run_packed_dir(replayer, cfg, resume_height)
    } else {
        run_single(replayer, cfg)
    }
}

fn run_single(replayer: &mut Replayer, cfg: &DriverConfig) -> Result<()> {
    let packet = std::fs::read(&cfg.input)
        .with_context(|| format!("read packet {}", cfg.input.display()))?;
    let report = replayer.execute_packet(&packet)?;
    print_single_report(&report);
    report_mismatches(&report.epochs, cfg.verbose_epochs, cfg.max_mismatches, &mut 0);
    let mut streak = StreakTracker::default();
    for epoch in &report.epochs {
        streak.observe(epoch.pivot_height, epoch_matched(epoch));
    }
    save_checkpoint(replayer, cfg);
    finish_verdict(&streak, cfg.anomaly_streak)
}

struct RunTracker {
    totals: Totals,
    streak: StreakTracker,
    progress: ProgressLogger,
    ckpt: CheckpointCadence,
    printed_mismatches: usize,
    groups_done: usize,
}

/// Execute one epoch-group and accumulate into the tracker.
/// Returns `true` when stop-after-checkpoint fires.
fn process_group(
    tracker: &mut RunTracker, replayer: &mut Replayer, cfg: &DriverConfig,
    payload: &[u8], start_epoch: u64, end_epoch: u64,
) -> Result<bool> {
    let report = replayer.execute_packet(payload).with_context(|| {
        format!("execute group starting at epoch {start_epoch}")
    })?;
    accumulate(&mut tracker.totals, &report);
    report_mismatches(
        &report.epochs,
        cfg.verbose_epochs,
        cfg.max_mismatches,
        &mut tracker.printed_mismatches,
    );
    for epoch in &report.epochs {
        tracker.streak.observe(epoch.pivot_height, epoch_matched(epoch));
    }
    let last_block_ts = report.epochs.last().map_or(0, |e| e.pivot_timestamp);

    tracker.groups_done += 1;
    tracker.ckpt.tick();
    if tracker.ckpt.should_write(cfg) {
        tracker.ckpt.write_and_reset(replayer, cfg, end_epoch);
        if cfg.stop_after_checkpoint && cfg.checkpoint.is_some() {
            println!(
                "stop-after-checkpoint: wrote checkpoint at height {end_epoch}, exiting"
            );
            return Ok(true);
        }
    }
    tracker.progress.maybe_log(
        end_epoch, last_block_ts, tracker.groups_done, &tracker.totals, &tracker.streak,
    );
    Ok(false)
}

fn run_packed_dir(replayer: &mut Replayer, cfg: &DriverConfig, resume_height: u64) -> Result<()> {
    let files = container::collect_files(&cfg.input)?;
    let mut tracker = RunTracker {
        totals: Totals::default(),
        streak: StreakTracker::default(),
        progress: ProgressLogger::new(),
        ckpt: CheckpointCadence::new(),
        printed_mismatches: 0,
        groups_done: 0,
    };
    let mut next_expected_epoch: Option<u64> = None;

    for path in &files {
        if container::end_epoch(path).is_some_and(|end| end <= resume_height) {
            continue;
        }
        let data = std::fs::read(path)
            .with_context(|| format!("read container {}", path.display()))?;
        let entries = container::parse_directory(&data)
            .with_context(|| format!("parse container {}", path.display()))?;
        for (start_epoch, epoch_count, offset, length) in entries {
            let end_epoch = start_epoch + epoch_count.saturating_sub(1);
            if end_epoch <= resume_height {
                continue;
            }
            container::validate_contiguity(start_epoch, &mut next_expected_epoch, resume_height)?;
            next_expected_epoch = Some(end_epoch + 1);
            if process_group(&mut tracker, replayer, cfg, &data[offset..offset + length], start_epoch, end_epoch)? {
                return Ok(());
            }
        }
    }

    save_checkpoint(replayer, cfg);

    println!(
        "executed packed dir: files={}, epochs={}, blocks={}, txs={}, receipt_matches={}, log_matches={}, state_matches={}",
        files.len(),
        tracker.totals.epoch_count,
        tracker.totals.block_count,
        tracker.totals.transaction_count,
        tracker.totals.receipts_root_prefix_matches,
        tracker.totals.logs_bloom_prefix_matches,
        tracker.totals.state_root_prefix_matches,
    );
    finish_verdict(&tracker.streak, cfg.anomaly_streak)
}

/// Write a checkpoint if one is configured. No-op without the minimal-mpt
/// backend (the only build where checkpointing exists).
#[cfg(feature = "backend-minimal-mpt")]
fn save_checkpoint(replayer: &Replayer, cfg: &DriverConfig) {
    if let Some(path) = &cfg.checkpoint {
        match replayer.export_checkpoint().save(path) {
            Ok(()) => eprintln!(
                "wrote checkpoint {} at height {}",
                path.display(),
                replayer.committed_height(),
            ),
            Err(e) => eprintln!("warning: failed to write checkpoint: {e:#}"),
        }
    }
}

#[cfg(not(feature = "backend-minimal-mpt"))]
fn save_checkpoint(_replayer: &Replayer, _cfg: &DriverConfig) {}

/// Tracks when to write the next checkpoint: either every N groups, or after T
/// wall-clock seconds (still only at a group boundary), whichever comes first.
struct CheckpointCadence {
    groups_since: u64,
    last_time: Instant,
}

impl CheckpointCadence {
    fn new() -> Self {
        Self { groups_since: 0, last_time: Instant::now() }
    }

    fn tick(&mut self) {
        self.groups_since += 1;
    }

    fn should_write(&self, cfg: &DriverConfig) -> bool {
        let by_groups = cfg.checkpoint_every_groups > 0
            && self.groups_since >= cfg.checkpoint_every_groups;
        let by_time = cfg
            .checkpoint_every_seconds
            .is_some_and(|t| self.last_time.elapsed().as_secs() >= t);
        by_groups || by_time
    }

    fn write_and_reset(&mut self, replayer: &Replayer, cfg: &DriverConfig, end_epoch: u64) {
        let by_groups = cfg.checkpoint_every_groups > 0
            && self.groups_since >= cfg.checkpoint_every_groups;
        let by_time = cfg
            .checkpoint_every_seconds
            .is_some_and(|t| self.last_time.elapsed().as_secs() >= t);
        let elapsed = self.last_time.elapsed().as_secs();
        save_checkpoint(replayer, cfg);
        if cfg.checkpoint.is_some() {
            eprintln!(
                "[ckpt] height={end_epoch} trigger={} groups_since={} elapsed={elapsed}s",
                match (by_groups, by_time) {
                    (true, true) => "groups+time",
                    (true, false) => "groups",
                    _ => "time",
                },
                self.groups_since,
            );
        }
        self.groups_since = 0;
        self.last_time = Instant::now();
    }
}
