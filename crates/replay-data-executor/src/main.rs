use anyhow::{Context, Result};
#[cfg(feature = "backend-minimal-mpt")]
use cfx_replay_data_executor::checkpoint::ReplayCheckpoint;
use cfx_replay_data_executor::replay_exec::{
    EpochExecReport, ReplayExecConfig, ReplayExecReport, ReplayExecutor,
};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

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
    /// Checkpoint file for resumable replay (minimal-mpt backend only). When
    /// set: if the file exists the run resumes from it instead of genesis, and
    /// it is (re)written every `--checkpoint-every-groups` 2000-epoch groups.
    /// A crash then resumes from the middle, not from the start.
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    /// Number of 2000-epoch groups between checkpoint writes (default: 100,
    /// i.e. every 200,000 epochs).
    #[arg(long, default_value_t = 100)]
    checkpoint_every_groups: u64,
    /// Also write a checkpoint when this many wall-clock seconds have elapsed
    /// since the last write (still only on a 2000-epoch group boundary).
    /// Combined with `--checkpoint-every-groups`, whichever limit is reached
    /// first triggers the write and both counters reset. Unset (default)
    /// disables the time trigger.
    #[arg(long)]
    checkpoint_every_seconds: Option<u64>,
    /// Exit cleanly right after writing the FIRST checkpoint. With
    /// `--checkpoint-every-groups N` (resuming from height R), the first write
    /// lands at `R + N*2000` (a snapshot boundary), so this builds a debug
    /// "jump-off point" at a chosen height and stops — instead of running the
    /// whole input. Resume from that checkpoint to reach a target epoch fast.
    #[arg(long, default_value_t = false)]
    stop_after_checkpoint: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = ReplayExecConfig {
        config_path: cli.config.clone(),
    };
    // Recover from the checkpoint BEFORE arming the profiler, so the one-off
    // resume cost (checkpoint deserialize + full root recompute) is excluded
    // from the steady-state sample.
    let (mut executor, resume_height) = build_executor(config, &cli)?;

    // pprof-rs samples via SIGPROF/setitimer (no perf_event), so it works even
    // where perf_event_paranoid is locked down. Writes flamegraph.svg on exit.
    #[cfg(feature = "profile")]
    let profiler = pprof::ProfilerGuardBuilder::default()
        .frequency(997)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .ok();

    let result = run_replay(&mut executor, &cli, resume_height);

    #[cfg(feature = "profile")]
    if let Some(guard) = profiler {
        match guard.report().build() {
            Ok(report) => {
                if let Ok(file) = std::fs::File::create("flamegraph.svg") {
                    let _ = report.flamegraph(file);
                    eprintln!("profile: wrote flamegraph.svg");
                }
                // Folded stacks (`root;...;leaf count`) for textual self/total
                // analysis with awk.
                let mut folded = String::new();
                for (frames, count) in report.data.iter() {
                    let mut stack: Vec<String> = Vec::new();
                    for frame in frames.frames.iter().rev() {
                        for sym in frame.iter() {
                            stack.push(sym.to_string());
                        }
                    }
                    folded.push_str(&stack.join(";"));
                    folded.push_str(&format!(" {count}\n"));
                }
                if std::fs::write("profile.folded", &folded).is_ok() {
                    eprintln!(
                        "profile: wrote profile.folded ({} unique stacks)",
                        report.data.len()
                    );
                }
            }
            Err(e) => eprintln!("profile: building report failed: {e}"),
        }
    }

    result
}

fn run_replay(
    executor: &mut ReplayExecutor, cli: &Cli, resume_height: u64,
) -> Result<()> {
    if cli.input.is_dir() {
        run_packed_dir(executor, cli, resume_height)
    } else {
        let packet = std::fs::read(&cli.input)
            .with_context(|| format!("read packet {}", cli.input.display()))?;
        let report = executor.execute_packet(&packet)?;
        print_single_report(&report);
        report_mismatches(&report.epochs, cli, &mut 0);
        let mut streak = StreakTracker::default();
        for epoch in &report.epochs {
            streak.observe(epoch.pivot_height, epoch_matched(epoch));
        }
        save_checkpoint(executor, cli);
        finish_verdict(&streak, cli.anomaly_streak)
    }
}

/// Build the executor, resuming from a checkpoint when one is configured and
/// present. Returns the executor and the committed height it starts at (0 for
/// a fresh genesis run).
#[cfg(feature = "backend-minimal-mpt")]
fn build_executor(
    config: ReplayExecConfig, cli: &Cli,
) -> Result<(ReplayExecutor, u64)> {
    if let Some(path) = &cli.checkpoint {
        if let Some(ckpt) = ReplayCheckpoint::load(path)? {
            let height = ckpt.height();
            eprintln!(
                "resuming from checkpoint {} at height {}",
                path.display(),
                height,
            );
            let executor = ReplayExecutor::restore(config, ckpt)?;
            return Ok((executor, height));
        }
        eprintln!(
            "no checkpoint at {} yet; starting from genesis",
            path.display(),
        );
    }
    Ok((ReplayExecutor::new(config)?, 0))
}

/// Without the minimal-mpt backend there is no latest-only state to snapshot,
/// so checkpointing is unsupported; reject it rather than silently ignore.
#[cfg(not(feature = "backend-minimal-mpt"))]
fn build_executor(
    config: ReplayExecConfig, cli: &Cli,
) -> Result<(ReplayExecutor, u64)> {
    anyhow::ensure!(
        cli.checkpoint.is_none(),
        "--checkpoint requires the backend-minimal-mpt build",
    );
    Ok((ReplayExecutor::new(config)?, 0))
}

/// Write a checkpoint if one is configured. No-op without the minimal-mpt
/// backend (the only build where checkpointing exists).
#[cfg(feature = "backend-minimal-mpt")]
fn save_checkpoint(executor: &ReplayExecutor, cli: &Cli) {
    if let Some(path) = &cli.checkpoint {
        match executor.export_checkpoint().save(path) {
            Ok(()) => eprintln!(
                "wrote checkpoint {} at height {}",
                path.display(),
                executor.committed_height(),
            ),
            Err(e) => eprintln!("warning: failed to write checkpoint: {e:#}"),
        }
    }
}

#[cfg(not(feature = "backend-minimal-mpt"))]
fn save_checkpoint(_executor: &ReplayExecutor, _cli: &Cli) {}

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

fn format_block_date(timestamp: u64) -> String {
    if timestamp == 0 {
        return "?".to_string();
    }
    let dt = OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!("{}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

struct CheckpointCadence {
    groups_since: u64,
    last_time: Instant,
}

impl CheckpointCadence {
    fn new() -> Self {
        Self { groups_since: 0, last_time: Instant::now() }
    }

    fn tick(&mut self) { self.groups_since += 1; }

    fn should_write(&self, cli: &Cli) -> bool {
        let by_groups = cli.checkpoint_every_groups > 0
            && self.groups_since >= cli.checkpoint_every_groups;
        let by_time = cli
            .checkpoint_every_seconds
            .is_some_and(|t| self.last_time.elapsed().as_secs() >= t);
        by_groups || by_time
    }

    fn write_and_reset(
        &mut self, executor: &ReplayExecutor, cli: &Cli, end_epoch: u64,
    ) {
        let by_groups = cli.checkpoint_every_groups > 0
            && self.groups_since >= cli.checkpoint_every_groups;
        let by_time = cli
            .checkpoint_every_seconds
            .is_some_and(|t| self.last_time.elapsed().as_secs() >= t);
        let elapsed = self.last_time.elapsed().as_secs();
        save_checkpoint(executor, cli);
        if cli.checkpoint.is_some() {
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

struct ProgressLogger {
    started: Instant,
    last_log: Instant,
}

impl ProgressLogger {
    fn new() -> Self {
        let now = Instant::now();
        Self { started: now, last_log: now }
    }

    fn maybe_log(
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

fn collect_pack_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().map(|ext| ext == "cfxpack").unwrap_or(false))
        .collect();
    files.sort_by_key(|path| container_start_epoch(path).unwrap_or(u64::MAX));
    anyhow::ensure!(!files.is_empty(), "no .cfxpack files in {}", dir.display());
    Ok(files)
}

fn validate_contiguity(
    start_epoch: u64, next_expected: &mut Option<u64>, resume_height: u64,
) -> Result<()> {
    match *next_expected {
        Some(expected) => anyhow::ensure!(
            start_epoch == expected,
            "non-contiguous groups: expected start epoch {expected}, got {start_epoch}",
        ),
        None => anyhow::ensure!(
            resume_height == 0 || start_epoch == resume_height + 1,
            "resume gap: checkpoint height {resume_height}, first pending group starts at epoch {start_epoch}",
        ),
    }
    Ok(())
}

fn run_packed_dir(
    executor: &mut ReplayExecutor, cli: &Cli, resume_height: u64,
) -> Result<()> {
    let files = collect_pack_files(&cli.input)?;

    let mut totals = Totals::default();
    let mut printed_mismatches = 0usize;
    let mut groups_done = 0usize;
    let mut ckpt = CheckpointCadence::new();
    let mut next_expected_epoch: Option<u64> = None;
    let mut streak = StreakTracker::default();
    let mut progress = ProgressLogger::new();

    for path in &files {
        if let Some(end) = container_end_epoch(path) {
            if end <= resume_height {
                continue;
            }
        }
        let data = std::fs::read(path)
            .with_context(|| format!("read container {}", path.display()))?;
        let entries = parse_container_directory(&data)
            .with_context(|| format!("parse container {}", path.display()))?;
        for (start_epoch, epoch_count, offset, length) in entries {
            let end_epoch = start_epoch + epoch_count.saturating_sub(1);
            if end_epoch <= resume_height {
                continue;
            }
            validate_contiguity(start_epoch, &mut next_expected_epoch, resume_height)?;
            next_expected_epoch = Some(end_epoch + 1);

            let payload = &data[offset..offset + length];
            let report = executor.execute_packet(payload).with_context(|| {
                format!("execute group starting at epoch {start_epoch}")
            })?;
            accumulate(&mut totals, &report);
            report_mismatches(&report.epochs, cli, &mut printed_mismatches);
            let mut last_block_ts = 0u64;
            for epoch in &report.epochs {
                streak.observe(epoch.pivot_height, epoch_matched(epoch));
                last_block_ts = epoch.pivot_timestamp;
            }
            groups_done += 1;
            ckpt.tick();
            if ckpt.should_write(cli) {
                ckpt.write_and_reset(executor, cli, end_epoch);
                if cli.stop_after_checkpoint && cli.checkpoint.is_some() {
                    println!(
                        "stop-after-checkpoint: wrote checkpoint at height {end_epoch}, exiting"
                    );
                    return Ok(());
                }
            }
            progress.maybe_log(end_epoch, last_block_ts, groups_done, &totals, &streak);
        }
    }

    save_checkpoint(executor, cli);

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

fn container_end_epoch(path: &Path) -> Option<u64> {
    let stem = path.file_stem()?.to_str()?;
    // `<prefix>_<start>_<end>` -> last underscore field
    stem.rsplit('_').next()?.parse().ok()
}
