//! CLI entry: parse args, arm the profiler, map to a `DriverConfig`, and run the
//! driver. No replay logic lives here — it is a thin shell over the library.

use anyhow::Result;
use cfx_replay_data_executor::driver::{self, DriverConfig};
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "cfx-replay-exec")]
struct Cli {
    /// A single packet file, or a directory of `.cfxpack` containers that are
    /// replayed in epoch order through one cumulative replayer.
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

impl Cli {
    fn into_driver_config(self) -> DriverConfig {
        DriverConfig {
            input: self.input,
            config_path: self.config,
            verbose_epochs: self.verbose_epochs,
            max_mismatches: self.max_mismatches,
            anomaly_streak: self.anomaly_streak,
            checkpoint: self.checkpoint,
            checkpoint_every_groups: self.checkpoint_every_groups,
            checkpoint_every_seconds: self.checkpoint_every_seconds,
            stop_after_checkpoint: self.stop_after_checkpoint,
        }
    }
}

fn main() -> Result<()> {
    let cfg = Cli::parse().into_driver_config();
    // Build (and any checkpoint resume) BEFORE arming the profiler, so the
    // one-off resume cost is excluded from the steady-state sample.
    let (mut replayer, resume_height) = driver::build(&cfg)?;

    // pprof-rs samples via SIGPROF/setitimer (no perf_event), so it works even
    // where perf_event_paranoid is locked down. Writes flamegraph.svg on exit.
    #[cfg(feature = "profile")]
    let profiler = pprof::ProfilerGuardBuilder::default()
        .frequency(997)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .ok();

    let result = driver::run(&mut replayer, &cfg, resume_height);

    #[cfg(feature = "profile")]
    if let Some(guard) = profiler {
        write_profile(guard);
    }

    result
}

#[cfg(feature = "profile")]
fn write_profile(guard: pprof::ProfilerGuard<'_>) {
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
