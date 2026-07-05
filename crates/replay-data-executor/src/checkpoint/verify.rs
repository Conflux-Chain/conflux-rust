use super::Checkpoint;
use anyhow::{Context, Result};
use std::path::Path;

impl Checkpoint {
    /// Test helper: assert `load_streaming` reconstructs exactly what the full
    /// `load` + `into_parts` path does. Lives in-crate so it can touch the
    /// crate-private commitment/executed window types. Returns `true` on match.
    /// Reference path materializes the full byte-keyed snapshot, so use a small
    /// early checkpoint.
    pub fn verify_streaming_load_matches(path: &Path) -> Result<bool> {
        let full = Self::load(path)?.context("no checkpoint at path")?;
        let ref_height = full.height();
        let (ref_mmpt, ref_ph, ref_pr, ref_pv, ref_fe, ref_comm, ref_exec) =
            full.into_parts()?;

        let restored = Self::load_streaming(path)?.context("load_streaming None")?;
        let stream_mmpt = restored.state.persisted();

        let mut ok = true;
        if ref_mmpt != stream_mmpt {
            ok = false;
            eprintln!("FAIL: mmpt differs");
            if ref_mmpt.snapshot != stream_mmpt.snapshot {
                eprintln!(
                    "  snapshot: ref={} stream={}",
                    ref_mmpt.snapshot.len(),
                    stream_mmpt.snapshot.len()
                );
                for (k, v) in ref_mmpt.snapshot.iter() {
                    match stream_mmpt.snapshot.get(k) {
                        None => {
                            eprintln!("  key missing in stream: {:02x?}", &k[..k.len().min(8)]);
                            break;
                        }
                        Some(sv) if sv != v => {
                            eprintln!("  value differs at {:02x?}", &k[..k.len().min(8)]);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            if ref_mmpt.intermediate != stream_mmpt.intermediate {
                eprintln!("  intermediate differs");
            }
            if ref_mmpt.delta != stream_mmpt.delta {
                eprintln!("  delta differs");
            }
            if ref_mmpt.height != stream_mmpt.height {
                eprintln!("  height {} vs {}", ref_mmpt.height, stream_mmpt.height);
            }
            if ref_mmpt.last_root != stream_mmpt.last_root {
                eprintln!("  last_root differs");
            }
            if ref_mmpt.intermediate_mpt_key_padding != stream_mmpt.intermediate_mpt_key_padding
                || ref_mmpt.delta_mpt_key_padding != stream_mmpt.delta_mpt_key_padding
            {
                eprintln!("  padding differs");
            }
            if ref_mmpt.snapshot_epoch_count != stream_mmpt.snapshot_epoch_count {
                eprintln!("  epoch_count differs");
            }
        }
        if ref_height != restored.height {
            ok = false;
            eprintln!("FAIL: height {ref_height} vs {}", restored.height);
        }
        if ref_ph != restored.previous_epoch_hash {
            ok = false;
            eprintln!("FAIL: previous_epoch_hash differs");
        }
        if ref_pr != restored.previous_state_root {
            ok = false;
            eprintln!("FAIL: previous_state_root differs");
        }
        if ref_pv != restored.previous_epoch_pos_view {
            ok = false;
            eprintln!("FAIL: previous_epoch_pos_view differs");
        }
        if ref_fe != restored.previous_epoch_finalized_epoch {
            ok = false;
            eprintln!("FAIL: previous_epoch_finalized_epoch differs");
        }
        // window contents decode identically (same bincode calls); check counts.
        if ref_comm.len() != restored.commitments.len() {
            ok = false;
            eprintln!("FAIL: commitments count differs");
        }
        if ref_exec.len() != restored.executed_epochs.len() {
            ok = false;
            eprintln!("FAIL: executed_epochs count differs");
        }

        eprintln!(
            "height={ref_height} snapshot={} intermediate={} delta={} commitments={} executed={}",
            stream_mmpt.snapshot.len(),
            stream_mmpt.intermediate.len(),
            stream_mmpt.delta.len(),
            restored.commitments.len(),
            restored.executed_epochs.len(),
        );
        Ok(ok)
    }
}
