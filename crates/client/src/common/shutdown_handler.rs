use std::{
    sync::{Arc, Weak},
    thread,
    time::{Duration, Instant},
};

use ctrlc::CtrlC;
use parking_lot::{Condvar, Mutex};

use super::ClientTrait;

pub fn run(
    this: Box<dyn ClientTrait>, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
) -> bool {
    CtrlC::set_handler({
        let e = exit_cond_var.clone();
        move || {
            *e.0.lock() = true;
            e.1.notify_all();
        }
    });

    let mut lock = exit_cond_var.0.lock();
    if !*lock {
        exit_cond_var.1.wait(&mut lock);
    }

    shutdown(this)
}

/// Returns whether the shutdown is considered clean.
pub fn shutdown(this: Box<dyn ClientTrait>) -> bool {
    let (ledger_db, maybe_pos_handler, maybe_blockgen) =
        this.take_out_components_for_shutdown();
    drop(this);
    if let Some(blockgen) = maybe_blockgen {
        blockgen.stop();
        drop(blockgen);
    }
    let maybe_pos_db = if let Some(pos_handler) = maybe_pos_handler {
        let maybe_pos_db = pos_handler.stop();
        drop(pos_handler);
        maybe_pos_db
    } else {
        None
    };

    // Make sure ledger_db is properly dropped, so rocksdb can be closed
    // cleanly
    let mut graceful = true;
    graceful &= check_graceful_shutdown(ledger_db);
    debug!("ledger_db drop: graceful = {}", graceful);
    if let Some((pos_ledger_db, consensus_db)) = maybe_pos_db {
        graceful &= check_graceful_shutdown(pos_ledger_db);
        debug!("pos_ledger_db drop: graceful = {}", graceful);
        graceful &= check_graceful_shutdown(consensus_db);
        debug!("consensus_db drop: graceful = {}", graceful);
    }
    graceful
}

/// Most Conflux components references block data manager.
/// When block data manager is freed, all background threads must have
/// already stopped.
fn check_graceful_shutdown<T>(blockdata_manager_weak_ptr: Weak<T>) -> bool {
    let sleep_duration = Duration::from_secs(1);
    let warn_timeout = Duration::from_secs(5);
    let max_timeout = Duration::from_secs(1200);
    let instant = Instant::now();
    let mut warned = false;
    while instant.elapsed() < max_timeout {
        if blockdata_manager_weak_ptr.upgrade().is_none() {
            return true;
        }
        if !warned && instant.elapsed() > warn_timeout {
            warned = true;
            warn!("Shutdown is taking longer than expected.");
        }
        thread::sleep(sleep_duration);
    }
    eprintln!("Shutdown timeout reached, exiting uncleanly.");
    false
}
