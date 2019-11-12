// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::state_manager::StateManager, sync::state::delta::StateDumper,
};
use cfx_types::H256;
use parking_lot::{Mutex, RwLock};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        mpsc::{channel, Sender},
        Arc,
    },
    thread,
};

lazy_static! {
    pub static ref CHECKPOINT_DUMP_MANAGER: RwLock<CheckpointDumpManager> =
        RwLock::new(CheckpointDumpManager::default());
}

#[derive(Default)]
pub struct CheckpointDumpManager {
    // use Mutex to allow use Sender in multiple threads
    checkpoint_dump_sender: Mutex<Option<Sender<H256>>>,
    // used to notify that new checkpoint ready for sync
    checkpoint_dumped: Arc<Mutex<H256>>,
    // only allow to dump when previous checkpoint dumped
    dumping: Arc<AtomicBool>,
}

impl CheckpointDumpManager {
    const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

    pub fn initialize(&mut self, state_manager: Arc<StateManager>) {
        if self.checkpoint_dump_sender.lock().is_some() {
            return;
        }

        let (sender, receiver) = channel();
        let checkpoint_dumped = self.checkpoint_dumped.clone();
        let dumping = self.dumping.clone();

        thread::Builder::new()
            .name("DumpCheckpointState".into())
            .spawn(move || {
                let root_dir = StateDumper::default_root_dir();
                let mut previous_checkpoint = None;

                info!("CheckpointDumpManager: ready to dump checkpoint state to {:?}", root_dir);

                while let Ok(checkpoint) = receiver.recv() {
                    info!(
                        "CheckpointDumpManager: begin to dump checkpoint state, checkpoint = {:?}",
                        checkpoint
                    );

                    dumping.store(true, Relaxed);

                    // remove previous dumped checkpoint state
                    if previous_checkpoint.is_some() {
                        debug!("CheckpointDumpManager: begin to remove previous dumped checkpoint state");
                        match StateDumper::remove(
                            root_dir.clone(),
                            previous_checkpoint,
                        ) {
                            Ok(()) => debug!("CheckpointDumpManager: previous dumped checkpoint state removed"),
                            Err(e) => error!("CheckpointDumpManager: failed to remove previous dumped checkpoint states: {:?}", e),
                        }
                    }

                    // dump state of new checkpoint
                    let mut dumper = StateDumper::new(
                        root_dir.clone(),
                        checkpoint,
                        CheckpointDumpManager::MAX_CHUNK_SIZE,
                    );
                    match dumper.dump(state_manager.as_ref()) {
                        Ok(true) => {
                            info!("CheckpointDumpManager: succeed to dump checkpoint state");
                            *checkpoint_dumped.lock() = checkpoint;
                            previous_checkpoint = Some(checkpoint);
                        }
                        Ok(false) => error!(
                            "CheckpointDumpManager: failed to dump checkpoint state: state missed"
                        ),
                        Err(e) => {
                            error!("CheckpointDumpManager: failed to dump checkpoint state: {:?}", e)
                        }
                    }

                    dumping.store(false, Relaxed);
                }

                info!("CheckpointDumpManager: complete to dump checkpoint state");
            })
            .expect("failed to spawn thread to dump checkpoint state");

        self.checkpoint_dump_sender.lock().replace(sender);
    }

    pub fn dump_async(&self, checkpoint: H256) {
        debug!(
            "dump checkpoint state requested, checkpoint = {:?}",
            checkpoint
        );

        if self.dumping.load(Relaxed) {
            warn!("failed to dump checkpoint async, it's still in progress");
            return;
        }

        let maybe_sender = self.checkpoint_dump_sender.lock();

        if let Some(ref sender) = *maybe_sender {
            if let Err(e) = sender.send(checkpoint) {
                warn!("failed to dump checkpoint async, error = {:?}", e);
            }
        } else {
            // TODO Handle possible inconsistency for skipped or cancelled state
            // dumping
            debug!("Skip checkpoint dumping during shutdown");
        }
    }

    pub fn dumped(&self) -> Option<H256> {
        let checkpoint = self.checkpoint_dumped.lock();
        if checkpoint.is_zero() {
            None
        } else {
            Some(*checkpoint)
        }
    }

    pub fn stop(&self) { *self.checkpoint_dump_sender.lock() = None; }
}
