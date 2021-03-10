// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub fn prefetch_accounts<'a>(
    prefetcher: &'a ExecutionStatePrefetcher, task_epoch_id: EpochId,
    state: &State, account_vec: Vec<&'a Address>,
) -> PrefetchTaskHandle<'a> {
    // transmute the references so that they can be passed into threads.
    let state = unsafe { std::mem::transmute::<&State, &'static State>(state) };
    let accounts = unsafe {
        std::mem::transmute::<&[&Address], &'static [&'static Address]>(
            &account_vec,
        )
    };

    prefetcher.add_task(task_epoch_id, state, accounts).ok();

    PrefetchTaskHandle {
        prefetcher: Some(prefetcher),
        state,
        task_epoch_id,
        accounts: account_vec,
    }
}

pub struct ExecutionStatePrefetcher {
    task_sender: Mutex<CancelableTaskSender<PrefetchTaskKey>>,
    workers: Vec<Arc<PrefetcherThreadWorker>>,
    worker_join_handles: Vec<JoinHandle<()>>,

    join_handle: Mutex<Option<JoinHandle<()>>>,
}

struct PrefetcherThreadWorker {
    task_queue_sender: Mutex<
        mpsc::Sender<(
            EpochId,
            u64,
            &'static State,
            &'static [&'static Address],
        )>,
    >,
    /// All threads should be processing the same task.
    /// Abort the current task when the cancel task id matches.
    cancel_task_id: AtomicU64,
    current_task_id: RwLock<(EpochId, u64)>,
}

impl PrefetcherThreadWorker {
    fn new(
        task_queue_sender: mpsc::Sender<(
            EpochId,
            u64,
            &'static State,
            &'static [&'static Address],
        )>,
    ) -> Self {
        Self {
            task_queue_sender: Mutex::new(task_queue_sender),
            cancel_task_id: Default::default(),
            current_task_id: Default::default(),
        }
    }

    /// Unsafe because there shouldn't be concurrent calls to this function.
    /// It also doesn't wait for the task to finish.
    unsafe fn signal_current_task_cancellation(&self, task_epoch_id: &EpochId) {
        let current_task = self.current_task_id.read();
        if PrefetchTaskKey::key_matches(&current_task.0, task_epoch_id) {
            self.cancel_task_id.store(current_task.1, Ordering::Relaxed);
        }
    }

    fn send_new_task(
        &self, task_epoch_id: EpochId, task_id: u64, state: &'static State,
        addresses: &'static [&'static Address],
    ) {
        self.task_queue_sender
            .lock()
            .send((task_epoch_id, task_id, state, addresses))
            .ok();
    }

    /// Unsafe because we only want the Prefetcher to stop the thread.
    unsafe fn stop(&self) {
        self.task_queue_sender
            .lock()
            .send((Default::default(), 0, &*null(), &[]))
            .ok();
    }

    fn prefetch_accounts(
        &self, task_id: u64, state: &'static State,
        accounts: &'static [&'static Address],
    ) -> DbResult<()> {
        self.cancel_task_id.store(0, Ordering::Relaxed);
        for address in accounts {
            let cancel_task_id = self.cancel_task_id.load(Ordering::Relaxed);
            if cancel_task_id != 0 {
                if cancel_task_id == task_id {
                    break;
                }
                self.cancel_task_id.store(0, Ordering::Relaxed);
            }
            state.try_load(address)?;
        }

        Ok(())
    }

    fn run(
        &self,
        task_queue: mpsc::Receiver<(
            EpochId,
            u64,
            &'static State,
            &'static [&'static Address],
        )>,
        task_finish_signal: mpsc::Sender<()>,
    ) {
        while let Ok((task_epoch_id, task_id, state, accounts)) =
            task_queue.recv()
        {
            if task_id == 0 {
                // Stopped by the Prefetcher.
                return;
            } else {
                *self.current_task_id.write() = (task_epoch_id, task_id);

                // prefetch accounts, ignore db errors for now
                let _ = self.prefetch_accounts(task_id, state, accounts);

                task_finish_signal.send(()).expect(
                    // Should not return error.
                    &concat!(file!(), ":", line!(), ":", column!()),
                );
            }
        }
        error!("State prefetch worker stopped due to exception.");
    }
}

impl ExecutionStatePrefetcher {
    pub fn new(
        num_threads: usize,
    ) -> io::Result<Arc<ExecutionStatePrefetcher>> {
        let mut thread_finish_signal_receivers =
            Vec::with_capacity(num_threads);
        let mut workers = Vec::with_capacity(num_threads);
        let mut worker_join_handles = Vec::with_capacity(num_threads);

        // Start worker threads.
        for i in 0..num_threads {
            let (task_queue_sender, task_queue_receiver) = mpsc::channel();
            let (task_finish_sender, task_finish_receiver) = mpsc::channel();
            let worker =
                Arc::new(PrefetcherThreadWorker::new(task_queue_sender));
            let worker_to_run = worker.clone();
            let worker_join_handle = thread::Builder::new()
                .name(format!("Execution state prefetcher worker thread {}", i))
                .spawn(move || {
                    worker_to_run.run(task_queue_receiver, task_finish_sender)
                })?;

            thread_finish_signal_receivers.push(task_finish_receiver);
            workers.push(worker);
            worker_join_handles.push(worker_join_handle);
        }

        // Start task queue controller.
        let (task_sender, task_receiver) = new_cancellable_task_channel();
        let prefetcher = Arc::new(Self {
            task_sender: Mutex::new(task_sender),
            workers,
            worker_join_handles,
            join_handle: Default::default(),
        });

        let prefetcher_to_run = prefetcher.clone();
        let prefetcher_join_handle = thread::Builder::new()
            .name("Execution state prefetcher".into())
            .spawn(move || {
                prefetcher_to_run
                    .run(thread_finish_signal_receivers, task_receiver);
            })?;
        *prefetcher.join_handle.lock() = Some(prefetcher_join_handle);

        Ok(prefetcher)
    }

    pub fn stop(&self) {
        self.task_sender.lock().stop().ok();
    }

    pub fn add_task(
        &self, task_epoch_id: EpochId, state: &'static State,
        accounts: &'static [&'static Address],
    ) -> Result<(), SendError<bool>> {
        self.task_sender.lock().send(PrefetchTaskKey(
            task_epoch_id,
            state,
            accounts,
        ))
    }

    // Return false when the task does not exist in the queue. It may already
    // finished processing.
    pub fn wait_for_task(&self, task_epoch_id: &EpochId) -> bool {
        match self.task_sender.lock().wait_for(task_epoch_id) {
            Some((cond_var, mut mutex)) => {
                cond_var.wait(&mut mutex);
                true
            }
            _ => false,
        }
    }

    pub fn cancel_task(&self, task_epoch_id: &EpochId) {
        if self.task_sender.lock().remove(task_epoch_id) {
            // Inform workers about the cancellation.
            unsafe {
                for worker in &self.workers {
                    worker.signal_current_task_cancellation(task_epoch_id);
                }
            }
        }
    }

    #[inline]
    fn wait_for_current_task(
        finish_signal_receivers: &mut [mpsc::Receiver<()>],
    ) {
        for receiver in finish_signal_receivers {
            receiver.recv().expect(
                // Should not return error.
                &concat!(file!(), ":", line!(), ":", column!()),
            );
        }
    }

    fn run(
        &self, mut finish_signal_receivers: Vec<mpsc::Receiver<()>>,
        task_receiver: CancelableTaskReceiver<PrefetchTaskKey>,
    ) {
        let mut current_task_id = 0u64;
        loop {
            match task_receiver.recv() {
                Ok(PrefetchTaskKey(task_epoch_id, state, accounts)) => {
                    if current_task_id == std::u64::MAX {
                        current_task_id = 1;
                    } else {
                        current_task_id += 1;
                    }

                    // Dispatch split task to workers.
                    let num_accounts = accounts.len();
                    let num_threads = self.workers.len();
                    for thread_idx in 0..num_threads {
                        let range_start =
                            num_accounts * thread_idx / num_threads;
                        let range_end =
                            num_accounts * (thread_idx + 1) / num_threads;

                        self.workers[thread_idx].send_new_task(
                            task_epoch_id,
                            current_task_id,
                            state,
                            &accounts[range_start..range_end],
                        );
                    }

                    Self::wait_for_current_task(&mut finish_signal_receivers);
                }
                Err(StopOr::Stop) => {
                    // Stop
                    return;
                }
                Err(_) => {
                    // Exception
                    break;
                }
            }
        }
        error!("State prefetcher stopped due to exception.");
    }
}

impl Drop for ExecutionStatePrefetcher {
    fn drop(&mut self) {
        // Signal the prefetcher to exit.
        self.stop();

        // Let workers stop after the current task.
        for worker in &self.workers {
            unsafe {
                worker.stop();
            }
        }
        // Cancel the current task.
        if let Some(key) = &*self.task_sender.lock().current_task() {
            self.cancel_task(key);
        }

        for join_handle in self.worker_join_handles.split_off(0) {
            join_handle.join().ok();
        }

        let self_join_handle = self.join_handle.lock().take().unwrap();
        self_join_handle.join().ok();
    }
}

pub struct PrefetchTaskHandle<'a> {
    pub prefetcher: Option<&'a ExecutionStatePrefetcher>,
    pub state: &'a State,
    pub task_epoch_id: EpochId,
    pub accounts: Vec<&'a Address>,
}

impl PrefetchTaskHandle<'_> {
    pub fn wait_for_task(&self) -> bool {
        match self.prefetcher.as_ref() {
            None => false,
            Some(prefetcher) => prefetcher.wait_for_task(&self.task_epoch_id),
        }
    }
}

impl Drop for PrefetchTaskHandle<'_> {
    fn drop(&mut self) {
        match self.prefetcher.take() {
            None => {}
            Some(prefetcher) => prefetcher.cancel_task(&self.task_epoch_id),
        }
        // To mute the compiler's complain over the variable isn't used.
        self.accounts.clear();
    }
}

struct PrefetchTaskKey(
    pub EpochId,
    pub &'static State,
    pub &'static [&'static Address],
);

impl CancelByKey for PrefetchTaskKey {
    type Key = EpochId;

    #[inline]
    fn key(&self) -> &Self::Key {
        &self.0
    }
}

use crate::state::State;
use cfx_statedb::Result as DbResult;
use cfx_types::Address;
use cfx_utils::cancellable_task_channel::*;
use parking_lot::{Mutex, RwLock};
use primitives::EpochId;
use std::{
    io,
    ptr::null,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SendError},
        Arc,
    },
    thread::{self, JoinHandle},
};
