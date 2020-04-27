// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub fn prefetch_accounts<'a>(
    prefetcher: &'a ExecutionStatePrefetcher, task_epoch_id: EpochId,
    state: &State, account_vec: Vec<&'a Address>,
) -> PrefetchTaskHandle<'a>
{
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
    current_task_id: Mutex<Option<(EpochId, u64)>>,
    current_task_canceled_receiver: Mutex<mpsc::Receiver<()>>,
    workers: Vec<Arc<PrefetcherThreadWorker>>,
    worker_join_handles: Vec<JoinHandle<()>>,

    join_handle: Mutex<Option<JoinHandle<()>>>,
}

struct PrefetcherThreadWorker {
    task_queue_sender:
        Mutex<mpsc::Sender<(u64, &'static State, &'static [&'static Address])>>,
    /// All threads should be processing the same task.
    /// Abort the current task when the task id changed.
    cancel_task_id: AtomicU64,
}

impl PrefetcherThreadWorker {
    fn new(
        task_queue_sender: mpsc::Sender<(
            u64,
            &'static State,
            &'static [&'static Address],
        )>,
    ) -> Self
    {
        Self {
            task_queue_sender: Mutex::new(task_queue_sender),
            cancel_task_id: Default::default(),
        }
    }

    /// Unsafe because there shouldn't be concurrent calls to this function.
    /// It also doesn't wait for the task to ffinish.
    unsafe fn signal_current_task_cancellation(&self, task_id: u64) {
        self.cancel_task_id.store(task_id, Ordering::Relaxed);
    }

    fn send_new_task(
        &self, task_id: u64, state: &'static State,
        addresses: &'static [&'static Address],
    )
    {
        self.task_queue_sender
            .lock()
            .send((task_id, state, addresses))
            .ok();
    }

    /// Unsafe because we only want the Prefetcher to stop the thread.
    unsafe fn stop(&self) {
        self.task_queue_sender.lock().send((0, &*null(), &[])).ok();
    }

    fn prefetch_accounts(
        &self, task_id: u64, state: &'static State,
        accounts: &'static [&'static Address],
    )
    {
        self.cancel_task_id.store(0, Ordering::Relaxed);
        for address in accounts {
            let cancel_task_id = self.cancel_task_id.load(Ordering::Relaxed);
            if cancel_task_id != 0 {
                if cancel_task_id == task_id {
                    break;
                }
                self.cancel_task_id.store(0, Ordering::Relaxed);
            }
            state.try_load(address);
        }
    }

    fn run(
        &self,
        task_queue: mpsc::Receiver<(
            u64,
            &'static State,
            &'static [&'static Address],
        )>,
        task_finish_signal: mpsc::Sender<()>,
    )
    {
        while let Ok((task_id, state, accounts)) = task_queue.recv() {
            if task_id == 0 {
                // Stopped by the Prefetcher.
                return;
            } else {
                self.prefetch_accounts(task_id, state, accounts);
                task_finish_signal.send(()).expect(
                    // sender shouln not return error.
                    &concat!(file!(), ":", line!(), ":", column!()),
                );
            }
        }
        error!("State prefetcher thread Stopped due to exception.");
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
            let (task_finish_sender, task_finish_receiver) = mpsc::channel();
            let (task_queue_sender, task_queue_receiver) = mpsc::channel();
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
        let (task_canceled_sender, task_canceled_receiver) = mpsc::channel();
        let (task_sender, task_receiver) = new_cancelable_task_channel();
        let prefetcher = Arc::new(Self {
            task_sender: Mutex::new(task_sender),
            workers,
            current_task_id: Default::default(),
            current_task_canceled_receiver: Mutex::new(task_canceled_receiver),
            worker_join_handles,
            join_handle: Default::default(),
        });

        let prefetcher_to_run = prefetcher.clone();
        let prefetcher_join_handle = thread::Builder::new()
            .name("Execution state prefetcher".into())
            .spawn(move || {
                prefetcher_to_run.run(
                    thread_finish_signal_receivers,
                    task_canceled_sender,
                    task_receiver,
                );
            })?;
        *prefetcher.join_handle.lock() = Some(prefetcher_join_handle);

        Ok(prefetcher)
    }

    pub fn stop(&self) { self.task_sender.lock().stop().ok(); }

    pub fn add_task(
        &self, task_epoch_id: EpochId, state: &'static State,
        accounts: &'static [&'static Address],
    ) -> Result<(), SendError<bool>>
    {
        self.task_sender
            .lock()
            .send((task_epoch_id, state, accounts))
    }

    pub fn wait_for_task(&self, task_epoch_id: &EpochId) {
        self.cancel_task(task_epoch_id, /* cancel = */ false);
    }

    pub fn cancel_task(&self, task_epoch_id: &EpochId, cancel: bool) {
        // Hold the current task lock because we don't want a pending task
        // becomes the current task while we are trying to cancel it.
        let mut current_task_locked = self.current_task_id.lock();
        if current_task_locked.as_ref().map_or(false, |current| {
            PrefetchTaskKey::key_matches(&current.0, task_epoch_id)
        }) {
            let current_task_id = current_task_locked.as_ref().unwrap().1;
            // It's the current task.
            // Inform the thread about the cancellation.
            if cancel {
                unsafe {
                    for thread in &self.workers {
                        thread
                            .signal_current_task_cancellation(current_task_id);
                    }
                }
            }
            *current_task_locked = None;
            // Search in pending queue.
            self.task_sender
                .lock()
                .cancel(task_epoch_id, &current_task_locked);
            drop(current_task_locked);
            // Wait for the cancelled task to finish.
            self.current_task_canceled_receiver.lock().recv().expect(
                // recv shouldn't return error.
                &concat!(file!(), ":", line!(), ":", column!()),
            );
        } else {
            // Search in pending queue.
            self.task_sender
                .lock()
                .cancel(task_epoch_id, &current_task_locked);
        }
    }

    fn wait_for_previous_task(
        finish_signal_receivers: &mut [mpsc::Receiver<()>],
    ) {
        for receiver in finish_signal_receivers {
            receiver.recv().expect(
                // recv shouldn't return error.
                &concat!(file!(), ":", line!(), ":", column!()),
            );
        }
    }

    fn run(
        &self, mut finish_signal_receivers: Vec<mpsc::Receiver<()>>,
        task_canceled_sender: mpsc::Sender<()>,
        task_receiver: CancelableTaskReceiver<PrefetchTaskKey>,
    )
    {
        let mut current_task_id = 0u64;
        loop {
            let mut current_task_epoch_id = self.current_task_id.lock();

            match task_receiver.recv(&mut current_task_epoch_id) {
                Ok((task_epoch_id, state, accounts)) => {
                    if current_task_id == std::u64::MAX {
                        current_task_id = 1;
                    } else {
                        current_task_id += 1;
                    }
                    *current_task_epoch_id =
                        Some((task_epoch_id, current_task_id));
                    drop(current_task_epoch_id);

                    // Dispatch tasks to threads.
                    let num_accounts = accounts.len();
                    let num_threads = self.workers.len();
                    for thread_idx in 0..num_threads {
                        let range_start =
                            num_accounts * thread_idx / num_threads;
                        let range_end =
                            num_accounts * (thread_idx + 1) / num_threads;

                        self.workers[thread_idx].send_new_task(
                            current_task_id,
                            state,
                            &accounts[range_start..range_end],
                        );
                    }

                    Self::wait_for_previous_task(&mut finish_signal_receivers);
                    let mut current_task_id_locked =
                        self.current_task_id.lock();
                    // The current task has been canceled while it was being
                    // processed.
                    if current_task_id_locked.is_none() {
                        task_canceled_sender.send(()).expect(
                            // recv shouldn't return error.
                            &concat!(file!(), ":", line!(), ":", column!()),
                        );
                    } else {
                        // Clear the current task id so that it can not be
                        // canceled any more.
                        *current_task_id_locked = None;
                    }
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
        error!("State prefetcher thread Stopped due to exception.");
    }
}

impl Drop for ExecutionStatePrefetcher {
    fn drop(&mut self) {
        // Signal the prefetch thread to exit.
        self.stop();

        // Let workers Stop after current task.
        for worker in &self.workers {
            unsafe {
                worker.stop();
            }
        }
        // Cancel the current task
        let current_task = self.current_task_id.lock().clone();
        if let Some(task) = &current_task {
            self.cancel_task(&task.0, /* cancel = */ true);
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
    pub fn wait_for_task(&self) {
        match self.prefetcher.as_ref() {
            None => {}
            Some(prefetcher) => prefetcher.wait_for_task(&self.task_epoch_id),
        }
    }
}

impl Drop for PrefetchTaskHandle<'_> {
    fn drop(&mut self) {
        match self.prefetcher.take() {
            None => {}
            Some(prefetcher) => prefetcher
                .cancel_task(&self.task_epoch_id, /* cancel = */ true),
        }
        // To mute the compiler complain about accounts isn't used.
        self.accounts.clear();
    }
}

pub trait CancelByKey {
    type Key: PartialEq;

    fn key(&self) -> &Self::Key;

    #[inline]
    fn match_key(&self, key: &Self::Key) -> bool {
        Self::key_matches(self.key(), key)
    }

    #[inline]
    fn key_matches(this: &Self::Key, other: &Self::Key) -> bool {
        this.eq(other)
    }
}

type PrefetchTaskKey = (EpochId, &'static State, &'static [&'static Address]);

impl CancelByKey for PrefetchTaskKey {
    type Key = EpochId;

    #[inline]
    fn key(&self) -> &Self::Key { &self.0 }
}

#[derive(Clone)]
pub struct CancelableTaskSender<T: CancelByKey> {
    sender: mpsc::Sender<bool>,
    queue: Arc<Mutex<VecDeque<Option<T>>>>,
}

pub struct CancelableTaskReceiver<T> {
    queue: Arc<Mutex<VecDeque<Option<T>>>>,
    receiver: mpsc::Receiver<bool>,
    should_pop_recv: AtomicBool,
}

impl<T: CancelByKey> CancelableTaskSender<T> {
    pub fn stop(&self) -> Result<(), SendError<bool>> {
        self.sender.send(false)
    }

    pub fn send(&self, task: T) -> Result<(), SendError<bool>> {
        self.queue.lock().push_back(Some(task));
        self.sender.send(true)
    }

    pub fn cancel<'a, O>(
        &self, key: &T::Key, _current_task_guard: &MutexGuard<'a, O>,
    ) {
        let queue = &mut *self.queue.lock();
        for maybe_task in queue.iter_mut() {
            if maybe_task
                .as_ref()
                .map_or(false, |task| task.match_key(key))
            {
                *maybe_task = None
            }
        }
    }
}

pub fn new_cancelable_task_channel<T: CancelByKey>(
) -> (CancelableTaskSender<T>, CancelableTaskReceiver<T>) {
    let (sender, receiver) = mpsc::channel();
    let queue: Arc<Mutex<VecDeque<Option<T>>>> = Default::default();
    (
        CancelableTaskSender {
            sender,
            queue: queue.clone(),
        },
        CancelableTaskReceiver {
            queue,
            receiver,
            should_pop_recv: AtomicBool::new(true),
        },
    )
}

pub enum StopOr<RecvError> {
    Stop,
    RecvError(RecvError),
}

impl<T> CancelableTaskReceiver<T> {
    fn pop_recv(&self) {
        if self.should_pop_recv.load(Ordering::Relaxed) {
            // Pop the task from task receiver as well.
            self.receiver.recv().ok();
        } else {
            self.should_pop_recv.store(true, Ordering::Relaxed);
        }
    }

    pub fn recv<'a, O>(
        &self, current_task_guard: &mut MutexGuard<'a, O>,
    ) -> Result<T, StopOr<RecvError>> {
        loop {
            let new_task = {
                let queue = &mut self.queue.lock();
                loop {
                    match queue.pop_front() {
                        Some(None) => {
                            self.pop_recv();
                            continue;
                        }
                        None => break None,
                        Some(Some(task)) => break Some(task),
                    }
                }
            };
            // Wait for new task if task queue is empty.
            match new_task {
                None => {
                    // Retry when we already received the new task from
                    // task_receiver, but task_queue is still empty.
                    if !self.should_pop_recv.load(Ordering::Relaxed) {
                        continue;
                    }
                    // Should not block cancel_task when we are waiting for
                    // new tasks.
                    match MutexGuard::unlocked(current_task_guard, || {
                        self.receiver.recv()
                    }) {
                        Ok(true) => {
                            self.should_pop_recv
                                .store(false, Ordering::Relaxed);
                            continue;
                        }
                        Ok(false) => {
                            // Received stop signal.
                            return Err(StopOr::Stop);
                        }
                        Err(e) => return Err(StopOr::RecvError(e)),
                    }
                }
                Some(task) => {
                    self.pop_recv();
                    return Ok(task);
                }
            }
        }
    }
}

use crate::state::State;
use cfx_types::Address;
use parking_lot::{Mutex, MutexGuard};
use primitives::EpochId;
use std::{
    collections::VecDeque,
    io,
    ptr::null,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvError, SendError},
        Arc,
    },
    thread::{self, JoinHandle},
};
