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
    ) -> Self
    {
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
    )
    {
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
            EpochId,
            u64,
            &'static State,
            &'static [&'static Address],
        )>,
        task_finish_signal: mpsc::Sender<()>,
    )
    {
        while let Ok((task_epoch_id, task_id, state, accounts)) =
            task_queue.recv()
        {
            if task_id == 0 {
                // Stopped by the Prefetcher.
                return;
            } else {
                *self.current_task_id.write() = (task_epoch_id, task_id);
                self.prefetch_accounts(task_id, state, accounts);
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
    )
    {
        let mut current_task_id = 0u64;
        loop {
            match task_receiver.recv() {
                Ok((task_epoch_id, state, accounts)) => {
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

pub trait CancelByKey {
    type Key: Clone + std::fmt::Debug + PartialEq;

    fn key(&self) -> &Self::Key;

    #[inline]
    fn matches_key(&self, key: &Self::Key) -> bool {
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
    // Use std Mutex in combination with CondVar.
    task_info: Arc<Mutex<TaskInfo<T>>>,
    queue: Arc<RwLock<VecDeque<Option<T>>>>,
}

pub struct CancelableTaskReceiver<T: CancelByKey> {
    queue: Arc<RwLock<VecDeque<Option<T>>>>,
    task_info: Arc<Mutex<TaskInfo<T>>>,
    receiver: mpsc::Receiver<bool>,
    should_pop_recv: AtomicBool,
}

#[derive(Default)]
pub struct TaskInfo<T: CancelByKey> {
    // It is None at the very beginning of the execution, or when the task
    // execution is canceled.
    maybe_current_task_key: Option<T::Key>,
    // Maintained when a task become the current key. All old waiters are
    // informed about the finish.
    current_task_waits: Option<Arc<Condvar>>,
    pending_tasks_waits: Vec<(T::Key, Arc<Condvar>)>,
}

impl<T: CancelByKey> TaskInfo<T> {
    pub fn inform_previous_task_finish(&mut self) {
        let waits = self.current_task_waits.take();
        if let Some(wait) = waits {
            wait.notify_all();
        }
    }

    fn set_current_task(&mut self, maybe_key: Option<T::Key>) {
        if self.current_task_waits.is_some() {
            self.inform_previous_task_finish();
        }
        if let Some(key) = maybe_key.as_ref() {
            for i in 0..self.pending_tasks_waits.len() {
                if T::key_matches(&self.pending_tasks_waits[i].0, key) {
                    self.current_task_waits =
                        Some(self.pending_tasks_waits.swap_remove(i).1);
                }
            }
        }
        self.maybe_current_task_key = maybe_key;
    }

    pub fn clone_existing_wait(&self, key: &T::Key) -> Option<Arc<Condvar>> {
        for wait in &self.pending_tasks_waits {
            if T::key_matches(&wait.0, key) {
                return Some(wait.1.clone());
            }
        }
        None
    }
}

impl<T: CancelByKey> CancelableTaskSender<T> {
    pub fn stop(&self) -> Result<(), SendError<bool>> {
        self.sender.send(false)
    }

    pub fn send(&self, task: T) -> Result<(), SendError<bool>> {
        self.queue.write().push_back(Some(task));
        self.sender.send(true)
    }

    pub fn current_task(&self) -> MappedMutexGuard<Option<T::Key>> {
        MutexGuard::map(self.task_info.lock(), |info| {
            &mut info.maybe_current_task_key
        })
    }

    fn notify_pending_task_waits(
        task_info_locked: &mut TaskInfo<T>, key: &T::Key,
    ) {
        task_info_locked.pending_tasks_waits.retain(|task| {
            if T::key_matches(&task.0, key) {
                task.1.notify_all();
                false
            } else {
                true
            }
        })
    }

    // Return whether a task is removed.
    fn remove_pending(
        &self, task_info_locked: &mut TaskInfo<T>, key: &T::Key,
    ) -> bool {
        let queue = &mut *self.queue.write();
        let mut found = false;
        // Remove tasks from queue.
        for maybe_task in queue.iter_mut() {
            if maybe_task
                .as_ref()
                .map_or(false, |task| task.matches_key(key))
            {
                found = true;
                *maybe_task = None
            }
        }
        if found {
            Self::notify_pending_task_waits(task_info_locked, key);
        }
        found
    }

    // Return whether the key to remove is the current task.
    pub fn remove(&self, key: &T::Key) -> bool {
        let is_current_task_removed;
        // Hold the current task lock because we don't want a pending task
        // becomes the current task while we are trying to cancel it.
        let mut task_info_locked = self.task_info.lock();
        if task_info_locked
            .maybe_current_task_key
            .as_ref()
            .map_or(false, |current_task_key| {
                T::key_matches(current_task_key, key)
            })
        {
            // It's the current task.
            is_current_task_removed = true;

            // Search in pending queue because we allow multiple tasks with same
            // id.
            self.remove_pending(&mut task_info_locked, key);
            // Set the cancellation flag.
            task_info_locked.maybe_current_task_key = None;
        } else {
            is_current_task_removed = false;
            // Search in pending queue.
            self.remove_pending(&mut task_info_locked, key);
        }

        is_current_task_removed
    }

    // Return None if the key can not be found.
    pub fn wait_for(
        &self, key: &T::Key,
    ) -> Option<(Arc<Condvar>, MutexGuard<TaskInfo<T>>)> {
        let mut task_info_locked = self.task_info.lock();
        if task_info_locked
            .maybe_current_task_key
            .as_ref()
            .map_or(false, |current_key| T::key_matches(current_key, key))
        {
            // It's the current task.
            if task_info_locked.current_task_waits.is_none() {
                // There are no existing waits.
                let new_waits = Arc::<Condvar>::default();
                task_info_locked.current_task_waits = Some(new_waits.clone());

                Some((new_waits, task_info_locked))
            } else {
                // There are existing waits.
                Some((
                    task_info_locked.current_task_waits.clone().unwrap(),
                    task_info_locked,
                ))
            }
        } else {
            // Search in pending waits.
            let wait = task_info_locked.clone_existing_wait(key);
            if wait.is_some() {
                Some((wait.unwrap(), task_info_locked))
            } else {
                let queue = &*self.queue.read();
                for pending_task in queue {
                    if pending_task
                        .as_ref()
                        .map_or(false, |task| task.matches_key(key))
                    {
                        let cond_var = Arc::<Condvar>::default();
                        task_info_locked
                            .pending_tasks_waits
                            .push((key.clone(), cond_var.clone()));

                        return Some((cond_var, task_info_locked));
                    }
                }

                None
            }
        }
    }
}

pub fn new_cancellable_task_channel<T: CancelByKey>(
) -> (CancelableTaskSender<T>, CancelableTaskReceiver<T>) {
    let (sender, receiver) = mpsc::channel();
    let queue = Arc::<RwLock<VecDeque<Option<T>>>>::default();
    let task_info = Arc::new(Mutex::new(TaskInfo {
        maybe_current_task_key: None,
        current_task_waits: None,
        pending_tasks_waits: vec![],
    }));
    (
        CancelableTaskSender {
            sender,
            task_info: task_info.clone(),
            queue: queue.clone(),
        },
        CancelableTaskReceiver {
            queue,
            receiver,
            task_info,
            should_pop_recv: AtomicBool::new(true),
        },
    )
}

pub enum StopOr<RecvError> {
    Stop,
    RecvError(RecvError),
}

impl<T: CancelByKey> CancelableTaskReceiver<T> {
    fn pop_recv(&self) {
        if self.should_pop_recv.load(Ordering::Relaxed) {
            // Pop the task from task receiver as well.
            self.receiver.recv().ok();
        } else {
            self.should_pop_recv.store(true, Ordering::Relaxed);
        }
    }

    pub fn try_recv(&self) -> Result<T, StopOr<TryRecvError>> {
        self.recv_impl(/* try_recv = */ true)
    }

    pub fn recv(&self) -> Result<T, StopOr<RecvError>> {
        match self.recv_impl(/* try_recv = */ false) {
            Ok(t) => Ok(t),
            Err(StopOr::Stop) => Err(StopOr::Stop),
            Err(StopOr::RecvError(TryRecvError::Disconnected)) => {
                Err(StopOr::RecvError(RecvError))
            }
            _ => unsafe { unreachable_unchecked() },
        }
    }

    fn recv_impl(&self, try_recv: bool) -> Result<T, StopOr<TryRecvError>> {
        let mut current_task_guard = self.task_info.lock();
        loop {
            let new_task = {
                let queue = &mut self.queue.write();
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
                    current_task_guard.set_current_task(None);
                    // Should not block cancel_task when we are waiting for
                    // new tasks.
                    match MutexGuard::unlocked(&mut current_task_guard, || {
                        match self.receiver.try_recv() {
                            Err(TryRecvError::Empty) if !try_recv => {
                                match self.receiver.recv() {
                                    Ok(t) => Ok(t),
                                    Err(_) => Err(TryRecvError::Disconnected),
                                }
                            }
                            maybe_task => maybe_task,
                        }
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
                    // Notify all waits on the previous task, and set current
                    // key.
                    current_task_guard
                        .set_current_task(Some(task.key().clone()));
                    return Ok(task);
                }
            }
        }
    }
}

use crate::state::State;
use cfx_types::Address;
use parking_lot::{Condvar, MappedMutexGuard, Mutex, MutexGuard, RwLock};
use primitives::EpochId;
use std::{
    collections::VecDeque,
    hint::unreachable_unchecked,
    io,
    ptr::null,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvError, SendError, TryRecvError},
        Arc,
    },
    thread::{self, JoinHandle},
};
