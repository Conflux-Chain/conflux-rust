// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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
        },
    )
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

#[derive(Clone)]
pub struct CancelableTaskSender<T: CancelByKey> {
    sender: mpsc::Sender<bool>,
    // Use Mutex in combination with Condvar.
    task_info: Arc<Mutex<TaskInfo<T>>>,
    queue: Arc<RwLock<VecDeque<Option<T>>>>,
}

pub struct CancelableTaskReceiver<T: CancelByKey> {
    queue: Arc<RwLock<VecDeque<Option<T>>>>,
    task_info: Arc<Mutex<TaskInfo<T>>>,
    receiver: mpsc::Receiver<bool>,
}

pub enum StopOr<RecvError> {
    Stop,
    RecvError(RecvError),
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
            self.remove_pending(
                &mut task_info_locked,
                key,
                // There are no waits in pending queue for the current task.
                /* notify_waits = */
                false,
            );
            // Set the cancellation flag.
            task_info_locked.maybe_current_task_key = None;
        } else {
            is_current_task_removed = false;
            // Search in pending queue.
            self.remove_pending(
                &mut task_info_locked,
                key,
                /* notify_waits = */ true,
            );
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
            let wait = task_info_locked.clone_pending_task_wait(key);
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

impl<T: CancelByKey> CancelableTaskSender<T> {
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
        notify_waits: bool,
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
        if notify_waits && found {
            Self::notify_pending_task_waits(task_info_locked, key);
        }
        found
    }
}

impl<T: CancelByKey> CancelableTaskReceiver<T> {
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
}

impl<T: CancelByKey> CancelableTaskReceiver<T> {
    #[inline]
    fn recv_task_from_receiver(&self) -> Result<bool, StopOr<TryRecvError>> {
        match self.receiver.recv() {
            Ok(true) => Ok(true),
            Ok(false) => Err(StopOr::Stop),
            Err(_) => Err(StopOr::RecvError(TryRecvError::Disconnected)),
        }
    }

    fn pop_task_from_receiver(
        &self, try_recv: bool, may_block_indefinitely: bool,
        task_guard: &mut MutexGuard<TaskInfo<T>>,
        queue_guard: &mut RwLockWriteGuard<VecDeque<Option<T>>>,
    ) -> Result<bool, StopOr<TryRecvError>> {
        match self.receiver.try_recv() {
            Err(TryRecvError::Disconnected) => {
                Err(StopOr::RecvError(TryRecvError::Disconnected))
            }
            Err(TryRecvError::Empty) => {
                if try_recv {
                    Err(StopOr::RecvError(TryRecvError::Empty))
                } else {
                    if may_block_indefinitely {
                        // Notify all waits of the previous task.
                        task_guard.set_current_task(None);
                        // Unblock all locks when we are waiting.
                        RwLockWriteGuard::unlocked(queue_guard, || {
                            MutexGuard::unlocked(task_guard, || {
                                self.recv_task_from_receiver()
                            })
                        })
                    } else {
                        self.recv_task_from_receiver()
                    }
                }
            }
            Ok(true) => Ok(true),
            Ok(false) => Err(StopOr::Stop),
        }
    }

    fn recv_impl(&self, try_recv: bool) -> Result<T, StopOr<TryRecvError>> {
        let mut current_task_guard = self.task_info.lock();
        let mut queue_locked = self.queue.write();
        let mut should_pop_recv = true;
        loop {
            if should_pop_recv {
                self.pop_task_from_receiver(
                    try_recv,
                    /* may_block_indefinitely = */
                    queue_locked.is_empty(),
                    &mut current_task_guard,
                    &mut queue_locked,
                )?;
            }
            match queue_locked.pop_front() {
                None => {
                    // Retry when we already received the new task from
                    // task_receiver, but task_queue is still empty.
                    should_pop_recv = false;
                    continue;
                }
                Some(None) => {
                    // Received a task, however it's already cancelled, retry.
                    should_pop_recv = true;
                    continue;
                }
                Some(Some(task)) => {
                    // Task received

                    // Notify all waits on the previous task, and set current
                    // key.
                    current_task_guard
                        .set_current_task(Some(task.key().clone()));
                    break Ok(task);
                }
            }
        }
    }
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

    fn clone_pending_task_wait(&self, key: &T::Key) -> Option<Arc<Condvar>> {
        for wait in &self.pending_tasks_waits {
            if T::key_matches(&wait.0, key) {
                return Some(wait.1.clone());
            }
        }
        None
    }
}

use parking_lot::{
    Condvar, MappedMutexGuard, Mutex, MutexGuard, RwLock, RwLockWriteGuard,
};
use std::{
    collections::VecDeque,
    hint::unreachable_unchecked,
    sync::{
        mpsc::{self, RecvError, SendError, TryRecvError},
        Arc,
    },
};
