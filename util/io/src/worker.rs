// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    service_mio::{HandlerId, IoChannel, IoContext},
    IoHandler, LOCAL_STACK_SIZE,
};
use crossbeam_deque;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        mpsc::Receiver,
        Arc,
    },
    thread::{self, JoinHandle},
};

use std::sync::{Condvar as SCondvar, Mutex as SMutex};

const STACK_SIZE: usize = 16 * 1024 * 1024;

pub enum WorkType<Message> {
    Timeout,
    Message(Arc<Message>),
}

pub struct Work<Message> {
    pub work_type: WorkType<Message>,
    pub token: usize,
    pub handler_id: HandlerId,
    pub handler: Arc<dyn IoHandler<Message>>,
}

/// A socket IO worker thread
pub struct SocketWorker {
    thread: Option<JoinHandle<()>>,
    deleting: Arc<AtomicBool>,
}

impl SocketWorker {
    /// Creates a socket worker instance
    pub fn new<Message>(
        index: usize, rx: Receiver<Work<Message>>, channel: IoChannel<Message>,
    ) -> SocketWorker
    where Message: Send + Sync + 'static {
        let deleting = Arc::new(AtomicBool::new(false));
        let mut worker = SocketWorker {
            thread: None,
            deleting: deleting.clone(),
        };
        worker.thread = Some(
            thread::Builder::new()
                .stack_size(STACK_SIZE)
                .name(format!("Socket IO Worker #{}", index))
                .spawn(move || {
                    LOCAL_STACK_SIZE.with(|val| val.set(STACK_SIZE));
                    SocketWorker::work_loop(rx, channel.clone(), deleting)
                })
                .expect("Error creating socket worker thread"),
        );
        worker
    }

    fn work_loop<Message>(
        rx: Receiver<Work<Message>>, channel: IoChannel<Message>,
        deleting: Arc<AtomicBool>,
    ) where
        Message: Send + Sync + 'static,
    {
        loop {
            if deleting.load(AtomicOrdering::Acquire) {
                return;
            }
            while !deleting.load(AtomicOrdering::Acquire) {
                // TODO recv_timeout() may panic, not sure if it's the cause for
                // returning SendError on the sender
                match rx.recv() {
                    Ok(work) => SocketWorker::do_work(work, channel.clone()),
                    _ => break,
                }
            }
        }
    }

    fn do_work<Message>(work: Work<Message>, channel: IoChannel<Message>)
    where Message: Send + Sync + 'static {
        match work.work_type {
            WorkType::Message(message) => {
                work.handler.message(
                    &IoContext::new(channel, work.handler_id),
                    &*message,
                );
            }
            _ => warn!(target: "SocketWorker::do_work", "Unexpected WorkType"),
        }
    }
}

impl Drop for SocketWorker {
    fn drop(&mut self) {
        trace!(target: "shutdown", "[SocketIoWorker] Closing...");
        self.deleting.store(true, AtomicOrdering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
        trace!(target: "shutdown", "[SocketIoWorker] Closed");
    }
}

/// An IO worker thread
/// Sorts them ready for blockchain insertion.
pub struct Worker {
    thread: Option<JoinHandle<()>>,
    wait: Arc<SCondvar>,
    deleting: Arc<AtomicBool>,
    wait_mutex: Arc<SMutex<()>>,
}

impl Worker {
    /// Creates a new worker instance.
    pub fn new<Message>(
        index: usize, stealer: crossbeam_deque::Stealer<Work<Message>>,
        channel: IoChannel<Message>, wait: Arc<SCondvar>,
        wait_mutex: Arc<SMutex<()>>,
    ) -> Worker
    where
        Message: Send + Sync + 'static,
    {
        let deleting = Arc::new(AtomicBool::new(false));
        let mut worker = Worker {
            thread: None,
            wait: wait.clone(),
            deleting: deleting.clone(),
            wait_mutex: wait_mutex.clone(),
        };
        worker.thread = Some(
            thread::Builder::new()
                .stack_size(STACK_SIZE)
                .name(format!("IO Worker #{}", index))
                .spawn(move || {
                    LOCAL_STACK_SIZE.with(|val| val.set(STACK_SIZE));
                    Worker::work_loop(
                        stealer,
                        channel.clone(),
                        wait,
                        wait_mutex.clone(),
                        deleting,
                    )
                })
                .expect("Error creating worker thread"),
        );
        worker
    }

    fn work_loop<Message>(
        stealer: crossbeam_deque::Stealer<Work<Message>>,
        channel: IoChannel<Message>, wait: Arc<SCondvar>,
        wait_mutex: Arc<SMutex<()>>, deleting: Arc<AtomicBool>,
    ) where
        Message: Send + Sync + 'static,
    {
        loop {
            {
                let lock = wait_mutex.lock().expect("Poisoned work_loop mutex");
                if deleting.load(AtomicOrdering::Acquire) {
                    return;
                }
                let _ = wait.wait(lock);
            }

            while !deleting.load(AtomicOrdering::Acquire) {
                match stealer.steal() {
                    crossbeam_deque::Steal::Success(work) => {
                        Worker::do_work(work, channel.clone())
                    }
                    _ => break,
                }
            }
        }
    }

    fn do_work<Message>(work: Work<Message>, channel: IoChannel<Message>)
    where Message: Send + Sync + 'static {
        match work.work_type {
            WorkType::Timeout => {
                work.handler.timeout(
                    &IoContext::new(channel, work.handler_id),
                    work.token,
                );
            }
            WorkType::Message(message) => {
                work.handler.message(
                    &IoContext::new(channel, work.handler_id),
                    &*message,
                );
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        trace!(target: "shutdown", "[IoWorker] Closing...");
        let _ = self.wait_mutex.lock().expect("Poisoned work_loop mutex");
        self.deleting.store(true, AtomicOrdering::Release);
        self.wait.notify_all();
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
        trace!(target: "shutdown", "[IoWorker] Closed");
    }
}
