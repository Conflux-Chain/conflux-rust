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
    worker::{SocketWorker, Work, WorkType, Worker},
    IoError, IoHandler,
};
use crossbeam_deque;
use lazy_static::lazy_static;
use log::{debug, error, trace, warn};
use metrics::{register_meter_with_group, Meter, MeterTimer};
use mio::{
    deprecated::{EventLoop, EventLoopBuilder, Handler, Sender},
    timer::Timeout,
    *,
};
use parking_lot::{Mutex, RwLock};
use slab::Slab;
use std::{
    collections::HashMap,
    sync::{Arc, Condvar as SCondvar, Mutex as SMutex, Weak},
    thread::{self, JoinHandle},
    time::Duration,
};

// FIXME: Use a enum type instead for function calls.
/// Timer ID
pub type TimerToken = usize;
/// Timer ID
pub type StreamToken = usize;
/// IO Handler ID
pub type HandlerId = usize;

/// Maximum number of tokens a handler can use
pub const TOKENS_PER_HANDLER: usize = 16384;
const MAX_HANDLERS: usize = 8;

lazy_static! {
    static ref NET_POLL_THREAD_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "service_mio::network_poll_thread");
}

/// Messages used to communicate with the event loop from other threads.
#[derive(Clone)]
pub enum IoMessage<Message>
where Message: Send + Sized
{
    /// Shutdown the event loop
    Shutdown,
    /// Register a new protocol handler.
    AddHandler {
        handler: Arc<dyn IoHandler<Message> + Send>,
    },
    RemoveHandler {
        handler_id: HandlerId,
    },
    AddTimer {
        handler_id: HandlerId,
        token: TimerToken,
        delay: Duration,
        once: bool,
        /// same as UserTimer.cancel_all
        cancel_all: bool,
    },
    RemoveTimer {
        handler_id: HandlerId,
        token: TimerToken,
    },
    RegisterStream {
        handler_id: HandlerId,
        token: StreamToken,
    },
    DeregisterStream {
        handler_id: HandlerId,
        token: StreamToken,
    },
    UpdateStreamRegistration {
        handler_id: HandlerId,
        token: StreamToken,
    },
    /// Broadcast a message across all protocol handlers.
    UserMessage(Arc<Message>),
    /// Handle a message received from a peer by a specified protocol handler
    RemoteMessage {
        peer: StreamToken,
        handler_id: HandlerId,
        msg: Arc<Message>,
    },
}

/// IO access point. This is passed to all IO handlers and provides an interface
/// to the IO subsystem.
#[derive(Clone)]
pub struct IoContext<Message>
where Message: Send + Sync + 'static
{
    channel: IoChannel<Message>,
    handler: HandlerId,
}

impl<Message> IoContext<Message>
where Message: Send + Sync + 'static
{
    /// Create a new IO access point. Takes references to all the data that can
    /// be updated within the IO handler.
    pub fn new(
        channel: IoChannel<Message>, handler: HandlerId,
    ) -> IoContext<Message> {
        IoContext { handler, channel }
    }

    /// Register a new recurring IO timer. 'IoHandler::timeout' will be called
    /// with the token.
    pub fn register_timer(
        &self, token: TimerToken, delay: Duration,
    ) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::AddTimer {
            token,
            delay,
            handler_id: self.handler,
            once: false,
            cancel_all: false,
        })?;
        Ok(())
    }

    /// Register a new IO timer once. 'IoHandler::timeout' will be called with
    /// the token.
    pub fn register_timer_once(
        &self, token: TimerToken, delay: Duration,
    ) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::AddTimer {
            token,
            delay,
            handler_id: self.handler,
            once: true,
            cancel_all: true,
        })?;
        Ok(())
    }

    /// Register a new IO timer once. 'IoHandler::timeout' will be called with
    /// the token. Do NOT cancel other timer on the same token after
    /// timeout.
    pub fn register_timer_once_nocancel(
        &self, token: TimerToken, delay: Duration,
    ) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::AddTimer {
            token,
            delay,
            handler_id: self.handler,
            once: true,
            cancel_all: false,
        })?;
        Ok(())
    }

    /// Delete a timer.
    pub fn clear_timer(&self, token: TimerToken) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::RemoveTimer {
            token,
            handler_id: self.handler,
        })?;
        Ok(())
    }

    /// Register a new IO stream.
    pub fn register_stream(&self, token: StreamToken) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::RegisterStream {
            token,
            handler_id: self.handler,
        })?;
        Ok(())
    }

    /// Deregister an IO stream.
    pub fn deregister_stream(&self, token: StreamToken) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::DeregisterStream {
            token,
            handler_id: self.handler,
        })?;
        Ok(())
    }

    /// Reregister an IO stream.
    pub fn update_registration(
        &self, token: StreamToken,
    ) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::UpdateStreamRegistration {
            token,
            handler_id: self.handler,
        })?;
        Ok(())
    }

    /// Broadcast a message to other IO clients
    pub fn message(&self, message: Message) -> Result<(), IoError> {
        self.channel.send(message)?;
        Ok(())
    }

    pub fn handle(
        &self, peer: usize, handler_id: HandlerId, msg: Message,
    ) -> Result<(), IoError> {
        self.channel.send_io(IoMessage::RemoteMessage {
            peer,
            handler_id,
            msg: Arc::new(msg),
        })
    }

    /// Get message channel
    pub fn channel(&self) -> IoChannel<Message> { self.channel.clone() }

    /// Unregister current IO handler.
    pub fn unregister_handler(&self) {
        // `send_io` returns an error only if the channel is closed, which means
        // that the background thread is no longer running. Therefore
        // the handler is no longer active and can be considered as
        // unregistered.
        let _ = self.channel.send_io(IoMessage::RemoveHandler {
            handler_id: self.handler,
        });
    }
}

#[derive(Clone)]
struct UserTimer {
    delay: Duration,
    timeout: Timeout,
    once: bool,

    /// Only used when once is true. Do not remove timer after timeout, so
    /// later other once timer can be triggered again
    cancel_all: bool,
}

/// Root IO handler. Manages user handlers, messages and IO timers.
pub struct IoManager<Message>
where Message: Send + Sync
{
    timers: Arc<RwLock<HashMap<HandlerId, UserTimer>>>,
    handlers: Arc<RwLock<Slab<Arc<dyn IoHandler<Message>>>>>,
    workers: Vec<Worker>,
    worker_channel: crossbeam_deque::Worker<Work<Message>>,
    work_ready: Arc<SCondvar>,
    socket_workers:
        Vec<(crossbeam_channel::Sender<Work<Message>>, SocketWorker)>,
    network_poll: Arc<Poll>,
}

impl<Message> IoManager<Message>
where Message: Send + Sync + 'static
{
    /// Creates a new instance and registers it with the event loop.
    pub fn start(
        event_loop: &mut EventLoop<IoManager<Message>>,
        handlers: Arc<RwLock<Slab<Arc<dyn IoHandler<Message>>>>>,
        network_poll: Arc<Poll>,
    ) -> Result<(), IoError> {
        let worker = crossbeam_deque::Worker::new_fifo();
        let stealer = worker.stealer();
        let num_workers = 4;
        let work_ready_mutex = Arc::new(SMutex::new(()));
        let work_ready = Arc::new(SCondvar::new());
        let workers = (0..num_workers)
            .map(|i| {
                Worker::new(
                    i,
                    stealer.clone(),
                    IoChannel::new(
                        event_loop.channel(),
                        Arc::downgrade(&handlers),
                    ),
                    work_ready.clone(),
                    work_ready_mutex.clone(),
                )
            })
            .collect();

        let num_socket_workers = 4;
        let socket_workers = (0..num_socket_workers)
            .map(|i| {
                let (tx, rx) = crossbeam_channel::unbounded();
                (
                    tx,
                    SocketWorker::new(
                        i,
                        rx,
                        IoChannel::new(
                            event_loop.channel(),
                            Arc::downgrade(&handlers),
                        ),
                    ),
                )
            })
            .collect();

        let mut io = IoManager {
            timers: Arc::new(RwLock::new(HashMap::new())),
            handlers,
            worker_channel: worker,
            workers,
            work_ready,
            socket_workers,
            network_poll,
        };
        event_loop.run(&mut io)?;
        Ok(())
    }
}

impl<Message> Handler for IoManager<Message>
where Message: Send + Sync + 'static
{
    type Message = IoMessage<Message>;
    type Timeout = Token;

    // All network reading and writing is now handled by the network_poll, so
    // this event loop will not have any ready event.
    //    fn ready(...

    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, token: Token) {
        let handler_index = token.0 / TOKENS_PER_HANDLER;
        let token_id = token.0 % TOKENS_PER_HANDLER;
        if let Some(handler) = self.handlers.read().get(handler_index) {
            let maybe_timer = self.timers.read().get(&token.0).cloned();
            if let Some(timer) = maybe_timer {
                if timer.once {
                    if timer.cancel_all {
                        self.timers.write().remove(&token_id);
                        event_loop.clear_timeout(&timer.timeout);
                    }
                } else {
                    event_loop
                        .timeout(token, timer.delay)
                        .expect("Error re-registering user timer");
                }
                self.worker_channel.push(Work {
                    work_type: WorkType::Timeout,
                    token: token_id,
                    handler: handler.clone(),
                    handler_id: handler_index,
                });
                self.work_ready.notify_all();
            }
        }
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        match msg {
            IoMessage::Shutdown => {
                self.workers.clear();
                event_loop.shutdown();
            }
            IoMessage::AddHandler { handler } => {
                let handler_id = self.handlers.write().insert(handler.clone());
                assert!(
                    handler_id <= MAX_HANDLERS,
                    "Too many handlers registered"
                );
                trace!("add handler {}", handler_id);
                handler.initialize(&IoContext::new(
                    IoChannel::new(
                        event_loop.channel(),
                        Arc::downgrade(&self.handlers),
                    ),
                    handler_id,
                ));
            }
            IoMessage::RemoveHandler { handler_id } => {
                // TODO: flush event loop
                self.handlers.write().remove(handler_id);
                // unregister timers
                let mut timers = self.timers.write();
                let to_remove: Vec<_> = timers
                    .keys()
                    .cloned()
                    .filter(|timer_id| {
                        timer_id / TOKENS_PER_HANDLER == handler_id
                    })
                    .collect();
                for timer_id in to_remove {
                    let timer = timers.remove(&timer_id).expect(
                        "to_remove only contains keys from timers; qed",
                    );
                    event_loop.clear_timeout(&timer.timeout);
                }
            }
            IoMessage::AddTimer {
                handler_id,
                token,
                delay,
                once,
                cancel_all,
            } => {
                let timer_id = token + handler_id * TOKENS_PER_HANDLER;
                let timeout = event_loop
                    .timeout(Token(timer_id), delay)
                    .expect("Error registering user timer");
                self.timers.write().insert(
                    timer_id,
                    UserTimer {
                        delay,
                        timeout,
                        once,
                        cancel_all,
                    },
                );
            }
            IoMessage::RemoveTimer { handler_id, token } => {
                let timer_id = token + handler_id * TOKENS_PER_HANDLER;
                if let Some(timer) = self.timers.write().remove(&timer_id) {
                    event_loop.clear_timeout(&timer.timeout);
                }
            }
            IoMessage::RegisterStream { handler_id, token } => {
                trace!("register stream {} {}", handler_id, token);
                if let Some(handler) = self.handlers.read().get(handler_id) {
                    trace!("do register stream {} {}", handler_id, token);
                    handler.register_stream(
                        token,
                        Token(token + handler_id * TOKENS_PER_HANDLER),
                        self.network_poll.as_ref(),
                    );
                }
            }
            IoMessage::DeregisterStream { handler_id, token } => {
                if let Some(handler) = self.handlers.read().get(handler_id) {
                    handler
                        .deregister_stream(token, self.network_poll.as_ref());
                    // unregister a timer associated with the token (if any)
                    let timer_id = token + handler_id * TOKENS_PER_HANDLER;
                    if let Some(timer) = self.timers.write().remove(&timer_id) {
                        event_loop.clear_timeout(&timer.timeout);
                    }
                }
            }
            IoMessage::UpdateStreamRegistration { handler_id, token } => {
                if let Some(handler) = self.handlers.read().get(handler_id) {
                    handler.update_stream(
                        token,
                        Token(token + handler_id * TOKENS_PER_HANDLER),
                        self.network_poll.as_ref(),
                    );
                }
            }
            IoMessage::UserMessage(data) => {
                //TODO: better way to iterate the slab
                for id in 0..MAX_HANDLERS {
                    if let Some(h) = self.handlers.read().get(id) {
                        let handler = h.clone();
                        self.worker_channel.push(Work {
                            work_type: WorkType::Message(data.clone()),
                            token: 0,
                            handler,
                            handler_id: id,
                        });
                    }
                }
                self.work_ready.notify_all();
            }
            IoMessage::RemoteMessage {
                peer,
                handler_id,
                msg,
            } => {
                let worker_id = peer % 4;
                if let Some(handler) = self.handlers.read().get(handler_id) {
                    self.socket_workers[worker_id]
                        .0
                        .send(Work {
                            work_type: WorkType::Message(msg),
                            token: peer,
                            handler: handler.clone(),
                            handler_id,
                        })
                        .expect("fail to send message to socket_worker");
                }
            }
        }
    }
}

enum Handlers<Message>
where Message: Send
{
    SharedCollection(Weak<RwLock<Slab<Arc<dyn IoHandler<Message>>>>>),
    Single(Weak<dyn IoHandler<Message>>),
}

impl<Message: Send> Clone for Handlers<Message> {
    fn clone(&self) -> Self {
        use self::Handlers::*;

        match *self {
            SharedCollection(ref w) => SharedCollection(w.clone()),
            Single(ref w) => Single(w.clone()),
        }
    }
}

/// Allows sending messages into the event loop. All the IO handlers will get
/// the message in the `message` callback.
pub struct IoChannel<Message>
where Message: Send
{
    channel: Option<Sender<IoMessage<Message>>>,
    handlers: Handlers<Message>,
}

impl<Message> Clone for IoChannel<Message>
where Message: Send + Sync + 'static
{
    fn clone(&self) -> IoChannel<Message> {
        IoChannel {
            channel: self.channel.clone(),
            handlers: self.handlers.clone(),
        }
    }
}

impl<Message> IoChannel<Message>
where Message: Send + Sync + 'static
{
    /// Send a message through the channel
    pub fn send(&self, message: Message) -> Result<(), IoError> {
        match self.channel {
            Some(ref channel) => {
                channel.send(IoMessage::UserMessage(Arc::new(message)))?
            }
            None => self.send_sync(message)?,
        }
        Ok(())
    }

    /// Send a message through the channel and handle it synchronously
    pub fn send_sync(&self, message: Message) -> Result<(), IoError> {
        match self.handlers {
            Handlers::SharedCollection(ref handlers) => {
                if let Some(handlers) = handlers.upgrade() {
                    for id in 0..MAX_HANDLERS {
                        if let Some(h) = handlers.read().get(id) {
                            let handler = h.clone();
                            handler.message(
                                &IoContext::new(self.clone(), id),
                                &message,
                            );
                        }
                    }
                }
            }
            Handlers::Single(ref handler) => {
                if let Some(handler) = handler.upgrade() {
                    handler.message(&IoContext::new(self.clone(), 0), &message);
                }
            }
        }
        Ok(())
    }

    /// Send low level io message
    pub fn send_io(&self, message: IoMessage<Message>) -> Result<(), IoError> {
        if let Some(ref channel) = self.channel {
            if let Err(e) = channel.send(message) {
                warn!("Error sending message to eventloop channel, err={}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Create a new channel disconnected from an event loop.
    pub fn disconnected() -> IoChannel<Message> {
        IoChannel {
            channel: None,
            handlers: Handlers::SharedCollection(Weak::default()),
        }
    }

    /// Create a new synchronous channel to a given handler.
    pub fn to_handler(
        handler: Weak<dyn IoHandler<Message>>,
    ) -> IoChannel<Message> {
        IoChannel {
            channel: None,
            handlers: Handlers::Single(handler),
        }
    }

    fn new(
        channel: Sender<IoMessage<Message>>,
        handlers: Weak<RwLock<Slab<Arc<dyn IoHandler<Message>>>>>,
    ) -> IoChannel<Message> {
        IoChannel {
            channel: Some(channel),
            handlers: Handlers::SharedCollection(handlers),
        }
    }
}

/// General IO Service. Starts an event loop and dispatches IO requests.
/// 'Message' is a notification message type
pub struct IoService<Message>
where Message: Send + Sync + 'static
{
    thread: Mutex<Option<JoinHandle<()>>>,
    host_channel: Mutex<Sender<IoMessage<Message>>>,
    handlers: Arc<RwLock<Slab<Arc<dyn IoHandler<Message>>>>>,
    network_poll_thread: Mutex<Option<JoinHandle<()>>>,
    network_poll_stopped: Arc<(Registration, SetReadiness)>,
}

impl<Message> IoService<Message>
where Message: Send + Sync + 'static
{
    /// Starts IO event loop
    pub fn start(
        network_poll: Arc<Poll>,
    ) -> Result<IoService<Message>, IoError> {
        debug!("start IoService");
        let mut config = EventLoopBuilder::new();
        config.messages_per_tick(1024);
        config.notify_capacity(20960);
        let mut event_loop = config.build().expect("Error creating event loop");
        let channel = event_loop.channel();
        let handlers = Arc::new(RwLock::new(Slab::with_capacity(MAX_HANDLERS)));
        let h = handlers.clone();

        let thread = thread::Builder::new()
            .name("io_service".into())
            .spawn(move || {
                IoManager::<Message>::start(&mut event_loop, h, network_poll)
                    .expect("Error starting IO service");
            })
            .expect("only one io_service thread, so it should not fail");
        Ok(IoService {
            thread: Mutex::new(Some(thread)),
            host_channel: Mutex::new(channel),
            handlers,
            network_poll_thread: Mutex::new(None),
            network_poll_stopped: Arc::new(Registration::new2()),
        })
    }

    pub fn stop(&self) {
        debug!("[IoService] Closing...");
        // Network poll should be closed before the main EventLoop, otherwise it
        // will send messages to a closed EventLoop.
        self.network_poll_stopped
            .1
            .set_readiness(Ready::readable())
            .expect("Set network_poll_stopped readiness failure");
        if let Some(thread) = self.network_poll_thread.lock().take() {
            thread.join().unwrap_or_else(|e| match e.downcast_ref::<&'static str>() {
                Some(e) => error!("Error joining network poll thread: {}", e),
                None => error!("Error joining network poll thread: Unknown error: {:?}", e),
            });
        }
        // Clear handlers so that shared pointers are not stuck on stack
        // in Channel::send_sync
        self.handlers.write().clear();
        self.host_channel
            .lock()
            .send(IoMessage::Shutdown)
            .unwrap_or_else(|e| warn!("Error on IO service shutdown: {:?}", e));
        if let Some(thread) = self.thread.lock().take() {
            thread.join().unwrap_or_else(|e| match e.downcast_ref::<&'static str>() {
                Some(e) => error!("Error joining IO service event loop thread: {}", e),
                None => error!("Error joining IO service event loop thread: Unknown error: {:?}", e),
            });
        }
        debug!("[IoService] Closed.");
    }

    pub fn start_network_poll(
        &self, network_poll: Arc<Poll>, handler: Arc<dyn IoHandler<Message>>,
        main_event_loop_channel: IoChannel<Message>, max_sessions: usize,
        stop_token: usize,
    ) {
        network_poll
            .register(
                &self.network_poll_stopped.0,
                Token(stop_token),
                Ready::readable(),
                PollOpt::edge(),
            )
            .expect("network_poll register failure");
        let thread = thread::Builder::new()
            .name("network_eventloop".into())
            .spawn(move || {
                let mut events = Events::with_capacity(max_sessions);
                loop {
                    network_poll
                        .poll(&mut events, None)
                        .expect("Network poll failure");
                    let _timer =
                        MeterTimer::time_func(NET_POLL_THREAD_TIMER.as_ref());
                    for event in &events {
                        // IoService is dropped and we should stop this thread
                        if event.token().0 == stop_token {
                            assert!(event.readiness().is_readable());
                            return;
                        }

                        let handler_id = 0;
                        let token_id = event.token().0 % TOKENS_PER_HANDLER;
                        if event.readiness().is_readable() {
                            handler.stream_readable(
                                &IoContext::new(
                                    main_event_loop_channel.clone(),
                                    handler_id,
                                ),
                                token_id,
                            );
                        }
                        if event.readiness().is_writable() {
                            handler.stream_writable(
                                &IoContext::new(
                                    main_event_loop_channel.clone(),
                                    handler_id,
                                ),
                                token_id,
                            );
                        }
                        if event.readiness().is_hup() {
                            handler.stream_hup(
                                &IoContext::new(
                                    main_event_loop_channel.clone(),
                                    handler_id,
                                ),
                                token_id,
                            );
                        }
                    }
                }
            })
            .expect("only one io_service thread, so it should not fail");
        *self.network_poll_thread.lock() = Some(thread);
    }

    /// Register an IO handler with the event loop.
    pub fn register_handler(
        &self, handler: Arc<dyn IoHandler<Message> + Send>,
    ) -> Result<(), IoError> {
        self.host_channel
            .lock()
            .send(IoMessage::AddHandler { handler })?;
        Ok(())
    }

    /// Send a message over the network. Normally `HostIo::send` should be used.
    /// This can be used from non-io threads.
    pub fn send_message(&self, message: Message) -> Result<(), IoError> {
        self.host_channel
            .lock()
            .send(IoMessage::UserMessage(Arc::new(message)))?;
        Ok(())
    }

    /// Create a new message channel
    pub fn channel(&self) -> IoChannel<Message> {
        IoChannel::new(
            self.host_channel.lock().clone(),
            Arc::downgrade(&self.handlers),
        )
    }
}

impl<Message> Drop for IoService<Message>
where Message: Send + Sync
{
    fn drop(&mut self) { self.stop() }
}
