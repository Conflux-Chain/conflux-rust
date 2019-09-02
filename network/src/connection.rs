// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    io::{IoContext, StreamToken},
    throttling::THROTTLING_SERVICE,
    Error, ErrorKind,
};
use bytes::Bytes;
use lazy_static::lazy_static;
use metrics::{register_meter_with_group, Meter};
use mio::{deprecated::*, tcp::*, *};
use priority_send_queue::{PrioritySendQueue, SendQueuePriority};
use serde_derive::Serialize;
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
        Arc,
    },
};

lazy_static! {
    static ref READ_METER: Arc<dyn Meter> =
        register_meter_with_group("network_connection_data", "read");
    static ref WRITE_METER: Arc<dyn Meter> =
        register_meter_with_group("network_connection_data", "write");
    static ref SEND_METER: Arc<dyn Meter> =
        register_meter_with_group("network_connection_data", "send");
    static ref SEND_LOW_PRIORITY_METER: Arc<dyn Meter> =
        register_meter_with_group("network_connection_data", "send_low");
    static ref SEND_HIGH_PRIORITY_METER: Arc<dyn Meter> =
        register_meter_with_group("network_connection_data", "send_high");
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteStatus {
    Ongoing,
    LowPriority,
    Complete,
}

const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

static HIGH_PRIORITY_PACKETS: AtomicUsize = AtomicUsize::new(0);

fn incr_high_priority_packets() {
    assert_ne!(
        HIGH_PRIORITY_PACKETS.fetch_add(1, AtomicOrdering::SeqCst),
        std::usize::MAX
    );
}

fn decr_high_priority_packets() {
    assert_ne!(
        HIGH_PRIORITY_PACKETS.fetch_sub(1, AtomicOrdering::SeqCst),
        0
    );
}

fn has_high_priority_packets() -> bool {
    HIGH_PRIORITY_PACKETS.load(AtomicOrdering::SeqCst) > 0
}

pub fn get_high_priority_packets() -> usize {
    HIGH_PRIORITY_PACKETS.load(AtomicOrdering::SeqCst)
}

pub trait GenericSocket: Read + Write {}

impl GenericSocket for TcpStream {}

pub trait PacketAssembler: Send + Sync {
    fn is_oversized(&self, len: usize) -> bool;
    fn assemble(&self, data: &[u8]) -> Result<Bytes, Error>;
    fn load(&self, buf: &mut Bytes) -> Option<Bytes>;
}

/// This information is to measure the congestion situation of network.
#[allow(dead_code)]
pub struct SendQueueStatus {
    queue_length: usize,
}

pub struct GenericConnection<Socket: GenericSocket> {
    token: StreamToken,
    socket: Socket,
    recv_buf: Bytes,
    send_queue: PrioritySendQueue<(Vec<u8>, usize)>,
    interest: Ready,
    registered: AtomicBool,
    assembler: Box<dyn PacketAssembler>,
}

impl<Socket: GenericSocket> Drop for GenericConnection<Socket> {
    fn drop(&mut self) {
        let mut service = THROTTLING_SERVICE.write();
        while let Some(((packet, pos), priority)) = self.send_queue.pop_front()
        {
            if pos < packet.len() {
                service.on_dequeue(packet.len() - pos);
                if priority == SendQueuePriority::High {
                    decr_high_priority_packets();
                }
            }
        }
    }
}

impl<Socket: GenericSocket> GenericConnection<Socket> {
    pub fn readable(&mut self) -> io::Result<Option<Bytes>> {
        let mut buf: [u8; 1024] = [0; 1024];
        loop {
            match self.socket.read(&mut buf) {
                Ok(size) => {
                    trace!(
                        "Succeed to read socket data, token = {}, size = {}",
                        self.token,
                        size
                    );
                    READ_METER.mark(size);
                    if size == 0 {
                        break;
                    }
                    self.recv_buf.extend_from_slice(&buf[0..size]);
                }
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        debug!("Failed to read socket data, token = {}, err = {:?}", self.token, e);
                        return Err(e);
                    }
                    break;
                }
            }
        }

        let packet = self.assembler.load(&mut self.recv_buf);

        if let Some(ref p) = packet {
            trace!(
                "Packet received, token = {}, size = {}",
                self.token,
                p.len()
            );
        }

        Ok(packet)
    }

    pub fn write_raw_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        trace!(
            "Sending raw buffer, token = {}, data = {:?}",
            self.token,
            data
        );

        let data = self.assembler.assemble(data)?;
        let size = self.socket.write(&data)?;

        trace!(
            "Succeed to send socket data, token = {}, size = {}",
            self.token,
            size,
        );

        WRITE_METER.mark(size);
        Ok(size)
    }

    fn write_next_from_queue(&mut self) -> Result<WriteStatus, Error> {
        if self.send_queue.is_send_queue_empty(SendQueuePriority::High)
            && has_high_priority_packets()
        {
            trace!(
                "Give up to send socket data due to low priority, token = {}",
                self.token
            );
            return Ok(WriteStatus::LowPriority);
        }

        let buf = match self.send_queue.front_mut() {
            Some((buf, promoted)) => {
                if promoted {
                    trace!("Low priority packet promoted to high priority, token = {}", self.token);
                    incr_high_priority_packets();
                }
                buf
            }
            None => return Ok(WriteStatus::Complete),
        };
        let len = buf.0.len();
        let pos = buf.1;
        if pos >= len {
            error!(
                "Unexpected connection data, token = {}, len = {}, pos = {}",
                self.token, len, pos
            );
            return Ok(WriteStatus::Complete);
        }

        let size = self.socket.write(&buf.0[pos..])?;

        trace!(
            "Succeed to send socket data, token = {}, size = {}",
            self.token,
            size
        );
        THROTTLING_SERVICE.write().on_dequeue(size);
        WRITE_METER.mark(size);

        // NOTE: the line below does not work due the error:
        // `cannot borrow `*self` as mutable more than once at a time`
        // let size = self.write_raw_data(&buf.0)?;

        if pos + size < len {
            buf.1 += size;
            Ok(WriteStatus::Ongoing)
        } else {
            trace!("Packet sent, token = {}, size = {}", self.token, len);
            decr_high_priority_packets();
            Ok(WriteStatus::Complete)
        }
    }

    pub fn writable<Message: Sync + Send + Clone + 'static>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<WriteStatus, Error> {
        let status = self.write_next_from_queue();

        if let Ok(WriteStatus::Complete) = status {
            self.send_queue.pop_front();
        }

        if self.send_queue.is_empty() {
            self.interest.remove(Ready::writable());
        }

        io.update_registration(self.token)?;

        status
    }

    pub fn send<Message: Sync + Send + Clone + 'static>(
        &mut self, io: &IoContext<Message>, data: &[u8],
        priority: SendQueuePriority,
    ) -> Result<SendQueueStatus, Error>
    {
        if !data.is_empty() {
            let data = self.assembler.assemble(data)?;
            let size = data.len();

            trace!("Sending packet, token = {}, size = {}", self.token, size);

            SEND_METER.mark(size);
            THROTTLING_SERVICE.write().on_enqueue(size)?;
            let message = data.to_vec();
            self.send_queue.push_back((message, 0), priority);

            match priority {
                SendQueuePriority::High => {
                    incr_high_priority_packets();
                    SEND_HIGH_PRIORITY_METER.mark(size);
                }
                SendQueuePriority::Normal => {
                    SEND_LOW_PRIORITY_METER.mark(size);
                }
            }

            if !self.interest.is_writable() {
                self.interest.insert(Ready::writable());
            }
            io.update_registration(self.token).ok();
        }

        Ok(SendQueueStatus {
            queue_length: self.send_queue.len(),
        })
    }

    pub fn is_sending(&self) -> bool { self.interest.is_writable() }
}

pub type Connection = GenericConnection<TcpStream>;

impl Connection {
    pub fn new(token: StreamToken, socket: TcpStream) -> Self {
        Connection {
            token,
            socket,
            recv_buf: Bytes::new(),
            send_queue: PrioritySendQueue::new(),
            interest: Ready::hup() | Ready::readable(),
            registered: AtomicBool::new(false),
            assembler: Box::new(PacketWithLenAssembler::default()),
        }
    }

    pub fn register_socket<H: Handler>(
        &self, reg: Token, event_loop: &mut EventLoop<H>,
    ) -> io::Result<()> {
        if self.registered.load(AtomicOrdering::SeqCst) {
            return Ok(());
        }
        trace!(
            "Connection register, token = {}, reg = {:?}",
            self.token,
            reg
        );
        if let Err(e) = event_loop.register(
            &self.socket,
            reg,
            self.interest,
            PollOpt::edge(),
        ) {
            trace!(
                "Failed to register socket, token = {}, reg = {:?}, err = {:?}",
                self.token,
                reg,
                e
            );
        }
        self.registered.store(true, AtomicOrdering::SeqCst);
        Ok(())
    }

    pub fn update_socket<H: Handler>(
        &self, reg: Token, event_loop: &mut EventLoop<H>,
    ) -> io::Result<()> {
        trace!(
            "Connection reregister, token = {}, reg = {:?}",
            self.token,
            reg
        );
        if !self.registered.load(AtomicOrdering::SeqCst) {
            self.register_socket(reg, event_loop)
        } else {
            event_loop
                .reregister(&self.socket, reg, self.interest, PollOpt::edge())
                .unwrap_or_else(|e| {
                    trace!("Failed to reregister socket, token = {}, reg = {:?}, err = {:?}", self.token, reg, e);
                });
            Ok(())
        }
    }

    pub fn deregister_socket<H: Handler>(
        &self, event_loop: &mut EventLoop<H>,
    ) -> io::Result<()> {
        trace!("Connection deregister, token = {}", self.token);
        event_loop.deregister(&self.socket).ok();
        Ok(())
    }

    pub fn token(&self) -> StreamToken { self.token }

    /// Get remote peer address
    pub fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }

    /// Get remote peer address string
    pub fn remote_addr_str(&self) -> String {
        self.remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "Unknown".to_owned())
    }

    pub fn details(&self) -> ConnectionDetails {
        ConnectionDetails {
            token: self.token,
            recv_buf: self.recv_buf.len(),
            priority_queue_normal: self
                .send_queue
                .len_by_priority(SendQueuePriority::Normal),
            priority_queue_high: self
                .send_queue
                .len_by_priority(SendQueuePriority::High),
            interest: format!("{:?}", self.interest),
            registered: self.registered.load(AtomicOrdering::SeqCst),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDetails {
    pub token: StreamToken,
    pub recv_buf: usize,
    pub priority_queue_normal: usize,
    pub priority_queue_high: usize,
    pub interest: String,
    pub registered: bool,
}

pub struct PacketWithLenAssembler {
    data_len_bytes: usize,
    max_data_len: usize,
}

impl PacketWithLenAssembler {
    fn new(data_len_bytes: usize, mut max_packet_len: usize) -> Self {
        assert!(data_len_bytes > 0 && data_len_bytes <= 8);

        let max = usize::max_value() >> (64 - 8 * data_len_bytes);
        assert!(max_packet_len <= max);
        if max_packet_len == 0 {
            max_packet_len = max;
        }

        PacketWithLenAssembler {
            data_len_bytes,
            max_data_len: max_packet_len - data_len_bytes,
        }
    }
}

impl Default for PacketWithLenAssembler {
    fn default() -> Self { PacketWithLenAssembler::new(3, MAX_PAYLOAD_SIZE) }
}

impl PacketAssembler for PacketWithLenAssembler {
    #[inline]
    fn is_oversized(&self, len: usize) -> bool { len > self.max_data_len }

    fn assemble(&self, data: &[u8]) -> Result<Bytes, Error> {
        if self.is_oversized(data.len()) {
            return Err(ErrorKind::OversizedPacket.into());
        }

        let mut packet = Bytes::with_capacity(self.data_len_bytes + data.len());

        packet.extend_from_slice(
            &data.len().to_le_bytes()[..self.data_len_bytes],
        );
        packet.extend_from_slice(data);

        Ok(packet)
    }

    fn load(&self, buf: &mut Bytes) -> Option<Bytes> {
        if buf.len() < self.data_len_bytes {
            return None;
        }

        let mut le_bytes = [0u8; 8];
        le_bytes
            .split_at_mut(self.data_len_bytes)
            .0
            .copy_from_slice(&buf[..self.data_len_bytes]);
        let data_size = usize::from_le_bytes(le_bytes);

        if buf.len() < self.data_len_bytes + data_size {
            return None;
        }

        buf.split_to(self.data_len_bytes);

        Some(buf.split_to(data_size))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp,
        io::{Read, Result, Write},
    };

    use super::*;
    use crate::io::*;
    use bytes::Bytes;
    use mio::Ready;

    struct TestSocket {
        read_buf: Vec<u8>,
        write_buf: Vec<u8>,
        cursor: usize,
        buf_size: usize,
    }

    impl TestSocket {
        fn new() -> Self {
            TestSocket {
                read_buf: vec![],
                write_buf: vec![],
                cursor: 0,
                buf_size: 0,
            }
        }

        fn with_buf(buf_size: usize) -> Self {
            TestSocket {
                read_buf: vec![],
                write_buf: vec![],
                cursor: 0,
                buf_size,
            }
        }
    }

    impl Read for TestSocket {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let end = cmp::min(self.read_buf.len(), self.cursor + buf.len());
            if self.cursor > end {
                return Ok(0);
            }
            let len = end - self.cursor;
            if len == 0 {
                Ok(0)
            } else {
                for i in self.cursor..end {
                    buf[i - self.cursor] = self.read_buf[i];
                }
                self.cursor = end;
                Ok(len)
            }
        }
    }

    impl Write for TestSocket {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            if self.buf_size == 0 || buf.len() < self.buf_size {
                self.write_buf.extend(buf.iter().cloned());
                Ok(buf.len())
            } else {
                self.write_buf
                    .extend(buf.iter().take(self.buf_size).cloned());
                Ok(self.buf_size)
            }
        }

        fn flush(&mut self) -> Result<()> {
            unimplemented!();
        }
    }

    impl GenericSocket for TestSocket {}

    type TestConnection = GenericConnection<TestSocket>;

    impl TestConnection {
        fn new() -> Self {
            TestConnection {
                token: 1234567890usize,
                socket: TestSocket::new(),
                send_queue: PrioritySendQueue::new(),
                recv_buf: Bytes::new(),
                interest: Ready::hup() | Ready::readable(),
                registered: AtomicBool::new(false),
                packet: Packet::new(1, 0),
            }
        }
    }

    fn test_io() -> IoContext<i32> {
        IoContext::new(IoChannel::disconnected(), 0)
    }

    #[test]
    fn connection_write_empty() {
        let mut connection = TestConnection::new();
        let status = connection.writable(&test_io());
        assert!(status.is_ok());
        let status = status.unwrap();
        assert!(
            WriteStatus::Complete == status
                || WriteStatus::LowPriority == status
        );
    }

    #[test]
    fn connection_write_is_buffered() {
        let mut connection = TestConnection::new();
        connection.socket = TestSocket::with_buf(1024);
        let data = (vec![0; 10240], 0);
        connection
            .send_queue
            .push_back(data, SendQueuePriority::High);
        incr_high_priority_packets();

        let status = connection.writable(&test_io());

        assert!(status.is_ok());
        assert_eq!(1, connection.send_queue.len());
    }

    #[test]
    fn connection_read() {
        let mut connection = TestConnection::new();

        connection.socket.read_buf = vec![3, 0];
        {
            let status = connection.readable();
            assert!(status.is_ok());
            assert!(status.unwrap().is_none());
        }

        connection.socket.read_buf.extend_from_slice(&[3, 8]);
        {
            let status = connection.readable();
            assert!(status.is_ok());
            assert_eq!(&status.unwrap().unwrap()[..], &[0, 3, 8]);
        }

        {
            let status = connection.readable();
            assert!(status.is_ok());
            assert!(status.unwrap().is_none());
        }
    }
}
