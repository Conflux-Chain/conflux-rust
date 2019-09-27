// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    io::{IoContext, StreamToken},
    throttling::THROTTLING_SERVICE,
    Error, ErrorKind,
};
use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Histogram, Meter, Sample,
};
use mio::{tcp::*, *};
use priority_send_queue::{PrioritySendQueue, SendQueuePriority};
use serde_derive::Serialize;
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
        Arc,
    },
    time::Instant,
};

lazy_static! {
    static ref READ_METER: Arc<dyn Meter> =
        register_meter_with_group("network_system_data", "read");
    static ref WRITE_METER: Arc<dyn Meter> =
        register_meter_with_group("network_system_data", "write");
    static ref SEND_METER: Arc<dyn Meter> =
        register_meter_with_group("network_system_data", "send");
    static ref SEND_LOW_PRIORITY_METER: Arc<dyn Meter> =
        register_meter_with_group("network_system_data", "send_low");
    static ref SEND_HIGH_PRIORITY_METER: Arc<dyn Meter> =
        register_meter_with_group("network_system_data", "send_high");
    static ref HIGH_PACKET_SEND_TO_WRITE_ELAPSED_TIME: Arc<dyn Histogram> =
        Sample::ExpDecay(0.015).register_with_group(
            "network_system_data",
            "high_packet_wait_time",
            1024
        );
    static ref LOW_PACKET_SEND_TO_WRITE_ELAPSED_TIME: Arc<dyn Histogram> =
        Sample::ExpDecay(0.015).register_with_group(
            "network_system_data",
            "low_packet_wait_time",
            1024
        );
    static ref WRITABLE_COUNTER: Arc<dyn Meter> =
        register_meter_with_group("network_system_data", "writable_counter");
    static ref WRITABLE_YIELD_SEND_RIGHT_COUNTER: Arc<dyn Meter> =
        register_meter_with_group(
            "network_system_data",
            "writable_yield_send_right_counter"
        );
    static ref WRITABLE_ZERO_COUNTER: Arc<dyn Meter> =
        register_meter_with_group(
            "network_system_data",
            "writable_zero_counter"
        );
    static ref WRITABLE_PACKET_COUNTER: Arc<dyn Meter> =
        register_meter_with_group(
            "network_system_data",
            "writable_packet_counter"
        );
    static ref NETWORK_SEND_QUEUE_SIZE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "network_system_data",
            "send_queue_size"
        );
}

/// Connection write status.
#[derive(Debug, PartialEq, Eq)]
pub enum WriteStatus {
    /// Some data is still pending for current packet.
    Ongoing,
    /// Give up to write data due to low priority.
    LowPriority,
    /// All data sent.
    Complete,
}

const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

/// Global counter for high priority packets.
/// It is used among connections to send high priority packets.
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

/// Trait to assemble/load packet with extra information.
/// E.g. prefix packet with length information
pub trait PacketAssembler: Send + Sync {
    /// Check if the specified packet `len` is oversized.
    fn is_oversized(&self, len: usize) -> bool;

    /// Assemble packet with extra information.
    fn assemble(&self, data: &mut Vec<u8>) -> Result<(), Error>;

    /// Load packet and remove the extra information from the specified buffer.
    fn load(&self, buf: &mut BytesMut) -> Option<BytesMut>;
}

/// Packet with guard to automatically update throttling and high priority
/// packets counter.

struct Packet {
    // data to write to socket
    data: Vec<u8>,
    // current data position to write to socket.
    sending_pos: usize,
    is_high_priority: bool,
    original_is_high_priority: bool,
    throttling_size: usize,
    creation_time: Instant,
}

impl Packet {
    fn new(data: Vec<u8>, priority: SendQueuePriority) -> Result<Self, Error> {
        // update throttling
        let throttling_size = data.len();
        THROTTLING_SERVICE
            .write()
            .on_enqueue(throttling_size, priority == SendQueuePriority::High)?;

        // update high priority packet counter
        let is_high_priority = priority == SendQueuePriority::High;
        if is_high_priority {
            incr_high_priority_packets();
        }

        Ok(Packet {
            data,
            sending_pos: 0,
            is_high_priority,
            original_is_high_priority: is_high_priority,
            throttling_size,
            creation_time: Instant::now(),
        })
    }

    fn set_high_priority(&mut self) {
        if !self.is_high_priority {
            incr_high_priority_packets();
            self.is_high_priority = true;
        }
    }

    fn write(&mut self, writer: &mut dyn Write) -> Result<usize, Error> {
        if self.is_send_completed() {
            return Ok(0);
        }

        let size = writer.write(&self.data[self.sending_pos..])?;
        self.sending_pos += size;
        Ok(size)
    }

    fn is_send_completed(&self) -> bool { self.sending_pos >= self.data.len() }
}

impl Drop for Packet {
    fn drop(&mut self) {
        THROTTLING_SERVICE
            .write()
            .on_dequeue(self.throttling_size, self.original_is_high_priority);

        if self.is_high_priority {
            decr_high_priority_packets();
        }
        if self.original_is_high_priority {
            HIGH_PACKET_SEND_TO_WRITE_ELAPSED_TIME
                .update_since(self.creation_time);
        } else {
            LOW_PACKET_SEND_TO_WRITE_ELAPSED_TIME
                .update_since(self.creation_time)
        }
    }
}

/// This information is to measure the congestion situation of network.
#[allow(dead_code)]
pub struct SendQueueStatus {
    queue_length: usize,
}

pub struct GenericConnection<Socket: GenericSocket> {
    /// Connection id (token)
    token: StreamToken,
    /// Network socket
    socket: Socket,
    /// Receive buffer
    recv_buf: BytesMut,
    /// Packets that waiting for sending out.
    send_queue: PrioritySendQueue<Packet>,
    /// Sending packet.
    sending_packet: Option<Packet>,
    /// Event flags this connection interested
    interest: Ready,
    /// Registered flag
    registered: AtomicBool,
    /// Assemble packet with extra information before sending out.
    assembler: Box<dyn PacketAssembler>,
}

impl<Socket: GenericSocket> GenericConnection<Socket> {
    /// Readable IO handler. Called when there is some data to be read.
    pub fn readable(&mut self) -> io::Result<Option<Bytes>> {
        let mut buf: [u8; 1024] = [0; 1024];

        // Read until the socket has no data to read.
        // This is to avoid accumulating too much data in kernal.
        //
        // In this way, N packets may be read at a time, and Readable IO event
        // will not be triggered again if no more data sent to socket. So, the
        // caller should guarantee to read all packets in a loop when Readable
        // IO event triggered.
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

        Ok(packet.map(|p| p.freeze()))
    }

    /// Send the specified data out immediately
    pub fn write_raw_data(
        &mut self, mut data: Vec<u8>,
    ) -> Result<usize, Error> {
        trace!(
            "Sending raw buffer, token = {} data_len = {}, data = {:?}",
            self.token,
            data.len(),
            data
        );

        self.assembler.assemble(&mut data)?;
        let size = self.socket.write(&data)?;

        trace!(
            "Succeed to send socket data, token = {}, size = {}",
            self.token,
            size
        );

        WRITE_METER.mark(size);
        Ok(size)
    }

    /// Continue to send out the uncompleted packet, or pop new packet from
    /// queue to send out.
    fn write_next_from_queue(&mut self) -> Result<WriteStatus, Error> {
        // In case of last packet is all sent out.
        if self.sending_packet.is_none() {
            // give up to send low priority packet
            if self.send_queue.is_send_queue_empty(SendQueuePriority::High)
                && has_high_priority_packets()
            {
                trace!("Give up to send socket data due to low priority, token = {}", self.token);
                WRITABLE_YIELD_SEND_RIGHT_COUNTER.mark(1);
                return Ok(WriteStatus::LowPriority);
            }

            // get packet from queue to send
            let (mut packet, priority) = match self.send_queue.pop_front() {
                Some(item) => item,
                None => return Ok(WriteStatus::Complete),
            };

            if priority != SendQueuePriority::High {
                trace!(
                    "Low priority packet promoted to high priority, token = {}",
                    self.token
                );
                packet.set_high_priority();
            }

            // assemble packet to send, e.g. prefix length to packet
            self.assembler.assemble(&mut packet.data)?;

            trace!(
                "Packet ready for sent, token = {}, size = {}",
                self.token,
                packet.data.len()
            );

            self.sending_packet = Some(packet);
        }

        let packet = self
            .sending_packet
            .as_mut()
            .expect("should pop packet from send queue");

        let size = packet.write(&mut self.socket)?;
        if size == 0 {
            WRITABLE_ZERO_COUNTER.mark(1);
        }

        trace!(
            "Succeed to send socket data, token = {}, size = {}",
            self.token,
            size
        );

        WRITE_METER.mark(size);
        WRITABLE_COUNTER.mark(1);
        if packet.is_send_completed() {
            trace!("Packet sent, token = {}", self.token);
            self.sending_packet = None;

            WRITABLE_PACKET_COUNTER.mark(1);

            Ok(WriteStatus::Complete)
        } else {
            Ok(WriteStatus::Ongoing)
        }
    }

    /// Writable IO handler. Called when the socket is ready to send.
    pub fn writable<Message: Sync + Send + Clone + 'static>(
        &mut self, io: &IoContext<Message>,
    ) -> Result<WriteStatus, Error> {
        let status = self.write_next_from_queue()?;

        if self.sending_packet.is_none() && self.send_queue.is_empty() {
            self.interest.remove(Ready::writable());
        }
        NETWORK_SEND_QUEUE_SIZE.update(self.send_queue.len());
        io.update_registration(self.token)?;
        Ok(status)
    }

    /// Add a packet to send queue.
    pub fn send<Message: Sync + Send + Clone + 'static>(
        &mut self, io: &IoContext<Message>, data: Vec<u8>,
        priority: SendQueuePriority,
    ) -> Result<SendQueueStatus, Error>
    {
        if !data.is_empty() {
            let size = data.len();
            if self.assembler.is_oversized(size) {
                return Err(ErrorKind::OversizedPacket.into());
            }

            trace!("Sending packet, token = {}, size = {}", self.token, size);

            let packet = Packet::new(data, priority)?;
            self.send_queue.push_back(packet, priority);

            SEND_METER.mark(size);
            match priority {
                SendQueuePriority::High => {
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
            recv_buf: BytesMut::new(),
            send_queue: PrioritySendQueue::new(),
            sending_packet: None,
            interest: Ready::hup() | Ready::readable(),
            registered: AtomicBool::new(false),
            assembler: Box::new(PacketWithLenAssembler::default()),
        }
    }

    /// Register this connection with the IO event loop.
    pub fn register_socket(
        &self, reg: Token, event_loop: &Poll,
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

    /// Update connection registration. Should be called at the end of the IO
    /// handler.
    pub fn update_socket(
        &self, reg: Token, event_loop: &Poll,
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

    /// Delete connection registration. Should be called at the end of the IO
    /// handler.
    pub fn deregister_socket(&self, event_loop: &Poll) -> io::Result<()> {
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
            sending_buf: self
                .sending_packet
                .as_ref()
                .map_or(0, |p| p.data.len() - p.sending_pos),
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

/// User friendly connection information that used by Debug RPC.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDetails {
    pub token: StreamToken,
    pub recv_buf: usize,
    pub sending_buf: usize,
    pub priority_queue_normal: usize,
    pub priority_queue_high: usize,
    pub interest: String,
    pub registered: bool,
}

/// Assembler that prefix packet with length information.
///
/// To avoid memory copy, the first n-bytes will be swapped into the end, and
/// use the first n-bytes for packet length information.
pub struct PacketWithLenAssembler {
    data_len_bytes: usize,
    max_data_len: usize,
}

impl PacketWithLenAssembler {
    fn new(data_len_bytes: usize, max_packet_len: Option<usize>) -> Self {
        assert!(data_len_bytes > 0 && data_len_bytes <= 3);

        let max = usize::max_value() >> (64 - 8 * data_len_bytes);
        let max_packet_len = max_packet_len.unwrap_or(max);
        assert!(max_packet_len > data_len_bytes && max_packet_len <= max);

        PacketWithLenAssembler {
            data_len_bytes,
            max_data_len: max_packet_len - data_len_bytes,
        }
    }
}

impl Default for PacketWithLenAssembler {
    fn default() -> Self {
        PacketWithLenAssembler::new(3, Some(MAX_PAYLOAD_SIZE))
    }
}

impl PacketAssembler for PacketWithLenAssembler {
    #[inline]
    fn is_oversized(&self, len: usize) -> bool { len > self.max_data_len }

    fn assemble(&self, data: &mut Vec<u8>) -> Result<(), Error> {
        if self.is_oversized(data.len()) {
            return Err(ErrorKind::OversizedPacket.into());
        }

        // first n-bytes swapped to the end
        let swapped: Vec<u8> =
            data.iter().take(self.data_len_bytes).cloned().collect();

        // extend n-bytes
        let data_len = data.len();
        data.resize(data_len + self.data_len_bytes, 0);

        // fill first n-bytes with LE data_len
        data[..self.data_len_bytes]
            .copy_from_slice(&data_len.to_le_bytes()[..self.data_len_bytes]);

        // fill the last n-bytes with swapped values
        let start = data.len() - swapped.len();
        data[start..].copy_from_slice(&swapped);

        Ok(())
    }

    fn load(&self, buf: &mut BytesMut) -> Option<BytesMut> {
        if buf.len() < self.data_len_bytes {
            return None;
        }

        // parse data length from first n-bytes
        let mut le_bytes = [0u8; 8];
        le_bytes
            .split_at_mut(self.data_len_bytes)
            .0
            .copy_from_slice(&buf[..self.data_len_bytes]);
        let data_size = usize::from_le_bytes(le_bytes);

        // some data not received yet
        if buf.len() < self.data_len_bytes + data_size {
            return None;
        }

        let mut packet = buf.split_to(self.data_len_bytes + data_size);

        if data_size >= self.data_len_bytes {
            // last n-bytes are swapped
            let swapped = packet.split_off(data_size);
            packet[..self.data_len_bytes].copy_from_slice(&swapped);
        } else {
            // just ignore the first n-bytes of msg length
            packet.split_to(self.data_len_bytes);
        };

        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::*;
    use mio::Ready;
    use std::{
        cmp,
        io::{Read, Result, Write},
    };

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
                sending_packet: None,
                recv_buf: BytesMut::new(),
                interest: Ready::hup() | Ready::readable(),
                registered: AtomicBool::new(false),
                assembler: Box::new(PacketWithLenAssembler::new(1, None)),
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
        connection.socket = TestSocket::with_buf(10);
        let packet =
            Packet::new(vec![0; 60].into(), SendQueuePriority::High).unwrap();
        connection
            .send_queue
            .push_back(packet, SendQueuePriority::High);

        let status = connection.writable(&test_io());

        assert!(status.is_ok());
        assert_eq!(0, connection.send_queue.len());

        let sending_packet = connection.sending_packet.unwrap();
        assert_eq!(sending_packet.data.len(), 61);
        assert_eq!(sending_packet.sending_pos, 10);
    }

    #[test]
    fn connection_read() {
        let mut connection = TestConnection::new();

        let mut data = vec![1, 3, 5, 7];
        connection.assembler.assemble(&mut data).unwrap();

        connection.socket.read_buf = data[..2].to_vec();
        {
            let status = connection.readable();
            assert!(status.is_ok());
            assert!(status.unwrap().is_none());
        }

        connection.socket.read_buf.extend_from_slice(&data[2..]);
        {
            let status = connection.readable();
            assert!(status.is_ok());
            assert_eq!(&status.unwrap().unwrap()[..], &[1, 3, 5, 7]);
        }

        {
            let status = connection.readable();
            assert!(status.is_ok());
            assert!(status.unwrap().is_none());
        }
    }

    #[test]
    fn test_assembler_oversized() {
        let assembler = PacketWithLenAssembler::default();
        assert_eq!(assembler.is_oversized(MAX_PAYLOAD_SIZE - 4), false);
        assert_eq!(assembler.is_oversized(MAX_PAYLOAD_SIZE - 3), false);
        assert_eq!(assembler.is_oversized(MAX_PAYLOAD_SIZE - 2), true);
    }

    #[test]
    fn test_assembler_assemble() {
        let assembler = PacketWithLenAssembler::default();

        // data length > 3
        let mut data = vec![1, 2, 3, 4, 5];
        assembler.assemble(&mut data).unwrap();
        assert_eq!(data, vec![5, 0, 0, 4, 5, 1, 2, 3]);

        // data length == 3
        let mut data = vec![1, 2, 3];
        assembler.assemble(&mut data).unwrap();
        assert_eq!(data, vec![3, 0, 0, 1, 2, 3]);

        // data length < 3
        let mut data = vec![1, 2];
        assembler.assemble(&mut data).unwrap();
        assert_eq!(data, vec![2, 0, 0, 1, 2]);
    }

    #[test]
    fn test_assembler_load() {
        let assembler = PacketWithLenAssembler::default();

        // packet not ready
        assert_eq!(assembler.load(&mut vec![5].into()), None);
        assert_eq!(assembler.load(&mut vec![5, 0, 0].into()), None);
        assert_eq!(assembler.load(&mut vec![5, 0, 0, 4, 5, 1, 2].into()), None);

        // packet ready and length > 3
        let mut buf = vec![5, 0, 0, 4, 5, 1, 2, 3].into();
        assert_eq!(&assembler.load(&mut buf).unwrap()[..], &[1, 2, 3, 4, 5]);
        assert_eq!(buf.is_empty(), true);

        // packet ready and length < 3
        let mut buf = vec![2, 0, 0, 1, 2].into();
        assert_eq!(&assembler.load(&mut buf).unwrap()[..], &[1, 2]);
        assert_eq!(buf.is_empty(), true);

        // packet ready with some data of the next packet
        let mut buf = vec![5, 0, 0, 4, 5, 1, 2, 3, 6, 7].into();
        assert_eq!(&assembler.load(&mut buf).unwrap()[..], &[1, 2, 3, 4, 5]);
        assert_eq!(&buf[..], &[6, 7]);
    }
}
