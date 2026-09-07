use std::io::{self, ErrorKind};
use std::time::Duration;

use smb_io_wire::{
    DIRECT_TCP_HEADER_SIZE, DIRECT_TCP_MAX_PAYLOAD, decode_direct_tcp_length,
    encode_direct_tcp_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ClientError;

const TCP_READ_CHUNK_SIZE: usize = 64 * 1024;

/// Message-oriented transport used by the SMB state machine.
///
/// Payloads passed through this trait start at the SMB protocol identifier. The transport owns
/// direct-TCP framing so higher layers never mix packet offsets with the 4-byte TCP prefix.
///
/// `receive_message` implementations must be cancellation-safe: if its future is dropped while
/// awaiting data, a later call must resume from the same byte position without losing a partial
/// frame. The client relies on this contract to interrupt a blocked READ wait long enough to send
/// SMB2 CANCEL on the same full-duplex connection.
#[allow(async_fn_in_trait)]
pub trait Transport: Send {
    async fn send_message(&mut self, message: &[u8]) -> Result<(), ClientError>;
    async fn receive_message(&mut self) -> Result<Vec<u8>, ClientError>;
}

#[derive(Debug, Clone, Copy)]
pub struct TcpTransportConfig {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_message_size: usize,
    pub tcp_nodelay: bool,
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(8),
            io_timeout: Duration::from_secs(30),
            max_message_size: DIRECT_TCP_MAX_PAYLOAD,
            tcp_nodelay: true,
        }
    }
}

pub struct TcpTransport {
    stream: TcpStream,
    io_timeout: Duration,
    max_message_size: usize,
    read_buffer: Vec<u8>,
}

impl TcpTransport {
    pub async fn connect(
        host: &str,
        port: u16,
        config: TcpTransportConfig,
    ) -> Result<Self, ClientError> {
        if config.max_message_size == 0 || config.max_message_size > DIRECT_TCP_MAX_PAYLOAD {
            return Err(ClientError::Protocol(
                "TCP max_message_size must fit the 24-bit direct-TCP length field",
            ));
        }
        let stream = timeout(config.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| ClientError::Timeout("TCP connect"))??;
        stream.set_nodelay(config.tcp_nodelay)?;
        Ok(Self {
            stream,
            io_timeout: config.io_timeout,
            max_message_size: config.max_message_size,
            read_buffer: Vec::with_capacity(TCP_READ_CHUNK_SIZE),
        })
    }

    pub fn peer_addr(&self) -> Result<std::net::SocketAddr, ClientError> {
        Ok(self.stream.peer_addr()?)
    }

    fn try_take_message(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        if self.read_buffer.len() < DIRECT_TCP_HEADER_SIZE {
            return Ok(None);
        }
        let payload_len = decode_direct_tcp_length(&self.read_buffer[..DIRECT_TCP_HEADER_SIZE])?;
        if payload_len > self.max_message_size {
            return Err(ClientError::Protocol(
                "SMB peer advertised a frame larger than configured transport maximum",
            ));
        }
        let frame_len = DIRECT_TCP_HEADER_SIZE
            .checked_add(payload_len)
            .ok_or(ClientError::Protocol("direct-TCP frame length overflow"))?;
        if self.read_buffer.len() < frame_len {
            return Ok(None);
        }

        let mut frame = std::mem::take(&mut self.read_buffer);
        let remainder = frame.split_off(frame_len);
        self.read_buffer = remainder;
        frame.copy_within(DIRECT_TCP_HEADER_SIZE..frame_len, 0);
        frame.truncate(payload_len);
        Ok(Some(frame))
    }
}

impl Transport for TcpTransport {
    async fn send_message(&mut self, message: &[u8]) -> Result<(), ClientError> {
        if message.len() > self.max_message_size {
            return Err(ClientError::Protocol(
                "SMB message exceeds configured transport maximum",
            ));
        }
        let frame = encode_direct_tcp_frame(message)?;
        timeout(self.io_timeout, self.stream.write_all(&frame))
            .await
            .map_err(|_| ClientError::Timeout("TCP write"))??;
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<Vec<u8>, ClientError> {
        loop {
            if let Some(message) = self.try_take_message()? {
                return Ok(message);
            }

            let mut chunk = [0u8; TCP_READ_CHUNK_SIZE];
            let read = timeout(self.io_timeout, self.stream.read(&mut chunk))
                .await
                .map_err(|_| ClientError::Timeout("TCP message read"))??;
            if read == 0 {
                return Err(ClientError::Io(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "SMB TCP connection closed while receiving a frame",
                )));
            }
            self.read_buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelled_receive_preserves_partial_direct_tcp_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let payload = vec![0xFE, b'S', b'M', b'B', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let frame = encode_direct_tcp_frame(&payload).unwrap();
        let split_at = 9;
        let first_half = frame[..split_at].to_vec();
        let second_half = frame[split_at..].to_vec();
        let (first_sent_tx, first_sent_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&first_half).await.unwrap();
            first_sent_tx.send(()).unwrap();
            release_rx.await.unwrap();
            socket.write_all(&second_half).await.unwrap();
        });

        let mut transport = TcpTransport::connect(
            "127.0.0.1",
            address.port(),
            TcpTransportConfig {
                io_timeout: Duration::from_secs(2),
                ..TcpTransportConfig::default()
            },
        )
        .await
        .unwrap();

        first_sent_rx.await.unwrap();
        let interrupted = timeout(Duration::from_millis(100), transport.receive_message()).await;
        assert!(interrupted.is_err());
        assert_eq!(transport.read_buffer.len(), split_at);

        release_tx.send(()).unwrap();
        let recovered = transport.receive_message().await.unwrap();
        assert_eq!(recovered, payload);
        assert!(transport.read_buffer.is_empty());
        server.await.unwrap();
    }
}
