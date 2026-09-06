use std::time::Duration;

use smb_io_wire::{
    DIRECT_TCP_HEADER_SIZE, DIRECT_TCP_MAX_PAYLOAD, decode_direct_tcp_length,
    encode_direct_tcp_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ClientError;

/// Message-oriented transport used by the SMB state machine.
///
/// Payloads passed through this trait start at the SMB protocol identifier. The transport owns
/// direct-TCP framing so higher layers never mix packet offsets with the 4-byte TCP prefix.
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
        })
    }

    pub fn peer_addr(&self) -> Result<std::net::SocketAddr, ClientError> {
        Ok(self.stream.peer_addr()?)
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
        let mut header = [0u8; DIRECT_TCP_HEADER_SIZE];
        timeout(self.io_timeout, self.stream.read_exact(&mut header))
            .await
            .map_err(|_| ClientError::Timeout("TCP frame header read"))??;
        let len = decode_direct_tcp_length(&header)?;
        if len > self.max_message_size {
            return Err(ClientError::Protocol(
                "SMB peer advertised a frame larger than configured transport maximum",
            ));
        }
        let mut message = vec![0u8; len];
        timeout(self.io_timeout, self.stream.read_exact(&mut message))
            .await
            .map_err(|_| ClientError::Timeout("TCP message read"))??;
        Ok(message)
    }
}
