use smb_io_wire::{
    Command, HeaderId, ReadRequest, ReadResponse, Smb2Header, StatusField, flags, session_flags,
};

use crate::{ClientError, FileHandle, SessionConnection, Transport};

pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const CREDIT_UNIT_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct ReadOptions {
    /// Minimum number of credits to request back from the server on each READ.
    pub credit_request: u16,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self { credit_request: 32 }
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Reads bytes from an already-open file without changing any shared file position.
    ///
    /// Large reads are split to respect both the negotiated MaxReadSize and the credits currently
    /// available on the connection. This keeps the API suitable for media players and FFmpeg-style
    /// random access while the transport remains serial; a later dispatcher can pipeline the same
    /// individual READ requests without changing this public API.
    pub async fn read_at(
        &mut self,
        file: &FileHandle,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, ClientError> {
        self.read_at_with_options(file, offset, length, ReadOptions::default())
            .await
    }

    pub async fn read_at_with_options(
        &mut self,
        file: &FileHandle,
        offset: u64,
        length: usize,
        options: ReadOptions,
    ) -> Result<Vec<u8>, ClientError> {
        if length == 0 || offset >= file.len() {
            return Ok(Vec::new());
        }
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }

        let requested = u64::try_from(length)
            .map_err(|_| ClientError::Protocol("READ length does not fit in u64"))?;
        let target_u64 = requested.min(file.len() - offset);
        let target = usize::try_from(target_u64)
            .map_err(|_| ClientError::Protocol("READ length does not fit in usize"))?;
        let mut out = Vec::with_capacity(target);
        let mut next_offset = offset;

        while out.len() < target {
            let remaining = target - out.len();
            let (supports_multi_credit, max_read_size) = {
                let negotiated = self
                    .connection
                    .negotiated
                    .as_ref()
                    .ok_or(ClientError::Protocol("READ requires negotiated parameters"))?;
                (
                    negotiated.supports_multi_credit(),
                    usize::try_from(negotiated.max_read_size)
                        .map_err(|_| ClientError::Protocol("MaxReadSize does not fit in usize"))?,
                )
            };

            let available_credits =
                self.connection
                    .available_credits()
                    .ok_or(ClientError::Protocol(
                        "SMB credit window is not initialized",
                    ))?;
            if available_credits == 0 {
                return Err(ClientError::Protocol(
                    "SMB connection has no credits available for READ",
                ));
            }

            let credit_limited = if supports_multi_credit {
                usize::try_from(available_credits)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(CREDIT_UNIT_BYTES)
            } else {
                CREDIT_UNIT_BYTES
            };
            let chunk_len = remaining.min(max_read_size).min(credit_limited);
            if chunk_len == 0 {
                return Err(ClientError::Protocol("READ chunk size resolved to zero"));
            }
            let wire_length = u32::try_from(chunk_len)
                .map_err(|_| ClientError::Protocol("READ chunk exceeds u32 length"))?;
            let credit_charge = if supports_multi_credit {
                let units = (chunk_len - 1) / CREDIT_UNIT_BYTES + 1;
                u16::try_from(units)
                    .map_err(|_| ClientError::Protocol("READ CreditCharge exceeds u16"))?
            } else {
                0
            };
            let credit_request = self
                .connection
                .reserve_credits(credit_charge, options.credit_request)?;
            let message_id = self.connection.message_ids.allocate(credit_charge)?;
            let request = ReadRequest::direct(file.file_id(), next_offset, wire_length);
            let mut request_message = request.encode_message(
                message_id,
                self.session_id,
                file.tree_id(),
                credit_charge,
                credit_request,
            )?;
            if self.signing_required {
                let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                    "READ requires signing but the session has no signing key",
                ))?;
                signing.sign(&mut request_message)?;
            }

            self.connection
                .transport
                .send_message(&request_message)
                .await?;
            let mut response_message = self.connection.transport.receive_message().await?;
            let header = Smb2Header::decode(&response_message)?;
            if header.command != Command::Read {
                return Err(ClientError::Protocol(
                    "READ response command does not match request",
                ));
            }
            if header.message_id != message_id {
                return Err(ClientError::Protocol(
                    "READ response MessageId does not match request",
                ));
            }
            if header.session_id != self.session_id {
                return Err(ClientError::Protocol(
                    "READ response SessionId does not match session",
                ));
            }
            match header.id {
                HeaderId::Sync { tree_id, .. } if tree_id == file.tree_id() => {}
                HeaderId::Sync { .. } => {
                    return Err(ClientError::Protocol(
                        "READ response TreeId does not match file tree",
                    ));
                }
                HeaderId::Async { .. } => {
                    return Err(ClientError::Protocol(
                        "READ response unexpectedly used async header form",
                    ));
                }
            }
            self.connection.grant_credits(header.credits)?;

            if header.flags & flags::SIGNED != 0 {
                let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                    "server signed READ without an available signing key",
                ))?;
                signing.verify(&mut response_message)?;
            } else if self.signing_required {
                return Err(ClientError::Protocol(
                    "server omitted a required READ signature",
                ));
            }

            match header.status {
                StatusField::Status(0) => {}
                StatusField::Status(STATUS_END_OF_FILE) => break,
                StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
                StatusField::ChannelSequence { .. } => {
                    return Err(ClientError::Protocol(
                        "READ response used request header form",
                    ));
                }
            }

            let response = ReadResponse::decode_message(&response_message)?;
            if response.data.len() > chunk_len {
                return Err(ClientError::Protocol(
                    "READ response returned more data than requested",
                ));
            }
            if response.data.is_empty() {
                break;
            }

            let received = response.data.len();
            out.extend_from_slice(&response.data);
            next_offset = next_offset
                .checked_add(
                    u64::try_from(received)
                        .map_err(|_| ClientError::Protocol("READ result length overflow"))?,
                )
                .ok_or(ClientError::Protocol("READ offset overflow"))?;
            if received < chunk_len {
                break;
            }
        }

        Ok(out)
    }
}
