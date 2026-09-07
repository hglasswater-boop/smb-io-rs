use smb_io_wire::{
    Command, HeaderId, ReadRequest, ReadResponse, Smb2Header, StatusField, flags, session_flags,
};

use crate::{ClientError, FileHandle, SessionConnection, Transport};

pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const CREDIT_UNIT_BYTES: usize = 65_536;
const DEFAULT_PIPELINE_CHUNK_SIZE: usize = 256 * 1024;
const DEFAULT_MAX_IN_FLIGHT: usize = 4;

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

#[derive(Debug, Clone, Copy)]
pub struct PipelinedReadOptions {
    /// Maximum payload carried by one outstanding READ request.
    pub chunk_size: usize,
    /// Maximum number of READ requests sent before collecting responses.
    pub max_in_flight: usize,
    /// Minimum number of credits to request back from the server on each READ.
    pub credit_request: u16,
}

impl Default for PipelinedReadOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_PIPELINE_CHUNK_SIZE,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            credit_request: 32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingRead {
    message_id: u64,
    chunk_len: usize,
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Reads bytes from an already-open file without changing any shared file position.
    ///
    /// Large reads are split to respect both the negotiated MaxReadSize and the credits currently
    /// available on the connection.
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
        self.ensure_read_session()?;

        let target = read_target_len(file, offset, length)?;
        let mut out = Vec::with_capacity(target);
        let mut next_offset = offset;

        while out.len() < target {
            let remaining = target - out.len();
            let (supports_multi_credit, max_read_size) = self.read_limits()?;
            let available_credits = self.available_read_credits()?;
            let credit_limited = credit_limited_payload(supports_multi_credit, available_credits);
            let chunk_len = remaining.min(max_read_size).min(credit_limited);
            if chunk_len == 0 {
                return Err(ClientError::Protocol("READ chunk size resolved to zero"));
            }
            let credit_charge = read_credit_charge(supports_multi_credit, chunk_len)?;
            let credit_request = self
                .connection
                .reserve_credits(credit_charge, options.credit_request)?;
            let message_id = self.connection.message_ids.allocate(credit_charge)?;
            let request = ReadRequest::direct(
                file.file_id(),
                next_offset,
                u32::try_from(chunk_len)
                    .map_err(|_| ClientError::Protocol("READ chunk exceeds u32 length"))?,
            );
            let mut request_message = request.encode_message(
                message_id,
                self.session_id,
                file.tree_id(),
                credit_charge,
                credit_request,
            )?;
            self.sign_read_request(&mut request_message)?;

            self.connection
                .transport
                .send_message(&request_message)
                .await?;
            let mut response_message = self.connection.transport.receive_message().await?;
            let header = Smb2Header::decode(&response_message)?;
            self.validate_read_header(file, &header, message_id)?;
            self.connection.grant_credits(header.credits)?;
            self.verify_read_response(&mut response_message, &header)?;

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

    /// Reads a random-access window with several SMB READ requests outstanding at once.
    ///
    /// Requests are sent back-to-back before responses are collected. SMB servers may complete
    /// them out of order, so responses are correlated by MessageId and reassembled in file order.
    pub async fn read_at_pipelined(
        &mut self,
        file: &FileHandle,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, ClientError> {
        self.read_at_pipelined_with_options(file, offset, length, PipelinedReadOptions::default())
            .await
    }

    pub async fn read_at_pipelined_with_options(
        &mut self,
        file: &FileHandle,
        offset: u64,
        length: usize,
        options: PipelinedReadOptions,
    ) -> Result<Vec<u8>, ClientError> {
        if length == 0 || offset >= file.len() {
            return Ok(Vec::new());
        }
        if options.chunk_size == 0 {
            return Err(ClientError::Protocol(
                "pipelined READ chunk_size must be greater than zero",
            ));
        }
        if options.max_in_flight == 0 {
            return Err(ClientError::Protocol(
                "pipelined READ max_in_flight must be greater than zero",
            ));
        }
        self.ensure_read_session()?;

        let target = read_target_len(file, offset, length)?;
        let mut out = Vec::with_capacity(target);

        while out.len() < target {
            let (supports_multi_credit, max_read_size) = self.read_limits()?;
            let mut pending = Vec::with_capacity(options.max_in_flight);
            let mut scheduled = 0usize;
            let remaining = target - out.len();

            while pending.len() < options.max_in_flight && scheduled < remaining {
                let available_credits = match self.connection.available_credits() {
                    Some(0) => break,
                    Some(credits) => credits,
                    None => {
                        return Err(ClientError::Protocol(
                            "SMB credit window is not initialized",
                        ));
                    }
                };
                let credit_limited =
                    credit_limited_payload(supports_multi_credit, available_credits);
                let chunk_len = (remaining - scheduled)
                    .min(options.chunk_size)
                    .min(max_read_size)
                    .min(credit_limited);
                if chunk_len == 0 {
                    break;
                }

                let credit_charge = read_credit_charge(supports_multi_credit, chunk_len)?;
                let credit_request = self
                    .connection
                    .reserve_credits(credit_charge, options.credit_request)?;
                let message_id = self.connection.message_ids.allocate(credit_charge)?;
                let request_offset =
                    offset
                        .checked_add(u64::try_from(out.len() + scheduled).map_err(|_| {
                            ClientError::Protocol("READ offset conversion overflow")
                        })?)
                        .ok_or(ClientError::Protocol("READ offset overflow"))?;
                let request = ReadRequest::direct(
                    file.file_id(),
                    request_offset,
                    u32::try_from(chunk_len)
                        .map_err(|_| ClientError::Protocol("READ chunk exceeds u32 length"))?,
                );
                let mut request_message = request.encode_message(
                    message_id,
                    self.session_id,
                    file.tree_id(),
                    credit_charge,
                    credit_request,
                )?;
                self.sign_read_request(&mut request_message)?;
                self.connection
                    .transport
                    .send_message(&request_message)
                    .await?;

                pending.push(PendingRead {
                    message_id,
                    chunk_len,
                });
                scheduled += chunk_len;
            }

            if pending.is_empty() {
                return Err(ClientError::Protocol(
                    "SMB connection has no credits available for pipelined READ",
                ));
            }

            let mut completed = vec![None; pending.len()];
            let mut short_response_at: Option<usize> = None;

            for _ in 0..pending.len() {
                let mut response_message = self.connection.transport.receive_message().await?;
                let header = Smb2Header::decode(&response_message)?;
                let position = pending
                    .iter()
                    .position(|request| request.message_id == header.message_id)
                    .ok_or(ClientError::Protocol(
                        "pipelined READ response MessageId is not outstanding",
                    ))?;
                if completed[position].is_some() {
                    return Err(ClientError::Protocol(
                        "pipelined READ received a duplicate response",
                    ));
                }

                self.validate_read_header(file, &header, pending[position].message_id)?;
                self.connection.grant_credits(header.credits)?;
                self.verify_read_response(&mut response_message, &header)?;

                match header.status {
                    StatusField::Status(0) => {
                        let response = ReadResponse::decode_message(&response_message)?;
                        if response.data.len() > pending[position].chunk_len {
                            return Err(ClientError::Protocol(
                                "READ response returned more data than requested",
                            ));
                        }
                        if response.data.len() < pending[position].chunk_len {
                            short_response_at = Some(
                                short_response_at.map_or(position, |current| current.min(position)),
                            );
                        }
                        completed[position] = Some(response.data);
                    }
                    StatusField::Status(STATUS_END_OF_FILE) => {
                        short_response_at = Some(
                            short_response_at.map_or(position, |current| current.min(position)),
                        );
                        completed[position] = Some(Vec::new());
                    }
                    StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
                    StatusField::ChannelSequence { .. } => {
                        return Err(ClientError::Protocol(
                            "READ response used request header form",
                        ));
                    }
                }
            }

            for (position, data) in completed.into_iter().enumerate() {
                let data = data.ok_or(ClientError::Protocol(
                    "pipelined READ did not receive every outstanding response",
                ))?;
                out.extend_from_slice(&data);
                if short_response_at == Some(position) {
                    return Ok(out);
                }
            }
        }

        Ok(out)
    }

    fn ensure_read_session(&self) -> Result<(), ClientError> {
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }
        Ok(())
    }

    fn read_limits(&self) -> Result<(bool, usize), ClientError> {
        let negotiated = self
            .connection
            .negotiated
            .as_ref()
            .ok_or(ClientError::Protocol("READ requires negotiated parameters"))?;
        Ok((
            negotiated.supports_multi_credit(),
            usize::try_from(negotiated.max_read_size)
                .map_err(|_| ClientError::Protocol("MaxReadSize does not fit in usize"))?,
        ))
    }

    fn available_read_credits(&self) -> Result<u32, ClientError> {
        match self.connection.available_credits() {
            Some(0) => Err(ClientError::Protocol(
                "SMB connection has no credits available for READ",
            )),
            Some(credits) => Ok(credits),
            None => Err(ClientError::Protocol(
                "SMB credit window is not initialized",
            )),
        }
    }

    fn sign_read_request(&self, message: &mut [u8]) -> Result<(), ClientError> {
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "READ requires signing but the session has no signing key",
            ))?;
            signing.sign(message)?;
        }
        Ok(())
    }

    fn verify_read_response(
        &self,
        message: &mut [u8],
        header: &Smb2Header,
    ) -> Result<(), ClientError> {
        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed READ without an available signing key",
            ))?;
            signing.verify(message)?;
        } else if self.signing_required {
            return Err(ClientError::Protocol(
                "server omitted a required READ signature",
            ));
        }
        Ok(())
    }

    fn validate_read_header(
        &self,
        file: &FileHandle,
        header: &Smb2Header,
        message_id: u64,
    ) -> Result<(), ClientError> {
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
            HeaderId::Sync { tree_id, .. } if tree_id == file.tree_id() => Ok(()),
            HeaderId::Sync { .. } => Err(ClientError::Protocol(
                "READ response TreeId does not match file tree",
            )),
            HeaderId::Async { .. } => Err(ClientError::Protocol(
                "READ response unexpectedly used async header form",
            )),
        }
    }
}

fn read_target_len(file: &FileHandle, offset: u64, length: usize) -> Result<usize, ClientError> {
    let requested = u64::try_from(length)
        .map_err(|_| ClientError::Protocol("READ length does not fit in u64"))?;
    let target_u64 = requested.min(file.len() - offset);
    usize::try_from(target_u64)
        .map_err(|_| ClientError::Protocol("READ length does not fit in usize"))
}

fn credit_limited_payload(supports_multi_credit: bool, available_credits: u32) -> usize {
    if supports_multi_credit {
        usize::try_from(available_credits)
            .unwrap_or(usize::MAX)
            .saturating_mul(CREDIT_UNIT_BYTES)
    } else if available_credits > 0 {
        CREDIT_UNIT_BYTES
    } else {
        0
    }
}

fn read_credit_charge(supports_multi_credit: bool, length: usize) -> Result<u16, ClientError> {
    if !supports_multi_credit {
        return Ok(0);
    }
    let units = (length - 1) / CREDIT_UNIT_BYTES + 1;
    u16::try_from(units).map_err(|_| ClientError::Protocol("READ CreditCharge exceeds u16"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mib_read_costs_sixteen_credits() {
        assert_eq!(read_credit_charge(true, 1024 * 1024).unwrap(), 16);
    }

    #[test]
    fn legacy_read_uses_zero_credit_charge() {
        assert_eq!(read_credit_charge(false, 64 * 1024).unwrap(), 0);
    }
}
