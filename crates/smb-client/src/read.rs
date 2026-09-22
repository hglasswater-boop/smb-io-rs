use std::collections::HashMap;

use smb_io_wire::{ReadRequest, ReadResponse, Smb2Header, StatusField, flags, session_flags};

use crate::read_async::{AsyncReadState, ReadResponsePhase};
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
    /// Maximum number of READ requests simultaneously outstanding on the connection.
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct PipelinedReadStats {
    pub requests_sent: usize,
    pub responses_completed: usize,
    pub peak_in_flight: usize,
    /// Number of scheduler turns where no credit was available while at least one READ was still
    /// outstanding. In that state the scheduler waits for a response and resumes from its grant.
    pub credit_stalls: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PipelinedReadResult {
    pub data: Vec<u8>,
    pub stats: PipelinedReadStats,
}

#[derive(Debug, Clone, Copy)]
struct PendingRead {
    position: usize,
    chunk_len: usize,
    async_state: AsyncReadState,
}

#[derive(Debug)]
struct OutstandingReads {
    by_message_id: HashMap<u64, PendingRead>,
}

impl OutstandingReads {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_message_id: HashMap::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.by_message_id.len()
    }

    fn is_empty(&self) -> bool {
        self.by_message_id.is_empty()
    }

    fn insert(&mut self, message_id: u64, request: PendingRead) -> Result<(), ClientError> {
        if self.by_message_id.contains_key(&message_id) {
            return Err(ClientError::Protocol(
                "pipelined READ reused an outstanding MessageId",
            ));
        }
        self.by_message_id.insert(message_id, request);
        Ok(())
    }

    fn get_mut(&mut self, message_id: u64) -> Result<&mut PendingRead, ClientError> {
        self.by_message_id
            .get_mut(&message_id)
            .ok_or(ClientError::Protocol(
                "pipelined READ response MessageId is not outstanding",
            ))
    }

    fn finish(&mut self, message_id: u64) -> Result<PendingRead, ClientError> {
        self.by_message_id
            .remove(&message_id)
            .ok_or(ClientError::Protocol(
                "pipelined READ received a duplicate or unknown final response",
            ))
    }
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

            let mut async_state = AsyncReadState::default();
            let (response_message, header) = loop {
                let mut response_message = self.connection.transport.receive_message().await?;
                let header = Smb2Header::decode(&response_message)?;
                let phase =
                    async_state.validate(file.tree_id(), self.session_id, message_id, &header)?;
                self.connection.grant_credits(header.credits)?;
                self.verify_read_response(&mut response_message, &header, phase)?;
                if phase == ReadResponsePhase::InterimPending {
                    continue;
                }
                break (response_message, header);
            };

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

    /// Reads a random-access window while keeping several SMB READ requests outstanding.
    ///
    /// The scheduler is credit-driven rather than batch-driven: it fills the current credit/window
    /// allowance, consumes whichever response arrives next, applies that response's credit grant,
    /// and immediately fills newly available capacity. Responses are correlated through an
    /// explicit MessageId table and reassembled in file order. On a terminal server-status error,
    /// no new READs are issued and every already-sent READ is drained before the first error is
    /// returned so the framed transport is not left with stale responses.
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
        Ok(self
            .read_at_pipelined_with_stats(file, offset, length, options)
            .await?
            .data)
    }

    pub async fn read_at_pipelined_with_stats(
        &mut self,
        file: &FileHandle,
        offset: u64,
        length: usize,
        options: PipelinedReadOptions,
    ) -> Result<PipelinedReadResult, ClientError> {
        if length == 0 || offset >= file.len() {
            return Ok(PipelinedReadResult {
                data: Vec::new(),
                stats: PipelinedReadStats::default(),
            });
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
        let (supports_multi_credit, max_read_size) = self.read_limits()?;
        let mut outstanding = OutstandingReads::with_capacity(options.max_in_flight);
        let mut completed: Vec<Option<Vec<u8>>> = Vec::new();
        let mut scheduled_bytes = 0usize;
        let mut short_response_at: Option<usize> = None;
        let mut first_server_error: Option<u32> = None;
        let mut stats = PipelinedReadStats::default();

        loop {
            let mut stalled_for_credit = false;
            while first_server_error.is_none()
                && short_response_at.is_none()
                && outstanding.len() < options.max_in_flight
                && scheduled_bytes < target
            {
                let available_credits = match self.connection.available_credits() {
                    Some(0) => {
                        stalled_for_credit = true;
                        break;
                    }
                    Some(credits) => credits,
                    None => {
                        return Err(ClientError::Protocol(
                            "SMB credit window is not initialized",
                        ));
                    }
                };
                let credit_limited =
                    credit_limited_payload(supports_multi_credit, available_credits);
                let chunk_len = (target - scheduled_bytes)
                    .min(options.chunk_size)
                    .min(max_read_size)
                    .min(credit_limited);
                if chunk_len == 0 {
                    stalled_for_credit = true;
                    break;
                }

                let credit_charge = read_credit_charge(supports_multi_credit, chunk_len)?;
                let credit_request = self
                    .connection
                    .reserve_credits(credit_charge, options.credit_request)?;
                let message_id = self.connection.message_ids.allocate(credit_charge)?;
                let request_offset =
                    offset
                        .checked_add(u64::try_from(scheduled_bytes).map_err(|_| {
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

                let position = completed.len();
                completed.push(None);
                outstanding.insert(
                    message_id,
                    PendingRead {
                        position,
                        chunk_len,
                        async_state: AsyncReadState::default(),
                    },
                )?;
                scheduled_bytes += chunk_len;
                stats.requests_sent += 1;
                stats.peak_in_flight = stats.peak_in_flight.max(outstanding.len());
            }

            if stalled_for_credit && !outstanding.is_empty() {
                stats.credit_stalls += 1;
            }

            if outstanding.is_empty() {
                if let Some(status) = first_server_error {
                    return Err(ClientError::ServerStatus(status));
                }
                if short_response_at.is_some() || scheduled_bytes >= target {
                    break;
                }
                return Err(ClientError::Protocol(
                    "SMB connection exhausted credits with no outstanding READ able to restore them",
                ));
            }

            let mut response_message = self.connection.transport.receive_message().await?;
            let header = Smb2Header::decode(&response_message)?;
            let (position, chunk_len, phase) = {
                let pending = outstanding.get_mut(header.message_id)?;
                let phase = pending.async_state.validate(
                    file.tree_id(),
                    self.session_id,
                    header.message_id,
                    &header,
                )?;
                (pending.position, pending.chunk_len, phase)
            };

            self.connection.grant_credits(header.credits)?;
            self.verify_read_response(&mut response_message, &header, phase)?;
            if phase == ReadResponsePhase::InterimPending {
                continue;
            }

            let finished = outstanding.finish(header.message_id)?;
            debug_assert_eq!(finished.position, position);
            debug_assert_eq!(finished.chunk_len, chunk_len);

            let data = match header.status {
                StatusField::Status(0) => {
                    if first_server_error.is_some() {
                        Vec::new()
                    } else {
                        let response = ReadResponse::decode_message(&response_message)?;
                        if response.data.len() > chunk_len {
                            return Err(ClientError::Protocol(
                                "READ response returned more data than requested",
                            ));
                        }
                        if response.data.len() < chunk_len {
                            short_response_at = Some(
                                short_response_at.map_or(position, |current| current.min(position)),
                            );
                        }
                        response.data
                    }
                }
                StatusField::Status(STATUS_END_OF_FILE) => {
                    if first_server_error.is_none() {
                        short_response_at = Some(
                            short_response_at.map_or(position, |current| current.min(position)),
                        );
                    }
                    Vec::new()
                }
                StatusField::Status(status) => {
                    if first_server_error.is_none() {
                        first_server_error = Some(status);
                    }
                    Vec::new()
                }
                StatusField::ChannelSequence { .. } => {
                    return Err(ClientError::Protocol(
                        "READ response used request header form",
                    ));
                }
            };

            if completed[position].replace(data).is_some() {
                return Err(ClientError::Protocol(
                    "pipelined READ completed the same output slot twice",
                ));
            }
            stats.responses_completed += 1;
        }

        let take_count = short_response_at
            .map(|position| position.saturating_add(1))
            .unwrap_or(completed.len());
        let mut out = Vec::with_capacity(target);
        for data in completed.into_iter().take(take_count) {
            let data = data.ok_or(ClientError::Protocol(
                "pipelined READ did not receive every required response",
            ))?;
            out.extend_from_slice(&data);
        }

        Ok(PipelinedReadResult { data: out, stats })
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
        phase: ReadResponsePhase,
    ) -> Result<(), ClientError> {
        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed READ without an available signing key",
            ))?;
            signing.verify(message)?;
        } else if phase.requires_signature(self.signing_required) {
            return Err(ClientError::Protocol(
                "server omitted a required READ signature",
            ));
        }
        Ok(())
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
    if length == 0 {
        return Err(ClientError::Protocol(
            "READ CreditCharge cannot be calculated for zero bytes",
        ));
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

    #[test]
    fn zero_credit_window_cannot_schedule_payload() {
        assert_eq!(credit_limited_payload(true, 0), 0);
        assert_eq!(credit_limited_payload(false, 0), 0);
    }

    #[test]
    fn one_multi_credit_unit_limits_payload_to_64k() {
        assert_eq!(credit_limited_payload(true, 1), 65_536);
    }

    #[test]
    fn outstanding_table_rejects_duplicate_message_id() {
        let mut outstanding = OutstandingReads::with_capacity(2);
        let request = PendingRead {
            position: 0,
            chunk_len: 64 * 1024,
            async_state: AsyncReadState::default(),
        };
        outstanding.insert(7, request).unwrap();
        assert!(outstanding.insert(7, request).is_err());
        assert_eq!(outstanding.len(), 1);
    }

    #[test]
    fn finishing_outstanding_request_removes_message_id() {
        let mut outstanding = OutstandingReads::with_capacity(1);
        outstanding
            .insert(
                11,
                PendingRead {
                    position: 3,
                    chunk_len: 128 * 1024,
                    async_state: AsyncReadState::default(),
                },
            )
            .unwrap();
        let finished = outstanding.finish(11).unwrap();
        assert_eq!(finished.position, 3);
        assert!(outstanding.is_empty());
        assert!(outstanding.finish(11).is_err());
    }
}
