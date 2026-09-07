use smb_io_wire::{CancelRequest, ReadRequest, ReadResponse, Smb2Header, StatusField, flags, session_flags};

use crate::read_async::{AsyncReadState, ReadResponsePhase};
use crate::{
    ClientError, FileHandle, PipelinedReadOptions, ReadCancellationToken, SessionConnection,
    Transport,
};

pub const STATUS_CANCELLED: u32 = 0xC000_0120;
const CREDIT_UNIT_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy)]
struct PendingRead {
    message_id: u64,
    chunk_len: usize,
    async_state: AsyncReadState,
    async_cancel_sent: bool,
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Pipelined positional READ that can be invalidated by a seek generation change.
    ///
    /// When `cancellation` advances away from `generation`, SMB2 CANCEL is sent for every
    /// outstanding READ. If a request has transitioned through STATUS_PENDING, its AsyncId is used
    /// in the CANCEL header. The method drains every final READ response before returning
    /// `ClientError::Cancelled`, preserving transport framing for the next request.
    pub async fn read_at_pipelined_cancelable_with_options(
        &mut self,
        file: &FileHandle,
        offset: u64,
        length: usize,
        options: PipelinedReadOptions,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<Vec<u8>, ClientError> {
        if length == 0 || offset >= file.len() {
            return Ok(Vec::new());
        }
        validate_options(options)?;
        ensure_read_session(self)?;
        if !cancellation.is_current(generation) {
            return Err(ClientError::Cancelled);
        }

        let target = read_target_len(file, offset, length)?;
        let mut out = Vec::with_capacity(target);

        while out.len() < target {
            if !cancellation.is_current(generation) {
                return Err(ClientError::Cancelled);
            }

            let (supports_multi_credit, max_read_size) = read_limits(self)?;
            let remaining = target - out.len();
            let mut pending = Vec::with_capacity(options.max_in_flight);
            let mut scheduled = 0usize;

            while pending.len() < options.max_in_flight && scheduled < remaining {
                if !cancellation.is_current(generation) {
                    break;
                }

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
                sign_request(self, &mut request_message, "READ")?;
                self.connection
                    .transport
                    .send_message(&request_message)
                    .await?;

                pending.push(PendingRead {
                    message_id,
                    chunk_len,
                    async_state: AsyncReadState::default(),
                    async_cancel_sent: false,
                });
                scheduled += chunk_len;
            }

            if pending.is_empty() {
                if !cancellation.is_current(generation) {
                    return Err(ClientError::Cancelled);
                }
                return Err(ClientError::Protocol(
                    "SMB connection has no credits available for pipelined READ",
                ));
            }

            let mut completed = vec![None; pending.len()];
            let mut short_response_at: Option<usize> = None;
            let mut first_status_error: Option<u32> = None;
            let mut cancelled = !cancellation.is_current(generation);

            if cancelled {
                send_cancel_requests(self, &mut pending, &completed).await?;
            }

            let mut received = 0usize;
            while received < pending.len() {
                if !cancelled && !cancellation.is_current(generation) {
                    cancelled = true;
                    send_cancel_requests(self, &mut pending, &completed).await?;
                }

                let response_result = if cancelled {
                    self.connection.transport.receive_message().await
                } else {
                    tokio::select! {
                        changed = cancellation.wait_for_change(generation) => {
                            let _ = changed;
                            cancelled = true;
                            send_cancel_requests(self, &mut pending, &completed).await?;
                            continue;
                        }
                        response = self.connection.transport.receive_message() => response,
                    }
                };

                let mut response_message = response_result?;
                let header = Smb2Header::decode(&response_message)?;
                let position = pending
                    .iter()
                    .position(|request| request.message_id == header.message_id)
                    .ok_or(ClientError::Protocol(
                        "pipelined READ response MessageId is not outstanding",
                    ))?;
                if completed[position].is_some() {
                    return Err(ClientError::Protocol(
                        "pipelined READ received a duplicate final response",
                    ));
                }

                let phase = pending[position].async_state.validate(
                    file.tree_id(),
                    self.session_id,
                    pending[position].message_id,
                    &header,
                )?;
                self.connection.grant_credits(header.credits)?;
                verify_response(self, &mut response_message, &header)?;

                if phase == ReadResponsePhase::InterimPending {
                    if cancelled && !pending[position].async_cancel_sent {
                        let async_id = pending[position]
                            .async_state
                            .async_id()
                            .ok_or(ClientError::Protocol(
                                "STATUS_PENDING READ did not record an AsyncId",
                            ))?;
                        self.send_cancel_for_message_id(
                            pending[position].message_id,
                            Some(async_id),
                        )
                        .await?;
                        pending[position].async_cancel_sent = true;
                    }
                    continue;
                }

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
                    StatusField::Status(STATUS_CANCELLED) => {
                        cancelled = true;
                        completed[position] = Some(Vec::new());
                    }
                    StatusField::Status(crate::STATUS_END_OF_FILE) => {
                        short_response_at = Some(
                            short_response_at.map_or(position, |current| current.min(position)),
                        );
                        completed[position] = Some(Vec::new());
                    }
                    StatusField::Status(status) => {
                        first_status_error.get_or_insert(status);
                        completed[position] = Some(Vec::new());
                    }
                    StatusField::ChannelSequence { .. } => {
                        return Err(ClientError::Protocol(
                            "READ response used request header form",
                        ));
                    }
                }
                received += 1;
            }

            if cancelled || !cancellation.is_current(generation) {
                return Err(ClientError::Cancelled);
            }
            if let Some(status) = first_status_error {
                return Err(ClientError::ServerStatus(status));
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

    async fn send_cancel_for_message_id(
        &mut self,
        message_id: u64,
        async_id: Option<u64>,
    ) -> Result<(), ClientError> {
        let mut message = match async_id {
            Some(async_id) => {
                CancelRequest.encode_async_message(message_id, self.session_id, async_id)
            }
            None => CancelRequest.encode_sync_message(message_id, self.session_id),
        };
        sign_request(self, &mut message, "CANCEL")?;
        self.connection.transport.send_message(&message).await
    }
}

async fn send_cancel_requests<T: Transport>(
    session: &mut SessionConnection<T>,
    pending: &mut [PendingRead],
    completed: &[Option<Vec<u8>>],
) -> Result<(), ClientError> {
    for (request, result) in pending.iter_mut().zip(completed) {
        if result.is_none() {
            let async_id = request.async_state.async_id();
            session
                .send_cancel_for_message_id(request.message_id, async_id)
                .await?;
            request.async_cancel_sent = async_id.is_some();
        }
    }
    Ok(())
}

fn validate_options(options: PipelinedReadOptions) -> Result<(), ClientError> {
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
    Ok(())
}

fn ensure_read_session<T>(session: &SessionConnection<T>) -> Result<(), ClientError> {
    if session.session_flags & session_flags::ENCRYPT_DATA != 0 {
        return Err(ClientError::Protocol(
            "encrypted SMB sessions are not implemented yet",
        ));
    }
    Ok(())
}

fn read_limits<T>(session: &SessionConnection<T>) -> Result<(bool, usize), ClientError> {
    let negotiated = session
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

fn sign_request<T>(
    session: &SessionConnection<T>,
    message: &mut [u8],
    command: &'static str,
) -> Result<(), ClientError> {
    if session.signing_required {
        let signing = session.signing.as_ref().ok_or(ClientError::Protocol(
            "signed request requires a session signing key",
        ))?;
        signing.sign(message).map_err(|error| match error {
            ClientError::Protocol(_) => ClientError::Protocol(match command {
                "CANCEL" => "CANCEL signing failed",
                _ => "READ signing failed",
            }),
            other => other,
        })?;
    }
    Ok(())
}

fn verify_response<T>(
    session: &SessionConnection<T>,
    message: &mut [u8],
    header: &Smb2Header,
) -> Result<(), ClientError> {
    if header.flags & flags::SIGNED != 0 {
        let signing = session.signing.as_ref().ok_or(ClientError::Protocol(
            "server signed READ without an available signing key",
        ))?;
        signing.verify(message)?;
    } else if session.signing_required {
        return Err(ClientError::Protocol(
            "server omitted a required READ signature",
        ));
    }
    Ok(())
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
