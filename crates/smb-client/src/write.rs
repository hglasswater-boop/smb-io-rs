use smb_io_wire::{
    Command, HeaderId, Smb2Header, StatusField, WriteRequest, WriteResponse, flags, session_flags,
};

use crate::{ClientError, FileHandle, SessionConnection, Transport};

const CREDIT_UNIT_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct WriteOptions {
    /// Minimum number of credits to request back from the server on each WRITE.
    pub credit_request: u16,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self { credit_request: 32 }
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Writes bytes to an already-open file without changing any shared file position.
    ///
    /// Large writes are split to respect both the negotiated MaxWriteSize and the credits currently
    /// available on the connection. Mutation requests are never replayed automatically after a
    /// transport error because completion may be ambiguous.
    pub async fn write_at(
        &mut self,
        file: &FileHandle,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, ClientError> {
        self.write_at_with_options(file, offset, data, WriteOptions::default())
            .await
    }

    pub async fn write_at_with_options(
        &mut self,
        file: &FileHandle,
        offset: u64,
        data: &[u8],
        options: WriteOptions,
    ) -> Result<usize, ClientError> {
        if data.is_empty() {
            return Ok(0);
        }
        self.ensure_write_session()?;

        let mut written = 0usize;
        while written < data.len() {
            let remaining = data.len() - written;
            let (supports_multi_credit, max_write_size) = self.write_limits()?;
            let available_credits = self.available_write_credits()?;
            let credit_limited = credit_limited_payload(supports_multi_credit, available_credits);
            let chunk_len = remaining.min(max_write_size).min(credit_limited);
            if chunk_len == 0 {
                return Err(ClientError::Protocol("WRITE chunk size resolved to zero"));
            }

            let credit_charge = write_credit_charge(supports_multi_credit, chunk_len)?;
            let credit_request = self
                .connection
                .reserve_credits(credit_charge, options.credit_request)?;
            let message_id = self.connection.message_ids.allocate(credit_charge)?;
            let chunk_offset = offset
                .checked_add(
                    u64::try_from(written)
                        .map_err(|_| ClientError::Protocol("WRITE offset conversion overflow"))?,
                )
                .ok_or(ClientError::Protocol("WRITE offset overflow"))?;
            let request = WriteRequest::direct(
                file.file_id(),
                chunk_offset,
                data[written..written + chunk_len].to_vec(),
            );
            let mut request_message = request.encode_message(
                message_id,
                self.session_id,
                file.tree_id(),
                credit_charge,
                credit_request,
            )?;
            self.sign_write_request(&mut request_message)?;

            self.connection
                .transport
                .send_message(&request_message)
                .await?;
            let mut response_message = self.connection.transport.receive_message().await?;
            let header = Smb2Header::decode(&response_message)?;
            self.validate_write_response_header(file, message_id, &header)?;
            self.connection.grant_credits(header.credits)?;
            self.verify_write_response(&mut response_message, &header)?;

            match header.status {
                StatusField::Status(0) => {}
                StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
                StatusField::ChannelSequence { .. } => {
                    return Err(ClientError::Protocol(
                        "WRITE response used request header form",
                    ));
                }
            }

            let response = WriteResponse::decode_message(&response_message)?;
            let count = usize::try_from(response.count)
                .map_err(|_| ClientError::Protocol("WRITE response Count does not fit usize"))?;
            if count > chunk_len {
                return Err(ClientError::Protocol(
                    "WRITE response reported more bytes than requested",
                ));
            }
            if count == 0 {
                return Err(ClientError::Protocol(
                    "successful WRITE response reported zero bytes",
                ));
            }
            written = written
                .checked_add(count)
                .ok_or(ClientError::Protocol("WRITE result length overflow"))?;
        }

        Ok(written)
    }

    fn ensure_write_session(&self) -> Result<(), ClientError> {
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }
        Ok(())
    }

    fn write_limits(&self) -> Result<(bool, usize), ClientError> {
        let negotiated = self
            .connection
            .negotiated
            .as_ref()
            .ok_or(ClientError::Protocol(
                "WRITE requires negotiated parameters",
            ))?;
        let max_write_size = usize::try_from(negotiated.max_write_size)
            .map_err(|_| ClientError::Protocol("MaxWriteSize does not fit in usize"))?;
        if max_write_size == 0 {
            return Err(ClientError::Protocol(
                "MaxWriteSize must be greater than zero",
            ));
        }
        Ok((negotiated.supports_multi_credit(), max_write_size))
    }

    fn available_write_credits(&self) -> Result<u32, ClientError> {
        match self.connection.available_credits() {
            Some(0) => Err(ClientError::Protocol(
                "SMB connection has no credits available for WRITE",
            )),
            Some(credits) => Ok(credits),
            None => Err(ClientError::Protocol(
                "SMB credit window is not initialized",
            )),
        }
    }

    fn sign_write_request(&self, message: &mut [u8]) -> Result<(), ClientError> {
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "WRITE requires signing but the session has no signing key",
            ))?;
            signing.sign(message)?;
        }
        Ok(())
    }

    fn validate_write_response_header(
        &self,
        file: &FileHandle,
        message_id: u64,
        header: &Smb2Header,
    ) -> Result<(), ClientError> {
        if header.command != Command::Write {
            return Err(ClientError::Protocol(
                "WRITE response command does not match request",
            ));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(
                "WRITE response MessageId does not match request",
            ));
        }
        if header.session_id != self.session_id {
            return Err(ClientError::Protocol(
                "WRITE response SessionId does not match session",
            ));
        }
        match header.id {
            HeaderId::Sync { tree_id, .. } if tree_id == file.tree_id() => Ok(()),
            HeaderId::Sync { .. } => Err(ClientError::Protocol(
                "WRITE response TreeId does not match file tree",
            )),
            HeaderId::Async { .. } => Err(ClientError::Protocol(
                "WRITE response unexpectedly used async header form",
            )),
        }
    }

    fn verify_write_response(
        &self,
        message: &mut [u8],
        header: &Smb2Header,
    ) -> Result<(), ClientError> {
        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed WRITE without an available signing key",
            ))?;
            signing.verify(message)?;
        } else if self.signing_required {
            return Err(ClientError::Protocol(
                "server omitted a required WRITE signature",
            ));
        }
        Ok(())
    }
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

fn write_credit_charge(supports_multi_credit: bool, length: usize) -> Result<u16, ClientError> {
    if !supports_multi_credit {
        return Ok(0);
    }
    if length == 0 {
        return Err(ClientError::Protocol(
            "WRITE CreditCharge cannot be calculated for zero bytes",
        ));
    }
    let units = (length - 1) / CREDIT_UNIT_BYTES + 1;
    u16::try_from(units).map_err(|_| ClientError::Protocol("WRITE CreditCharge exceeds u16"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mib_write_costs_sixteen_credits() {
        assert_eq!(write_credit_charge(true, 1024 * 1024).unwrap(), 16);
    }

    #[test]
    fn legacy_write_uses_zero_credit_charge() {
        assert_eq!(write_credit_charge(false, 64 * 1024).unwrap(), 0);
    }

    #[test]
    fn zero_length_credit_calculation_is_rejected() {
        assert!(write_credit_charge(true, 0).is_err());
    }

    #[test]
    fn credit_window_limits_write_payload() {
        assert_eq!(credit_limited_payload(true, 0), 0);
        assert_eq!(credit_limited_payload(true, 1), CREDIT_UNIT_BYTES);
        assert_eq!(credit_limited_payload(true, 4), 4 * CREDIT_UNIT_BYTES);
        assert_eq!(credit_limited_payload(false, 1), CREDIT_UNIT_BYTES);
    }
}
