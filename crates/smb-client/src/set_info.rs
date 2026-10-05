use smb_io_wire::{
    Command, SetInfoRequest, SetInfoResponse, Smb2Header, StatusField, flags, session_flags,
};

use crate::async_response::{AsyncResponseState, ResponsePhase};
use crate::{ClientError, FileHandle, SessionConnection, Transport};

const CREDIT_UNIT_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoOptions {
    pub info_type: u8,
    pub file_info_class: u8,
    pub buffer: Vec<u8>,
    pub additional_information: u32,
    pub credit_request: u16,
}

impl SetInfoOptions {
    pub fn file(file_info_class: u8, buffer: Vec<u8>) -> Self {
        Self {
            info_type: smb_io_wire::info_type::FILE,
            file_info_class,
            buffer,
            additional_information: 0,
            credit_request: 16,
        }
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Applies one SMB2 SET_INFO mutation to an already-open handle.
    ///
    /// The request is sent exactly once. Transport failure after send is returned to the caller
    /// because mutation completion may be ambiguous and must never be blindly replayed.
    pub async fn set_info(
        &mut self,
        file: &FileHandle,
        options: SetInfoOptions,
    ) -> Result<(), ClientError> {
        self.ensure_set_info_session()?;
        if options.buffer.is_empty() {
            return Err(ClientError::Protocol(
                "SET_INFO input buffer must not be empty",
            ));
        }
        let (supports_multi_credit, max_transact_size) = self.set_info_limits()?;
        if options.buffer.len() > max_transact_size {
            return Err(ClientError::Protocol(
                "SET_INFO input buffer exceeds negotiated MaxTransactSize",
            ));
        }
        if !supports_multi_credit && options.buffer.len() > CREDIT_UNIT_BYTES {
            return Err(ClientError::Protocol(
                "SET_INFO payload exceeds single-credit 64 KiB limit",
            ));
        }

        let credit_charge = set_info_credit_charge(supports_multi_credit, options.buffer.len())?;
        let request = SetInfoRequest {
            info_type: options.info_type,
            file_info_class: options.file_info_class,
            buffer: options.buffer,
            additional_information: options.additional_information,
            file_id: file.file_id(),
        };
        let credit_request = self
            .connection
            .reserve_credits(credit_charge, options.credit_request)?;
        let message_id = self.connection.message_ids.allocate(credit_charge)?;
        let mut request_message = request.encode_message(
            message_id,
            self.session_id,
            file.tree_id(),
            credit_charge,
            credit_request,
        )?;
        self.sign_set_info_request(&mut request_message)?;
        self.connection
            .transport
            .send_message(&request_message)
            .await?;

        let mut async_state = AsyncResponseState::default();
        let (response_message, header) = loop {
            let mut response_message = self.connection.transport.receive_message().await?;
            let header = Smb2Header::decode(&response_message)?;
            let phase = async_state.validate(
                Command::SetInfo,
                file.tree_id(),
                self.session_id,
                message_id,
                &header,
            )?;
            self.connection.grant_credits(header.credits)?;
            self.verify_set_info_response(&mut response_message, &header, phase)?;
            if phase == ResponsePhase::InterimPending {
                continue;
            }
            break (response_message, header);
        };

        validate_set_info_status(header.status)?;
        SetInfoResponse::decode_message(&response_message)?;
        Ok(())
    }

    fn ensure_set_info_session(&self) -> Result<(), ClientError> {
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }
        Ok(())
    }

    fn set_info_limits(&self) -> Result<(bool, usize), ClientError> {
        let negotiated = self
            .connection
            .negotiated
            .as_ref()
            .ok_or(ClientError::Protocol(
                "SET_INFO requires negotiated parameters",
            ))?;
        let max_transact_size = usize::try_from(negotiated.max_transact_size)
            .map_err(|_| ClientError::Protocol("MaxTransactSize does not fit in usize"))?;
        if max_transact_size == 0 {
            return Err(ClientError::Protocol(
                "MaxTransactSize must be greater than zero",
            ));
        }
        Ok((negotiated.supports_multi_credit(), max_transact_size))
    }

    fn sign_set_info_request(&self, message: &mut [u8]) -> Result<(), ClientError> {
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "SET_INFO requires signing but the session has no signing key",
            ))?;
            signing.sign(message)?;
        }
        Ok(())
    }

    fn verify_set_info_response(
        &self,
        message: &mut [u8],
        header: &Smb2Header,
        phase: ResponsePhase,
    ) -> Result<(), ClientError> {
        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed SET_INFO without an available signing key",
            ))?;
            signing.verify(message)?;
        } else if phase.requires_signature(self.signing_required) {
            return Err(ClientError::Protocol(
                "server omitted a required SET_INFO signature",
            ));
        }
        Ok(())
    }
}

fn validate_set_info_status(status: StatusField) -> Result<(), ClientError> {
    match status {
        StatusField::Status(0) => Ok(()),
        StatusField::Status(status) => Err(ClientError::ServerStatus(status)),
        StatusField::ChannelSequence { .. } => Err(ClientError::Protocol(
            "SET_INFO response used request header form",
        )),
    }
}

fn set_info_credit_charge(
    supports_multi_credit: bool,
    length: usize,
) -> Result<u16, ClientError> {
    if !supports_multi_credit {
        return Ok(0);
    }
    if length == 0 {
        return Err(ClientError::Protocol(
            "SET_INFO CreditCharge cannot be calculated for zero bytes",
        ));
    }
    let units = (length - 1) / CREDIT_UNIT_BYTES + 1;
    u16::try_from(units).map_err(|_| ClientError::Protocol("SET_INFO CreditCharge exceeds u16"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mib_set_info_costs_sixteen_credits() {
        assert_eq!(set_info_credit_charge(true, 1024 * 1024).unwrap(), 16);
    }

    #[test]
    fn legacy_set_info_uses_zero_credit_charge() {
        assert_eq!(set_info_credit_charge(false, 64 * 1024).unwrap(), 0);
    }

    #[test]
    fn server_status_is_preserved() {
        let status = 0xC000_0035;
        match validate_set_info_status(StatusField::Status(status)) {
            Err(ClientError::ServerStatus(actual)) => assert_eq!(actual, status),
            result => panic!("unexpected SET_INFO status result: {result:?}"),
        }
    }
}
