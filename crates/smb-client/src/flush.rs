use smb_io_wire::{
    Command, FlushRequest, FlushResponse, Smb2Header, StatusField, flags, session_flags,
};

use crate::async_response::{AsyncResponseState, ResponsePhase};
use crate::{ClientError, FileHandle, SessionConnection, Transport};

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Flush all pending writes for one open file on the same authenticated SMB session.
    ///
    /// A transport error after send is ambiguous; FLUSH must never be replayed automatically.
    pub async fn flush_file(&mut self, file: &FileHandle) -> Result<(), ClientError> {
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }

        let credit_charge = self.connection.single_request_credit_charge()?;
        let credit_request = self.connection.reserve_credits(credit_charge, 8)?;
        let message_id = self.connection.message_ids.allocate(credit_charge)?;
        let mut request = FlushRequest::new(file.file_id()).encode_message(
            message_id,
            self.session_id,
            file.tree_id(),
            credit_charge,
            credit_request,
        )?;
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "FLUSH requires signing but the session has no signing key",
            ))?;
            signing.sign(&mut request)?;
        }

        self.connection.transport.send_message(&request).await?;
        let mut async_state = AsyncResponseState::default();
        let (message, header) = loop {
            let mut message = self.connection.transport.receive_message().await?;
            let header = Smb2Header::decode(&message)?;
            let phase = async_state.validate(
                Command::Flush,
                file.tree_id(),
                self.session_id,
                message_id,
                &header,
            )?;
            self.connection.grant_credits(header.credits)?;
            if header.flags & flags::SIGNED != 0 {
                let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                    "server signed FLUSH without an available signing key",
                ))?;
                signing.verify(&mut message)?;
            } else if phase.requires_signature(self.signing_required) {
                return Err(ClientError::Protocol(
                    "server omitted a required FLUSH signature",
                ));
            }
            if phase == ResponsePhase::InterimPending {
                continue;
            }
            break (message, header);
        };

        validate_flush_status(header.status)?;
        FlushResponse::decode_message(&message)?;
        Ok(())
    }
}

fn validate_flush_status(status: StatusField) -> Result<(), ClientError> {
    match status {
        StatusField::Status(0) => Ok(()),
        StatusField::Status(status) => Err(ClientError::ServerStatus(status)),
        StatusField::ChannelSequence { .. } => Err(ClientError::Protocol(
            "FLUSH response used request header form",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_requires_success_status_not_transport_guessing() {
        assert!(validate_flush_status(StatusField::Status(0)).is_ok());
        let denied = 0xC000_0022;
        assert!(matches!(
            validate_flush_status(StatusField::Status(denied)),
            Err(ClientError::ServerStatus(0xC000_0022))
        ));
        assert!(
            validate_flush_status(StatusField::ChannelSequence {
                sequence: 0,
                reserved: 0,
            })
            .is_err()
        );
    }
}
