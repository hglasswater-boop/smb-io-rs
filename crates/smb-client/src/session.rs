use smb_io_auth::{AuthMechanism, AuthProvider, AuthState, SecretBytes};
use smb_io_wire::{
    Command, SessionSetupRequest, SessionSetupResponse, Smb2Header, StatusField, security_mode,
};

use crate::{ClientError, Connection, NegotiatedParameters, PreauthIntegrityHash, Transport};

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

#[derive(Debug, Clone, Copy)]
pub struct SessionSetupConfig {
    /// Client signing policy encoded with SMB2_NEGOTIATE_SIGNING_* values.
    pub security_mode: u8,
    /// SESSION_SETUP currently only defines the DFS capability bit. Keep this zero unless needed.
    pub capabilities: u32,
    pub previous_session_id: u64,
    pub credit_request: u16,
    pub max_rounds: usize,
}

impl Default for SessionSetupConfig {
    fn default() -> Self {
        Self {
            security_mode: security_mode::SIGNING_ENABLED as u8,
            capabilities: 0,
            previous_session_id: 0,
            credit_request: 32,
            max_rounds: 8,
        }
    }
}

pub struct SessionConnection<T> {
    connection: Connection<T>,
    session_id: u64,
    session_flags: u16,
    mechanism: AuthMechanism,
    session_key: Option<SecretBytes>,
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn session_flags(&self) -> u16 {
        self.session_flags
    }

    pub fn mechanism(&self) -> AuthMechanism {
        self.mechanism
    }

    pub fn has_session_key(&self) -> bool {
        self.session_key.is_some()
    }

    pub fn negotiated(&self) -> Option<&NegotiatedParameters> {
        self.connection.negotiated.as_ref()
    }

    pub fn preauth_hash(&self) -> Option<&PreauthIntegrityHash> {
        self.connection.preauth_hash.as_ref()
    }

    pub fn into_connection(self) -> Connection<T> {
        self.connection
    }
}

impl<T> Connection<T>
where
    T: Transport,
{
    /// Runs the SMB SESSION_SETUP token exchange and transitions this connection into an
    /// authenticated `SessionConnection`.
    pub async fn session_setup<P>(
        mut self,
        provider: &mut P,
        config: SessionSetupConfig,
    ) -> Result<SessionConnection<T>, ClientError>
    where
        P: AuthProvider,
    {
        if self.negotiated.is_none() {
            return Err(ClientError::Protocol(
                "SESSION_SETUP requires a negotiated SMB connection",
            ));
        }
        if config.max_rounds == 0 {
            return Err(ClientError::Protocol(
                "SESSION_SETUP max_rounds must be greater than zero",
            ));
        }

        let mechanism = provider.mechanism();
        let mut step = provider.initial_token()?;
        let mut session_id = 0u64;

        for _round in 0..config.max_rounds {
            let step_state = step.state;
            let request = SessionSetupRequest {
                flags: 0,
                security_mode: config.security_mode,
                capabilities: config.capabilities,
                previous_session_id: config.previous_session_id,
                security_blob: core::mem::take(&mut step.token),
            };
            let message_id = self.message_ids.allocate(0)?;
            let request_message =
                request.encode_message(message_id, session_id, config.credit_request)?;
            update_preauth(&mut self.preauth_hash, &request_message);

            self.transport.send_message(&request_message).await?;
            let response_message = self.transport.receive_message().await?;
            update_preauth(&mut self.preauth_hash, &response_message);

            let response_header = Smb2Header::decode(&response_message)?;
            if response_header.command != Command::SessionSetup {
                return Err(ClientError::Protocol(
                    "SESSION_SETUP response command does not match request",
                ));
            }
            if response_header.message_id != message_id {
                return Err(ClientError::Protocol(
                    "SESSION_SETUP response MessageId does not match request",
                ));
            }

            let status = match response_header.status {
                StatusField::Status(status) => status,
                StatusField::ChannelSequence { .. } => {
                    return Err(ClientError::Protocol(
                        "SESSION_SETUP response used request header form",
                    ));
                }
            };

            if status != STATUS_SUCCESS && status != STATUS_MORE_PROCESSING_REQUIRED {
                return Err(ClientError::ServerStatus(status));
            }

            let response = SessionSetupResponse::decode_message(&response_message)?;
            validate_session_id(session_id, response.header.session_id)?;
            if response.header.session_id != 0 {
                session_id = response.header.session_id;
            }

            if status == STATUS_MORE_PROCESSING_REQUIRED {
                if session_id == 0 {
                    return Err(ClientError::Protocol(
                        "server did not assign a SessionId during authentication",
                    ));
                }
                step = provider.next_token(&response.security_blob)?;
                continue;
            }

            let final_state = if response.security_blob.is_empty() {
                step_state
            } else {
                let final_step = provider.next_token(&response.security_blob)?;
                if !final_step.token.is_empty() {
                    return Err(ClientError::Protocol(
                        "authentication provider produced another token after STATUS_SUCCESS",
                    ));
                }
                final_step.state
            };

            if final_state != AuthState::Complete {
                return Err(ClientError::Protocol(
                    "server completed SESSION_SETUP before authentication provider completed",
                ));
            }
            if session_id == 0 {
                return Err(ClientError::Protocol(
                    "successful SESSION_SETUP response has a zero SessionId",
                ));
            }

            let session_key = provider.take_session_key();
            if mechanism != AuthMechanism::Anonymous && session_key.is_none() {
                return Err(ClientError::Protocol(
                    "authenticated session completed without a session key",
                ));
            }

            return Ok(SessionConnection {
                connection: self,
                session_id,
                session_flags: response.session_flags,
                mechanism,
                session_key,
            });
        }

        Err(ClientError::Protocol(
            "SESSION_SETUP exceeded the configured authentication round limit",
        ))
    }
}

fn validate_session_id(current: u64, received: u64) -> Result<(), ClientError> {
    if current != 0 && received != current {
        return Err(ClientError::Protocol(
            "server changed SessionId during SESSION_SETUP",
        ));
    }
    Ok(())
}

fn update_preauth(hash: &mut Option<PreauthIntegrityHash>, message: &[u8]) {
    if let Some(hash) = hash.as_mut() {
        hash.update(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_must_remain_stable_after_assignment() {
        assert!(validate_session_id(0, 7).is_ok());
        assert!(validate_session_id(7, 7).is_ok());
        assert!(validate_session_id(7, 8).is_err());
    }
}
