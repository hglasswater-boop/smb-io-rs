use smb_io_wire::{
    Dialect, NegotiateContext, NegotiateRequest, NegotiateResponse, Smb2Header, StatusField,
    capabilities, context_type, preauth_hash_algorithm, security_mode,
};

use crate::{ClientError, MessageIdAllocator, PreauthIntegrityHash, Transport};

#[derive(Debug, Clone)]
pub struct NegotiateConfig {
    pub dialects: Vec<Dialect>,
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    /// Caller-provided random salt for the SMB 3.1.1 preauthentication context.
    pub preauth_salt: Vec<u8>,
    pub credit_request: u16,
}

impl NegotiateConfig {
    pub fn modern(client_guid: [u8; 16], preauth_salt: Vec<u8>) -> Self {
        Self {
            dialects: vec![
                Dialect::Smb202,
                Dialect::Smb210,
                Dialect::Smb300,
                Dialect::Smb302,
                Dialect::Smb311,
            ],
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: capabilities::LARGE_MTU,
            client_guid,
            preauth_salt,
            credit_request: 64,
        }
    }

    fn request(&self) -> Result<NegotiateRequest, ClientError> {
        let contexts = if self.dialects.contains(&Dialect::Smb311) {
            if self.preauth_salt.is_empty() {
                return Err(ClientError::Protocol(
                    "SMB 3.1.1 negotiation requires a non-empty preauth salt",
                ));
            }
            vec![NegotiateContext::preauth_sha512(self.preauth_salt.clone())?]
        } else {
            Vec::new()
        };
        Ok(NegotiateRequest {
            security_mode: self.security_mode,
            capabilities: self.capabilities,
            client_guid: self.client_guid,
            dialects: self.dialects.clone(),
            contexts,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedParameters {
    pub dialect: Dialect,
    pub security_mode: u16,
    pub capabilities: u32,
    pub server_guid: [u8; 16],
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub initial_credits: u16,
}

impl NegotiatedParameters {
    pub fn signing_enabled(&self) -> bool {
        self.security_mode & security_mode::SIGNING_ENABLED != 0
    }

    pub fn signing_required(&self) -> bool {
        self.security_mode & security_mode::SIGNING_REQUIRED != 0
    }
}

pub struct Connection<T> {
    transport: T,
    message_ids: MessageIdAllocator,
    negotiated: Option<NegotiatedParameters>,
    preauth_hash: Option<PreauthIntegrityHash>,
}

impl<T> Connection<T>
where
    T: Transport,
{
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            message_ids: MessageIdAllocator::new(),
            negotiated: None,
            preauth_hash: None,
        }
    }

    pub fn negotiated(&self) -> Option<&NegotiatedParameters> {
        self.negotiated.as_ref()
    }

    pub fn preauth_hash(&self) -> Option<&PreauthIntegrityHash> {
        self.preauth_hash.as_ref()
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub async fn negotiate(
        &mut self,
        config: &NegotiateConfig,
    ) -> Result<&NegotiatedParameters, ClientError> {
        if self.negotiated.is_some() {
            return Err(ClientError::Protocol("SMB connection is already negotiated"));
        }

        let request = config.request()?;
        let message_id = self.message_ids.allocate(0)?;
        let request_message = request.encode_message(message_id, config.credit_request)?;

        let advertised_311 = config.dialects.contains(&Dialect::Smb311);
        let mut preauth = advertised_311.then(PreauthIntegrityHash::new);
        if let Some(hash) = preauth.as_mut() {
            hash.update(&request_message);
        }

        self.transport.send_message(&request_message).await?;
        let response_message = self.transport.receive_message().await?;

        let response_header = Smb2Header::decode(&response_message)?;
        if response_header.message_id != message_id {
            return Err(ClientError::Protocol(
                "NEGOTIATE response MessageId does not match request",
            ));
        }
        match response_header.status {
            StatusField::Status(0) => {}
            StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol("NEGOTIATE response used request header form"));
            }
        }

        let response = NegotiateResponse::decode_message(&response_message)?;
        if !config.dialects.contains(&response.dialect) {
            return Err(ClientError::Protocol(
                "server selected a dialect that was not offered",
            ));
        }

        let preauth_hash = if response.dialect == Dialect::Smb311 {
            validate_server_preauth_sha512(&response.contexts)?;
            let mut hash = preauth.ok_or(ClientError::Protocol(
                "SMB 3.1.1 selected without a client preauth hash",
            ))?;
            hash.update(&response_message);
            Some(hash)
        } else {
            None
        };

        let parameters = NegotiatedParameters {
            dialect: response.dialect,
            security_mode: response.security_mode,
            capabilities: response.capabilities,
            server_guid: response.server_guid,
            max_transact_size: response.max_transact_size,
            max_read_size: response.max_read_size,
            max_write_size: response.max_write_size,
            initial_credits: response.header.credits,
        };
        if parameters.max_transact_size == 0
            || parameters.max_read_size == 0
            || parameters.max_write_size == 0
        {
            return Err(ClientError::Protocol(
                "server negotiated a zero SMB operation size limit",
            ));
        }

        self.preauth_hash = preauth_hash;
        self.negotiated = Some(parameters);
        Ok(self.negotiated.as_ref().expect("negotiated parameters just set"))
    }
}

fn validate_server_preauth_sha512(contexts: &[NegotiateContext]) -> Result<(), ClientError> {
    let context = contexts
        .iter()
        .find(|context| context.context_type == context_type::PREAUTH_INTEGRITY_CAPABILITIES)
        .ok_or(ClientError::Protocol(
            "SMB 3.1.1 response omitted preauth integrity capabilities",
        ))?;
    if context.data.len() < 6 {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 preauth integrity context is truncated",
        ));
    }
    let algorithm_count = u16::from_le_bytes([context.data[0], context.data[1]]) as usize;
    let salt_len = u16::from_le_bytes([context.data[2], context.data[3]]) as usize;
    if algorithm_count == 0 {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 server returned no preauth hash algorithm",
        ));
    }
    let algorithms_len = algorithm_count
        .checked_mul(2)
        .ok_or(ClientError::Protocol("preauth algorithm list overflow"))?;
    let required = 4usize
        .checked_add(algorithms_len)
        .and_then(|value| value.checked_add(salt_len))
        .ok_or(ClientError::Protocol("preauth context length overflow"))?;
    if context.data.len() < required {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 preauth integrity context length is invalid",
        ));
    }

    let has_sha512 = context.data[4..4 + algorithms_len]
        .chunks_exact(2)
        .any(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) == preauth_hash_algorithm::SHA_512);
    if !has_sha512 {
        return Err(ClientError::Protocol(
            "server did not offer SHA-512 for SMB 3.1.1 preauth integrity",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_config_offers_all_initial_dialects() {
        let config = NegotiateConfig::modern([1; 16], vec![2; 32]);
        assert_eq!(config.dialects.first(), Some(&Dialect::Smb202));
        assert_eq!(config.dialects.last(), Some(&Dialect::Smb311));
        let request = config.request().unwrap();
        assert_eq!(request.contexts.len(), 1);
    }

    #[test]
    fn sha512_server_context_is_accepted() {
        let context = NegotiateContext::preauth_sha512(vec![0x11; 32]).unwrap();
        validate_server_preauth_sha512(&[context]).unwrap();
    }

    #[test]
    fn missing_sha512_is_rejected() {
        let context = NegotiateContext {
            context_type: context_type::PREAUTH_INTEGRITY_CAPABILITIES,
            data: vec![1, 0, 0, 0, 2, 0],
        };
        assert!(validate_server_preauth_sha512(&[context]).is_err());
    }
}
