use smb_io_wire::{
    Dialect, NegotiateContext, NegotiateRequest, NegotiateResponse, Smb2Header, StatusField,
    capabilities, context_type, preauth_hash_algorithm, security_mode,
};

use crate::{
    ClientError, CreditManager, MessageIdAllocator, PreauthIntegrityHash, SigningAlgorithm,
    Transport,
};

#[derive(Debug, Clone)]
pub struct NegotiateConfig {
    pub dialects: Vec<Dialect>,
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    /// Caller-provided random salt for the SMB 3.1.1 preauthentication context.
    pub preauth_salt: Vec<u8>,
    /// SMB 3.1.1 signing algorithms in preference order. Unsupported algorithms must not be
    /// advertised. Pre-SMB3.1.1 dialects use their fixed signing algorithm regardless of this list.
    pub signing_algorithms: Vec<SigningAlgorithm>,
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
            signing_algorithms: vec![SigningAlgorithm::AesCmac, SigningAlgorithm::HmacSha256],
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
            let mut contexts = vec![NegotiateContext::preauth_sha512(self.preauth_salt.clone())?];
            if !self.signing_algorithms.is_empty() {
                contexts.push(signing_capabilities_context(&self.signing_algorithms)?);
            }
            contexts
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
    pub signing_algorithm: SigningAlgorithm,
    pub require_signing: bool,
}

impl NegotiatedParameters {
    pub fn signing_enabled(&self) -> bool {
        self.security_mode & security_mode::SIGNING_ENABLED != 0
    }

    pub fn signing_required(&self) -> bool {
        self.require_signing
    }

    pub fn supports_multi_credit(&self) -> bool {
        self.dialect != Dialect::Smb202 && self.capabilities & capabilities::LARGE_MTU != 0
    }
}

pub struct Connection<T> {
    pub(crate) transport: T,
    pub(crate) message_ids: MessageIdAllocator,
    pub(crate) negotiated: Option<NegotiatedParameters>,
    pub(crate) preauth_hash: Option<PreauthIntegrityHash>,
    pub(crate) credits: Option<CreditManager>,
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
            credits: None,
        }
    }

    pub fn negotiated(&self) -> Option<&NegotiatedParameters> {
        self.negotiated.as_ref()
    }

    pub fn preauth_hash(&self) -> Option<&PreauthIntegrityHash> {
        self.preauth_hash.as_ref()
    }

    pub fn available_credits(&self) -> Option<u32> {
        self.credits.as_ref().map(CreditManager::available)
    }

    pub(crate) fn single_request_credit_charge(&self) -> Result<u16, ClientError> {
        let negotiated = self.negotiated.as_ref().ok_or(ClientError::Protocol(
            "credit calculation requires negotiated parameters",
        ))?;
        Ok(if negotiated.supports_multi_credit() { 1 } else { 0 })
    }

    pub(crate) fn reserve_credits(
        &mut self,
        credit_charge: u16,
        minimum_credit_request: u16,
    ) -> Result<u16, ClientError> {
        let credits = self.credits.as_mut().ok_or(ClientError::Protocol(
            "SMB credit window is not initialized",
        ))?;
        credits.reserve(credit_charge)?;
        Ok(credits.request_hint(minimum_credit_request))
    }

    pub(crate) fn grant_credits(&mut self, credit_response: u16) -> Result<(), ClientError> {
        let credits = self.credits.as_mut().ok_or(ClientError::Protocol(
            "SMB credit window is not initialized",
        ))?;
        credits.grant(credit_response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub async fn negotiate(
        &mut self,
        config: &NegotiateConfig,
    ) -> Result<&NegotiatedParameters, ClientError> {
        if self.negotiated.is_some() {
            return Err(ClientError::Protocol(
                "SMB connection is already negotiated",
            ));
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
                return Err(ClientError::Protocol(
                    "NEGOTIATE response used request header form",
                ));
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

        let signing_algorithm = select_signing_algorithm(
            response.dialect,
            &response.contexts,
            &config.signing_algorithms,
        )?;
        let require_signing = response.security_mode & security_mode::SIGNING_REQUIRED != 0
            || config.security_mode & security_mode::SIGNING_REQUIRED != 0;

        let parameters = NegotiatedParameters {
            dialect: response.dialect,
            security_mode: response.security_mode,
            capabilities: response.capabilities,
            server_guid: response.server_guid,
            max_transact_size: response.max_transact_size,
            max_read_size: response.max_read_size,
            max_write_size: response.max_write_size,
            initial_credits: response.header.credits,
            signing_algorithm,
            require_signing,
        };
        if parameters.max_transact_size == 0
            || parameters.max_read_size == 0
            || parameters.max_write_size == 0
        {
            return Err(ClientError::Protocol(
                "server negotiated a zero SMB operation size limit",
            ));
        }

        let credits = CreditManager::new(parameters.initial_credits)?;
        self.preauth_hash = preauth_hash;
        self.credits = Some(credits);
        self.negotiated = Some(parameters);
        self.negotiated.as_ref().ok_or(ClientError::Protocol(
            "failed to store negotiated parameters",
        ))
    }
}

fn signing_capabilities_context(
    algorithms: &[SigningAlgorithm],
) -> Result<NegotiateContext, ClientError> {
    let count = u16::try_from(algorithms.len())
        .map_err(|_| ClientError::Protocol("too many SMB signing algorithms"))?;
    if count == 0 {
        return Err(ClientError::Protocol(
            "SMB signing capabilities must contain an algorithm",
        ));
    }
    if algorithms.contains(&SigningAlgorithm::AesGmac) {
        return Err(ClientError::Protocol(
            "AES-GMAC must not be advertised until it is implemented",
        ));
    }

    let mut data = Vec::with_capacity(2 + algorithms.len() * 2);
    data.extend_from_slice(&count.to_le_bytes());
    for algorithm in algorithms {
        data.extend_from_slice(&(*algorithm as u16).to_le_bytes());
    }
    Ok(NegotiateContext {
        context_type: context_type::SIGNING_CAPABILITIES,
        data,
    })
}

fn select_signing_algorithm(
    dialect: Dialect,
    contexts: &[NegotiateContext],
    offered: &[SigningAlgorithm],
) -> Result<SigningAlgorithm, ClientError> {
    match dialect {
        Dialect::Smb202 | Dialect::Smb210 => return Ok(SigningAlgorithm::HmacSha256),
        Dialect::Smb300 | Dialect::Smb302 => return Ok(SigningAlgorithm::AesCmac),
        Dialect::Smb311 => {}
    }

    let mut matches = contexts
        .iter()
        .filter(|context| context.context_type == context_type::SIGNING_CAPABILITIES);
    let Some(context) = matches.next() else {
        return Ok(SigningAlgorithm::AesCmac);
    };
    if matches.next().is_some() {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 response contains duplicate signing capabilities",
        ));
    }
    if context.data.len() < 4 {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 signing capabilities are truncated",
        ));
    }
    let count = usize::from(u16::from_le_bytes([context.data[0], context.data[1]]));
    if count != 1 {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 server must select exactly one signing algorithm",
        ));
    }
    let selected =
        SigningAlgorithm::try_from(u16::from_le_bytes([context.data[2], context.data[3]]))?;
    if !offered.contains(&selected) {
        return Err(ClientError::Protocol(
            "server selected an SMB signing algorithm that was not offered",
        ));
    }
    Ok(selected)
}

fn validate_server_preauth_sha512(contexts: &[NegotiateContext]) -> Result<(), ClientError> {
    let mut matches = contexts
        .iter()
        .filter(|context| context.context_type == context_type::PREAUTH_INTEGRITY_CAPABILITIES);
    let context = matches.next().ok_or(ClientError::Protocol(
        "SMB 3.1.1 response omitted preauth integrity capabilities",
    ))?;
    if matches.next().is_some() {
        return Err(ClientError::Protocol(
            "SMB 3.1.1 response contains duplicate preauth integrity capabilities",
        ));
    }
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
    fn modern_config_offers_all_initial_dialects_and_signing_context() {
        let config = NegotiateConfig::modern([1; 16], vec![2; 32]);
        assert_eq!(config.dialects.first(), Some(&Dialect::Smb202));
        assert_eq!(config.dialects.last(), Some(&Dialect::Smb311));
        let request = config.request().unwrap();
        assert_eq!(request.contexts.len(), 2);
        assert!(
            request
                .contexts
                .iter()
                .any(|context| context.context_type == context_type::SIGNING_CAPABILITIES)
        );
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

    #[test]
    fn smb311_defaults_to_cmac_when_server_omits_signing_context() {
        assert_eq!(
            select_signing_algorithm(
                Dialect::Smb311,
                &[],
                &[SigningAlgorithm::AesCmac, SigningAlgorithm::HmacSha256]
            )
            .unwrap(),
            SigningAlgorithm::AesCmac
        );
    }

    #[test]
    fn smb311_accepts_offered_signing_algorithm() {
        let context = NegotiateContext {
            context_type: context_type::SIGNING_CAPABILITIES,
            data: vec![1, 0, 0, 0],
        };
        assert_eq!(
            select_signing_algorithm(
                Dialect::Smb311,
                &[context],
                &[SigningAlgorithm::AesCmac, SigningAlgorithm::HmacSha256]
            )
            .unwrap(),
            SigningAlgorithm::HmacSha256
        );
    }
}
