use crate::ntlm::flags;
use crate::spnego::{encode_neg_token_init_ntlm, encode_neg_token_resp_ntlm, extract_ntlm_token};
use crate::{AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep, SecretBytes};

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_MESSAGE_TYPE: u32 = 1;
const CHALLENGE_MESSAGE_TYPE: u32 = 2;
const AUTHENTICATE_MESSAGE_TYPE: u32 = 3;
const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;

const CLIENT_FLAGS: u32 = flags::NEGOTIATE_UNICODE
    | flags::REQUEST_TARGET
    | flags::NEGOTIATE_NTLM
    | flags::NEGOTIATE_ALWAYS_SIGN
    | flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
    | flags::NEGOTIATE_TARGET_INFO
    | flags::NEGOTIATE_128
    | flags::NEGOTIATE_56
    | NEGOTIATE_ANONYMOUS;

const REQUIRED_CHALLENGE_FLAGS: u32 =
    flags::NEGOTIATE_UNICODE | flags::NEGOTIATE_NTLM | flags::NEGOTIATE_EXTENDED_SESSIONSECURITY;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProviderState {
    New,
    NegotiateSent,
    Complete,
}

/// NTLM NullSession provider transported through SPNEGO.
///
/// MS-NLMP defines anonymous authentication as an NTLM AUTHENTICATE message with an empty user,
/// an empty NT challenge response, and a one-byte zero LM challenge response. Anonymous sessions
/// intentionally have no usable SMB signing/session key.
#[derive(Debug)]
pub struct AnonymousNtlmProvider {
    state: ProviderState,
}

impl AnonymousNtlmProvider {
    pub const fn new() -> Self {
        Self {
            state: ProviderState::New,
        }
    }
}

impl Default for AnonymousNtlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for AnonymousNtlmProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Anonymous
    }

    fn initial_token(&mut self) -> Result<AuthStep, AuthError> {
        if self.state != ProviderState::New {
            return Err(AuthError::InvalidState(
                "anonymous NTLM NEGOTIATE token has already been emitted",
            ));
        }
        self.state = ProviderState::NegotiateSent;
        Ok(AuthStep {
            token: encode_neg_token_init_ntlm(&build_negotiate_message()),
            state: AuthState::Continue,
        })
    }

    fn next_token(&mut self, server_token: &[u8]) -> Result<AuthStep, AuthError> {
        match self.state {
            ProviderState::New => Err(AuthError::InvalidState(
                "anonymous NTLM CHALLENGE arrived before NEGOTIATE was sent",
            )),
            ProviderState::Complete => Ok(AuthStep {
                token: Vec::new(),
                state: AuthState::Complete,
            }),
            ProviderState::NegotiateSent => {
                let challenge = extract_ntlm_token(server_token)?;
                let challenge_flags = parse_challenge_flags(challenge)?;
                self.state = ProviderState::Complete;
                Ok(AuthStep {
                    token: encode_neg_token_resp_ntlm(&build_authenticate_message(challenge_flags)?),
                    state: AuthState::Complete,
                })
            }
        }
    }

    fn take_session_key(&mut self) -> Option<SecretBytes> {
        None
    }
}

fn build_negotiate_message() -> Vec<u8> {
    let mut message = vec![0u8; 32];
    message[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    put_u32(&mut message, 8, NEGOTIATE_MESSAGE_TYPE);
    put_u32(&mut message, 12, CLIENT_FLAGS);
    message
}

fn parse_challenge_flags(message: &[u8]) -> Result<u32, AuthError> {
    if message.len() < 24 {
        return Err(AuthError::InvalidToken(
            "anonymous NTLM CHALLENGE is truncated",
        ));
    }
    if &message[0..8] != NTLMSSP_SIGNATURE {
        return Err(AuthError::InvalidToken("invalid NTLMSSP signature"));
    }
    if read_u32(message, 8)? != CHALLENGE_MESSAGE_TYPE {
        return Err(AuthError::InvalidToken("expected NTLM CHALLENGE message"));
    }
    let challenge_flags = read_u32(message, 20)?;
    if challenge_flags & REQUIRED_CHALLENGE_FLAGS != REQUIRED_CHALLENGE_FLAGS {
        return Err(AuthError::Unsupported(
            "server NTLM challenge lacks Unicode, NTLM, or extended-session-security support",
        ));
    }
    Ok(challenge_flags)
}

fn build_authenticate_message(challenge_flags: u32) -> Result<Vec<u8>, AuthError> {
    let mut message = vec![0u8; 72];
    message[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    put_u32(&mut message, 8, AUTHENTICATE_MESSAGE_TYPE);
    put_u32(&mut message, 60, challenge_flags & CLIENT_FLAGS);

    // MS-NLMP anonymous special case: LM response is Z(1), NT response and user are empty.
    append_security_buffer(&mut message, 12, &[0])?;
    append_security_buffer(&mut message, 20, &[])?;
    append_security_buffer(&mut message, 28, &[])?;
    append_security_buffer(&mut message, 36, &[])?;
    append_security_buffer(&mut message, 44, &[])?;
    append_security_buffer(&mut message, 52, &[])?;
    Ok(message)
}

fn append_security_buffer(
    message: &mut Vec<u8>,
    field_offset: usize,
    value: &[u8],
) -> Result<(), AuthError> {
    let payload_offset = message.len();
    let length = u16::try_from(value.len())
        .map_err(|_| AuthError::Failed("anonymous NTLM payload exceeds 65535 bytes"))?;
    let payload_offset = u32::try_from(payload_offset)
        .map_err(|_| AuthError::Failed("anonymous NTLM message exceeds 4 GiB"))?;
    let end = field_offset
        .checked_add(8)
        .ok_or(AuthError::Failed("anonymous NTLM security-buffer offset overflow"))?;
    if end > message.len() {
        return Err(AuthError::Failed(
            "anonymous NTLM security-buffer header is truncated",
        ));
    }
    message[field_offset..field_offset + 2].copy_from_slice(&length.to_le_bytes());
    message[field_offset + 2..field_offset + 4].copy_from_slice(&length.to_le_bytes());
    message[field_offset + 4..field_offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, AuthError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(AuthError::InvalidToken("truncated anonymous NTLM u32 field"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_authenticate_uses_null_session_response_shape() {
        let message = build_authenticate_message(CLIENT_FLAGS).unwrap();
        assert_eq!(&message[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32(&message, 8).unwrap(), AUTHENTICATE_MESSAGE_TYPE);
        assert_eq!(u16::from_le_bytes([message[12], message[13]]), 1);
        assert_eq!(u16::from_le_bytes([message[20], message[21]]), 0);
        assert_eq!(u16::from_le_bytes([message[36], message[37]]), 0);
        assert_eq!(message[72], 0);
    }

    #[test]
    fn provider_reports_anonymous_mechanism_and_no_session_key() {
        let mut provider = AnonymousNtlmProvider::new();
        assert_eq!(provider.mechanism(), AuthMechanism::Anonymous);
        assert!(provider.take_session_key().is_none());
    }
}
