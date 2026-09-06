use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use md4::{Digest as _, Md4};
use md5::Md5;
use zeroize::{Zeroize, Zeroizing};

use crate::spnego::{encode_neg_token_init_ntlm, encode_neg_token_resp_ntlm, extract_ntlm_token};
use crate::{AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep, SecretBytes};

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_MESSAGE_TYPE: u32 = 1;
const CHALLENGE_MESSAGE_TYPE: u32 = 2;
const AUTHENTICATE_MESSAGE_TYPE: u32 = 3;
const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;

pub mod flags {
    pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
    pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;
    pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    pub const NEGOTIATE_56: u32 = 0x8000_0000;
}

mod av_id {
    pub const EOL: u16 = 0;
    pub const FLAGS: u16 = 6;
    pub const TIMESTAMP: u16 = 7;
}

const MSV_AV_FLAGS_MIC_PRESENT: u32 = 0x0000_0002;
const CLIENT_NEGOTIATE_FLAGS: u32 = flags::NEGOTIATE_UNICODE
    | flags::REQUEST_TARGET
    | flags::NEGOTIATE_NTLM
    | flags::NEGOTIATE_ALWAYS_SIGN
    | flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
    | flags::NEGOTIATE_TARGET_INFO
    | flags::NEGOTIATE_128
    | flags::NEGOTIATE_56;
const REQUIRED_CHALLENGE_FLAGS: u32 =
    flags::NEGOTIATE_UNICODE | flags::NEGOTIATE_NTLM | flags::NEGOTIATE_EXTENDED_SESSIONSECURITY;

/// NTLM credentials. Password memory is zeroized on drop and never rendered by `Debug`.
pub struct NtlmCredentials {
    username: String,
    domain: String,
    workstation: String,
    password: Zeroizing<String>,
}

impl NtlmCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            domain: String::new(),
            workstation: String::new(),
            password: Zeroizing::new(password.into()),
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn with_workstation(mut self, workstation: impl Into<String>) -> Self {
        self.workstation = workstation.into();
        self
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn workstation(&self) -> &str {
        &self.workstation
    }
}

impl fmt::Debug for NtlmCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmCredentials")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("workstation", &self.workstation)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
enum ProviderState {
    New,
    NegotiateSent(Vec<u8>),
    Complete,
}

/// Connection-oriented NTLMv2 provider transported through SPNEGO.
pub struct NtlmV2Provider {
    credentials: NtlmCredentials,
    state: ProviderState,
    session_key: Option<SecretBytes>,
}

impl NtlmV2Provider {
    pub fn new(credentials: NtlmCredentials) -> Self {
        Self {
            credentials,
            state: ProviderState::New,
            session_key: None,
        }
    }
}

impl AuthProvider for NtlmV2Provider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::NtlmV2
    }

    fn initial_token(&mut self) -> Result<AuthStep, AuthError> {
        if !matches!(self.state, ProviderState::New) {
            return Err(AuthError::InvalidState(
                "NTLM NEGOTIATE token has already been emitted",
            ));
        }
        if self.credentials.username.is_empty() {
            return Err(AuthError::Failed("NTLM username must not be empty"));
        }

        let negotiate = build_negotiate_message();
        let token = encode_neg_token_init_ntlm(&negotiate);
        self.state = ProviderState::NegotiateSent(negotiate);
        Ok(AuthStep {
            token,
            state: AuthState::Continue,
        })
    }

    fn next_token(&mut self, server_token: &[u8]) -> Result<AuthStep, AuthError> {
        if matches!(self.state, ProviderState::Complete) {
            return Ok(AuthStep {
                token: Vec::new(),
                state: AuthState::Complete,
            });
        }

        let negotiate = match &self.state {
            ProviderState::NegotiateSent(message) => message.clone(),
            ProviderState::New => {
                return Err(AuthError::InvalidState(
                    "NTLM CHALLENGE arrived before NEGOTIATE was sent",
                ));
            }
            ProviderState::Complete => unreachable!(),
        };
        let challenge_bytes = extract_ntlm_token(server_token)?.to_vec();
        let challenge = parse_challenge_message(&challenge_bytes)?;
        let (authenticate, session_key) = build_authenticate_message(
            &self.credentials,
            &negotiate,
            &challenge_bytes,
            &challenge,
        )?;

        self.session_key = Some(SecretBytes::new(session_key.to_vec()));
        self.state = ProviderState::Complete;
        Ok(AuthStep {
            token: encode_neg_token_resp_ntlm(&authenticate),
            state: AuthState::Complete,
        })
    }

    fn take_session_key(&mut self) -> Option<SecretBytes> {
        self.session_key.take()
    }
}

#[derive(Debug)]
struct ChallengeMessage {
    flags: u32,
    server_challenge: [u8; 8],
    target_info: Vec<u8>,
}

#[derive(Debug, Default)]
struct TargetInfoMeta {
    timestamp: Option<u64>,
    mic_required: bool,
}

struct ComputedResponse {
    lm_response: Vec<u8>,
    nt_response: Vec<u8>,
    session_base_key: Zeroizing<[u8; 16]>,
}

fn build_negotiate_message() -> Vec<u8> {
    let mut message = vec![0u8; 32];
    message[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    put_u32(&mut message, 8, NEGOTIATE_MESSAGE_TYPE);
    put_u32(&mut message, 12, CLIENT_NEGOTIATE_FLAGS);
    // DomainNameFields and WorkstationFields remain empty. They are supplied in AUTHENTICATE.
    message
}

fn parse_challenge_message(message: &[u8]) -> Result<ChallengeMessage, AuthError> {
    if message.len() < 48 {
        return Err(AuthError::InvalidToken("NTLM CHALLENGE is truncated"));
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

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&message[24..32]);
    let target_info = read_security_buffer(message, 40)?.to_vec();
    validate_target_info(&target_info)?;

    Ok(ChallengeMessage {
        flags: challenge_flags,
        server_challenge,
        target_info,
    })
}

fn build_authenticate_message(
    credentials: &NtlmCredentials,
    negotiate_message: &[u8],
    challenge_message: &[u8],
    challenge: &ChallengeMessage,
) -> Result<(Vec<u8>, [u8; 16]), AuthError> {
    let meta = validate_target_info(&challenge.target_info)?;
    let timestamp = match meta.timestamp {
        Some(value) => value,
        None => current_filetime()?,
    };
    let mut client_challenge = [0u8; 8];
    random_fill(&mut client_challenge)
        .map_err(|_| AuthError::Failed("operating-system random source failed"))?;

    let computed = compute_ntlmv2_response(credentials, challenge, timestamp, client_challenge)?;
    let negotiated_flags = challenge.flags & CLIENT_NEGOTIATE_FLAGS;
    let include_mic = meta.mic_required;
    let header_len = if include_mic { 88usize } else { 72usize };
    let mut message = vec![0u8; header_len];
    message[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    put_u32(&mut message, 8, AUTHENTICATE_MESSAGE_TYPE);
    put_u32(&mut message, 60, negotiated_flags);
    // Bytes 64..72 are the optional Version slot. We deliberately leave them zero and do not
    // negotiate NTLMSSP_NEGOTIATE_VERSION. If MIC is present it occupies bytes 72..88.

    let domain = utf16le(&credentials.domain);
    let username = utf16le(&credentials.username);
    let workstation = utf16le(&credentials.workstation);

    append_security_buffer(&mut message, 12, &computed.lm_response)?;
    append_security_buffer(&mut message, 20, &computed.nt_response)?;
    append_security_buffer(&mut message, 28, &domain)?;
    append_security_buffer(&mut message, 36, &username)?;
    append_security_buffer(&mut message, 44, &workstation)?;
    set_security_buffer(&mut message, 52, 0, message.len())?;

    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(computed.session_base_key.as_ref());

    if include_mic {
        let mut transcript =
            Vec::with_capacity(negotiate_message.len() + challenge_message.len() + message.len());
        transcript.extend_from_slice(negotiate_message);
        transcript.extend_from_slice(challenge_message);
        transcript.extend_from_slice(&message);
        let mic = hmac_md5(&session_key, &transcript)?;
        message[72..88].copy_from_slice(&mic);
    }

    Ok((message, session_key))
}

fn compute_ntlmv2_response(
    credentials: &NtlmCredentials,
    challenge: &ChallengeMessage,
    timestamp: u64,
    client_challenge: [u8; 8],
) -> Result<ComputedResponse, AuthError> {
    let password_utf16 = Zeroizing::new(utf16le(credentials.password.as_str()));
    let nt_digest = Md4::digest(password_utf16.as_slice());
    let mut nt_hash = Zeroizing::new([0u8; 16]);
    nt_hash.copy_from_slice(&nt_digest);

    let identity = format!(
        "{}{}",
        credentials.username.to_uppercase(),
        credentials.domain
    );
    let identity_utf16 = utf16le(&identity);
    let response_key = Zeroizing::new(hmac_md5(nt_hash.as_ref(), &identity_utf16)?);

    let mut temp = Vec::with_capacity(32 + challenge.target_info.len());
    temp.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0, 0, 0]);
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(&client_challenge);
    temp.extend_from_slice(&[0u8; 4]);
    temp.extend_from_slice(&challenge.target_info);
    temp.extend_from_slice(&[0u8; 4]);

    let mut proof_input = Vec::with_capacity(8 + temp.len());
    proof_input.extend_from_slice(&challenge.server_challenge);
    proof_input.extend_from_slice(&temp);
    let nt_proof = hmac_md5(response_key.as_ref(), &proof_input)?;

    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&temp);

    let lm_response = if challenge.target_info.is_empty() {
        let mut input = [0u8; 16];
        input[0..8].copy_from_slice(&challenge.server_challenge);
        input[8..16].copy_from_slice(&client_challenge);
        let proof = hmac_md5(response_key.as_ref(), &input)?;
        let mut response = Vec::with_capacity(24);
        response.extend_from_slice(&proof);
        response.extend_from_slice(&client_challenge);
        response
    } else {
        // Microsoft clients suppress LMv2 when target information is available.
        vec![0u8; 24]
    };

    let session_base_key = Zeroizing::new(hmac_md5(response_key.as_ref(), &nt_proof)?);
    nt_hash.zeroize();

    Ok(ComputedResponse {
        lm_response,
        nt_response,
        session_base_key,
    })
}

fn validate_target_info(target_info: &[u8]) -> Result<TargetInfoMeta, AuthError> {
    if target_info.is_empty() {
        return Ok(TargetInfoMeta::default());
    }

    let mut meta = TargetInfoMeta::default();
    let mut offset = 0usize;
    let mut saw_eol = false;
    while offset < target_info.len() {
        if target_info.len() - offset < 4 {
            return Err(AuthError::InvalidToken("truncated NTLM TargetInfo AV pair"));
        }
        let id = u16::from_le_bytes([target_info[offset], target_info[offset + 1]]);
        let length = usize::from(u16::from_le_bytes([
            target_info[offset + 2],
            target_info[offset + 3],
        ]));
        offset += 4;
        let end = offset
            .checked_add(length)
            .ok_or(AuthError::InvalidToken("NTLM TargetInfo length overflow"))?;
        if end > target_info.len() {
            return Err(AuthError::InvalidToken(
                "NTLM TargetInfo AV pair is truncated",
            ));
        }
        let value = &target_info[offset..end];
        match id {
            av_id::EOL => {
                if length != 0 {
                    return Err(AuthError::InvalidToken("MsvAvEOL must have zero length"));
                }
                if end != target_info.len() {
                    return Err(AuthError::InvalidToken("data follows MsvAvEOL"));
                }
                saw_eol = true;
            }
            av_id::FLAGS if length == 4 => {
                let value = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                meta.mic_required = value & MSV_AV_FLAGS_MIC_PRESENT != 0;
            }
            av_id::TIMESTAMP if length == 8 => {
                meta.timestamp = Some(u64::from_le_bytes([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ]));
            }
            av_id::FLAGS => {
                return Err(AuthError::InvalidToken("MsvAvFlags has invalid length"));
            }
            av_id::TIMESTAMP => {
                return Err(AuthError::InvalidToken("MsvAvTimestamp has invalid length"));
            }
            _ => {}
        }
        offset = end;
        if saw_eol {
            break;
        }
    }
    if !saw_eol {
        return Err(AuthError::InvalidToken(
            "NTLM TargetInfo is missing MsvAvEOL",
        ));
    }
    Ok(meta)
}

fn current_filetime() -> Result<u64, AuthError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Failed("system clock predates the Unix epoch"))?;
    let ticks_from_unix = elapsed
        .as_secs()
        .checked_mul(10_000_000)
        .and_then(|ticks| ticks.checked_add(u64::from(elapsed.subsec_nanos()) / 100))
        .ok_or(AuthError::Failed("system time overflow"))?;
    WINDOWS_EPOCH_OFFSET_100NS
        .checked_add(ticks_from_unix)
        .ok_or(AuthError::Failed("Windows FILETIME overflow"))
}

fn read_security_buffer(message: &[u8], field_offset: usize) -> Result<&[u8], AuthError> {
    if field_offset
        .checked_add(8)
        .is_none_or(|end| end > message.len())
    {
        return Err(AuthError::InvalidToken("truncated NTLM security buffer"));
    }
    let length = usize::from(u16::from_le_bytes([
        message[field_offset],
        message[field_offset + 1],
    ]));
    let max_length = usize::from(u16::from_le_bytes([
        message[field_offset + 2],
        message[field_offset + 3],
    ]));
    if max_length < length {
        return Err(AuthError::InvalidToken(
            "NTLM security buffer max length is smaller than its length",
        ));
    }
    if length == 0 {
        return Ok(&[]);
    }
    let start = usize::try_from(read_u32(message, field_offset + 4)?)
        .map_err(|_| AuthError::InvalidToken("NTLM security buffer offset overflow"))?;
    let end = start.checked_add(length).ok_or(AuthError::InvalidToken(
        "NTLM security buffer length overflow",
    ))?;
    message.get(start..end).ok_or(AuthError::InvalidToken(
        "NTLM security buffer points outside message",
    ))
}

fn append_security_buffer(
    message: &mut Vec<u8>,
    field_offset: usize,
    value: &[u8],
) -> Result<(), AuthError> {
    let payload_offset = message.len();
    set_security_buffer(message, field_offset, value.len(), payload_offset)?;
    message.extend_from_slice(value);
    Ok(())
}

fn set_security_buffer(
    message: &mut [u8],
    field_offset: usize,
    length: usize,
    payload_offset: usize,
) -> Result<(), AuthError> {
    let length = u16::try_from(length)
        .map_err(|_| AuthError::Failed("NTLM payload field exceeds 65535 bytes"))?;
    let payload_offset = u32::try_from(payload_offset)
        .map_err(|_| AuthError::Failed("NTLM message exceeds 4 GiB"))?;
    if field_offset
        .checked_add(8)
        .is_none_or(|end| end > message.len())
    {
        return Err(AuthError::Failed(
            "NTLM security-buffer header is truncated",
        ));
    }
    message[field_offset..field_offset + 2].copy_from_slice(&length.to_le_bytes());
    message[field_offset + 2..field_offset + 4].copy_from_slice(&length.to_le_bytes());
    message[field_offset + 4..field_offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
    Ok(())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, AuthError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(AuthError::InvalidToken("truncated NTLM u32 field"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn utf16le(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() * 2);
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn hmac_md5(key: &[u8], input: &[u8]) -> Result<[u8; 16], AuthError> {
    let mut mac = Hmac::<Md5>::new_from_slice(key)
        .map_err(|_| AuthError::Failed("failed to initialize HMAC-MD5"))?;
    mac.update(input);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_credentials() -> NtlmCredentials {
        NtlmCredentials::new("User", "Password")
            .with_domain("Domain")
            .with_workstation("COMPUTER")
    }

    fn spec_target_info() -> Vec<u8> {
        vec![
            0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00,
            0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn ntowfv2_matches_ms_nlmp_vector() {
        let credentials = spec_credentials();
        let password_utf16 = Zeroizing::new(utf16le(credentials.password.as_str()));
        let nt_digest = Md4::digest(password_utf16.as_slice());
        let identity = utf16le("USERDomain");
        let response_key = hmac_md5(&nt_digest, &identity).unwrap();
        assert_eq!(
            response_key,
            [
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
                0x2e, 0x3f,
            ]
        );
    }

    #[test]
    fn ntlmv2_proof_and_session_key_match_ms_nlmp_vector() {
        let credentials = spec_credentials();
        let challenge = ChallengeMessage {
            flags: CLIENT_NEGOTIATE_FLAGS,
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_info: spec_target_info(),
        };
        let response = compute_ntlmv2_response(
            &credentials,
            &challenge,
            0,
            [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa],
        )
        .unwrap();
        assert_eq!(
            &response.nt_response[..16],
            &[
                0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
                0x6a, 0x1c,
            ]
        );
        assert_eq!(
            response.session_base_key.as_ref(),
            &[
                0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9,
                0x5c, 0xa3,
            ]
        );
        assert_eq!(response.lm_response, vec![0u8; 24]);
    }

    #[test]
    fn malformed_target_info_is_rejected() {
        assert!(validate_target_info(&[1, 0, 8, 0, 1, 2]).is_err());
    }

    #[test]
    fn credentials_debug_redacts_password() {
        let credentials = NtlmCredentials::new("alice", "super-secret").with_domain("LAB");
        let rendered = format!("{credentials:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret"));
    }
}
