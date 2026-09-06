use aes::Aes128;
use cmac::{Cmac, Mac};
use hmac::Hmac;
use sha2::Sha256;
use smb_io_auth::SecretBytes;
use smb_io_wire::{Dialect, SMB2_HEADER_SIZE, Smb2Header, flags};
use subtle::ConstantTimeEq;

use crate::{ClientError, PreauthIntegrityHash};

const SIGNATURE_OFFSET: usize = 48;
const SIGNATURE_SIZE: usize = 16;
const KDF_OUTPUT_BITS: u32 = 128;

/// SMB signing algorithms as assigned by SMB2_SIGNING_CAPABILITIES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]\#[repr(u16)]
pub enum SigningAlgorithm {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002,
}

impl TryFrom<u16> for SigningAlgorithm {
    type Error = ClientError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::HmacSha256),
            0x0001 => Ok(Self::AesCmac),
            0x0002 => Ok(Self::AesGmac),
            _ => Err(ClientError::Protocol("unknown SMB signing algorithm")),
        }
    }
}

/// Per-session signing state. The key is zeroized when this value is dropped.
pub struct SigningState {
    algorithm: SigningAlgorithm,
    key: SecretBytes,
}

impl core::fmt::Debug for SigningState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningState")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SigningState {
    pub fn derive(
        dialect: Dialect,
        negotiated_algorithm: SigningAlgorithm,
        session_key: &SecretBytes,
        preauth_hash: Option<&PreauthIntegrityHash>,
    ) -> Result<Self, ClientError> {
        let normalized = normalize_session_key(session_key);
        let algorithm = match dialect {
            Dialect::Smb202 | Dialect::Smb210 => SigningAlgorithm::HmacSha256,
            Dialect::Smb300 | Dialect::Smb302 => SigningAlgorithm::AesCmac,
            Dialect::Smb311 => negotiated_algorithm,
        };

        if algorithm == SigningAlgorithm::AesGmac {
            return Err(ClientError::Protocol(
                "AES-GMAC signing is not implemented yet",
            ));
        }
        if dialect != Dialect::Smb311 && algorithm != SigningAlgorithm::HmacSha256
            && !matches!(dialect, Dialect::Smb300 | Dialect::Smb302)
        {
            return Err(ClientError::Protocol(
                "invalid SMB signing algorithm for negotiated dialect",
            ));
        }

        let key = match dialect {
            Dialect::Smb202 | Dialect::Smb210 => normalized.to_vec(),
            Dialect::Smb300 | Dialect::Smb302 => sp800_108_kdf_128(
                &normalized,
                b"SMB2AESCMAC\0",
                b"SmbSign\0",
            )?
            .to_vec(),
            Dialect::Smb311 => {
                let preauth = preauth_hash.ok_or(ClientError::Protocol(
                    "SMB 3.1.1 signing requires a preauthentication hash",
                ))?;
                sp800_108_kdf_128(
                    &normalized,
                    b"SMBSigningKey\0",
                    preauth.current(),
                )?
                .to_vec()
            }
        };

        Ok(Self {
            algorithm,
            key: SecretBytes::new(key),
        })
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub fn sign(&self, message: &mut [u8]) -> Result<(), ClientError> {
        ensure_smb2_message(message)?;
        set_signed_flag(message, true);
        message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE].fill(0);
        let signature = self.compute_signature(message)?;
        message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE]
            .copy_from_slice(&signature);
        Ok(())
    }

    pub fn verify(&self, message: &mut [u8]) -> Result<(), ClientError> {
        ensure_smb2_message(message)?;
        let header = Smb2Header::decode(message)?;
        if header.flags & flags::SIGNED == 0 {
            return Err(ClientError::Protocol("SMB message is not signed"));
        }

        let mut received = [0u8; SIGNATURE_SIZE];
        received.copy_from_slice(&message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE]);
        message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE].fill(0);
        let expected = self.compute_signature(message);
        message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE].copy_from_slice(&received);
        let expected = expected?;

        if !bool::from(received.ct_eq(&expected)) {
            return Err(ClientError::Protocol("SMB signature verification failed"));
        }
        Ok(())
    }

    fn compute_signature(&self, message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], ClientError> {
        match self.algorithm {
            SigningAlgorithm::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose())
                    .map_err(|_| ClientError::Protocol("invalid SMB HMAC signing key"))?;
                mac.update(message);
                let digest = mac.finalize().into_bytes();
                let mut signature = [0u8; SIGNATURE_SIZE];
                signature.copy_from_slice(&digest[..SIGNATURE_SIZE]);
                Ok(signature)
            }
            SigningAlgorithm::AesCmac => {
                let mut mac = Cmac::<Aes128>::new_from_slice(self.key.expose())
                    .map_err(|_| ClientError::Protocol("invalid SMB AES-CMAC signing key"))?;
                mac.update(message);
                let digest = mac.finalize().into_bytes();
                let mut signature = [0u8; SIGNATURE_SIZE];
                signature.copy_from_slice(&digest);
                Ok(signature)
            }
            SigningAlgorithm::AesGmac => Err(ClientError::Protocol(
                "AES-GMAC signing is not implemented yet",
            )),
        }
    }
}

fn ensure_smb2_message(message: &[u8]) -> Result<(), ClientError> {
    if message.len() < SMB2_HEADER_SIZE {
        return Err(ClientError::Protocol("SMB message is shorter than its header"));
    }
    Smb2Header::decode(message)?;
    Ok(())
}

fn set_signed_flag(message: &mut [u8], signed: bool) {
    let mut value = u32::from_le_bytes(message[16..20].try_into().unwrap_or([0; 4]));
    if signed {
        value |= flags::SIGNED;
    } else {
        value &= !flags::SIGNED;
    }
    message[16..20].copy_from_slice(&value.to_le_bytes());
}

fn normalize_session_key(session_key: &SecretBytes) -> [u8; 16] {
    let mut key = [0u8; 16];
    let copy_len = session_key.len().min(key.len());
    key[..copy_len].copy_from_slice(&session_key.expose()[..copy_len]);
    key
}

/// NIST SP800-108 counter-mode KDF with HMAC-SHA256, r=32 and L=128.
///
/// SMB passes null-terminated labels/contexts for 3.0/3.0.2. The KDF itself also inserts the
/// required zero separator between Label and Context.
fn sp800_108_kdf_128(
    key: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; 16], ClientError> {
    let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
    input.extend_from_slice(&1u32.to_be_bytes());
    input.extend_from_slice(label);
    input.push(0);
    input.extend_from_slice(context);
    input.extend_from_slice(&KDF_OUTPUT_BITS.to_be_bytes());

    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| ClientError::Protocol("invalid SMB key-derivation key"))?;
    mac.update(&input);
    let digest = mac.finalize().into_bytes();
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_io_wire::Command;

    #[test]
    fn smb300_kdf_matches_microsoft_vector() {
        let session_key = SecretBytes::new(
            [
                0x7c, 0xd4, 0x51, 0x82, 0x5d, 0x04, 0x50, 0xd2, 0x35, 0x42, 0x4e, 0x44, 0xba,
                0x6e, 0x78, 0xcc,
            ]
            .to_vec(),
        );
        let signing = SigningState::derive(
            Dialect::Smb300,
            SigningAlgorithm::AesCmac,
            &session_key,
            None,
        )
        .unwrap();
        assert_eq!(
            signing.key.expose(),
            &[
                0x0b, 0x7e, 0x9c, 0x5c, 0xac, 0x36, 0xc0, 0xf6, 0xea, 0x9a, 0xb2, 0x75, 0x29,
                0x8c, 0xed, 0xce,
            ]
        );
    }

    #[test]
    fn hmac_sign_and_verify_roundtrip() {
        let key = SecretBytes::new(vec![0x11; 16]);
        let signing = SigningState::derive(
            Dialect::Smb210,
            SigningAlgorithm::HmacSha256,
            &key,
            None,
        )
        .unwrap();
        let mut message = Smb2Header::request(Command::Echo, 7, 0, 1)
            .encode()
            .to_vec();
        message.extend_from_slice(&[4, 0, 0, 0]);
        signing.sign(&mut message).unwrap();
        assert_ne!(&message[SIGNATURE_OFFSET..64], &[0; 16]);
        signing.verify(&mut message).unwrap();
        message.push(0x99);
        assert!(signing.verify(&mut message).is_err());
    }

    #[test]
    fn cmac_sign_and_verify_roundtrip() {
        let key = SecretBytes::new(vec![0x22; 16]);
        let signing = SigningState::derive(
            Dialect::Smb302,
            SigningAlgorithm::AesCmac,
            &key,
            None,
        )
        .unwrap();
        let mut message = Smb2Header::request(Command::Echo, 8, 0, 1)
            .encode()
            .to_vec();
        message.extend_from_slice(&[4, 0, 0, 0]);
        signing.sign(&mut message).unwrap();
        signing.verify(&mut message).unwrap();
    }
}
