use sha2::{Digest, Sha512};

/// Rolling SMB 3.1.1 preauthentication integrity hash.
///
/// The hash begins as 64 zero bytes. Each exact SMB message updates the state as
/// `SHA512(previous_hash || message_bytes)`. Transport framing is deliberately excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreauthIntegrityHash {
    value: [u8; 64],
}

impl Default for PreauthIntegrityHash {
    fn default() -> Self {
        Self::new()
    }
}

impl PreauthIntegrityHash {
    pub const fn new() -> Self {
        Self { value: [0; 64] }
    }

    pub fn update(&mut self, message: &[u8]) {
        let mut hasher = Sha512::new();
        hasher.update(self.value);
        hasher.update(message);
        let digest = hasher.finalize();
        self.value.copy_from_slice(&digest);
    }

    pub const fn current(&self) -> &[u8; 64] {
        &self.value
    }

    pub fn into_bytes(self) -> [u8; 64] {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_zero_hash() {
        assert_eq!(PreauthIntegrityHash::new().current(), &[0; 64]);
    }

    #[test]
    fn exact_message_bytes_affect_state() {
        let mut left = PreauthIntegrityHash::new();
        let mut right = PreauthIntegrityHash::new();
        left.update(b"request");
        right.update(b"request");
        assert_eq!(left, right);
        right.update(b"response-b");
        left.update(b"response-a");
        assert_ne!(left, right);
    }
}
