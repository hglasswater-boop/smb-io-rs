use core::fmt;
use zeroize::Zeroizing;

/// Secret byte storage for session keys and derived authentication material.
///
/// Contents are zeroized on drop and deliberately redacted from `Debug` output.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_contains_secret_material() {
        let secret = SecretBytes::new(b"top-secret-session-key".to_vec());
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("top-secret"));
    }
}
