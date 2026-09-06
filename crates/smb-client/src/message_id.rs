use std::sync::atomic::{AtomicU64, Ordering};

use crate::ClientError;

/// Allocates SMB MessageIds from one connection's sequence-number space.
///
/// Multi-credit requests consume `CreditCharge` sequence numbers. Requests whose charge field is
/// zero still consume one sequence number (for example the initial NEGOTIATE request).
#[derive(Debug, Default)]
pub struct MessageIdAllocator {
    next: AtomicU64,
}

impl MessageIdAllocator {
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }

    pub fn allocate(&self, credit_charge: u16) -> Result<u64, ClientError> {
        let width = u64::from(credit_charge.max(1));
        self.next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(width)
            })
            .map_err(|_| ClientError::Protocol("SMB MessageId space exhausted"))
    }

    pub fn peek(&self) -> u64 {
        self.next.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_charge_still_advances_one_id() {
        let ids = MessageIdAllocator::new();
        assert_eq!(ids.allocate(0).unwrap(), 0);
        assert_eq!(ids.allocate(0).unwrap(), 1);
    }

    #[test]
    fn multi_credit_request_reserves_a_sequence_span() {
        let ids = MessageIdAllocator::new();
        assert_eq!(ids.allocate(4).unwrap(), 0);
        assert_eq!(ids.allocate(1).unwrap(), 4);
        assert_eq!(ids.peek(), 5);
    }
}
