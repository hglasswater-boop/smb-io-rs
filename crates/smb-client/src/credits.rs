use crate::ClientError;

const DEFAULT_TARGET_CREDITS: u32 = 128;

/// Tracks the number of SMB credits currently available on one transport connection.
///
/// The current request engine is serial, so this is deliberately small and deterministic. The
/// same accounting object can later gate a pipelined dispatcher with a semaphore-like wait queue.
#[derive(Debug, Clone)]
pub struct CreditManager {
    available: u32,
    target: u32,
}

impl CreditManager {
    pub fn new(initial: u16) -> Result<Self, ClientError> {
        if initial == 0 {
            return Err(ClientError::Protocol(
                "server granted zero credits in NEGOTIATE response",
            ));
        }
        Ok(Self {
            available: u32::from(initial),
            target: DEFAULT_TARGET_CREDITS,
        })
    }

    pub fn available(&self) -> u32 {
        self.available
    }

    pub fn reserve(&mut self, charge: u16) -> Result<(), ClientError> {
        let logical_charge = u32::from(charge.max(1));
        if logical_charge > self.available {
            return Err(ClientError::Protocol(
                "SMB request requires more credits than are currently available",
            ));
        }
        self.available -= logical_charge;
        Ok(())
    }

    pub fn grant(&mut self, credits: u16) -> Result<(), ClientError> {
        self.available = self
            .available
            .checked_add(u32::from(credits))
            .ok_or(ClientError::Protocol("SMB credit count overflow"))?;
        Ok(())
    }

    /// Returns a CreditRequest that preserves the caller's minimum while asking the server to
    /// grow the connection toward the default 128-credit window used by Windows clients.
    pub fn request_hint(&self, minimum: u16) -> u16 {
        let desired = self.target.saturating_sub(self.available);
        let desired = desired.min(u32::from(u16::MAX)) as u16;
        minimum.max(desired).max(1)
    }

    /// Maximum payload that can currently be covered by consecutive 64 KiB credit units.
    pub fn max_multi_credit_payload(&self) -> usize {
        let units = self.available.max(1) as usize;
        units.saturating_mul(65_536)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_grant_update_available_window() {
        let mut credits = CreditManager::new(8).unwrap();
        credits.reserve(4).unwrap();
        assert_eq!(credits.available(), 4);
        credits.grant(6).unwrap();
        assert_eq!(credits.available(), 10);
    }

    #[test]
    fn cannot_reserve_past_server_grant() {
        let mut credits = CreditManager::new(2).unwrap();
        assert!(credits.reserve(3).is_err());
        assert_eq!(credits.available(), 2);
    }

    #[test]
    fn request_hint_grows_toward_target() {
        let credits = CreditManager::new(32).unwrap();
        assert_eq!(credits.request_hint(1), 96);
    }
}
