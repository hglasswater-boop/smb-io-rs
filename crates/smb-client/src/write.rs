use crate::ClientError;

const CREDIT_UNIT_BYTES: usize = 65_536;

fn credit_limited_payload(_supports_multi_credit: bool, _available_credits: u32) -> usize {
    unimplemented!("Phase 8 WRITE scheduler implementation follows the tests")
}

fn write_credit_charge(_supports_multi_credit: bool, _length: usize) -> Result<u16, ClientError> {
    unimplemented!("Phase 8 WRITE credit accounting implementation follows the tests")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mib_write_costs_sixteen_credits() {
        assert_eq!(write_credit_charge(true, 1024 * 1024).unwrap(), 16);
    }

    #[test]
    fn legacy_write_uses_zero_credit_charge() {
        assert_eq!(write_credit_charge(false, 64 * 1024).unwrap(), 0);
    }

    #[test]
    fn zero_length_credit_calculation_is_rejected() {
        assert!(write_credit_charge(true, 0).is_err());
    }

    #[test]
    fn credit_window_limits_write_payload() {
        assert_eq!(credit_limited_payload(true, 0), 0);
        assert_eq!(credit_limited_payload(true, 1), CREDIT_UNIT_BYTES);
        assert_eq!(credit_limited_payload(true, 4), 4 * CREDIT_UNIT_BYTES);
        assert_eq!(credit_limited_payload(false, 1), CREDIT_UNIT_BYTES);
    }
}
