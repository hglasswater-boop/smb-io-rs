use crate::AuthError;

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLMSSP_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];
const MAX_DER_DEPTH: usize = 12;

pub(crate) fn encode_neg_token_init_ntlm(ntlm_token: &[u8]) -> Vec<u8> {
    let mech_list = der_tlv(0x30, NTLMSSP_OID);
    let mech_types = der_tlv(0xa0, &mech_list);
    let mech_token = der_tlv(0xa2, &der_tlv(0x04, ntlm_token));

    let mut sequence_body = Vec::with_capacity(mech_types.len() + mech_token.len());
    sequence_body.extend_from_slice(&mech_types);
    sequence_body.extend_from_slice(&mech_token);
    let neg_token_init = der_tlv(0xa0, &der_tlv(0x30, &sequence_body));

    let mut gss_body = Vec::with_capacity(SPNEGO_OID.len() + neg_token_init.len());
    gss_body.extend_from_slice(SPNEGO_OID);
    gss_body.extend_from_slice(&neg_token_init);
    der_tlv(0x60, &gss_body)
}

pub(crate) fn encode_neg_token_resp_ntlm(ntlm_token: &[u8]) -> Vec<u8> {
    let response_token = der_tlv(0xa2, &der_tlv(0x04, ntlm_token));
    der_tlv(0xa1, &der_tlv(0x30, &response_token))
}

pub(crate) fn extract_ntlm_token(token: &[u8]) -> Result<&[u8], AuthError> {
    if token.starts_with(NTLMSSP_SIGNATURE) {
        return Ok(token);
    }
    find_ntlm_in_der(token, 0)?.ok_or(AuthError::InvalidToken(
        "SPNEGO token does not contain an NTLMSSP message",
    ))
}

fn find_ntlm_in_der(input: &[u8], depth: usize) -> Result<Option<&[u8]>, AuthError> {
    if depth > MAX_DER_DEPTH {
        return Err(AuthError::InvalidToken("SPNEGO nesting is too deep"));
    }

    let mut offset = 0usize;
    while offset < input.len() {
        let (tag, content, consumed) = parse_tlv(&input[offset..])?;
        if content.starts_with(NTLMSSP_SIGNATURE) {
            return Ok(Some(content));
        }

        if tag & 0x20 != 0 {
            if let Some(found) = find_ntlm_in_der(content, depth + 1)? {
                return Ok(Some(found));
            }
        }
        offset = offset
            .checked_add(consumed)
            .ok_or(AuthError::InvalidToken("SPNEGO length overflow"))?;
    }
    Ok(None)
}

fn parse_tlv(input: &[u8]) -> Result<(u8, &[u8], usize), AuthError> {
    if input.len() < 2 {
        return Err(AuthError::InvalidToken("truncated DER TLV"));
    }
    let tag = input[0];
    let first = input[1];
    let (length, length_octets) = if first & 0x80 == 0 {
        (usize::from(first), 1usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() || input.len() < 2 + count {
            return Err(AuthError::InvalidToken("invalid DER length"));
        }
        if input[2] == 0 {
            return Err(AuthError::InvalidToken("non-minimal DER length"));
        }
        let mut value = 0usize;
        for byte in &input[2..2 + count] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*byte)))
                .ok_or(AuthError::InvalidToken("DER length overflow"))?;
        }
        if value < 128 {
            return Err(AuthError::InvalidToken("non-minimal DER long-form length"));
        }
        (value, 1 + count)
    };

    let header_len = 1usize
        .checked_add(length_octets)
        .ok_or(AuthError::InvalidToken("DER header length overflow"))?;
    let end = header_len
        .checked_add(length)
        .ok_or(AuthError::InvalidToken("DER content length overflow"))?;
    if end > input.len() {
        return Err(AuthError::InvalidToken("truncated DER content"));
    }
    Ok((tag, &input[header_len..end], end))
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + der_length_size(content.len()) + content.len());
    out.push(tag);
    encode_der_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn der_length_size(length: usize) -> usize {
    if length < 128 {
        1
    } else {
        1 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
    }
}

fn encode_der_length(length: usize, out: &mut Vec<u8>) {
    if length < 128 {
        out.push(length as u8);
        return;
    }

    let bytes = length.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let encoded = &bytes[first_non_zero..];
    out.push(0x80 | encoded.len() as u8);
    out.extend_from_slice(encoded);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_token_roundtrips_embedded_ntlm() {
        let ntlm = b"NTLMSSP\0\x01\x00\x00\x00test";
        let wrapped = encode_neg_token_init_ntlm(ntlm);
        assert_eq!(extract_ntlm_token(&wrapped).unwrap(), ntlm);
    }

    #[test]
    fn response_token_roundtrips_embedded_ntlm() {
        let ntlm = b"NTLMSSP\0\x03\x00\x00\x00test";
        let wrapped = encode_neg_token_resp_ntlm(ntlm);
        assert_eq!(extract_ntlm_token(&wrapped).unwrap(), ntlm);
    }

    #[test]
    fn raw_ntlm_is_accepted() {
        let ntlm = b"NTLMSSP\0\x02\x00\x00\x00";
        assert_eq!(extract_ntlm_token(ntlm).unwrap(), ntlm);
    }
}
