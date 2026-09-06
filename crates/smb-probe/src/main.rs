#![forbid(unsafe_code)]

use std::error::Error;

use smb_io_client::{Connection, Dialect, NegotiateConfig, TcpTransport, TcpTransportConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or("usage: smb-io-probe <host> [port]")?;
    let port = match args.next() {
        Some(value) => value.parse::<u16>()?,
        None => 445,
    };
    if args.next().is_some() {
        return Err("usage: smb-io-probe <host> [port]".into());
    }

    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut client_guid)?;
    getrandom::fill(&mut preauth_salt)?;

    let transport = TcpTransport::connect(&host, port, TcpTransportConfig::default()).await?;
    let peer = transport.peer_addr()?;
    let mut connection = Connection::new(transport);
    let config = NegotiateConfig::modern(client_guid, preauth_salt.to_vec());
    let negotiated = connection.negotiate(&config).await?.clone();

    println!("peer: {peer}");
    println!("dialect: {}", dialect_name(negotiated.dialect));
    println!("server_guid: {}", format_guid(negotiated.server_guid));
    println!("signing_enabled: {}", negotiated.signing_enabled());
    println!("signing_required: {}", negotiated.signing_required());
    println!("capabilities: 0x{:08X}", negotiated.capabilities);
    println!("initial_credits: {}", negotiated.initial_credits);
    println!("max_transact_size: {}", negotiated.max_transact_size);
    println!("max_read_size: {}", negotiated.max_read_size);
    println!("max_write_size: {}", negotiated.max_write_size);
    println!(
        "preauth_hash_active: {}",
        connection.preauth_hash().is_some()
    );

    Ok(())
}

fn dialect_name(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Smb202 => "SMB 2.0.2",
        Dialect::Smb210 => "SMB 2.1",
        Dialect::Smb300 => "SMB 3.0",
        Dialect::Smb302 => "SMB 3.0.2",
        Dialect::Smb311 => "SMB 3.1.1",
    }
}

fn format_guid(guid: [u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in guid {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialects_have_stable_display_names() {
        assert_eq!(dialect_name(Dialect::Smb311), "SMB 3.1.1");
        assert_eq!(dialect_name(Dialect::Smb202), "SMB 2.0.2");
    }

    #[test]
    fn guid_formatter_is_fixed_width_hex() {
        assert_eq!(format_guid([0xAB; 16]), "abababababababababababababababab");
    }
}
