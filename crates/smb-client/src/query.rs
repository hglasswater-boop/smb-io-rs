use smb_io_wire::{
    Command, HeaderId, QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest,
    QueryInfoResponse, Smb2Header, StatusField, flags, session_flags,
};

use crate::{ClientError, FileHandle, SessionConnection, Transport};

const CREDIT_UNIT_BYTES: u32 = 65_536;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoOptions {
    pub info_type: u8,
    pub file_info_class: u8,
    pub output_buffer_length: u32,
    pub input_buffer: Vec<u8>,
    pub additional_information: u32,
    pub flags: u32,
    pub credit_request: u16,
}

impl QueryInfoOptions {
    pub fn file(file_info_class: u8, output_buffer_length: u32) -> Self {
        Self {
            info_type: smb_io_wire::info_type::FILE,
            file_info_class,
            output_buffer_length,
            input_buffer: Vec::new(),
            additional_information: 0,
            flags: smb_io_wire::query_info_flags::NONE,
            credit_request: 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryOptions {
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_name: String,
    pub output_buffer_length: u32,
    pub credit_request: u16,
}

impl QueryDirectoryOptions {
    pub fn new(
        file_information_class: u8,
        file_name: impl Into<String>,
        output_buffer_length: u32,
    ) -> Self {
        Self {
            file_information_class,
            flags: smb_io_wire::query_directory_flags::NONE,
            file_index: 0,
            file_name: file_name.into(),
            output_buffer_length,
            credit_request: 16,
        }
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    pub async fn query_info(
        &mut self,
        file: &FileHandle,
        options: QueryInfoOptions,
    ) -> Result<Vec<u8>, ClientError> {
        self.ensure_query_session()?;
        let input_buffer_length = u32::try_from(options.input_buffer.len())
            .map_err(|_| ClientError::Protocol("QUERY_INFO input buffer exceeds u32 length"))?;
        self.validate_query_output_length(options.output_buffer_length)?;
        self.validate_single_credit_payload(
            options.output_buffer_length.max(input_buffer_length),
            "QUERY_INFO",
        )?;

        let credit_charge = self.query_credit_charge(
            options.output_buffer_length.max(input_buffer_length),
        )?;
        let request = QueryInfoRequest {
            info_type: options.info_type,
            file_info_class: options.file_info_class,
            output_buffer_length: options.output_buffer_length,
            input_buffer: options.input_buffer,
            additional_information: options.additional_information,
            flags: options.flags,
            file_id: file.file_id(),
        };
        let credit_request = self
            .connection
            .reserve_credits(credit_charge, options.credit_request)?;
        let message_id = self.connection.message_ids.allocate(credit_charge)?;
        let mut request_message = request.encode_message(
            message_id,
            self.session_id,
            file.tree_id(),
            credit_charge,
            credit_request,
        )?;
        self.sign_query_request(&mut request_message)?;

        self.connection
            .transport
            .send_message(&request_message)
            .await?;
        let mut response_message = self.connection.transport.receive_message().await?;
        let header = Smb2Header::decode(&response_message)?;
        self.validate_query_response_header(
            &header,
            Command::QueryInfo,
            message_id,
            file.tree_id(),
            "QUERY_INFO",
        )?;
        self.connection.grant_credits(header.credits)?;
        self.verify_query_response(&mut response_message, &header, "QUERY_INFO")?;
        match header.status {
            StatusField::Status(0) => {}
            StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "QUERY_INFO response used request header form",
                ));
            }
        }

        let response = QueryInfoResponse::decode_message(&response_message)?;
        if response.output_buffer.len() > options.output_buffer_length as usize {
            return Err(ClientError::Protocol(
                "QUERY_INFO response exceeded requested output buffer length",
            ));
        }
        Ok(response.output_buffer)
    }

    pub async fn query_directory(
        &mut self,
        file: &FileHandle,
        options: QueryDirectoryOptions,
    ) -> Result<Vec<u8>, ClientError> {
        self.ensure_query_session()?;
        self.validate_query_output_length(options.output_buffer_length)?;
        self.validate_single_credit_payload(options.output_buffer_length, "QUERY_DIRECTORY")?;

        let credit_charge = self.query_credit_charge(options.output_buffer_length)?;
        let request = QueryDirectoryRequest {
            file_information_class: options.file_information_class,
            flags: options.flags,
            file_index: options.file_index,
            file_id: file.file_id(),
            file_name: options.file_name,
            output_buffer_length: options.output_buffer_length,
        };
        let credit_request = self
            .connection
            .reserve_credits(credit_charge, options.credit_request)?;
        let message_id = self.connection.message_ids.allocate(credit_charge)?;
        let mut request_message = request.encode_message(
            message_id,
            self.session_id,
            file.tree_id(),
            credit_charge,
            credit_request,
        )?;
        self.sign_query_request(&mut request_message)?;

        self.connection
            .transport
            .send_message(&request_message)
            .await?;
        let mut response_message = self.connection.transport.receive_message().await?;
        let header = Smb2Header::decode(&response_message)?;
        self.validate_query_response_header(
            &header,
            Command::QueryDirectory,
            message_id,
            file.tree_id(),
            "QUERY_DIRECTORY",
        )?;
        self.connection.grant_credits(header.credits)?;
        self.verify_query_response(&mut response_message, &header, "QUERY_DIRECTORY")?;
        match header.status {
            StatusField::Status(0) => {}
            StatusField::Status(STATUS_NO_MORE_FILES) => return Ok(Vec::new()),
            StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "QUERY_DIRECTORY response used request header form",
                ));
            }
        }

        let response = QueryDirectoryResponse::decode_message(&response_message)?;
        if response.output_buffer.len() > options.output_buffer_length as usize {
            return Err(ClientError::Protocol(
                "QUERY_DIRECTORY response exceeded requested output buffer length",
            ));
        }
        Ok(response.output_buffer)
    }

    fn ensure_query_session(&self) -> Result<(), ClientError> {
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }
        Ok(())
    }

    fn validate_query_output_length(&self, output_buffer_length: u32) -> Result<(), ClientError> {
        if output_buffer_length == 0 {
            return Err(ClientError::Protocol(
                "SMB query output buffer length must be greater than zero",
            ));
        }
        let negotiated = self
            .connection
            .negotiated
            .as_ref()
            .ok_or(ClientError::Protocol(
                "SMB query requires negotiated parameters",
            ))?;
        if output_buffer_length > negotiated.max_transact_size {
            return Err(ClientError::Protocol(
                "SMB query output buffer exceeds negotiated MaxTransactSize",
            ));
        }
        Ok(())
    }

    fn validate_single_credit_payload(
        &self,
        payload_length: u32,
        operation: &'static str,
    ) -> Result<(), ClientError> {
        let negotiated = self
            .connection
            .negotiated
            .as_ref()
            .ok_or(ClientError::Protocol(
                "SMB query requires negotiated parameters",
            ))?;
        if !negotiated.supports_multi_credit() && payload_length > CREDIT_UNIT_BYTES {
            return Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "QUERY_INFO payload exceeds single-credit 64 KiB limit",
                "QUERY_DIRECTORY" => {
                    "QUERY_DIRECTORY payload exceeds single-credit 64 KiB limit"
                }
                _ => "SMB query payload exceeds single-credit 64 KiB limit",
            }));
        }
        Ok(())
    }

    fn query_credit_charge(&self, payload_length: u32) -> Result<u16, ClientError> {
        let negotiated = self
            .connection
            .negotiated
            .as_ref()
            .ok_or(ClientError::Protocol(
                "SMB query requires negotiated parameters",
            ))?;
        if !negotiated.supports_multi_credit() {
            return Ok(0);
        }
        let units = payload_length.saturating_sub(1) / CREDIT_UNIT_BYTES + 1;
        u16::try_from(units)
            .map_err(|_| ClientError::Protocol("SMB query CreditCharge exceeds u16"))
    }

    fn sign_query_request(&self, message: &mut [u8]) -> Result<(), ClientError> {
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "SMB query requires signing but the session has no signing key",
            ))?;
            signing.sign(message)?;
        }
        Ok(())
    }

    fn verify_query_response(
        &self,
        message: &mut [u8],
        header: &Smb2Header,
        operation: &'static str,
    ) -> Result<(), ClientError> {
        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed SMB query without an available signing key",
            ))?;
            signing.verify(message)?;
        } else if self.signing_required {
            return Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "server omitted a required QUERY_INFO signature",
                "QUERY_DIRECTORY" => "server omitted a required QUERY_DIRECTORY signature",
                _ => "server omitted a required SMB query signature",
            }));
        }
        Ok(())
    }

    fn validate_query_response_header(
        &self,
        header: &Smb2Header,
        command: Command,
        message_id: u64,
        tree_id: u32,
        operation: &'static str,
    ) -> Result<(), ClientError> {
        if header.command != command {
            return Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "QUERY_INFO response command does not match request",
                "QUERY_DIRECTORY" => "QUERY_DIRECTORY response command does not match request",
                _ => "SMB query response command does not match request",
            }));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "QUERY_INFO response MessageId does not match request",
                "QUERY_DIRECTORY" => "QUERY_DIRECTORY response MessageId does not match request",
                _ => "SMB query response MessageId does not match request",
            }));
        }
        if header.session_id != self.session_id {
            return Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "QUERY_INFO response SessionId does not match session",
                "QUERY_DIRECTORY" => "QUERY_DIRECTORY response SessionId does not match session",
                _ => "SMB query response SessionId does not match session",
            }));
        }
        match header.id {
            HeaderId::Sync {
                tree_id: response_tree_id,
                ..
            } if response_tree_id == tree_id => Ok(()),
            HeaderId::Sync { .. } => Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "QUERY_INFO response TreeId does not match tree",
                "QUERY_DIRECTORY" => "QUERY_DIRECTORY response TreeId does not match tree",
                _ => "SMB query response TreeId does not match tree",
            })),
            HeaderId::Async { .. } => Err(ClientError::Protocol(match operation {
                "QUERY_INFO" => "QUERY_INFO response unexpectedly used async header form",
                "QUERY_DIRECTORY" => {
                    "QUERY_DIRECTORY response unexpectedly used async header form"
                }
                _ => "SMB query response unexpectedly used async header form",
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_option_builders_use_sane_defaults() {
        let info = QueryInfoOptions::file(0x12, 64 * 1024);
        assert_eq!(info.info_type, smb_io_wire::info_type::FILE);
        assert_eq!(info.credit_request, 16);

        let directory = QueryDirectoryOptions::new(0x25, "*", 64 * 1024);
        assert_eq!(directory.flags, smb_io_wire::query_directory_flags::NONE);
        assert_eq!(directory.file_name, "*");
        assert_eq!(directory.credit_request, 16);
    }
}
