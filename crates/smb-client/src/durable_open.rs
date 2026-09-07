use smb_io_wire::{
    DURABLE_HANDLE_REQUEST_V2_NAME, Dialect, DurableHandleReconnectV2, DurableHandleRequestV2,
    DurableHandleResponseV2, capabilities, durable_handle_flags, oplock_level, share_capabilities,
};

use crate::{ClientError, FileHandle, FileOpenOptions, SessionConnection, Transport, TreeHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableHandleV2Options {
    /// Requested durable timeout in milliseconds. Zero lets the server choose its default.
    pub timeout_ms: u32,
    /// Requests a persistent handle. This requires both server support and a continuously
    /// available share; ordinary media shares should normally leave this false.
    pub persistent: bool,
}

impl Default for DurableHandleV2Options {
    fn default() -> Self {
        Self {
            timeout_ms: 0,
            persistent: false,
        }
    }
}

/// A file open for which the server granted SMB2 Durable Handle V2 state.
///
/// The effective CREATE parameters and CreateGuid are retained because SMB2 durable reconnect must
/// replay those identity parameters rather than silently degrading into a path-only reopen.
#[derive(Debug, Clone)]
pub struct DurableFileHandle {
    file: FileHandle,
    create_guid: [u8; 16],
    open_options: FileOpenOptions,
    server_timeout_ms: u32,
    server_flags: u32,
}

impl DurableFileHandle {
    pub fn file(&self) -> &FileHandle {
        &self.file
    }

    pub fn into_file(self) -> FileHandle {
        self.file
    }

    pub fn create_guid(&self) -> [u8; 16] {
        self.create_guid
    }

    pub fn open_options(&self) -> FileOpenOptions {
        self.open_options
    }

    pub fn server_timeout_ms(&self) -> u32 {
        self.server_timeout_ms
    }

    pub fn server_flags(&self) -> u32 {
        self.server_flags
    }

    pub fn persistent(&self) -> bool {
        self.server_flags & durable_handle_flags::PERSISTENT != 0
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Opens a file and requires the server to grant SMB2 Durable Handle V2 (`DH2Q`).
    pub async fn open_file_durable_v2(
        &mut self,
        tree: &TreeHandle,
        path: impl Into<String>,
        open_options: FileOpenOptions,
        create_guid: [u8; 16],
        durable_options: DurableHandleV2Options,
    ) -> Result<DurableFileHandle, ClientError> {
        ensure_durable_v2_supported(self, tree, durable_options.persistent)?;

        // Until leases are implemented, a non-CA durable open requests a batch oplock so the
        // server has handle-caching state it can preserve across a transport disconnect.
        let mut effective_open_options = open_options;
        if !durable_options.persistent {
            effective_open_options.requested_oplock_level = oplock_level::BATCH;
        }

        let request = DurableHandleRequestV2 {
            timeout_ms: durable_options.timeout_ms,
            flags: if durable_options.persistent {
                durable_handle_flags::PERSISTENT
            } else {
                0
            },
            create_guid,
        };
        let request_context = request.into_context()?;
        let result = self
            .open_file_with_contexts(
                tree,
                path,
                effective_open_options,
                std::slice::from_ref(&request_context),
            )
            .await?;
        let response = required_durable_response(&result.response_contexts)?;

        if durable_options.persistent && response.flags & durable_handle_flags::PERSISTENT == 0 {
            return Err(ClientError::Protocol(
                "server did not grant the requested persistent durable handle",
            ));
        }

        Ok(DurableFileHandle {
            file: result.file,
            create_guid,
            open_options: effective_open_options,
            server_timeout_ms: response.timeout_ms,
            server_flags: response.flags,
        })
    }

    /// Reconnects an already granted Durable Handle V2 using `DH2C`.
    ///
    /// This is deliberately distinct from path-only recovery. It reuses the original FileId,
    /// CreateGuid and CREATE parameters, with ImpersonationLevel reset to zero as required by the
    /// durable reconnect request form.
    pub async fn reconnect_file_durable_v2(
        &mut self,
        tree: &TreeHandle,
        durable: &DurableFileHandle,
    ) -> Result<DurableFileHandle, ClientError> {
        ensure_durable_v2_supported(self, tree, durable.persistent())?;

        let reconnect = DurableHandleReconnectV2 {
            file_id: durable.file.file_id(),
            create_guid: durable.create_guid,
            flags: if durable.persistent() {
                durable_handle_flags::PERSISTENT
            } else {
                0
            },
        };
        let reconnect_context = reconnect.into_context()?;
        let mut reconnect_options = durable.open_options;
        reconnect_options.requested_oplock_level = durable.file.oplock_level();
        reconnect_options.impersonation_level = 0;

        let result = self
            .open_file_with_contexts(
                tree,
                durable.file.path(),
                reconnect_options,
                std::slice::from_ref(&reconnect_context),
            )
            .await?;

        let refreshed = optional_durable_response(&result.response_contexts)?;
        let (server_timeout_ms, server_flags) = refreshed.map_or(
            (durable.server_timeout_ms, durable.server_flags),
            |response| (response.timeout_ms, response.flags),
        );
        if durable.persistent() && server_flags & durable_handle_flags::PERSISTENT == 0 {
            return Err(ClientError::Protocol(
                "durable reconnect lost persistent-handle state",
            ));
        }

        Ok(DurableFileHandle {
            file: result.file,
            create_guid: durable.create_guid,
            open_options: durable.open_options,
            server_timeout_ms,
            server_flags,
        })
    }
}

fn ensure_durable_v2_supported<T>(
    session: &SessionConnection<T>,
    tree: &TreeHandle,
    persistent: bool,
) -> Result<(), ClientError>
where
    T: Transport,
{
    let negotiated = session.negotiated().ok_or(ClientError::Protocol(
        "durable handle requires negotiated SMB parameters",
    ))?;
    if negotiated.dialect < Dialect::Smb300 {
        return Err(ClientError::Protocol("Durable Handle V2 requires SMB 3.x"));
    }
    if persistent {
        if negotiated.capabilities & capabilities::PERSISTENT_HANDLES == 0 {
            return Err(ClientError::Protocol(
                "server did not negotiate persistent-handle capability",
            ));
        }
        if tree.capabilities() & share_capabilities::CONTINUOUS_AVAILABILITY == 0 {
            return Err(ClientError::Protocol(
                "persistent durable handles require a continuously available share",
            ));
        }
    }
    Ok(())
}

fn required_durable_response(
    contexts: &[smb_io_wire::CreateContext],
) -> Result<DurableHandleResponseV2, ClientError> {
    optional_durable_response(contexts)?.ok_or(ClientError::Protocol(
        "server did not grant SMB2 Durable Handle V2",
    ))
}

fn optional_durable_response(
    contexts: &[smb_io_wire::CreateContext],
) -> Result<Option<DurableHandleResponseV2>, ClientError> {
    let mut matched = None;
    for context in contexts {
        if context.name.as_slice() != DURABLE_HANDLE_REQUEST_V2_NAME {
            continue;
        }
        if matched.is_some() {
            return Err(ClientError::Protocol(
                "CREATE response contained duplicate DH2Q contexts",
            ));
        }
        matched = Some(DurableHandleResponseV2::from_context(context)?);
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use smb_io_wire::{CreateContext, durable_handle_flags};

    use super::*;

    #[test]
    fn durable_response_can_coexist_with_unknown_create_contexts() {
        let contexts = vec![
            CreateContext::new(b"QFid".to_vec(), Vec::new()).unwrap(),
            CreateContext::new(
                DURABLE_HANDLE_REQUEST_V2_NAME.to_vec(),
                45_000u32
                    .to_le_bytes()
                    .into_iter()
                    .chain(0u32.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        ];
        let response = required_durable_response(&contexts).unwrap();
        assert_eq!(response.timeout_ms, 45_000);
        assert_eq!(response.flags, 0);
    }

    #[test]
    fn missing_dh2q_is_not_silently_accepted() {
        let contexts = vec![CreateContext::new(b"QFid".to_vec(), Vec::new()).unwrap()];
        assert!(required_durable_response(&contexts).is_err());
    }

    #[test]
    fn duplicate_dh2q_is_rejected() {
        let data = [0u8; 8];
        let contexts = vec![
            CreateContext::new(DURABLE_HANDLE_REQUEST_V2_NAME.to_vec(), data.to_vec()).unwrap(),
            CreateContext::new(DURABLE_HANDLE_REQUEST_V2_NAME.to_vec(), data.to_vec()).unwrap(),
        ];
        assert!(optional_durable_response(&contexts).is_err());
    }

    #[test]
    fn persistent_response_flag_is_exposed() {
        let mut data = Vec::new();
        data.extend_from_slice(&60_000u32.to_le_bytes());
        data.extend_from_slice(&durable_handle_flags::PERSISTENT.to_le_bytes());
        let contexts =
            vec![CreateContext::new(DURABLE_HANDLE_REQUEST_V2_NAME.to_vec(), data).unwrap()];
        let response = required_durable_response(&contexts).unwrap();
        assert_eq!(response.flags, durable_handle_flags::PERSISTENT);
    }
}
