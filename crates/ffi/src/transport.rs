use super::{AbiError, input_slice, response, response_coded};
use serde::{Deserialize, Serialize};
use std::{ffi::c_char, sync::Mutex};
use stogas_sdk::{SecurityMode, Transport as ManagedTransport, TransportOptions};

/// Opaque managed HTTP transport.
pub struct StogasTransport {
    transport: Mutex<ManagedTransport>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AbiTransportOptions {
    environment: stogas_sdk::Environment,
    security: String,
    max_connections: usize,
    base_url: Option<String>,
}

impl Default for AbiTransportOptions {
    fn default() -> Self {
        Self {
            environment: stogas_sdk::Environment::Production,
            security: "tls".into(),
            max_connections: 4,
            base_url: None,
        }
    }
}

#[derive(Serialize)]
struct StartedTransport {
    base_url: String,
}

/// Start an in-process managed transport and verify its initial bundle.
///
/// `configuration` is bounded JSON. `transport_out` is set only on success. The returned JSON
/// contains the capability-protected loopback `base_url`.
///
/// # Safety
///
/// `configuration` must point to `configuration_len` readable bytes. `transport_out` must be a
/// writable pointer and the caller must eventually free a successful handle exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_transport_start(
    configuration: *const u8,
    configuration_len: usize,
    transport_out: *mut *mut StogasTransport,
) -> *mut c_char {
    response_coded(|| {
        if transport_out.is_null() {
            return Err("transport output pointer is null".into());
        }
        // SAFETY: caller supplied a writable output pointer for this synchronous call.
        unsafe { transport_out.write(std::ptr::null_mut()) };
        // SAFETY: pointer and bound are validated by `input_slice`.
        let configuration =
            unsafe { input_slice(configuration, configuration_len, 16 * 1024, "configuration")? };
        let configuration: AbiTransportOptions = if configuration.is_empty() {
            AbiTransportOptions::default()
        } else {
            serde_json::from_slice(configuration)
                .map_err(|error| format!("invalid transport configuration: {error}"))?
        };
        let options = TransportOptions {
            environment: configuration.environment,
            security: match configuration.security.as_str() {
                "tls" => SecurityMode::Tls,
                "e2ee" => SecurityMode::E2ee,
                _ => return Err("security must be tls or e2ee".into()),
            },
            max_connections: configuration.max_connections,
            base_url: configuration.base_url,
        };
        let transport = ManagedTransport::start(&options).map_err(|error| AbiError {
            code: Some(
                error
                    .downcast_ref::<stogas_sdk::evidence_client::Error>()
                    .map_or(
                        "transport_unavailable",
                        stogas_sdk::evidence_client::Error::code,
                    ),
            ),
            message: error.to_string(),
        })?;
        let base_url = transport.base_url().to_owned();
        let transport = Box::into_raw(Box::new(StogasTransport {
            transport: Mutex::new(transport),
        }));
        // SAFETY: output was validated above and is written exactly once on success.
        unsafe { transport_out.write(transport) };
        Ok(StartedTransport { base_url })
    })
}

/// Refresh the managed transport's evidence bundle immediately.
///
/// # Safety
///
/// `transport` must be a live pointer returned by `stogas_transport_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_transport_refresh(
    transport: *const StogasTransport,
) -> *mut c_char {
    response(|| {
        // SAFETY: pointer validity is part of the public C ABI contract.
        let transport =
            unsafe { transport.as_ref() }.ok_or_else(|| "transport is null".to_owned())?;
        let transport = transport
            .transport
            .lock()
            .map_err(|_| "transport lock is poisoned".to_owned())?;
        transport
            .refresh_bundle()
            .map_err(|error| error.to_string())
    })
}

/// Stop and release a managed transport.
///
/// # Safety
///
/// `transport` must be null or a live pointer returned by `stogas_transport_start`, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stogas_transport_free(transport: *mut StogasTransport) {
    if !transport.is_null() {
        // SAFETY: ownership and exactly-once release are required by the public ABI.
        let mut transport = unsafe { Box::from_raw(transport) };
        transport
            .transport
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .close();
    }
}
