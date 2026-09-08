//! JNI surface for XFiles.
//!
//! This module is intentionally mechanical. Protocol behavior, authentication, cancellation,
//! caching, and SMB handle lifetime stay in [`crate::AndroidEngine`]. JNI owns only argument
//! validation, Java/Rust value conversion, opaque-handle transport, and Java exception mapping.

use std::fmt::Display;
use std::sync::OnceLock;

use jni::errors::{Result as JniResult, ThrowRuntimeExAndDefault};
use jni::objects::{JByteArray, JObject, JString};
use jni::strings::{JNIStr, JNIString};
use jni::sys::{jbyte, jint, jlong};
use jni::{Env, EnvUnowned, jni_mangle, jni_str};

use crate::{API_VERSION, AndroidEngine, AndroidEngineConfig, VideoHandle, VideoOpenRequest};

static ENGINE: OnceLock<Result<AndroidEngine, String>> = OnceLock::new();

fn engine() -> Result<&'static AndroidEngine, String> {
    match ENGINE.get_or_init(|| {
        AndroidEngine::new(AndroidEngineConfig::default()).map_err(|error| error.to_string())
    }) {
        Ok(engine) => Ok(engine),
        Err(error) => Err(error.clone()),
    }
}

fn throw_exception<T: Default>(
    env: &mut Env<'_>,
    class: &'static JNIStr,
    message: impl Display,
) -> JniResult<T> {
    let message = JNIString::new(message.to_string());
    env.throw_new(class, message.as_ref())?;
    Ok(T::default())
}

fn throw_io<T: Default>(env: &mut Env<'_>, error: impl Display) -> JniResult<T> {
    throw_exception(env, jni_str!("java/io/IOException"), error)
}

fn throw_argument<T: Default>(env: &mut Env<'_>, message: impl Display) -> JniResult<T> {
    throw_exception(env, jni_str!("java/lang/IllegalArgumentException"), message)
}

fn video_handle(env: &mut Env<'_>, raw: jlong) -> JniResult<Option<VideoHandle>> {
    if raw <= 0 {
        throw_argument::<()>(env, "SMB video handle must be positive")?;
        return Ok(None);
    }
    Ok(Some(VideoHandle::from_raw(raw as u64)))
}

fn rust_string(env: &mut Env<'_>, value: &JString<'_>) -> JniResult<String> {
    value.try_to_string(env)
}

/// Reinterprets the exact same byte bits for JNI's signed `jbyte` element type.
///
/// # Safety
///
/// `u8` and JNI `jbyte` (`i8`) both have size/alignment 1. The returned slice is immutable and has
/// exactly the source lifetime and length, so no element is read or written outside `bytes`.
fn as_jbytes(bytes: &[u8]) -> &[jbyte] {
    // SAFETY: documented above; this is a read-only bit reinterpretation of 1-byte elements.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<jbyte>(), bytes.len()) }
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_api_version<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
) -> jint {
    unowned_env
        .with_env(|_env| -> JniResult<jint> { Ok(API_VERSION as jint) })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_open_video<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    host: JString<'local>,
    port: jint,
    share: JString<'local>,
    path: JString<'local>,
    username: JString<'local>,
    password: JString<'local>,
    domain: JString<'local>,
    workstation: JString<'local>,
) -> jlong {
    unowned_env
        .with_env(|env| -> JniResult<jlong> {
            let Ok(port) = u16::try_from(port) else {
                return throw_argument(env, "SMB port must be between 1 and 65535");
            };
            if port == 0 {
                return throw_argument(env, "SMB port must be between 1 and 65535");
            }

            let mut request = VideoOpenRequest::new(
                rust_string(env, &host)?,
                rust_string(env, &share)?,
                rust_string(env, &path)?,
                rust_string(env, &username)?,
                rust_string(env, &password)?,
            );
            request.port = port;
            request.domain = rust_string(env, &domain)?;
            request.workstation = rust_string(env, &workstation)?;

            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.open_video(request) {
                Ok(handle) => match jlong::try_from(handle.raw()) {
                    Ok(raw) => Ok(raw),
                    Err(_) => throw_io(env, "SMB native handle space exceeded Java Long range"),
                },
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_len<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jlong {
    unowned_env
        .with_env(|env| -> JniResult<jlong> {
            let Some(handle) = video_handle(env, handle)? else {
                return Ok(-1);
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.len(handle) {
                Ok(length) => match jlong::try_from(length) {
                    Ok(length) => Ok(length),
                    Err(_) => throw_io(env, "SMB file length exceeds Java Long range"),
                },
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_read_at<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    position: jlong,
    destination: JByteArray<'local>,
    destination_offset: jint,
    length: jint,
) -> jint {
    unowned_env
        .with_env(|env| -> JniResult<jint> {
            let Some(handle) = video_handle(env, handle)? else {
                return Ok(-1);
            };
            if position < 0 {
                return throw_argument(env, "SMB read position must not be negative");
            }
            if destination_offset < 0 || length < 0 {
                return throw_argument(env, "SMB read buffer offset/length must not be negative");
            }
            if length == 0 {
                return Ok(0);
            }

            let destination_offset = destination_offset as usize;
            let length = length as usize;
            let array_len = destination.len(env)?;
            let Some(end) = destination_offset.checked_add(length) else {
                return throw_argument(env, "SMB read buffer range overflow");
            };
            if end > array_len {
                return throw_argument(env, "SMB read buffer range exceeds destination array");
            }

            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            let data = match engine.read_at(handle, position as u64, length) {
                Ok(data) => data,
                Err(error) => return throw_io(env, error),
            };
            destination.set_region(env, destination_offset as jint, as_jbytes(&data))?;
            match jint::try_from(data.len()) {
                Ok(count) => Ok(count),
                Err(_) => throw_io(env, "SMB native read result exceeds Java Int range"),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_prefetch<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    position: jlong,
    length: jint,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            let Some(handle) = video_handle(env, handle)? else {
                return Ok(());
            };
            if position < 0 {
                return throw_argument(env, "SMB prefetch position must not be negative");
            }
            if length < 0 {
                return throw_argument(env, "SMB prefetch length must not be negative");
            }
            if length == 0 {
                return Ok(());
            }

            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.prefetch(handle, position as u64, length as usize) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_seek<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    position: jlong,
) -> jlong {
    unowned_env
        .with_env(|env| -> JniResult<jlong> {
            let Some(handle) = video_handle(env, handle)? else {
                return Ok(-1);
            };
            if position < 0 {
                return throw_argument(env, "SMB seek position must not be negative");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.seek(handle) {
                Ok(generation) => match jlong::try_from(generation) {
                    Ok(generation) => Ok(generation),
                    Err(_) => throw_io(env, "SMB seek generation exceeds Java Long range"),
                },
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_close<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            let Some(handle) = video_handle(env, handle)? else {
                return Ok(());
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.close_video(handle) {
                Ok(_) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}
