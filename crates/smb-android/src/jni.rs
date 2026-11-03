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

use crate::{
    API_VERSION, AndroidEngine, AndroidEngineConfig, DirectoryHandle, SmbMutationRequest,
    RandomHandle, VideoHandle, VideoOpenRequest, WritableHandle,
};

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

/// Convert and validate JNI mutation connection arguments once for all one-shot operations.
#[allow(clippy::too_many_arguments)]
fn mutation_request(
    env: &mut Env<'_>,
    host: &JString<'_>,
    port: jint,
    share: &JString<'_>,
    path: &JString<'_>,
    username: &JString<'_>,
    password: &JString<'_>,
    domain: &JString<'_>,
    workstation: &JString<'_>,
) -> JniResult<Option<SmbMutationRequest>> {
    let Ok(port) = u16::try_from(port) else {
        throw_argument::<()>(env, "SMB port must be between 1 and 65535")?;
        return Ok(None);
    };
    if port == 0 {
        throw_argument::<()>(env, "SMB port must be between 1 and 65535")?;
        return Ok(None);
    }

    let mut request = SmbMutationRequest::new(
        rust_string(env, host)?,
        rust_string(env, share)?,
        rust_string(env, path)?,
        rust_string(env, username)?,
        rust_string(env, password)?,
    );
    request.port = port;
    request.domain = rust_string(env, domain)?;
    request.workstation = rust_string(env, workstation)?;
    Ok(Some(request))
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

/// Open a directory cursor. Kotlin must close this handle in finally.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_open_directory<'local>(
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
            let Some(request) = mutation_request(
                env,
                &host,
                port,
                &share,
                &path,
                &username,
                &password,
                &domain,
                &workstation,
            )?
            else {
                return Ok(0);
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.open_directory(request) {
                Ok(handle) => Ok(handle.raw() as jlong),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Return one signed SMB QUERY_DIRECTORY page; an XFL1 count=0 means EOF.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_read_directory_page<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> JByteArray<'local> {
    unowned_env
        .with_env(|env| -> JniResult<JByteArray<'local>> {
            if handle <= 0 {
                return throw_argument(env, "directory handle must be positive");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.read_directory_page(DirectoryHandle::from_raw(handle as u64)) {
                Ok(data) => env.byte_array_from_slice(&data),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Close the SMB handle even after a page read fails.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_close_directory<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            if handle <= 0 {
                return throw_argument(env, "directory handle must be positive");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.close_directory(DirectoryHandle::from_raw(handle as u64)) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Open a writable stream (OVERWRITE_IF) on one authenticated signed SMB session.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_open_writable<'local>(
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
            let Some(request) = mutation_request(
                env,
                &host,
                port,
                &share,
                &path,
                &username,
                &password,
                &domain,
                &workstation,
            )?
            else {
                return Ok(0);
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.open_writable(request) {
                Ok(handle) => Ok(handle.raw() as jlong),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// One bounded, non-replayed JNI positional WRITE from a Java ByteArray.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_write_at<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    position: jlong,
    source: JByteArray<'local>,
    source_offset: jint,
    length: jint,
) -> jint {
    unowned_env
        .with_env(|env| -> JniResult<jint> {
            if handle <= 0 {
                return throw_argument(env, "writable SMB handle must be positive");
            }
            if position < 0 {
                return throw_argument(env, "SMB write position must be nonnegative");
            }
            if source_offset < 0 || length < 0 {
                return throw_argument(env, "SMB write source range must be nonnegative");
            }
            if length as usize > 1024 * 1024 {
                return throw_argument(env, "SMB JNI write chunk exceeds 1 MiB");
            }
            let array_len = source.len(env)?;
            let Some(end) = (source_offset as usize).checked_add(length as usize) else {
                return throw_argument(env, "SMB write array range overflow");
            };
            if end > array_len {
                return throw_argument(env, "SMB write range exceeds source array");
            }

            let mut source_bytes = vec![0i8; length as usize];
            if length > 0 {
                source.get_region(env, source_offset, &mut source_bytes)?;
            }
            let bytes: Vec<u8> = source_bytes.into_iter().map(|byte| byte as u8).collect();
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.write_writable_at(
                WritableHandle::from_raw(handle as u64),
                position as u64,
                &bytes,
            ) {
                Ok(count) => match jint::try_from(count) {
                    Ok(count) => Ok(count),
                    Err(_) => throw_io(env, "SMB native write count exceeds Java Int"),
                },
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Explicit SMB2 FLUSH. A failed or poisoned handle must never return success.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_flush_writable<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            if handle <= 0 {
                return throw_argument(env, "writable SMB handle must be positive");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.flush_writable(WritableHandle::from_raw(handle as u64)) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Remove the writable handle then close it even if a previous WRITE failed.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_close_writable<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            if handle <= 0 {
                return throw_argument(env, "writable SMB handle must be positive");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.close_writable(WritableHandle::from_raw(handle as u64)) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Open an existing file without truncating it; unlike OVERWRITE_IF output streams.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_open_random<'local>(
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
            let Some(request) = mutation_request(
                env, &host, port, &share, &path, &username, &password, &domain, &workstation,
            )? else {
                return Ok(0);
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.open_random(request) {
                Ok(handle) => Ok(handle.raw() as jlong),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Read 0 for zero-byte request, -1 at EOF, and never return fabricated data on error.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_read_random_at<'local>(
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
            if handle <= 0 || position < 0 {
                return throw_argument(env, "random SMB handle and read position must be nonnegative");
            }
            if destination_offset < 0 || length < 0 || length > 1024 * 1024 {
                return throw_argument(env, "random SMB read range invalid or exceeds 1 MiB");
            }
            let array_len = destination.len(env)?;
            let Some(end) = (destination_offset as usize).checked_add(length as usize) else {
                return throw_argument(env, "random SMB destination range overflow");
            };
            if end > array_len {
                return throw_argument(env, "random SMB read exceeds destination array");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            let bytes = match engine.read_random_at(
                RandomHandle::from_raw(handle as u64),
                position as u64,
                length as usize,
            ) {
                Ok(bytes) => bytes,
                Err(error) => return throw_io(env, error),
            };
            if bytes.is_empty() && length != 0 {
                return Ok(-1);
            }
            destination.set_region(env, destination_offset, as_jbytes(&bytes))?;
            match jint::try_from(bytes.len()) {
                Ok(count) => Ok(count),
                Err(_) => throw_io(env, "random SMB read count exceeds Java Int"),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Position-based WRITE; return an error instead of retrying ambiguous partial writes.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_write_random_at<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    position: jlong,
    source: JByteArray<'local>,
    source_offset: jint,
    length: jint,
) -> jint {
    unowned_env
        .with_env(|env| -> JniResult<jint> {
            if handle <= 0 || position < 0 {
                return throw_argument(env, "random SMB handle and write position must be nonnegative");
            }
            if source_offset < 0 || length < 0 || length > 1024 * 1024 {
                return throw_argument(env, "random SMB write range invalid or exceeds 1 MiB");
            }
            let array_len = source.len(env)?;
            let Some(end) = (source_offset as usize).checked_add(length as usize) else {
                return throw_argument(env, "random SMB source range overflow");
            };
            if end > array_len {
                return throw_argument(env, "random SMB write exceeds source array");
            }
            let mut input = vec![0i8; length as usize];
            if length > 0 {
                source.get_region(env, source_offset, &mut input)?;
            }
            let bytes: Vec<u8> = input.into_iter().map(|byte| byte as u8).collect();
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.write_random_at(
                RandomHandle::from_raw(handle as u64),
                position as u64,
                &bytes,
            ) {
                Ok(count) => match jint::try_from(count) {
                    Ok(count) => Ok(count),
                    Err(_) => throw_io(env, "random SMB write count exceeds Java Int"),
                },
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Mutate the EOF of the existing open file, never a new/truncated file.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_set_random_length<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    length: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            if handle <= 0 || length < 0 {
                return throw_argument(env, "random SMB handle must be positive and length nonnegative");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.set_random_length(RandomHandle::from_raw(handle as u64), length as u64) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_flush_random<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            if handle <= 0 {
                return throw_argument(env, "random SMB handle must be positive");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.flush_random(RandomHandle::from_raw(handle as u64)) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Dispose of the native handle even if WRITE/SET_INFO/FLUSH previously failed.
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_close_random<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            if handle <= 0 {
                return throw_argument(env, "random SMB handle must be positive");
            }
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.close_random(RandomHandle::from_raw(handle as u64)) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Creates a single directory. Never retries the mutation or falls back to another backend.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_mkdir<'local>(
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
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            let Some(request) = mutation_request(
                env,
                &host,
                port,
                &share,
                &path,
                &username,
                &password,
                &domain,
                &workstation,
            )?
            else {
                return Ok(());
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.mkdir(request) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Creates one new empty regular file. Never overwrites or replays an ambiguous CREATE.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_create_file<'local>(
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
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            let Some(request) = mutation_request(
                env,
                &host,
                port,
                &share,
                &path,
                &username,
                &password,
                &domain,
                &workstation,
            )?
            else {
                return Ok(());
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.create_file(request) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Renames one entry inside its connected share, with no replace or retry.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_rename<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    host: JString<'local>,
    port: jint,
    share: JString<'local>,
    source: JString<'local>,
    destination: JString<'local>,
    username: JString<'local>,
    password: JString<'local>,
    domain: JString<'local>,
    workstation: JString<'local>,
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            let Some(request) = mutation_request(
                env,
                &host,
                port,
                &share,
                &source,
                &username,
                &password,
                &domain,
                &workstation,
            )?
            else {
                return Ok(());
            };
            let destination = rust_string(env, &destination)?;
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.rename(request, destination) {
                Ok(()) => Ok(()),
                Err(error) => throw_io(env, error),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// Deletes one regular file, without read-only recovery or directory recursion.
#[allow(clippy::too_many_arguments)]
#[jni_mangle("app.local1st.files.core.fs.rust.RustSmbNative")]
pub fn native_delete_file<'local>(
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
) {
    unowned_env
        .with_env(|env| -> JniResult<()> {
            let Some(request) = mutation_request(
                env,
                &host,
                port,
                &share,
                &path,
                &username,
                &password,
                &domain,
                &workstation,
            )?
            else {
                return Ok(());
            };
            let engine = match engine() {
                Ok(engine) => engine,
                Err(error) => return throw_io(env, error),
            };
            match engine.delete_file(request) {
                Ok(()) => Ok(()),
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
