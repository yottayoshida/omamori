//! Audit HMAC secret management, symlink-safe file I/O, and key rotation.
//!
//! SECURITY: Functions in this module handle cryptographic key material.
//! All functions are `pub(super)` — they must NEVER be `pub(crate)` or `pub`.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::AuditConfig;
use super::verify::AuditError;

// ---------------------------------------------------------------------------
// File locking (platform-specific)
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub(super) fn flock_exclusive(file: &fs::File) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn flock_exclusive(_file: &fs::File) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn flock_shared(file: &fs::File) -> Result<(), std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn flock_shared(_file: &fs::File) -> Result<(), std::io::Error> {
    Ok(())
}

// ---------------------------------------------------------------------------
// HMAC targets (event field hashing)
// ---------------------------------------------------------------------------

use super::chain::HmacSha256;
use hmac::Mac;

pub(super) fn hmac_targets(secret: Option<&[u8; 32]>, targets: &[&str]) -> String {
    let Some(key) = secret else {
        return "NO_HMAC_SECRET".to_string();
    };
    let mut mac =
        HmacSha256::new_from_slice(key).expect("32-byte key is always valid for HMAC-SHA256");
    for target in targets {
        mac.update(target.as_bytes());
        mac.update(&[0]); // null separator between targets
    }
    format!("hmac-sha256:{:x}", mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Secret path helpers
// ---------------------------------------------------------------------------

pub(super) fn secret_path_for(audit_path: &Path) -> PathBuf {
    audit_path.with_file_name("audit-secret")
}

/// Determine the current key_id based on retired key files.
/// "default" if no rotation has occurred; "key-N" where N = retired_count + 1.
pub(super) fn current_key_id(secret_path: &Path) -> String {
    let count = retired_key_count(secret_path);
    if count == 0 {
        "default".to_string()
    } else {
        format!("key-{}", count + 1)
    }
}

/// Count how many retired key files exist (audit-secret.N.retired).
pub(super) fn retired_key_count(secret_path: &Path) -> usize {
    let Some(parent) = secret_path.parent() else {
        return 0;
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("audit-secret.")
                && e.file_name().to_string_lossy().ends_with(".retired")
        })
        .count()
}

/// Load all keys (active + retired) into a key_id → secret mapping.
/// Used by verify_chain for multi-key verification.
pub(super) fn load_keyring(secret_path: &Path) -> std::collections::HashMap<String, [u8; 32]> {
    let mut keyring = std::collections::HashMap::new();

    // Active key → current key_id
    if let Ok(secret) = read_secret(secret_path) {
        keyring.insert(current_key_id(secret_path), secret);
        // Also register as "default" if no rotation has occurred
        if retired_key_count(secret_path) == 0 {
            keyring.insert("default".to_string(), secret);
        }
    }

    // Retired keys → key-1, key-2, ...
    if let Some(parent) = secret_path.parent() {
        for n in 1.. {
            let retired_path = parent.join(format!("audit-secret.{n}.retired"));
            match read_secret(&retired_path) {
                Ok(secret) => {
                    // First retired key was originally "default"
                    if n == 1 {
                        keyring.insert("default".to_string(), secret);
                    }
                    keyring.insert(format!("key-{n}"), secret);
                }
                Err(_) => break,
            }
        }
    }

    keyring
}

// ---------------------------------------------------------------------------
// Secret I/O (symlink-safe)
// ---------------------------------------------------------------------------

pub(super) fn load_or_create_secret(path: &Path) -> Option<[u8; 32]> {
    if let Ok(secret) = read_secret(path) {
        return Some(secret);
    }
    match create_secret(path) {
        Ok(secret) => Some(secret),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match read_secret(path) {
            Ok(secret) => Some(secret),
            Err(e) => {
                eprintln!("omamori warning: audit secret race: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("omamori warning: audit secret unavailable: {e}");
            None
        }
    }
}

pub(super) fn read_secret(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let file = open_read_nofollow(path)?;
    let mut hex = String::new();
    std::io::BufReader::new(file).read_to_string(&mut hex)?;
    decode_hex_secret(hex.trim())
}

pub(super) fn create_secret(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let mut secret = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path).map_err(|e| eloop_message(e, path))?;
    file.write_all(hex.as_bytes())?;

    Ok(secret)
}

pub(super) fn decode_hex_secret(hex: &str) -> Result<[u8; 32], std::io::Error> {
    if hex.len() != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit secret must be exactly 64 hex characters",
        ));
    }
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid hex in audit secret",
            )
        })?;
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Symlink-safe open helpers (O_NOFOLLOW)
// ---------------------------------------------------------------------------

/// Open a file for reading, refusing symlinks on Unix.
pub(super) fn open_read_nofollow(path: &Path) -> Result<fs::File, std::io::Error> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path).map_err(|e| eloop_message(e, path))
}

/// Open audit.jsonl for read+write+create, refusing symlinks on Unix.
pub(super) fn open_audit_rw(path: &Path) -> Result<fs::File, std::io::Error> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path).map_err(|e| eloop_message(e, path))
}

/// Convert ELOOP into a user-friendly error message.
fn eloop_message(e: std::io::Error, path: &Path) -> std::io::Error {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return std::io::Error::new(
            e.kind(),
            format!(
                "audit path is a symlink (possible attack): {}",
                path.display()
            ),
        );
    }
    e
}

// ---------------------------------------------------------------------------
// Default paths
// ---------------------------------------------------------------------------

pub(super) fn default_audit_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
        .join("omamori")
        .join("audit.jsonl")
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

/// Result of a key rotation operation.
pub struct RotationResult {
    pub new_key_id: String,
    pub retired_path: PathBuf,
}

/// Rotate the audit HMAC key.
///
/// 1. Rename current secret to audit-secret.N.retired
/// 2. Generate a new secret at audit-secret
/// 3. New entries will use the new key_id
/// 4. verify_chain uses keyring to verify old entries with old key
pub fn rotate_key(config: &AuditConfig) -> Result<RotationResult, AuditError> {
    let path = config.path.clone().unwrap_or_else(default_audit_path);
    let secret_path = secret_path_for(&path);

    // Verify current secret exists
    read_secret(&secret_path).map_err(|_| AuditError::SecretUnavailable)?;

    // Determine retired key number
    let n = retired_key_count(&secret_path) + 1;
    let retired_path = secret_path
        .parent()
        .unwrap()
        .join(format!("audit-secret.{n}.retired"));

    // Rename active → retired
    fs::rename(&secret_path, &retired_path).map_err(AuditError::Io)?;

    // Set restrictive permissions on retired key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&retired_path, fs::Permissions::from_mode(0o600));
    }

    // Generate new secret
    create_secret(&secret_path).map_err(AuditError::Io)?;

    let new_key_id = format!("key-{}", n + 1);
    Ok(RotationResult {
        new_key_id,
        retired_path,
    })
}
