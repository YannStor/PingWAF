//! Password-based encryption for self-contained configuration backups.
//!
//! The envelope is JSON with a public manifest and a base64 ciphertext. The
//! plaintext never leaves the control plane: S3 and GitHub receive this same
//! envelope, never the configuration or the backup password.

use std::io::Read as _;
use std::sync::{Arc, LazyLock};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use sea_orm::{
    AccessMode, DatabaseConnection, IsolationLevel, TransactionTrait,
};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::config_catalog::{self, VersionScope};
use crate::notify::secretbox;

fn open_instance_secrets(snapshot: &mut Value) -> Result<(), BackupError> {
    if let Some(rows) = snapshot
        .get_mut("tables")
        .and_then(|tables| tables.get_mut("ai_settings"))
        .and_then(Value::as_array_mut)
    {
        for row in rows {
            if let Some(api_key) = row.get_mut("api_key") {
                if let Some(value) = api_key.as_str() {
                    if value.starts_with("enc:v1:") {
                        let plain = secretbox::open_string(value).ok_or_else(|| {
                            BackupError::Operation(
                                "AI credential cannot be opened with this instance key".into(),
                            )
                        })?;
                        *api_key = json!(plain);
                    }
                }
            }
        }
    }
    if let Some(rows) = snapshot
        .get_mut("tables")
        .and_then(|tables| tables.get_mut("notification_channels"))
        .and_then(Value::as_array_mut)
    {
        for row in rows {
            let Some(config) =
                row.get_mut("config").and_then(Value::as_object_mut)
            else {
                continue;
            };
            for field in secretbox::SECRET_KEYS {
                if let Some(value) = config.get(field).and_then(Value::as_str) {
                    if value.starts_with("enc:v1:") {
                        let plain = secretbox::open_string(value).ok_or_else(|| {
                            BackupError::Operation(
                                "notification credential cannot be opened with this instance key"
                                    .into(),
                            )
                        })?;
                        config.insert(field.to_string(), json!(plain));
                    }
                }
            }
        }
    }
    Ok(())
}

fn seal_instance_secrets(snapshot: &mut Value) -> Result<(), BackupError> {
    let has_ai_secret = snapshot
        .get("tables")
        .and_then(|tables| tables.get("ai_settings"))
        .and_then(Value::as_array)
        .is_some_and(|rows| {
            rows.iter().any(|row| {
                row.get("api_key")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
        });
    let has_notification_secret = snapshot
        .get("tables")
        .and_then(|tables| tables.get("notification_channels"))
        .and_then(Value::as_array)
        .is_some_and(|rows| {
            rows.iter().any(|row| {
                row.get("config").and_then(Value::as_object).is_some_and(
                    |config| {
                        secretbox::SECRET_KEYS.iter().any(|field| {
                            config
                                .get(*field)
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                        })
                    },
                )
            })
        });
    if (has_ai_secret || has_notification_secret)
        && !secretbox::encryption_enabled()
    {
        return Err(BackupError::Operation(
            "PINGWAF_SECRET_KEY is required to restore sealed AI or notification credentials"
                .into(),
        ));
    }

    if let Some(rows) = snapshot
        .get_mut("tables")
        .and_then(|tables| tables.get_mut("ai_settings"))
        .and_then(Value::as_array_mut)
    {
        for row in rows {
            if let Some(api_key) = row.get_mut("api_key") {
                if let Some(value) = api_key.as_str() {
                    *api_key = json!(secretbox::seal_string(value));
                }
            }
        }
    }
    if let Some(rows) = snapshot
        .get_mut("tables")
        .and_then(|tables| tables.get_mut("notification_channels"))
        .and_then(Value::as_array_mut)
    {
        for row in rows {
            let Some(config) =
                row.get_mut("config").and_then(Value::as_object_mut)
            else {
                continue;
            };
            for field in secretbox::SECRET_KEYS {
                if let Some(value) = config.get(field).and_then(Value::as_str) {
                    config.insert(
                        field.to_string(),
                        json!(secretbox::seal_string(value)),
                    );
                }
            }
        }
    }
    Ok(())
}

static KDF_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(2)));

const AAD: &[u8] = b"pingwaf-config-backup-v1";
const FORMAT: &str = "pingwaf-config-backup";
const KDF_M_COST: u32 = 19 * 1024;
const KDF_T_COST: u32 = 2;
const KDF_P_COST: u32 = 1;
const MAX_ENVELOPE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_BACKUP_PASSWORD_CHARS: usize = 12;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup password must contain at least {MIN_BACKUP_PASSWORD_CHARS} characters")]
    Password,
    #[error("invalid backup file: {0}")]
    Format(String),
    #[error("backup checksum does not match")]
    Checksum,
    #[error("backup password is incorrect or the file was tampered with")]
    Decrypt,
    #[error("backup exceeds its size limit")]
    Limit,
    #[error("backup operation failed: {0}")]
    Operation(String),
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

#[derive(Debug)]
pub struct CreatedBackup {
    pub manifest: Value,
    pub payload: Vec<u8>,
    pub checksum: String,
    pub file_name: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_password(password: &str) -> Result<(), BackupError> {
    if password.chars().count() < MIN_BACKUP_PASSWORD_CHARS {
        return Err(BackupError::Password);
    }
    Ok(())
}

async fn derive_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], BackupError> {
    let password = password.as_bytes().to_vec();
    let salt = salt.to_vec();
    let _permit =
        KDF_PERMITS.clone().acquire_owned().await.map_err(|_| {
            BackupError::Operation("KDF queue is closed".into())
        })?;
    tokio::task::spawn_blocking(move || {
        let params = Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|error| BackupError::Operation(error.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(&password, &salt, &mut key)
            .map_err(|_| BackupError::Decrypt)?;
        Ok(key)
    })
    .await
    .map_err(|error| BackupError::Operation(error.to_string()))?
}

fn seal(
    key: &mut [u8; 32],
    nonce_bytes: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| {
        BackupError::Operation("could not construct AES key".into())
    })?;
    let key = LessSafeKey::new(unbound);
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(AAD),
        &mut buffer,
    )
    .map_err(|_| BackupError::Operation("AES-GCM sealing failed".into()))?;
    Ok(buffer)
}

fn open(
    key: &mut [u8; 32],
    nonce_bytes: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, BackupError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| {
        BackupError::Operation("could not construct AES key".into())
    })?;
    let key = LessSafeKey::new(unbound);
    let mut buffer = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(AAD),
            &mut buffer,
        )
        .map_err(|_| BackupError::Decrypt)?;
    Ok(plaintext.to_vec())
}

fn random<const N: usize>() -> Result<[u8; N], BackupError> {
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        BackupError::Operation("secure random source failed".into())
    })?;
    Ok(bytes)
}

pub async fn create_encrypted_backup(
    db: &DatabaseConnection,
    scope: VersionScope,
    password: &str,
) -> Result<CreatedBackup, BackupError> {
    let txn = db
        .begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await?;
    let created =
        create_encrypted_backup_with_connection(&txn, scope, password).await?;
    txn.commit().await?;
    Ok(created)
}

pub(crate) async fn create_encrypted_backup_with_connection<
    C: sea_orm::ConnectionTrait,
>(
    db: &C,
    scope: VersionScope,
    password: &str,
) -> Result<CreatedBackup, BackupError> {
    validate_password(password)?;
    let snapshot = config_catalog::capture(db, scope, true).await?;
    // Values sealed by the source instance must not be carried into another
    // instance as opaque `enc:v1` text. Open them before the backup password
    // protects the complete payload.
    let mut snapshot = snapshot;
    open_instance_secrets(&mut snapshot)?;

    let plaintext = serde_json::to_vec(&snapshot)
        .map_err(|error| BackupError::Operation(error.to_string()))?;
    if plaintext.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(BackupError::Limit);
    }
    let compressed = zstd::encode_all(plaintext.as_slice(), 3)
        .map_err(|error| BackupError::Operation(error.to_string()))?;
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let mut key =
        derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST).await?;
    let ciphertext = seal(&mut key, nonce, &compressed)?;
    key.fill(0);

    let plain_hash = hex(digest(&SHA256, &plaintext).as_ref());
    let checksum = hex(digest(&SHA256, &ciphertext).as_ref());
    let table_counts = snapshot
        .get("tables")
        .and_then(Value::as_object)
        .map(|tables| {
            tables
                .iter()
                .map(|(name, rows)| {
                    (name.clone(), json!(rows.as_array().map_or(0, Vec::len)))
                })
                .collect::<serde_json::Map<_, _>>()
        })
        .unwrap_or_default();
    let file_name = format!(
        "pingwaf-{}-{}-{}.pwb.json",
        scope.as_str(),
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let manifest = json!({
        "format": FORMAT,
        "version": 1,
        "scope": scope.as_str(),
        "site_id": scope.column_value(),
        "application_version": crate::boot_history::version(),
        "database_schema": 80,
        "created_at": chrono::Utc::now(),
        "tables": table_counts,
        "secret_policy": "password-encrypted-complete",
        "compression": "zstd",
        "kdf": {
            "name": "argon2id",
            "m_cost": KDF_M_COST,
            "t_cost": KDF_T_COST,
            "p_cost": KDF_P_COST,
            "salt": B64.encode(salt),
        },
        "cipher": {
            "name": "aes-256-gcm",
            "nonce": B64.encode(nonce),
        },
        "plaintext_sha256": plain_hash,
        "ciphertext_sha256": checksum,
    });
    let envelope = json!({
        "manifest": manifest,
        "payload": B64.encode(ciphertext),
    });
    let payload = serde_json::to_vec(&envelope)
        .map_err(|error| BackupError::Operation(error.to_string()))?;
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(BackupError::Limit);
    }
    Ok(CreatedBackup {
        manifest,
        payload,
        checksum,
        file_name,
    })
}

pub async fn decrypt_backup(
    payload: &[u8],
    password: &str,
    expected_scope: VersionScope,
) -> Result<(Value, Value), BackupError> {
    validate_password(password)?;
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(BackupError::Limit);
    }
    let envelope: Value = serde_json::from_slice(payload).map_err(|_| {
        BackupError::Format("not a JSON backup envelope".into())
    })?;
    let manifest = envelope
        .get("manifest")
        .cloned()
        .ok_or_else(|| BackupError::Format("missing manifest".into()))?;
    if envelope.get("format").is_some() {
        return Err(BackupError::Format(
            "format belongs in the manifest".into(),
        ));
    }
    if manifest.get("format").and_then(Value::as_str) != Some(FORMAT)
        || manifest.get("version").and_then(Value::as_i64) != Some(1)
    {
        return Err(BackupError::Format("unsupported backup format".into()));
    }
    if manifest.get("scope").and_then(Value::as_str)
        != Some(expected_scope.as_str())
    {
        return Err(BackupError::Format(
            "backup scope does not match the requested restore".into(),
        ));
    }
    let manifest_site = manifest.get("site_id").cloned().unwrap_or(Value::Null);
    if manifest_site != json!(expected_scope.column_value()) {
        return Err(BackupError::Format(
            "backup site_id does not match the requested restore".into(),
        ));
    }
    let encoded =
        envelope
            .get("payload")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                BackupError::Format("missing ciphertext payload".into())
            })?;
    let ciphertext = B64
        .decode(encoded)
        .map_err(|_| BackupError::Format("ciphertext is not base64".into()))?;
    let expected_checksum = manifest
        .get("ciphertext_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BackupError::Format("missing ciphertext checksum".into())
        })?;
    if hex(digest(&SHA256, &ciphertext).as_ref()) != expected_checksum {
        return Err(BackupError::Checksum);
    }

    let kdf = manifest
        .get("kdf")
        .ok_or_else(|| BackupError::Format("missing KDF parameters".into()))?;
    if kdf.get("name").and_then(Value::as_str) != Some("argon2id")
        || manifest
            .get("cipher")
            .and_then(|cipher| cipher.get("name"))
            .and_then(Value::as_str)
            != Some("aes-256-gcm")
        || manifest.get("compression").and_then(Value::as_str) != Some("zstd")
    {
        return Err(BackupError::Format(
            "unsupported backup encryption or compression algorithm".into(),
        ));
    }
    let number = |name: &str, default: u32| {
        kdf.get(name)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(default)
    };
    let m_cost = number("m_cost", KDF_M_COST);
    let t_cost = number("t_cost", KDF_T_COST);
    let p_cost = number("p_cost", KDF_P_COST);
    if !(8 * 1024..=64 * 1024).contains(&m_cost)
        || !(1..=4).contains(&t_cost)
        || !(1..=2).contains(&p_cost)
    {
        return Err(BackupError::Format(
            "KDF cost parameters are outside the permitted range".into(),
        ));
    }
    let salt = kdf
        .get("salt")
        .and_then(Value::as_str)
        .and_then(|value| B64.decode(value).ok())
        .filter(|salt| salt.len() == 16)
        .ok_or_else(|| BackupError::Format("invalid KDF salt".into()))?;
    let nonce = manifest
        .get("cipher")
        .and_then(|cipher| cipher.get("nonce"))
        .and_then(Value::as_str)
        .and_then(|value| B64.decode(value).ok())
        .and_then(|bytes| <[u8; 12]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| BackupError::Format("invalid AES nonce".into()))?;
    let mut key = derive_key(password, &salt, m_cost, t_cost, p_cost).await?;
    let compressed = open(&mut key, nonce, &ciphertext)?;
    key.fill(0);

    let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())
        .map_err(|error| BackupError::Operation(error.to_string()))?;
    let mut plaintext = Vec::new();
    decoder
        .take(MAX_PLAINTEXT_BYTES + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| {
            BackupError::Format("could not decompress the backup".into())
        })?;
    if plaintext.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(BackupError::Limit);
    }
    let expected_plain = manifest
        .get("plaintext_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BackupError::Format("missing plaintext checksum".into())
        })?;
    if hex(digest(&SHA256, &plaintext).as_ref()) != expected_plain {
        return Err(BackupError::Checksum);
    }
    let mut snapshot: Value =
        serde_json::from_slice(&plaintext).map_err(|_| {
            BackupError::Format("decrypted configuration is not JSON".into())
        })?;
    seal_instance_secrets(&mut snapshot)?;
    Ok((snapshot, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_passwords_are_refused() {
        assert!(matches!(
            validate_password("short"),
            Err(BackupError::Password)
        ));
        assert!(validate_password("a-long-backup-password").is_ok());
    }

    #[test]
    fn sha256_hex_has_the_expected_shape() {
        assert_eq!(hex(digest(&SHA256, b"abc").as_ref()).len(), 64);
    }

    #[tokio::test]
    async fn encryption_roundtrip_rejects_wrong_passwords_and_tampering() {
        let password = "correct-backup-password";
        let salt = [7u8; 16];
        let nonce = [9u8; 12];
        let mut key =
            derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)
                .await
                .expect("derive key");
        let ciphertext =
            seal(&mut key, nonce, b"configuration-secret").expect("seal");

        let mut same =
            derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)
                .await
                .expect("derive key again");
        assert_eq!(
            open(&mut same, nonce, &ciphertext).expect("open"),
            b"configuration-secret"
        );

        let mut wrong = derive_key(
            "wrong-backup-password",
            &salt,
            KDF_M_COST,
            KDF_T_COST,
            KDF_P_COST,
        )
        .await
        .expect("derive wrong key");
        assert!(matches!(
            open(&mut wrong, nonce, &ciphertext),
            Err(BackupError::Decrypt)
        ));

        let mut tampered = ciphertext.clone();
        if let Some(byte) = tampered.last_mut() {
            *byte ^= 1;
        }
        let mut same =
            derive_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)
                .await
                .expect("derive key once more");
        assert!(open(&mut same, nonce, &tampered).is_err());
    }
}
