//! Password hashing helpers built on bcrypt.

use std::sync::OnceLock;

use bcrypt::BcryptError;
pub use bcrypt::DEFAULT_COST;
use tokio::sync::Semaphore;

/// bcrypt only ever looks at the first 72 bytes of the input. Instead of
/// letting longer secrets fail at hash time we truncate on a character
/// boundary and document the limit.
pub const MAX_PASSWORD_BYTES: usize = 72;

/// Passwords shorter than this are rejected by the API layer.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Errors reported by the password helpers.
#[derive(Debug)]
pub enum PasswordError {
    TooShort,
    Backend(String),
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::TooShort => write!(
                f,
                "password must be at least {MIN_PASSWORD_LENGTH} characters long"
            ),
            PasswordError::Backend(msg) => write!(f, "password hashing failed: {msg}"),
        }
    }
}

impl std::error::Error for PasswordError {}

impl From<BcryptError> for PasswordError {
    fn from(err: BcryptError) -> Self {
        PasswordError::Backend(format!("{err:?}"))
    }
}

/// Truncates `plain` to at most [`MAX_PASSWORD_BYTES`] bytes without splitting a
/// UTF-8 sequence.
fn bcrypt_input(plain: &str) -> &str {
    if plain.len() <= MAX_PASSWORD_BYTES {
        return plain;
    }
    let mut end = MAX_PASSWORD_BYTES;
    while end > 0 && !plain.is_char_boundary(end) {
        end -= 1;
    }
    &plain[..end]
}

/// Hashes a plaintext password with the crate default cost.
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    if plain.len() < MIN_PASSWORD_LENGTH {
        return Err(PasswordError::TooShort);
    }
    Ok(bcrypt::hash(bcrypt_input(plain), DEFAULT_COST)?)
}

/// Hashes a plaintext password with an explicit cost (used by tests, where a low
/// cost keeps the suite fast).
pub fn hash_password_with_cost(
    plain: &str,
    cost: u32,
) -> Result<String, PasswordError> {
    Ok(bcrypt::hash(bcrypt_input(plain), cost)?)
}

/// Compares a plaintext password against a stored bcrypt hash.
///
/// Returns `Ok(false)` for a malformed or foreign-format hash so that callers can
/// treat every mismatch the same way.
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, PasswordError> {
    match bcrypt::verify(bcrypt_input(plain), hash) {
        Ok(valid) => Ok(valid),
        // A stored value that bcrypt cannot parse is simply "not a match".
        Err(BcryptError::InvalidHash(_)) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Ceiling on concurrent bcrypt work. One call at the default cost spends
/// hundreds of milliseconds of CPU; running it inline on the async runtime (or
/// letting an unbounded number of blocking tasks through) starves the reactor.
const BCRYPT_CONCURRENCY: usize = 4;

static BCRYPT_PERMITS: OnceLock<Semaphore> = OnceLock::new();

fn bcrypt_permits() -> &'static Semaphore {
    BCRYPT_PERMITS.get_or_init(|| Semaphore::new(BCRYPT_CONCURRENCY))
}

/// [`verify_password`] on the blocking pool, bounded by a process-wide
/// semaphore so a burst of visitor logins cannot occupy every worker.
pub async fn verify_password_offloaded(
    plain: String,
    hash: String,
) -> Result<bool, PasswordError> {
    let permit = bcrypt_permits()
        .acquire()
        .await
        .map_err(|err| PasswordError::Backend(err.to_string()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_password(&plain, &hash)
    })
    .await
    .map_err(|err| PasswordError::Backend(err.to_string()))?
}

/// [`hash_password`] on the blocking pool, under the same ceiling.
pub async fn hash_password_offloaded(
    plain: String,
) -> Result<String, PasswordError> {
    let permit = bcrypt_permits()
        .acquire()
        .await
        .map_err(|err| PasswordError::Backend(err.to_string()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&plain)
    })
    .await
    .map_err(|err| PasswordError::Backend(err.to_string()))?
}

/// Cheap structural check used by the registration endpoints: rejects empty and
/// obviously weak secrets before spending CPU on bcrypt.
pub fn validate_password(plain: &str) -> Result<(), PasswordError> {
    if plain.len() < MIN_PASSWORD_LENGTH {
        return Err(PasswordError::TooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_verifiable_and_salted() {
        let hash = hash_password_with_cost("correct horse battery", 4).unwrap();
        assert!(hash.starts_with("$2"));
        assert!(verify_password("correct horse battery", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn short_passwords_are_rejected() {
        assert!(matches!(
            hash_password("short"),
            Err(PasswordError::TooShort)
        ));
    }

    #[test]
    fn garbage_hash_is_not_a_match() {
        assert!(!verify_password("whatever", "not-a-bcrypt-hash").unwrap());
    }

    #[tokio::test]
    async fn offloaded_helpers_match_the_sync_ones() {
        let hash = hash_password_offloaded("correct horse battery".to_string())
            .await
            .unwrap();
        assert!(verify_password_offloaded(
            "correct horse battery".to_string(),
            hash.clone()
        )
        .await
        .unwrap());
        assert!(
            !verify_password_offloaded("wrong password".to_string(), hash)
                .await
                .unwrap()
        );
    }

    #[test]
    fn long_passwords_are_truncated_on_a_char_boundary() {
        let long = "é".repeat(60); // 120 bytes
        assert!(long.len() > MAX_PASSWORD_BYTES);
        let truncated = bcrypt_input(&long);
        assert!(truncated.len() <= MAX_PASSWORD_BYTES);
        assert!(truncated.chars().all(|c| c == 'é'));
    }
}
