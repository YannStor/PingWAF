pub mod page;
pub mod verify;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::cookie::{ClearanceLevel, ClearancePayload, CookieManager};
use crate::fingerprint::BrowserFingerprint;
use page::{
    generate_interactive_challenge_html, generate_js_challenge_html,
    ChallengePageParams,
};
use verify::{
    check_browser_integrity, verify_proof_of_work, verify_timestamp,
    IntegrityResult,
};

/// Configuration for the challenge system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Whether challenges are enabled
    pub enabled: bool,
    /// Under attack mode (challenge everything)
    pub under_attack_mode: bool,
    /// Default challenge level required
    pub default_level: ClearanceLevel,
    /// How long clearance lasts (seconds)
    pub clearance_duration_secs: i64,
    /// Paths exempt from challenge
    pub exempt_paths: Vec<String>,
    /// User agents exempt from challenge (health checks, etc.)
    pub exempt_user_agents: Vec<String>,
    /// Request rate threshold to trigger challenge (requests/min per IP)
    pub rate_threshold: u32,
    /// Whether to check browser integrity
    pub browser_integrity_check: bool,
    /// Whether to check TLS fingerprint
    pub tls_fingerprint_check: bool,
    /// Secret for signing cookies
    pub cookie_secret: String,
    /// Cookie name
    pub cookie_name: String,
    /// Proof-of-work difficulty (leading zero bits required)
    pub pow_difficulty: u32,
    /// Maximum age of a challenge submission (seconds)
    pub submission_max_age_secs: i64,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            under_attack_mode: false,
            default_level: ClearanceLevel::NonInteractive,
            clearance_duration_secs: 1800, // 30 minutes
            exempt_paths: vec!["/health".to_string(), "/ping".to_string()],
            exempt_user_agents: vec![],
            rate_threshold: 100,
            browser_integrity_check: true,
            tls_fingerprint_check: false,
            cookie_secret: "change-me".to_string(),
            cookie_name: "__pingwaf_clearance".to_string(),
            pow_difficulty: 20,
            submission_max_age_secs: 300, // 5 minutes
        }
    }
}

/// The challenge engine decides whether to challenge and generates pages
pub struct ChallengeEngine {
    config: ChallengeConfig,
    cookie_manager: CookieManager,
}

impl ChallengeEngine {
    /// Create a new ChallengeEngine with the given configuration
    pub fn new(config: ChallengeConfig) -> Self {
        let cookie_manager = CookieManager::with_name(
            config.cookie_secret.as_bytes(),
            config.clearance_duration_secs,
            &config.cookie_name,
        );
        Self {
            config,
            cookie_manager,
        }
    }

    /// Check if a request should be challenged
    pub fn should_challenge(
        &self,
        request: &ChallengeRequest,
    ) -> ChallengeDecision {
        // If challenges are disabled, always pass
        if !self.config.enabled {
            return ChallengeDecision::Pass;
        }

        // Check exempt paths
        if self.is_exempt_path(&request.path) {
            return ChallengeDecision::Pass;
        }

        // Check exempt user agents
        if self.is_exempt_user_agent(&request.user_agent) {
            return ChallengeDecision::Pass;
        }

        // Check existing clearance cookie
        if let Some(clearance) = self.extract_clearance(request) {
            match self.cookie_manager.validate_clearance(&clearance) {
                Ok(payload) => {
                    // A clearance earned on one site must not exempt another.
                    // Every site's engine signs with the same secret, so a
                    // valid signature says only that this deployment issued
                    // the cookie; the embedded site id is what binds it. The
                    // WAF's clearance path compares the same field
                    // (`pingap_plugin::waf::clearance_valid`). A cookie for
                    // somewhere else is treated as no cookie at all.
                    if !self.cookie_bound_to_site(&payload, request) {
                        return self.decide_challenge_level(request);
                    }
                    if self
                        .cookie_manager
                        .level_sufficient(&payload, self.config.default_level)
                    {
                        return ChallengeDecision::Pass;
                    }
                    // Clearance exists but level insufficient — escalate
                    return self.decide_challenge_level(request);
                },
                Err(_) => {
                    // Invalid/expired cookie — challenge
                },
            }
        }

        // Under attack mode: challenge everything
        if self.config.under_attack_mode {
            return ChallengeDecision::JsChallenge;
        }

        // Rate-based challenge
        if request.request_rate > self.config.rate_threshold {
            return self.decide_challenge_level(request);
        }

        // No challenge needed for normal traffic without a cookie
        // (challenge only on rate threshold or under_attack_mode)
        ChallengeDecision::Pass
    }

    /// Generate the JS challenge page (5-second shield)
    pub fn generate_js_challenge_page(
        &self,
        request_id: &str,
        original_url: &str,
    ) -> ChallengeResponse {
        let challenge_nonce = issue_nonce(self.config.cookie_secret.as_bytes());
        let params = ChallengePageParams {
            request_id: request_id.to_string(),
            challenge_nonce,
            difficulty: self.config.pow_difficulty,
            verify_endpoint: "/_pingwaf/challenge/verify".to_string(),
            original_url: original_url.to_string(),
            brand_name: "PingWAF".to_string(),
        };

        let body = generate_js_challenge_html(&params);

        ChallengeResponse {
            status_code: 503,
            content_type: "text/html; charset=utf-8".to_string(),
            body,
            headers: vec![
                (
                    "Cache-Control".to_string(),
                    "no-store, no-cache, must-revalidate".to_string(),
                ),
                ("Pragma".to_string(), "no-cache".to_string()),
                ("X-Frame-Options".to_string(), "DENY".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("X-PingWAF-Ray".to_string(), request_id.to_string()),
            ],
        }
    }

    /// Generate the interactive challenge page (CAPTCHA-style)
    pub fn generate_interactive_challenge_page(
        &self,
        request_id: &str,
        original_url: &str,
    ) -> ChallengeResponse {
        let challenge_nonce = issue_nonce(self.config.cookie_secret.as_bytes());
        let params = ChallengePageParams {
            request_id: request_id.to_string(),
            challenge_nonce,
            difficulty: self.config.pow_difficulty,
            verify_endpoint: "/_pingwaf/challenge/verify".to_string(),
            original_url: original_url.to_string(),
            brand_name: "PingWAF".to_string(),
        };

        let body = generate_interactive_challenge_html(&params);

        ChallengeResponse {
            status_code: 503,
            content_type: "text/html; charset=utf-8".to_string(),
            body,
            headers: vec![
                (
                    "Cache-Control".to_string(),
                    "no-store, no-cache, must-revalidate".to_string(),
                ),
                ("Pragma".to_string(), "no-cache".to_string()),
                ("X-Frame-Options".to_string(), "DENY".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("X-PingWAF-Ray".to_string(), request_id.to_string()),
            ],
        }
    }

    /// Verify a challenge solution submission. `secure` reflects whether the
    /// request arrived over TLS and controls the clearance cookie's `Secure`
    /// attribute.
    pub fn verify_solution(
        &self,
        submission: &ChallengeSubmission,
        secure: bool,
    ) -> VerifyResult {
        // 1. Verify timestamp (prevent replay)
        if !verify_timestamp(
            submission.timestamp,
            self.config.submission_max_age_secs,
        ) {
            return VerifyResult::Failed {
                reason: "submission expired or timestamp invalid".to_string(),
            };
        }

        // 2. The nonce must be one this engine issued and has not expired:
        // otherwise a client can pick its own nonce, solve once offline and
        // replay the pair forever.
        if !verify_nonce(
            self.config.cookie_secret.as_bytes(),
            &submission.challenge_nonce,
            self.config.submission_max_age_secs,
        ) {
            return VerifyResult::Failed {
                reason: "challenge nonce is invalid or expired".to_string(),
            };
        }
        // 3. A nonce is single-use: replaying a solved pair must not mint a
        // second clearance cookie.
        if !consume_nonce(
            &submission.challenge_nonce,
            Duration::from_secs(
                self.config.submission_max_age_secs.max(1) as u64
            ),
        ) {
            return VerifyResult::Failed {
                reason: "challenge nonce was already used".to_string(),
            };
        }

        // 4. Verify proof-of-work
        if !verify_proof_of_work(
            &submission.challenge_nonce,
            &submission.solution,
            self.config.pow_difficulty,
        ) {
            return VerifyResult::Failed {
                reason: "proof-of-work verification failed".to_string(),
            };
        }

        // 3. Parse and check browser fingerprint
        let fingerprint =
            match BrowserFingerprint::from_json(&submission.fingerprint_json) {
                Ok(fp) => fp,
                Err(e) => {
                    return VerifyResult::Failed {
                        reason: format!("invalid fingerprint data: {e}"),
                    };
                },
            };

        // 4. Browser integrity check
        if self.config.browser_integrity_check {
            match check_browser_integrity(&fingerprint, &fingerprint.user_agent)
            {
                IntegrityResult::Passed => {},
                IntegrityResult::Suspicious(reason) => {
                    tracing::warn!(
                        request_id = %submission.request_id,
                        reason = %reason,
                        "suspicious browser detected during challenge"
                    );
                    // Still allow, but log it
                },
                IntegrityResult::Failed(reason) => {
                    tracing::warn!(
                        request_id = %submission.request_id,
                        reason = %reason,
                        "browser integrity check failed"
                    );
                    return VerifyResult::Failed {
                        reason: format!(
                            "browser integrity check failed: {reason}"
                        ),
                    };
                },
            }
        }

        // 5. Issue clearance cookie
        let fp_hash = fingerprint.hash();
        let (cookie_value, payload) =
            self.cookie_manager.issue_clearance_with_payload(
                self.config.default_level,
                &submission.site_id,
                &fp_hash,
            );
        let cookie_attributes =
            self.cookie_manager.cookie_attributes(&payload, secure);

        tracing::info!(
            request_id = %submission.request_id,
            level = ?self.config.default_level,
            "challenge passed, clearance issued"
        );

        VerifyResult::Success {
            cookie_value,
            cookie_attributes,
        }
    }

    /// Validate an existing clearance cookie
    pub fn validate_clearance(
        &self,
        cookie_value: &str,
    ) -> Option<ClearancePayload> {
        self.cookie_manager.validate_clearance(cookie_value).ok()
    }

    /// Update configuration (hot reload)
    pub fn update_config(&mut self, config: ChallengeConfig) {
        self.cookie_manager = CookieManager::with_name(
            config.cookie_secret.as_bytes(),
            config.clearance_duration_secs,
            &config.cookie_name,
        );
        self.config = config;
    }

    /// Get a reference to the current configuration
    pub fn config(&self) -> &ChallengeConfig {
        &self.config
    }

    /// Get the cookie name
    pub fn cookie_name(&self) -> &str {
        self.cookie_manager.cookie_name()
    }

    // --- Internal helpers ---

    /// Check if a path is exempt from challenges
    fn is_exempt_path(&self, path: &str) -> bool {
        self.config.exempt_paths.iter().any(|exempt| {
            if exempt.ends_with('*') {
                // Wildcard match: /api/* matches /api/foo
                let prefix = &exempt[..exempt.len() - 1];
                path.starts_with(prefix)
            } else {
                path == exempt
            }
        })
    }

    /// Check if a user agent is exempt from challenges
    fn is_exempt_user_agent(&self, user_agent: &str) -> bool {
        if self.config.exempt_user_agents.is_empty() {
            return false;
        }
        let ua_lower = user_agent.to_lowercase();
        self.config
            .exempt_user_agents
            .iter()
            .any(|exempt| ua_lower.contains(&exempt.to_lowercase()))
    }

    /// Extract the clearance cookie value from the request
    fn extract_clearance(&self, request: &ChallengeRequest) -> Option<String> {
        let cookie_name = self.cookie_manager.cookie_name();
        request
            .cookies
            .iter()
            .find(|(name, _)| name == cookie_name)
            .map(|(_, value)| value.clone())
    }

    /// Whether a validated clearance was issued for the site this request is
    /// for. A caller that names no site keeps the previous behaviour: it has
    /// no boundary to enforce, and inventing one would reject every cookie.
    fn cookie_bound_to_site(
        &self,
        payload: &ClearancePayload,
        request: &ChallengeRequest,
    ) -> bool {
        request.site_id.is_empty() || payload.site_id == request.site_id
    }

    /// Whether a validated clearance satisfies the level this engine
    /// requires. Exposed so a caller that short-circuits before
    /// [`should_challenge`](Self::should_challenge) can apply the same rule
    /// instead of accepting any signed cookie.
    pub fn clearance_level_sufficient(
        &self,
        payload: &ClearancePayload,
    ) -> bool {
        self.cookie_manager
            .level_sufficient(payload, self.config.default_level)
    }

    /// Decide the challenge level based on request context
    fn decide_challenge_level(
        &self,
        request: &ChallengeRequest,
    ) -> ChallengeDecision {
        // High rate: use interactive challenge
        if request.request_rate > self.config.rate_threshold * 3 {
            return ChallengeDecision::InteractiveChallenge;
        }

        // Medium-high rate: managed challenge
        if request.request_rate > self.config.rate_threshold * 2 {
            return ChallengeDecision::ManagedChallenge;
        }

        // Default: JS challenge
        ChallengeDecision::JsChallenge
    }
}

/// Represents an incoming request for challenge evaluation
#[derive(Debug, Clone)]
pub struct ChallengeRequest {
    /// Request path
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Client IP address
    pub client_ip: String,
    /// User-Agent header
    pub user_agent: String,
    /// Parsed cookies (name, value pairs)
    pub cookies: Vec<(String, String)>,
    /// Whether the client has demonstrated JS support (from previous interaction)
    pub has_js_support: Option<bool>,
    /// Request rate per minute from this IP
    pub request_rate: u32,
    /// Site this request is for. A clearance cookie carries the site it was
    /// issued for, and per-site engines share one signing secret, so the
    /// signature alone only proves that *some* site in this deployment issued
    /// the cookie — without this the site id in the payload cannot be
    /// compared to anything, and one solved challenge exempted every site.
    /// Empty when the caller has no site notion, which keeps the previous
    /// behaviour for callers that never had a boundary to enforce.
    pub site_id: String,
}

/// Decision made by the challenge engine
#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeDecision {
    /// Allow through (has valid clearance or doesn't need challenge)
    Pass,
    /// Show JS challenge page (5-second shield)
    JsChallenge,
    /// Show managed challenge (system decides between JS and interactive)
    ManagedChallenge,
    /// Show interactive challenge (CAPTCHA)
    InteractiveChallenge,
    /// Block completely
    Block,
}

/// Response to send back for a challenge
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// HTTP status code (usually 503)
    pub status_code: u16,
    /// Content-Type header value
    pub content_type: String,
    /// The challenge page HTML body
    pub body: String,
    /// Additional response headers
    pub headers: Vec<(String, String)>,
}

/// Data submitted by the challenge page after solving
#[derive(Debug, Clone)]
pub struct ChallengeSubmission {
    /// The request ID that was issued with the challenge
    pub request_id: String,
    /// The challenge nonce that was issued
    pub challenge_nonce: String,
    /// Computed proof-of-work answer from the browser
    pub solution: String,
    /// Browser fingerprint data (JSON string)
    pub fingerprint_json: String,
    /// Unix timestamp when the solution was computed
    pub timestamp: i64,
    /// Site ID for the clearance cookie
    pub site_id: String,
}

/// Result of verifying a challenge submission
#[derive(Debug)]
pub enum VerifyResult {
    /// Verification succeeded — includes the clearance cookie value and attributes
    Success {
        cookie_value: String,
        cookie_attributes: String,
    },
    /// Verification failed — includes the reason
    Failed { reason: String },
}

type HmacSha256 = Hmac<Sha256>;

/// Upper bound on remembered nonces; reaching it rejects new submissions
/// rather than growing without bound.
const MAX_USED_NONCES: usize = 100_000;

static USED_NONCES: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn nonce_signature(secret: &[u8], body: &str) -> String {
    // HMAC accepts keys of any length; the guard only satisfies the API.
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Issues a nonce the client cannot forge: `<random>.<unix-seconds>.<hmac>`.
fn issue_nonce(secret: &[u8]) -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.random()).collect();
    let issued_at = chrono::Utc::now().timestamp();
    let body = format!("{}.{}", hex::encode(bytes), issued_at);
    let signature = nonce_signature(secret, &body);
    format!("{body}.{signature}")
}

/// Whether `nonce` was issued by this engine and is still fresh.
fn verify_nonce(secret: &[u8], nonce: &str, max_age_secs: i64) -> bool {
    let mut parts = nonce.rsplitn(3, '.');
    let (Some(signature), Some(issued_at), Some(random)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if random.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(issued_at) = issued_at.parse::<i64>() else {
        return false;
    };
    let now = chrono::Utc::now().timestamp();
    // A little clock skew is tolerable; anything older than the submission
    // window is not.
    if issued_at > now + 30 || now.saturating_sub(issued_at) > max_age_secs {
        return false;
    }
    let expected = nonce_signature(secret, &format!("{random}.{issued_at}"));
    if expected.len() != signature.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in expected.as_bytes().iter().zip(signature.as_bytes()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Marks `nonce` as used. Returns false when it was already spent (replay) or
/// the table is saturated (fail closed).
fn consume_nonce(nonce: &str, ttl: Duration) -> bool {
    let now = Instant::now();
    let mut used = USED_NONCES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    used.retain(|_, seen| now.duration_since(*seen) < ttl);
    if used.len() >= MAX_USED_NONCES || used.contains_key(nonce) {
        return false;
    }
    used.insert(nonce.to_string(), now);
    true
}

/// Generate a random request ID (shorter, for display)
pub fn generate_request_id() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..8).map(|_| rng.random()).collect();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ChallengeConfig {
        ChallengeConfig {
            cookie_secret: "test-secret-for-unit-tests".to_string(),
            pow_difficulty: 0, // No PoW required in tests
            rate_threshold: 10,
            ..Default::default()
        }
    }

    /// The site `test_request()` names. A clearance cookie is only recognised
    /// when it was issued for this site id, so the helper that mints one has
    /// to use it too.
    const TEST_SITE_ID: &str = "example.com";

    fn test_request() -> ChallengeRequest {
        ChallengeRequest {
            path: "/".to_string(),
            method: "GET".to_string(),
            client_ip: "192.168.1.1".to_string(),
            user_agent:
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
                    .to_string(),
            cookies: vec![],
            has_js_support: None,
            request_rate: 5,
            site_id: TEST_SITE_ID.to_string(),
        }
    }

    #[test]
    fn test_disabled_always_passes() {
        let config = ChallengeConfig {
            enabled: false,
            ..test_config()
        };
        let engine = ChallengeEngine::new(config);
        let decision = engine.should_challenge(&test_request());
        assert_eq!(decision, ChallengeDecision::Pass);
    }

    #[test]
    fn test_exempt_path_passes() {
        let engine = ChallengeEngine::new(test_config());
        let mut request = test_request();
        request.path = "/health".to_string();
        request.request_rate = 1000; // Even with high rate
        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::Pass);
    }

    #[test]
    fn test_exempt_user_agent_passes() {
        let config = ChallengeConfig {
            exempt_user_agents: vec!["kube-probe".to_string()],
            ..test_config()
        };
        let engine = ChallengeEngine::new(config);
        let mut request = test_request();
        request.user_agent = "kube-probe/1.28".to_string();
        request.request_rate = 1000;
        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::Pass);
    }

    #[test]
    fn test_under_attack_mode_challenges() {
        let config = ChallengeConfig {
            under_attack_mode: true,
            ..test_config()
        };
        let engine = ChallengeEngine::new(config);
        let decision = engine.should_challenge(&test_request());
        assert_eq!(decision, ChallengeDecision::JsChallenge);
    }

    #[test]
    fn test_rate_threshold_triggers_challenge() {
        let engine = ChallengeEngine::new(test_config());
        let mut request = test_request();
        request.request_rate = 15; // Above threshold of 10
        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::JsChallenge);
    }

    #[test]
    fn test_high_rate_triggers_interactive() {
        let engine = ChallengeEngine::new(test_config());
        let mut request = test_request();
        request.request_rate = 35; // Above 3x threshold (10*3=30)
        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::InteractiveChallenge);
    }

    #[test]
    fn test_medium_rate_triggers_managed() {
        let engine = ChallengeEngine::new(test_config());
        let mut request = test_request();
        request.request_rate = 25; // Above 2x threshold (10*2=20) but below 3x
        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::ManagedChallenge);
    }

    #[test]
    fn test_valid_clearance_cookie_passes() {
        let engine = ChallengeEngine::new(test_config());

        // Issue a clearance cookie
        let cookie_value = engine.cookie_manager_issue_clearance();

        let mut request = test_request();
        request.cookies =
            vec![("__pingwaf_clearance".to_string(), cookie_value)];
        request.request_rate = 1000; // Even with high rate, valid cookie should pass

        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::Pass);
    }

    #[test]
    fn test_clearance_from_another_site_does_not_pass() {
        let engine = ChallengeEngine::new(test_config());

        // Signed with the same secret — every site's engine shares it — so
        // nothing but the embedded site id tells the two apart. Without the
        // binding, one solved challenge exempted every site in the
        // deployment.
        let cookie_value = engine.cookie_manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "other.example.com",
            "test-fingerprint-hash",
        );

        let mut request = test_request();
        request.cookies =
            vec![("__pingwaf_clearance".to_string(), cookie_value)];
        request.request_rate = 1000;

        assert_ne!(
            engine.should_challenge(&request),
            ChallengeDecision::Pass,
            "a clearance earned elsewhere must not exempt this site"
        );
    }

    #[test]
    fn test_clearance_without_a_named_site_keeps_the_previous_behaviour() {
        // A caller with no site notion has no boundary to enforce; rejecting
        // every cookie there would just break it.
        let engine = ChallengeEngine::new(test_config());
        let cookie_value = engine.cookie_manager_issue_clearance();

        let mut request = test_request();
        request.site_id = String::new();
        request.cookies =
            vec![("__pingwaf_clearance".to_string(), cookie_value)];
        request.request_rate = 1000;

        assert_eq!(engine.should_challenge(&request), ChallengeDecision::Pass);
    }

    #[test]
    fn test_normal_traffic_passes() {
        let engine = ChallengeEngine::new(test_config());
        let request = test_request(); // rate=5, below threshold=10
        let decision = engine.should_challenge(&request);
        assert_eq!(decision, ChallengeDecision::Pass);
    }

    #[test]
    fn test_generate_js_challenge_page() {
        let engine = ChallengeEngine::new(test_config());
        let response =
            engine.generate_js_challenge_page("ray-123", "/protected");
        assert_eq!(response.status_code, 503);
        assert!(response.content_type.contains("text/html"));
        assert!(response.body.contains("ray-123"));
        assert!(response.body.contains("/protected"));
        assert!(response
            .headers
            .iter()
            .any(|(k, v)| k == "Cache-Control" && v.contains("no-store")));
    }

    #[test]
    fn test_verify_solution_success() {
        let config = ChallengeConfig {
            browser_integrity_check: false, // Skip for this test
            ..test_config()
        };
        let engine = ChallengeEngine::new(config);

        let submission = ChallengeSubmission {
            request_id: "test-ray".to_string(),
            challenge_nonce: issue_nonce(
                engine.config.cookie_secret.as_bytes(),
            ),
            solution: "anything".to_string(), // difficulty=0, any solution passes
            fingerprint_json: r#"{"user_agent":"Mozilla/5.0 Chrome/120","screen_width":1920,"screen_height":1080,"timezone_offset":-480,"language":"en-US","platform":"Win32","canvas_hash":"abc","webgl_vendor":"Google","webgl_renderer":"ANGLE","plugins_count":3,"touch_support":false,"hardware_concurrency":8,"device_memory":8.0}"#.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            site_id: "test-site".to_string(),
        };

        match engine.verify_solution(&submission, true) {
            VerifyResult::Success {
                cookie_value,
                cookie_attributes,
            } => {
                assert!(!cookie_value.is_empty());
                assert!(cookie_attributes.contains("HttpOnly"));
                assert!(cookie_attributes.contains("Secure"));
            },
            VerifyResult::Failed { reason } => {
                panic!("Expected success but got failure: {reason}");
            },
        }

        // The same solved pair must not mint a second cookie.
        match engine.verify_solution(&submission, true) {
            VerifyResult::Failed { reason } => {
                assert!(reason.contains("already used"));
            },
            _ => panic!("a replayed nonce must be rejected"),
        }

        // A plain HTTP origin gets a storable cookie: no Secure attribute.
        let mut second = submission.clone();
        second.challenge_nonce =
            issue_nonce(engine.config.cookie_secret.as_bytes());
        match engine.verify_solution(&second, false) {
            VerifyResult::Success {
                cookie_attributes, ..
            } => {
                assert!(cookie_attributes.contains("HttpOnly"));
                assert!(!cookie_attributes.contains("Secure"));
            },
            VerifyResult::Failed { reason } => {
                panic!("Expected success but got failure: {reason}");
            },
        }
    }

    #[test]
    fn test_verify_solution_expired_timestamp() {
        let engine = ChallengeEngine::new(test_config());
        let submission = ChallengeSubmission {
            request_id: "test-ray".to_string(),
            challenge_nonce: "nonce123".to_string(),
            solution: "anything".to_string(),
            fingerprint_json: "{}".to_string(),
            timestamp: chrono::Utc::now().timestamp() - 600, // 10 min ago, max is 5 min
            site_id: "test-site".to_string(),
        };

        match engine.verify_solution(&submission, true) {
            VerifyResult::Failed { reason } => {
                assert!(reason.contains("expired"));
            },
            _ => panic!("Expected failure"),
        }
    }

    #[test]
    fn test_wildcard_exempt_path() {
        let config = ChallengeConfig {
            exempt_paths: vec!["/api/*".to_string(), "/health".to_string()],
            ..test_config()
        };
        let engine = ChallengeEngine::new(config);

        let mut request = test_request();
        request.path = "/api/users".to_string();
        request.request_rate = 1000;
        assert_eq!(engine.should_challenge(&request), ChallengeDecision::Pass);

        request.path = "/api/v2/data".to_string();
        assert_eq!(engine.should_challenge(&request), ChallengeDecision::Pass);

        request.path = "/dashboard".to_string();
        assert_ne!(engine.should_challenge(&request), ChallengeDecision::Pass);
    }

    // Helper for tests to issue a clearance cookie directly
    impl ChallengeEngine {
        fn cookie_manager_issue_clearance(&self) -> String {
            self.cookie_manager.issue_clearance(
                ClearanceLevel::NonInteractive,
                TEST_SITE_ID,
                "test-fingerprint-hash",
            )
        }
    }
}
