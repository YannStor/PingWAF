use crate::fingerprint::fingerprint_collection_js;

/// The proof-of-work primitives, as JavaScript.
///
/// Extracted so a second page can compute the same answer without copying it.
/// That is a correctness requirement rather than tidiness: the verifier is
/// `verify_proof_of_work`, which hashes `nonce + solution` with SHA-256 and
/// counts leading zero bits, so a page whose SHA-256 or whose notion of
/// "leading zero bits" differed by one detail would produce answers that never
/// verify — and the failure would look like a broken password, not a broken
/// page.
///
/// Expects `CONFIG` in scope with `nonce` and `difficulty`, and defines
/// `sha256`, `leadingZeroBits` and `computeProofOfWork`. `computeProofOfWork`
/// calls `updateProgress(percent)` and assigns `solution`, both of which the
/// embedding page provides.
pub const POW_JS: &str = r#"
  // SHA-256 implementation (pure JS, no external deps)
  function sha256(message) {
    var K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

    // Convert string to byte array
    var bytes = [];
    for (var i = 0; i < message.length; i++) {
      var c = message.charCodeAt(i);
      if (c < 128) bytes.push(c);
      else if (c < 2048) { bytes.push((c >> 6) | 192); bytes.push((c & 63) | 128); }
      else { bytes.push((c >> 12) | 224); bytes.push(((c >> 6) & 63) | 128); bytes.push((c & 63) | 128); }
    }

    var l = bytes.length;
    bytes.push(0x80);
    while ((bytes.length % 64) !== 56) bytes.push(0);
    var bitLen = l * 8;
    for (var i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, i * 8)) & 0xFF);

    function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }
    function ch(x, y, z) { return (x & y) ^ (~x & z); }
    function maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
    function sigma0(x) { return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x); }
    function sigma1(x) { return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x); }
    function gamma0(x) { return rotr(7, x) ^ rotr(18, x) ^ (x >>> 3); }
    function gamma1(x) { return rotr(17, x) ^ rotr(19, x) ^ (x >>> 10); }

    for (var offset = 0; offset < bytes.length; offset += 64) {
      var W = [];
      for (var t = 0; t < 16; t++) {
        W[t] = (bytes[offset + t*4] << 24) | (bytes[offset + t*4+1] << 16) |
                (bytes[offset + t*4+2] << 8) | bytes[offset + t*4+3];
      }
      for (var t = 16; t < 64; t++) {
        W[t] = (gamma1(W[t-2]) + W[t-7] + gamma0(W[t-15]) + W[t-16]) | 0;
      }

      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (var t = 0; t < 64; t++) {
        var T1 = (h + sigma1(e) + ch(e,f,g) + K[t] + W[t]) | 0;
        var T2 = (sigma0(a) + maj(a,b,c)) | 0;
        h=g; g=f; f=e; e=(d+T1)|0; d=c; c=b; b=a; a=(T1+T2)|0;
      }
      H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+d)|0;
      H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
    }

    var hex = '';
    for (var i = 0; i < 8; i++) {
      hex += ('00000000' + (H[i] >>> 0).toString(16)).slice(-8);
    }
    return hex;
  }

  // Count leading zero bits in a hex string
  function leadingZeroBits(hex) {
    var bits = 0;
    for (var i = 0; i < hex.length; i++) {
      var nibble = parseInt(hex[i], 16);
      if (nibble === 0) { bits += 4; }
      else {
        if (nibble < 2) bits += 3;
        else if (nibble < 4) bits += 2;
        else if (nibble < 8) bits += 1;
        break;
      }
    }
    return bits;
  }

  // Proof-of-work: find nonce such that SHA-256(challenge_nonce + nonce) has enough leading zeros
  function computeProofOfWork() {
    var counter = 0;
    var batchSize = 5000;

    function batch() {
      for (var i = 0; i < batchSize; i++) {
        var candidate = counter.toString(16);
        var hash = sha256(CONFIG.nonce + candidate);
        if (leadingZeroBits(hash) >= CONFIG.difficulty) {
          solution = candidate;
          updateProgress(80);
          return true;
        }
        counter++;
      }
      // Update progress based on work done (cap at 70%)
      var progress = Math.min(70, 10 + Math.log2(counter + 1) * 3);
      updateProgress(progress);
      setTimeout(batch, 0);
      return false;
    }

    batch();
  }
"#;

/// Parameters for generating the challenge page
#[derive(Debug, Clone)]
pub struct ChallengePageParams {
    /// Unique request identifier
    pub request_id: String,
    /// Random nonce for proof-of-work computation
    pub challenge_nonce: String,
    /// Number of leading zero bits required in the SHA-256 hash
    pub difficulty: u32,
    /// URL endpoint to POST the solution to
    pub verify_endpoint: String,
    /// Original URL to redirect to after successful verification
    pub original_url: String,
    /// Brand name displayed on the page
    pub brand_name: String,
}

impl Default for ChallengePageParams {
    fn default() -> Self {
        Self {
            request_id: String::new(),
            challenge_nonce: String::new(),
            difficulty: 20,
            verify_endpoint: "/_pingwaf/challenge/verify".to_string(),
            original_url: "/".to_string(),
            brand_name: "PingWAF".to_string(),
        }
    }
}

/// Generate the JS challenge HTML page (5-second shield).
/// The page is self-contained with inline CSS and JS — no external dependencies.
pub fn generate_js_challenge_html(params: &ChallengePageParams) -> String {
    let fingerprint_js = fingerprint_collection_js();
    let pow_js = POW_JS;
    let nonce = &params.challenge_nonce;
    let difficulty = params.difficulty;
    let request_id = &params.request_id;
    let verify_endpoint = &params.verify_endpoint;
    let original_url = &params.original_url;
    let brand_name = &params.brand_name;

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Checking your browser — {brand_name}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#f8f9fa;--surface:#ffffff;--text:#1a1a2e;--text-secondary:#555;
  --accent:#2563eb;--accent-glow:rgba(37,99,235,0.15);
  --border:#e2e8f0;--error:#dc2626;--success:#16a34a;
  --radius:12px;--shadow:0 4px 24px rgba(0,0,0,0.06);
}}
@media(prefers-color-scheme:dark){{
  :root{{
    --bg:#0f1117;--surface:#1a1d2e;--text:#e8eaed;--text-secondary:#9ca3af;
    --accent:#60a5fa;--accent-glow:rgba(96,165,250,0.12);
    --border:#2d3348;--error:#f87171;--success:#4ade80;
    --shadow:0 4px 24px rgba(0,0,0,0.3);
  }}
}}
html,body{{height:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif}}
body{{background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}
.container{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:48px 40px;max-width:480px;width:100%;text-align:center;position:relative;overflow:hidden}}
.container::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),#7c3aed,var(--accent));background-size:200% 100%;animation:shimmer 2s linear infinite}}
@keyframes shimmer{{0%{{background-position:200% 0}}100%{{background-position:-200% 0}}}}
.brand{{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:32px}}
.brand svg{{width:32px;height:32px;color:var(--accent)}}
.brand span{{font-size:18px;font-weight:700;letter-spacing:-0.5px;color:var(--text)}}
.spinner-wrap{{margin:24px auto;width:64px;height:64px;position:relative}}
.spinner{{width:64px;height:64px;border-radius:50%;border:3px solid var(--border);border-top-color:var(--accent);animation:spin 1s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.spinner-wrap .countdown{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700;color:var(--accent)}}
h1{{font-size:20px;font-weight:600;margin-bottom:12px;color:var(--text)}}
.subtitle{{font-size:14px;color:var(--text-secondary);line-height:1.6;margin-bottom:24px}}
.status{{font-size:13px;color:var(--text-secondary);padding:12px 16px;background:var(--accent-glow);border-radius:8px;margin-top:20px;display:none}}
.status.visible{{display:block}}
.status.error{{background:rgba(220,38,38,0.08);color:var(--error)}}
.status.success{{background:rgba(22,163,74,0.08);color:var(--success)}}
.progress-bar{{width:100%;height:4px;background:var(--border);border-radius:2px;margin-top:16px;overflow:hidden;display:none}}
.progress-bar.visible{{display:block}}
.progress-bar .fill{{height:100%;width:0%;background:var(--accent);border-radius:2px;transition:width 0.3s ease}}
.footer{{margin-top:32px;font-size:11px;color:var(--text-secondary);opacity:0.7}}
.footer a{{color:var(--accent);text-decoration:none}}
@media(max-width:480px){{.container{{padding:32px 20px}}}}
</style>
</head>
<body>
<div class="container">
  <div class="brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <span>{brand_name}</span>
  </div>

  <div class="spinner-wrap" id="spinnerWrap">
    <div class="spinner"></div>
    <div class="countdown" id="countdown">5</div>
  </div>

  <h1 id="title">Checking your browser…</h1>
  <p class="subtitle" id="subtitle">
    Please wait while we verify your browser to ensure a secure connection.
    This process typically takes a few seconds.
  </p>

  <div class="progress-bar" id="progressBar">
    <div class="fill" id="progressFill"></div>
  </div>

  <div class="status" id="status"></div>

  <div class="footer">
    Protected by <a href="#">{brand_name}</a> · Ray ID: {request_id}
  </div>
</div>

<script>
{fingerprint_js}
</script>
<script>
(function() {{
  'use strict';

  var CONFIG = {{
    requestId: '{request_id}',
    nonce: '{nonce}',
    difficulty: {difficulty},
    verifyEndpoint: '{verify_endpoint}',
    originalUrl: '{original_url}',
    countdownSeconds: 5
  }};

  var elements = {{
    countdown: document.getElementById('countdown'),
    title: document.getElementById('title'),
    subtitle: document.getElementById('subtitle'),
    status: document.getElementById('status'),
    spinnerWrap: document.getElementById('spinnerWrap'),
    progressBar: document.getElementById('progressBar'),
    progressFill: document.getElementById('progressFill')
  }};

  var solution = null;
  var fingerprint = null;
  var startTime = Date.now();

  function showStatus(msg, type) {{
    elements.status.textContent = msg;
    elements.status.className = 'status visible' + (type ? ' ' + type : '');
  }}

  function updateProgress(pct) {{
    elements.progressBar.classList.add('visible');
    elements.progressFill.style.width = pct + '%';
  }}

  {pow_js}

  // Collect fingerprint data
  function collectFingerprint() {{
    try {{
      if (window.__pingwaf_fingerprint) {{
        fingerprint = window.__pingwaf_fingerprint();
      }} else {{
        fingerprint = JSON.stringify({{ user_agent: navigator.userAgent }});
      }}
    }} catch (e) {{
      fingerprint = JSON.stringify({{ user_agent: navigator.userAgent || '' }});
    }}
  }}

  // Detect automation (navigator.webdriver, etc.)
  function checkAutomation() {{
    if (navigator.webdriver) return true;
    if (window.__nightmare) return true;
    if (window.callPhantom || window._phantom) return true;
    if (document.__selenium_unwrapped) return true;
    if (window.domAutomation || window.domAutomationController) return true;
    return false;
  }}

  // Submit the solution to the server
  function submitSolution() {{
    if (!solution) {{
      showStatus('Computation failed. Please refresh the page.', 'error');
      return;
    }}

    if (checkAutomation()) {{
      showStatus('Automation detected. Access denied.', 'error');
      return;
    }}

    updateProgress(90);
    showStatus('Verifying solution…', '');

    var payload = {{
      request_id: CONFIG.requestId,
      solution: solution,
      fingerprint_json: fingerprint || '{{}}',
      timestamp: Math.floor(Date.now() / 1000)
    }};

    var xhr = new XMLHttpRequest();
    xhr.open('POST', CONFIG.verifyEndpoint, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function() {{
      if (xhr.readyState !== 4) return;
      if (xhr.status === 200) {{
        updateProgress(100);
        showStatus('Verification successful! Redirecting…', 'success');
        elements.title.textContent = 'Verified!';
        elements.spinnerWrap.style.display = 'none';
        setTimeout(function() {{
          window.location.href = CONFIG.originalUrl;
        }}, 500);
      }} else {{
        showStatus('Verification failed. Please refresh and try again.', 'error');
        elements.title.textContent = 'Verification Failed';
      }}
    }};
    xhr.onerror = function() {{
      showStatus('Network error. Please check your connection and refresh.', 'error');
    }};
    xhr.send(JSON.stringify(payload));
  }}

  // Countdown timer
  function startCountdown() {{
    var remaining = CONFIG.countdownSeconds;
    elements.countdown.textContent = remaining;

    var interval = setInterval(function() {{
      remaining--;
      if (remaining <= 0) {{
        clearInterval(interval);
        elements.countdown.textContent = '…';
        submitSolution();
      }} else {{
        elements.countdown.textContent = remaining;
        // Update progress during countdown
        var elapsed = Date.now() - startTime;
        var pct = Math.min(60, (elapsed / (CONFIG.countdownSeconds * 1000)) * 60);
        updateProgress(pct);
      }}
    }}, 1000);
  }}

  // Main flow
  function init() {{
    collectFingerprint();
    computeProofOfWork();
    startCountdown();
  }}

  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', init);
  }} else {{
    init();
  }}
}})();
</script>
<noscript>
<style>.container{{border-color:var(--error)}}</style>
<div class="container" style="margin-top:16px">
  <h1 style="color:var(--error)">JavaScript Required</h1>
  <p class="subtitle">Please enable JavaScript in your browser to pass the security check.</p>
</div>
</noscript>
</body>
</html>"##
    )
}

/// Generate the managed challenge HTML page.
/// This page can escalate to interactive verification if needed.
pub fn generate_managed_challenge_html(params: &ChallengePageParams) -> String {
    // Managed challenge uses the same page but with a flag for potential escalation
    let mut managed_params = params.clone();
    managed_params.difficulty = params.difficulty + 4; // Slightly harder PoW
    generate_js_challenge_html(&managed_params)
}

/// Generate the interactive challenge HTML page (CAPTCHA-style).
/// This is a placeholder for future CAPTCHA integration.
pub fn generate_interactive_challenge_html(
    params: &ChallengePageParams,
) -> String {
    let brand_name = &params.brand_name;
    let request_id = &params.request_id;
    let original_url = &params.original_url;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Security Check — {brand_name}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#f8f9fa;--surface:#ffffff;--text:#1a1a2e;--text-secondary:#555;
  --accent:#2563eb;--border:#e2e8f0;--radius:12px;
  --shadow:0 4px 24px rgba(0,0,0,0.06);
}}
@media(prefers-color-scheme:dark){{
  :root{{
    --bg:#0f1117;--surface:#1a1d2e;--text:#e8eaed;--text-secondary:#9ca3af;
    --accent:#60a5fa;--border:#2d3348;--shadow:0 4px 24px rgba(0,0,0,0.3);
  }}
}}
html,body{{height:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}}
body{{background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}
.container{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:48px 40px;max-width:480px;width:100%;text-align:center}}
.brand{{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:32px}}
.brand svg{{width:32px;height:32px;color:var(--accent)}}
.brand span{{font-size:18px;font-weight:700;letter-spacing:-0.5px}}
h1{{font-size:20px;font-weight:600;margin-bottom:12px}}
.subtitle{{font-size:14px;color:var(--text-secondary);line-height:1.6;margin-bottom:24px}}
.checkbox-wrap{{display:flex;align-items:center;justify-content:center;gap:12px;padding:16px;border:2px solid var(--border);border-radius:8px;cursor:pointer;transition:border-color 0.2s}}
.checkbox-wrap:hover{{border-color:var(--accent)}}
.checkbox{{width:24px;height:24px;border:2px solid var(--border);border-radius:4px;display:flex;align-items:center;justify-content:center;transition:all 0.2s}}
.checkbox.checked{{background:var(--accent);border-color:var(--accent)}}
.checkbox.checked::after{{content:'✓';color:white;font-size:14px;font-weight:bold}}
.checkbox-label{{font-size:15px;font-weight:500}}
.footer{{margin-top:32px;font-size:11px;color:var(--text-secondary);opacity:0.7}}
</style>
</head>
<body>
<div class="container">
  <div class="brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    <span>{brand_name}</span>
  </div>
  <h1>Security Verification</h1>
  <p class="subtitle">Please confirm you are human to continue to the requested page.</p>
  <div class="checkbox-wrap" id="verifyBox" onclick="verify()">
    <div class="checkbox" id="checkbox"></div>
    <span class="checkbox-label">I'm not a robot</span>
  </div>
  <div class="footer">
    Protected by {brand_name} · Ray ID: {request_id}
  </div>
</div>
<script>
function verify() {{
  var cb = document.getElementById('checkbox');
  cb.classList.add('checked');
  setTimeout(function() {{
    window.location.href = '{original_url}';
  }}, 1000);
}}
</script>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_js_challenge_html() {
        let params = ChallengePageParams {
            request_id: "test-ray-id-123".to_string(),
            challenge_nonce: "abc123def456".to_string(),
            difficulty: 20,
            verify_endpoint: "/_pingwaf/challenge/verify".to_string(),
            original_url: "/dashboard".to_string(),
            brand_name: "PingWAF".to_string(),
        };
        let html = generate_js_challenge_html(&params);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("test-ray-id-123"));
        assert!(html.contains("abc123def456"));
        // The page must carry the shared proof-of-work block, not a private
        // copy: the verifier hashes `nonce + solution` and counts leading
        // zero bits, so a page that computed anything else would produce
        // answers that never verify.
        assert!(
            html.contains("function computeProofOfWork"),
            "the page must include the shared PoW implementation"
        );
        assert!(
            html.contains("function sha256"),
            "the page must include the shared SHA-256"
        );
        // And it must be the *same* block, not a lookalike.
        assert!(
            POW_JS.contains("function computeProofOfWork")
                && html.contains(POW_JS),
            "the page's PoW block must be POW_JS verbatim"
        );
        assert!(html.contains("/dashboard"));
        assert!(html.contains("PingWAF"));
        assert!(html.contains("sha256"));
        assert!(html.contains("__pingwaf_fingerprint"));
        assert!(html.contains("Checking your browser"));
    }

    #[test]
    fn test_generate_interactive_challenge_html() {
        let params = ChallengePageParams {
            request_id: "ray-456".to_string(),
            challenge_nonce: "nonce".to_string(),
            difficulty: 20,
            verify_endpoint: "/_pingwaf/challenge/verify".to_string(),
            original_url: "/".to_string(),
            brand_name: "PingWAF".to_string(),
        };
        let html = generate_interactive_challenge_html(&params);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Security Verification"));
        assert!(html.contains("ray-456"));
        assert!(html.contains("I'm not a robot"));
    }

    #[test]
    fn test_challenge_page_has_dark_mode() {
        let params = ChallengePageParams::default();
        let html = generate_js_challenge_html(&params);
        assert!(html.contains("prefers-color-scheme:dark"));
    }

    #[test]
    fn test_challenge_page_has_noscript() {
        let params = ChallengePageParams::default();
        let html = generate_js_challenge_html(&params);
        assert!(html.contains("<noscript>"));
        assert!(html.contains("JavaScript Required"));
    }
}
