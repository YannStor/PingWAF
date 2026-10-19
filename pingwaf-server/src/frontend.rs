//! Embedded frontend asset serving.
//!
//! The React dashboard is compiled into `web/dist/` and embedded into the
//! binary at compile time via `rust-embed`. This module provides an Axum
//! fallback handler that serves those assets, with SPA routing support
//! (any unmatched path returns `index.html`).

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../web/dist/"]
struct FrontendAssets;

/// Paths that must 404 when the file is missing instead of falling back to
/// the SPA shell: hashed bundles under the assets directory, plus the static
/// extensions the SPA never routes through (a client-route path containing a
/// dot is not a page in this app).
fn is_asset_path(path: &str) -> bool {
    const ASSET_EXTS: [&str; 9] = [
        "js", "css", "map", "png", "svg", "ico", "woff", "woff2", "webp",
    ];
    if path.starts_with("assets/") {
        return true;
    }
    path.rsplit_once('.')
        .map(|(_, ext)| ASSET_EXTS.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Serve an embedded static file, or fall back to `index.html` for SPA routing.
///
/// This handler is mounted as the router's fallback so that:
/// - Known static assets (JS, CSS, images) are served with proper MIME types
/// - Unknown paths return `index.html` so the React router can handle them
/// - API routes are unaffected (they are matched before the fallback)
pub async fn serve_frontend(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try to serve the exact file first
    if let Some(file) = FrontendAssets::get(path) {
        return build_asset_response(file, path);
    }

    // A missing hashed asset is a hard 404. Falling back to index.html would
    // answer 200 text/html for a JS/CSS URL, so a browser holding a stale
    // index.html (or a proxy that cached one) sees a "successful" HTML
    // response instead of a missing-file signal — which is exactly how a
    // stale bundle hides during cache investigations (2026-10-19 E2E).
    if is_asset_path(path) {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(
                r#"{"error":{"code":"not_found","message":"asset not found"}}"#,
            ),
        )
            .into_response();
    }

    // SPA fallback: serve index.html for non-API, non-asset paths
    if let Some(index) = FrontendAssets::get("index.html") {
        return build_asset_response(index, "index.html");
    }

    // No frontend embedded (e.g. web/dist/ was empty at build time)
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(r#"{"error":{"code":"not_found","message":"no frontend assets embedded"}}"#),
    )
        .into_response()
}

fn build_asset_response(
    file: rust_embed::EmbeddedFile,
    _path: &str,
) -> Response {
    // rust-embed's mime-guess feature provides mimetype()
    let content_type = file.metadata.mimetype().to_string();

    // HTML files should not be cached (they reference hashed asset filenames)
    let cache_control = if content_type.contains("text/html") {
        "no-cache, no-store, must-revalidate"
    } else {
        // Static assets with content hashes can be cached aggressively
        "public, max-age=31536000, immutable"
    };

    // Use the file length and a simple hash as ETag
    let hash = file.metadata.sha256_hash();
    let etag = format!(
        "\"{:x}-{:02x}{:02x}{:02x}{:02x}\"",
        file.data.len(),
        hash[0],
        hash[1],
        hash[2],
        hash[3]
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::ETAG, &etag)
        .body(Body::from(file.data.to_vec()))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response()
        })
}

#[cfg(test)]
mod tests {
    use super::is_asset_path;

    #[test]
    fn hashed_assets_do_not_fall_back_to_the_spa_shell() {
        assert!(is_asset_path("assets/index-K3jA9zY0.js"));
        assert!(is_asset_path("favicon.svg"));
        assert!(is_asset_path("fonts/inter.woff2"));
        // Client-side routes must keep falling back to index.html.
        assert!(!is_asset_path("dashboard"));
        assert!(!is_asset_path(
            "sites/163365ca-89f1-4955-aca1-e7ff2655be8f/basic"
        ));
    }
}
