// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use snafu::Snafu;
use tracing::error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;

mod access;
mod async_logger;
mod file_appender;
#[cfg(unix)]
mod syslog;
mod writer;

const LOG_TARGET: &str = "pingap::logger";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IO error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Invalid {message}"))]
    Invalid { message: String },
}

pub fn new_env_filter(level: &str) -> EnvFilter {
    let mut initial_filter = EnvFilter::from_default_env();
    // pingora's listener logs every failed downstream TLS handshake at ERROR.
    // Internet scanners do that continuously (2026-10-19 E2E: 12 lines in
    // 30 s from one address), which drowns real errors. Default that target to
    // WARN; an operator who wants the raw stream sets RUST_LOG with an
    // explicit `pingora_core` directive, which wins because we only add ours
    // when the environment says nothing about that crate.
    let configured = std::env::var("RUST_LOG").unwrap_or_default();
    if !configured.contains("pingora_core")
        && let Ok(directive) =
            "pingora_core::services::listening=warn".parse::<Directive>()
    {
        initial_filter = initial_filter.add_directive(directive);
    }
    for item in level.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match item.parse::<Directive>() {
            Ok(directive) => {
                initial_filter = initial_filter.add_directive(directive);
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = e.to_string(),
                    "parse directive fail"
                );
            },
        };
    }
    initial_filter
}

pub use access::*;
pub use async_logger::*;
pub use writer::*;
