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

//! Optional TOML configuration file for the PingWAF modes.
//!
//! `--config <path>` (or `PINGWAF_CONFIG`) names a file whose `[server]` and
//! `[agent]` tables hold the same settings as the command-line flags, so a
//! deployment can be described in one place instead of a wall of environment
//! variables. Keys are the flag names with dashes replaced by underscores
//! (`--admin-addr` is `admin_addr`), and array values are written as TOML
//! arrays (`tls_sans = ["waf.example.com"]`).
//!
//! Precedence is file, then environment, then command line: the file only
//! fills in the arguments neither of the others set, which is implemented by
//! asking clap where each value came from and injecting the file's arguments
//! for the ones still at their default.

use std::path::Path;

use clap::CommandFactory;
use clap::parser::ValueSource;

use crate::cli::PingWafCli;

/// The subcommand tables of the file, per mode.
///
/// All-in-one runs both halves, so it reads both tables.
fn sections(mode: &str) -> &'static [&'static str] {
    match mode {
        "server" => &["server"],
        "agent" => &["agent"],
        "all-in-one" => &["server", "agent"],
        // Unknown modes contribute nothing: guessing "all-in-one" used to
        // inject server/agent keys into a command that never declared them.
        _ => &[],
    }
}

/// Reads the configuration file and returns the arguments it contributes.
///
/// `argv` is the command line with the subcommand at index 1. The returned
/// arguments are meant to be inserted right after it, where the real command
/// line still overrides them.
pub fn injections(mode: &str, argv: &[String]) -> anyhow::Result<Vec<String>> {
    let Some(sub) = PingWafCli::command().find_subcommand(mode).cloned() else {
        return Ok(Vec::new());
    };
    // Only the run modes carry `--config`; the maintenance commands have no
    // file to read (and asking for the argument would panic clap's lookup).
    if sub
        .get_arguments()
        .all(|arg| arg.get_id().as_str() != "config")
    {
        return Ok(Vec::new());
    }

    let mut sub_args = argv.to_vec();
    sub_args.remove(1);
    let matches = match sub.clone().try_get_matches_from(&sub_args) {
        Ok(matches) => matches,
        // `--help` and `--version` are not really parse errors: hand the
        // command line back untouched so the final parse can print them.
        Err(err)
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return Ok(Vec::new());
        },
        // Report a bad command line exactly as clap would.
        Err(err) => err.exit(),
    };

    // clap resolves `--config` against `PINGWAF_CONFIG` for us.
    let Some(path) = matches.get_one::<String>("config") else {
        return Ok(Vec::new());
    };
    if path.trim().is_empty() {
        return Ok(Vec::new());
    }

    let text = std::fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!("cannot read config file {path}: {err}")
    })?;
    // A whole document, not `Value::from_str`, which parses a single value.
    let document: toml::Value = toml::from_str(&text).map_err(|err| {
        anyhow::anyhow!("cannot parse config file {path}: {err}")
    })?;

    let mut injections = Vec::new();
    for section in sections(mode) {
        let Some(table) = document.get(*section) else {
            continue;
        };
        let Some(table) = table.as_table() else {
            eprintln!(
                "warning: [{section}] in {path} is not a table, ignoring it"
            );
            continue;
        };
        for (key, value) in table {
            let Some(arg) = sub.get_arguments().find(|arg| {
                arg.get_id().as_str() == key && arg.get_id() != "config"
            }) else {
                eprintln!(
                    "warning: unknown key {key:?} in [{section}] of {path}, ignoring it"
                );
                continue;
            };
            let id = arg.get_id().as_str();
            if matches!(
                matches.value_source(id),
                Some(ValueSource::CommandLine | ValueSource::EnvVariable)
            ) {
                continue;
            }
            let Some(flag) = arg.get_long() else {
                continue;
            };
            let Some(text) = argument_text(value) else {
                eprintln!(
                    "warning: {key:?} in [{section}] of {path} has an unsupported value, ignoring it"
                );
                continue;
            };
            injections.push(format!("--{flag}={text}"));
        }
    }

    if !injections.is_empty() {
        eprintln!(
            "pingwaf: loaded {} setting(s) from {}",
            injections.len(),
            Path::new(path).display()
        );
    }
    Ok(injections)
}

/// Renders a TOML value the way the matching flag expects it.
///
/// Lists become the comma-separated form clap's `value_delimiter` splits;
/// anything structured is refused rather than flattened into something the
/// operator did not write.
fn argument_text(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(text) => Some(text.clone()),
        toml::Value::Integer(number) => Some(number.to_string()),
        toml::Value::Float(number) => Some(number.to_string()),
        toml::Value::Boolean(flag) => Some(flag.to_string()),
        toml::Value::Array(items) => {
            let mut texts = Vec::with_capacity(items.len());
            for item in items {
                texts.push(item.as_str()?.to_string());
            }
            Some(texts.join(","))
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value of `v` in a one-line document.
    fn value(entry: &str) -> toml::Value {
        let table: toml::Table = toml::from_str(entry).unwrap();
        table.get("v").unwrap().clone()
    }

    #[test]
    fn values_are_rendered_the_way_flags_expect_them() {
        assert_eq!(
            argument_text(&value("v = \"postgres://db/x\"")).unwrap(),
            "postgres://db/x"
        );
        assert_eq!(argument_text(&value("v = 30")).unwrap(), "30");
        assert_eq!(argument_text(&value("v = false")).unwrap(), "false");
        assert_eq!(
            argument_text(&value("v = [\"a.com\", \"b.com\"]")).unwrap(),
            "a.com,b.com"
        );
        // A list of something other than strings has no flag spelling.
        assert!(argument_text(&value("v = [1, 2]")).is_none());
        assert!(argument_text(&value("v = { a = 1 }")).is_none());
    }

    #[test]
    fn each_mode_reads_its_own_sections() {
        assert_eq!(sections("server"), &["server"]);
        assert_eq!(sections("agent"), &["agent"]);
        assert_eq!(sections("all-in-one"), &["server", "agent"]);
    }
}
