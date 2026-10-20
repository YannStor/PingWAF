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

use hickory_resolver::net::NetError;
use pingap_core::NotificationSender;
use snafu::Snafu;
use std::net::IpAddr;
use std::sync::Arc;

pub static LOG_TARGET: &str = "pingap::discovery";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Io error {source}, {content}"))]
    Io {
        source: std::io::Error,
        content: String,
    },
    #[snafu(display("Resolve error {source}"))]
    Resolve { source: NetError },
    #[snafu(display("{message}"))]
    Invalid { message: String },
    #[snafu(display("Docker error {source}"))]
    Docker { source: bollard::errors::Error },
}
impl From<Error> for pingora::BError {
    fn from(value: Error) -> Self {
        pingora::Error::because(
            pingora::ErrorType::HTTPStatus(500),
            value.to_string(),
            pingora::Error::new(pingora::ErrorType::InternalError),
        )
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A configured backend address: host (a name or a bare IP literal, an
/// IPv6 one without its brackets), port and weight.
pub(crate) type Addr = (String, u16, usize);

fn invalid(message: String) -> Error {
    Error::Invalid { message }
}

/// Splits one `addrs` entry - `host[:port] [weight]`, where an IPv6 literal
/// with a port is written `[::1]:8080` - into its host, optional port and
/// weight. Every part is checked here, once, so a bad port or weight is a
/// configuration error rather than something each discovery tick trips
/// over: a weight of zero would never be selected, and a port that does
/// not parse used to fail silently on every refresh.
pub(crate) fn split_addr(addr: &str) -> Result<(String, Option<u16>, usize)> {
    let mut parts = addr.split_whitespace();
    let host_port = parts
        .next()
        .ok_or_else(|| invalid("address is empty".to_string()))?;
    let weight = match parts.next() {
        None => 1,
        Some(weight) => weight
            .parse::<usize>()
            .ok()
            .filter(|weight| *weight > 0)
            .ok_or_else(|| {
                invalid(format!("weight of {addr} must be a positive integer"))
            })?,
    };
    if parts.next().is_some() {
        return Err(invalid(format!(
            "{addr} has more than a weight after the address"
        )));
    }
    let parse_port = |port: &str| {
        port.parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| invalid(format!("port of {addr} is invalid")))
    };
    // `[v6]` or `[v6]:port`
    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| {
            invalid(format!("{addr} is missing the closing bracket"))
        })?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid(format!(
                "{addr} has brackets around something that is not an IPv6 address"
            )));
        }
        let port = match after.strip_prefix(':') {
            Some(port) => Some(parse_port(port)?),
            None if after.is_empty() => None,
            None => return Err(invalid(format!("{addr} is invalid"))),
        };
        return Ok((host.to_string(), port, weight));
    }
    // A bare IPv6 literal has more than one colon and no port.
    if host_port.matches(':').count() > 1 {
        if host_port.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid(format!(
                "{addr} is not an IPv6 address; write [addr]:port for a port"
            )));
        }
        return Ok((host_port.to_string(), None, weight));
    }
    match host_port.split_once(':') {
        Some((host, port)) if !host.is_empty() => {
            Ok((host.to_string(), Some(parse_port(port)?), weight))
        },
        Some(_) => Err(invalid(format!("{addr} has no host"))),
        None => Ok((host_port.to_string(), None, weight)),
    }
}

/// Parses every `addrs` entry, filling in the default port (443 under TLS,
/// 80 otherwise) where none is given.
pub(crate) fn format_addrs(addrs: &[String], tls: bool) -> Result<Vec<Addr>> {
    let default_port = if tls { 443 } else { 80 };
    addrs
        .iter()
        .map(|addr| {
            let (host, port, weight) = split_addr(addr)?;
            Ok((host, port.unwrap_or(default_port), weight))
        })
        .collect()
}

pub const DNS_DISCOVERY: &str = "dns";
pub const DOCKER_DISCOVERY: &str = "docker";
pub const STATIC_DISCOVERY: &str = "static";
pub const TRANSPARENT_DISCOVERY: &str = "transparent";

/// `address_family = "auto"`: prefer IPv4, fall back to IPv6.
pub const ADDRESS_FAMILY_AUTO: &str = "auto";
/// `address_family = "ipv4"`: A records only.
pub const ADDRESS_FAMILY_IPV4: &str = "ipv4";
/// `address_family = "ipv6"`: AAAA records only.
pub const ADDRESS_FAMILY_IPV6: &str = "ipv6";

/// The address family an upstream may connect over.
///
/// This is the single source of truth; `pingap-upstream` re-exports it so
/// both crates (and the config layer) spell the type the same way.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum AddressFamily {
    /// Prefer IPv4; keep IPv6 only when the host has no A record at all.
    #[default]
    Auto,
    /// A records only.
    Ipv4,
    /// AAAA records only.
    Ipv6,
}

impl AddressFamily {
    /// Parses the control plane's spelling. `None` for anything else, so the
    /// caller keeps its own default instead of silently narrowing.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            ADDRESS_FAMILY_AUTO => Some(Self::Auto),
            ADDRESS_FAMILY_IPV4 => Some(Self::Ipv4),
            ADDRESS_FAMILY_IPV6 => Some(Self::Ipv6),
            _ => None,
        }
    }

    /// The spelling [`Self::parse`] accepts.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => ADDRESS_FAMILY_AUTO,
            Self::Ipv4 => ADDRESS_FAMILY_IPV4,
            Self::Ipv6 => ADDRESS_FAMILY_IPV6,
        }
    }

    /// Maps the legacy `ipv4_only` switch: `true` pins IPv4, unset or `false`
    /// is [`Self::Auto`] - never a wider family than the operator asked for.
    /// There is no legacy spelling for IPv6-only.
    #[must_use]
    pub fn from_ipv4_only(ipv4_only: Option<bool>) -> Self {
        if ipv4_only.unwrap_or_default() {
            Self::Ipv4
        } else {
            Self::Auto
        }
    }

    /// Whether an address of this family may be used. [`Self::Auto`]
    /// accepts both families at the filter stage; the IPv4 preference is
    /// applied by the static pool afterwards (it needs the whole resolved
    /// set before it can decide).
    #[must_use]
    pub fn accepts(self, ip: IpAddr) -> bool {
        match self {
            Self::Auto => true,
            Self::Ipv4 => ip.is_ipv4(),
            Self::Ipv6 => ip.is_ipv6(),
        }
    }
}

#[derive(Default)]
pub struct Discovery {
    addr: Vec<String>,
    tls: bool,
    /// Legacy `ipv4_only` switch, still consulted by the DNS and Docker
    /// discovery paths; kept in sync with `address_family` by the builders.
    ipv4_only: bool,
    /// Three-valued address family; the static pool filters on this.
    address_family: AddressFamily,
    dns_server: Option<String>,
    dns_domain: Option<String>,
    dns_search: Option<String>,
    sender: Option<Arc<NotificationSender>>,
}

impl Discovery {
    pub fn new(addr: Vec<String>) -> Self {
        Self {
            addr,
            tls: false,
            ipv4_only: false,
            address_family: AddressFamily::default(),
            dns_server: None,
            dns_domain: None,
            dns_search: None,
            sender: None,
        }
    }
    pub fn with_sender(
        mut self,
        sender: Option<Arc<NotificationSender>>,
    ) -> Self {
        self.sender = sender;
        self
    }
    pub fn with_tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }
    /// Legacy spelling: `true` pins IPv4, `false` leaves [`AddressFamily::Auto`].
    pub fn with_ipv4_only(mut self, ipv4_only: bool) -> Self {
        self.ipv4_only = ipv4_only;
        if ipv4_only {
            self.address_family = AddressFamily::Ipv4;
        }
        self
    }
    /// The three-valued spelling. An explicit `Ipv4` also drives the legacy
    /// `ipv4_only` switch so the DNS and Docker paths narrow the same way;
    /// `Auto` and `Ipv6` leave it unset (`Ipv6` filtering is applied by the
    /// static pool).
    pub fn with_address_family(mut self, family: AddressFamily) -> Self {
        self.address_family = family;
        self.ipv4_only = family == AddressFamily::Ipv4;
        self
    }
    pub fn with_dns_server(mut self, dns_server: String) -> Self {
        if dns_server.is_empty() {
            self.dns_server = None;
        } else {
            self.dns_server = Some(dns_server);
        }
        self
    }
    pub fn with_domain(mut self, domain: String) -> Self {
        self.dns_domain = Some(domain).filter(|domain| !domain.is_empty());
        self
    }
    pub fn with_search(mut self, search: String) -> Self {
        self.dns_search = Some(search).filter(|search| !search.is_empty());
        self
    }
}

mod common;
mod dns;
mod docker;
pub use common::{is_static_discovery, new_static_discovery};
pub use dns::{is_dns_discovery, new_dns_discover_backends};
pub use docker::{is_docker_discovery, new_docker_discover_backends};

#[cfg(test)]
mod tests {
    use super::{Discovery, format_addrs, split_addr};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_format_addrs() {
        let one = |addr: &str, tls: bool| {
            format_addrs(&[addr.to_string()], tls).unwrap().remove(0)
        };
        assert_eq!(
            ("127.0.0.1".to_string(), 8080, 1),
            one("127.0.0.1:8080", false)
        );
        assert_eq!(("127.0.0.1".to_string(), 80, 1), one("127.0.0.1", false));
        assert_eq!(("127.0.0.1".to_string(), 443, 1), one("127.0.0.1", true));
        assert_eq!(
            ("127.0.0.1".to_string(), 80, 10),
            one("127.0.0.1 10", false)
        );
        // Any amount of whitespace separates the weight.
        assert_eq!(("api".to_string(), 8080, 3), one("  api:8080   3 ", false));
        // IPv6 literals keep their address, lose the brackets.
        assert_eq!(("::1".to_string(), 8080, 1), one("[::1]:8080", false));
        assert_eq!(("::1".to_string(), 443, 2), one("[::1] 2", true));
        assert_eq!(
            ("2001:db8::1".to_string(), 80, 1),
            one("2001:db8::1", false)
        );

        for bad in [
            "",
            "127.0.0.1:abc",
            "127.0.0.1:0",
            "127.0.0.1:70000",
            "127.0.0.1:80 0",
            "127.0.0.1:80 x",
            "127.0.0.1:80 1 2",
            ":80",
            "[::1",
            "[::1]8080",
            "[nope]:80",
            "a:b:c",
        ] {
            assert_eq!(
                true,
                split_addr(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert_eq!(
            true,
            format_addrs(&["ok:80".to_string(), "bad:x".to_string()], false)
                .is_err()
        );
    }

    #[test]
    fn test_discovery_builder_drops_empty_values() {
        let discovery = Discovery::new(vec![])
            .with_dns_server(String::new())
            .with_domain(String::new())
            .with_search(String::new());
        assert_eq!(None, discovery.dns_server);
        assert_eq!(None, discovery.dns_domain);
        assert_eq!(None, discovery.dns_search);
        let discovery = Discovery::new(vec![])
            .with_domain("svc".to_string())
            .with_search("a,b".to_string());
        assert_eq!(Some("svc".to_string()), discovery.dns_domain);
        assert_eq!(Some("a,b".to_string()), discovery.dns_search);
    }
}
