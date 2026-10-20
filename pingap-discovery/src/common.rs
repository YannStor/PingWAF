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

use super::{AddressFamily, Discovery, LOG_TARGET, STATIC_DISCOVERY};
use super::{Result, format_addrs};
use http::Extensions;
use pingora::lb::discovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Instant;
use tracing::{info, warn};

/// Checks if the discovery type is static
///
/// # Arguments
/// * `value` - The discovery type string to check
///
/// # Returns
/// * `bool` - True if the discovery type is static (empty or matches STATIC_DISCOVERY)
pub fn is_static_discovery(value: &str) -> bool {
    // Using a match statement is slightly more idiomatic and extensible.
    matches!(value, "" | STATIC_DISCOVERY)
}

/// Applies [`AddressFamily::Auto`]'s IPv4 preference to a resolved static
/// pool. `Auto` must accept both families at the filter stage - it cannot
/// know there is an IPv4 address to prefer until the whole set is in - so
/// the preference is applied here instead: a dual-stack pool keeps only its
/// A records, because an AAAA backend on a host without an IPv6 route can
/// never pass a health check. A pool with no IPv4 address at all keeps its
/// IPv6 backends so an IPv6-only origin stays reachable. Pure memory work:
/// no additional DNS.
fn static_pool_prefers_ipv4(
    mut upstreams: BTreeSet<Backend>,
    family: AddressFamily,
) -> BTreeSet<Backend> {
    if family != AddressFamily::Auto {
        return upstreams;
    }
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    for backend in &upstreams {
        match backend.addr {
            SocketAddr::Inet(socket_addr) if socket_addr.is_ipv4() => {
                has_ipv4 = true;
            },
            SocketAddr::Inet(_) => has_ipv6 = true,
            _ => {},
        }
    }
    if has_ipv4 && has_ipv6 {
        upstreams.retain(|backend| {
            !matches!(&backend.addr, SocketAddr::Inet(socket_addr) if socket_addr.is_ipv6())
        });
    }
    upstreams
}

/// Create a static discovery, execute it only once.
/// It will resolve the domain to socket address at the beginning stage.
///
/// # Arguments
/// * `discovery` - The discovery configuration
///
/// # Returns
/// * `Result<Backends>` - Configured service discovery backend
pub fn new_static_discovery(discovery: &Discovery) -> Result<Backends> {
    let start_time = Instant::now();
    info!(
        target: LOG_TARGET,
        hosts = discovery.addr.join(","),
        "starting static discovery"
    );

    let formatted_addrs = format_addrs(&discovery.addr, discovery.tls)?;

    // Directly collect into a BTreeSet to handle deduplication and sorting automatically.
    let upstreams: BTreeSet<_> = formatted_addrs
        .into_iter()
        .flat_map(|(host, port, weight)| {
            // An IP literal needs no lookup - and no trip through the
            // blocking resolver this runs on during a hot reload.
            let resolved_addrs: Vec<_> = match host.parse::<IpAddr>() {
                Ok(ip) => vec![std::net::SocketAddr::new(ip, port)],
                Err(_) => match format!("{host}:{port}").to_socket_addrs() {
                    Ok(addrs) => addrs.collect(),
                    Err(e) => {
                        // Log the error but don't stop the whole process.
                        warn!(
                            target: LOG_TARGET,
                            error = %e,
                            host,
                            port,
                            "failed to resolve socket address"
                        );
                        vec![]
                    },
                },
            };
            // Pair each address with the weight.
            resolved_addrs.into_iter().map(move |addr| (addr, weight))
        })
        // Filter out only valid addresses and apply the family filter.
        .filter(|(socket_addr, _)| {
            discovery.address_family.accepts(socket_addr.ip())
        })
        // Map the resolved addresses to Backend structs.
        .map(|(socket_addr, weight)| Backend {
            addr: SocketAddr::Inet(socket_addr),
            weight,
            ext: Extensions::new(),
        })
        .collect();
    let upstreams =
        static_pool_prefers_ipv4(upstreams, discovery.address_family);

    // Generate the log message from the final, deduplicated set of backends.
    let resolved_addrs: Vec<String> =
        upstreams.iter().map(|b| b.addr.to_string()).collect();
    info!(
        target: LOG_TARGET,
        hosts = discovery.addr.join(","),
        addrs = resolved_addrs.join(","),
        count = upstreams.len(),
        elapsed = ?start_time.elapsed(),
        "static discovery finished"
    );

    let discovery_service = discovery::Static::new(upstreams);
    Ok(Backends::new(discovery_service))
}
#[cfg(test)]
mod tests {
    use super::Discovery;
    use super::new_static_discovery;
    use crate::AddressFamily;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_new_static_discovery() {
        let backends = new_static_discovery(&Discovery {
            addr: vec!["127.0.0.1:8080".to_string()],
            tls: false,
            ipv4_only: false,
            address_family: AddressFamily::default(),
            sender: None,
            dns_server: None,
            dns_domain: None,
            dns_search: None,
        })
        .unwrap();

        // no health check, so no healthy backend
        assert_eq!(backends.get_backend().len(), 0);

        backends.update(|_| {}).await.unwrap();
        assert_eq!(backends.get_backend().len(), 1);
    }

    /// Weights come through as configured, and a bad entry is rejected up
    /// front instead of being dropped with a warning. Under the default
    /// `Auto` family a dual-stack pool keeps only its IPv4 entries (see
    /// `auto_static_pool_prefers_ipv4_when_both_exist`).
    #[tokio::test]
    async fn test_static_discovery_ipv6_and_errors() {
        let backends = new_static_discovery(&Discovery {
            addr: vec![
                "[::1]:8080 3".to_string(),
                "127.0.0.1:8080".to_string(),
            ],
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        let addrs: Vec<(String, usize)> = backends
            .get_backend()
            .iter()
            .map(|backend| (backend.addr.to_string(), backend.weight))
            .collect();
        assert_eq!(vec![("127.0.0.1:8080".to_string(), 1)], addrs);

        // An IPv6-only pool under `Auto` keeps its (only) entries.
        let backends = new_static_discovery(&Discovery {
            addr: vec!["[::1]:8080 3".to_string()],
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        let addrs: Vec<(String, usize)> = backends
            .get_backend()
            .iter()
            .map(|backend| (backend.addr.to_string(), backend.weight))
            .collect();
        assert_eq!(vec![("[::1]:8080".to_string(), 3)], addrs);

        // ipv4_only drops the IPv6 backend.
        let backends = new_static_discovery(&Discovery {
            addr: vec!["[::1]:8080".to_string(), "127.0.0.1:8080".to_string()],
            ipv4_only: true,
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        assert_eq!(1, backends.get_backend().len());

        // `address_family = ipv4` narrows the same way without the legacy switch.
        let backends = new_static_discovery(&Discovery {
            addr: vec!["[::1]:8080".to_string(), "127.0.0.1:8080".to_string()],
            address_family: AddressFamily::Ipv4,
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        assert_eq!(1, backends.get_backend().len());

        let err = new_static_discovery(&Discovery {
            addr: vec!["127.0.0.1:8080 0".to_string()],
            ..Default::default()
        })
        .err()
        .expect("a zero weight must be rejected");
        assert_eq!(
            "weight of 127.0.0.1:8080 0 must be a positive integer",
            err.to_string()
        );
    }

    /// `Auto` keeps the IPv4-preference contract: a dual-stack static pool
    /// (IP literals, so no real DNS is involved) must not turn the AAAA
    /// entries into backends, while an IPv6-only pool still resolves.
    #[tokio::test]
    async fn auto_static_pool_prefers_ipv4_when_both_exist() {
        let backends = new_static_discovery(&Discovery {
            addr: vec!["[::1]:8080".to_string(), "127.0.0.1:8080".to_string()],
            ..Default::default()
        })
        .unwrap();
        backends.update(|_| {}).await.unwrap();
        let addrs: Vec<String> = backends
            .get_backend()
            .iter()
            .map(|backend| backend.addr.to_string())
            .collect();
        assert_eq!(vec!["127.0.0.1:8080".to_string()], addrs);
    }
}
