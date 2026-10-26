//! HTTPS termination for the control plane's HTTP listener.
//!
//! The dashboard has to be reachable over a secure origin — browsers only
//! expose WebAuthn (passkeys) and the other crypto APIs to HTTPS or localhost
//! — so the control plane can terminate TLS itself. The certificate lives in
//! the database and can be replaced from the dashboard; a
//! [`ReloadableResolver`] lets the running listener pick up a replacement
//! without a restart.
//!
//! The listener is *mixed*: it also accepts cleartext on the same port so
//! health probes and an operator typing `http://host:9080` get a real HTTP
//! answer instead of a connection reset. [`ConnInfo`] tells the request
//! middleware which half a connection arrived on, which is what drives the
//! redirect to HTTPS in [`crate::api`].

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Sleep;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::pki::mtls::MtlsError;
use crate::pki::tls::{certified_key, crypto_provider};

/// First byte of a TLS record carrying a handshake (the ClientHello).
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// How long a newly accepted socket may take to send its first byte. A
/// client that stalls before the protocol is known must not occupy a
/// pre-handshake task indefinitely.
#[cfg(not(test))]
const PROTOCOL_PEEK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const PROTOCOL_PEEK_TIMEOUT: Duration = Duration::from_millis(300);

/// How long the TLS handshake may take after the first TLS record is seen.
#[cfg(not(test))]
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum number of connections that may be in protocol detection or TLS
/// handshake at once. Connections beyond this bound are closed immediately
/// instead of growing the task set without limit.
#[cfg(not(test))]
const MAX_PENDING_HANDSHAKES: usize = 128;
#[cfg(test)]
const MAX_PENDING_HANDSHAKES: usize = 4;

/// Number of completed handshakes buffered for axum. A full queue means
/// accepted connections are dropped rather than blocking the accept loop.
#[cfg(not(test))]
const READY_QUEUE_CAPACITY: usize = 128;
#[cfg(test)]
const READY_QUEUE_CAPACITY: usize = 8;

/// Idle read budget after the protocol is known. Hyper reads request headers
/// and bodies through this wrapper; a client that sends one byte and then
/// stalls is closed instead of pinning a connection forever.
#[cfg(not(test))]
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_millis(500);

/// Total active control-plane connections (pre-handshake plus HTTP). This is
/// a second, larger bound behind the pre-handshake pool; it prevents a flood
/// of slow HTTP clients from exhausting the process fd table.
#[cfg(not(test))]
const MAX_ACTIVE_CONNECTIONS: usize = 512;
#[cfg(test)]
const MAX_ACTIVE_CONNECTIONS: usize = 16;

/// Loopback gets its own tiny pools so the local `/healthz` probe still gets
/// through when untrusted remote clients fill the public pools. The public and
/// loopback limits are deliberately unequal in tests so a test cannot pass
/// when one of the pools is accidentally removed.
#[cfg(not(test))]
const MAX_PENDING_LOOPBACK: usize = 16;
#[cfg(test)]
const MAX_PENDING_LOOPBACK: usize = 4;
#[cfg(not(test))]
const MAX_ACTIVE_LOOPBACK: usize = 16;
#[cfg(test)]
const MAX_ACTIVE_LOOPBACK: usize = 8;

// Keep the documented production bounds tied to the constants tests exercise
// through test-only shorter values.
#[cfg(not(test))]
const _: () = assert!(
    PROTOCOL_PEEK_TIMEOUT.as_secs() == 5
        && TLS_HANDSHAKE_TIMEOUT.as_secs() == 10
        && MAX_PENDING_HANDSHAKES == 128
        && READY_QUEUE_CAPACITY == 128
        && CONNECTION_IDLE_TIMEOUT.as_secs() == 60
        && MAX_ACTIVE_CONNECTIONS == 512
        && MAX_PENDING_LOOPBACK == 16
        && MAX_ACTIVE_LOOPBACK == 16
);

/// Holds the certificate the listener presents, swappable at runtime.
///
/// rustls asks the resolver for a certificate on every handshake, so
/// installing a new pair takes effect immediately; connections already
/// established keep the certificate they negotiated.
#[derive(Debug, Default)]
pub struct ReloadableResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl ReloadableResolver {
    /// Installs a certificate, replacing any previous one.
    pub fn install(&self, key: Arc<CertifiedKey>) {
        match self.current.write() {
            Ok(mut current) => *current = Some(key),
            Err(poisoned) => *poisoned.into_inner() = Some(key),
        }
    }

    /// The certificate currently served, if one has been installed.
    pub fn loaded(&self) -> Option<Arc<CertifiedKey>> {
        match self.current.read() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl ResolvesServerCert for ReloadableResolver {
    fn resolve(
        &self,
        _client_hello: ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        // One certificate for every name: the dashboard is a single-origin
        // service and the operator decides which names it answers on.
        self.loaded()
    }
}

/// The TLS state shared by the HTTP listener and the API that manages it.
pub struct ControlPlaneTls {
    /// `--tls-enabled`: whether this process terminates TLS at all.
    enabled: bool,
    resolver: Arc<ReloadableResolver>,
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for ControlPlaneTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneTls")
            .field("enabled", &self.enabled)
            .field("has_certificate", &self.has_certificate())
            .finish_non_exhaustive()
    }
}

impl ControlPlaneTls {
    /// Creates the TLS state. No certificate is required yet: a deployment
    /// that terminates TLS elsewhere never installs one.
    pub fn new(enabled: bool) -> Self {
        let resolver = Arc::new(ReloadableResolver::default());
        let config = rustls::ServerConfig::builder_with_provider(
            crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());

        Self {
            enabled,
            resolver,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    /// Whether the HTTP listener terminates TLS.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a certificate has been installed.
    pub fn has_certificate(&self) -> bool {
        self.resolver.loaded().is_some()
    }

    /// Validates and installs a certificate pair, replacing the current one.
    pub fn activate(
        &self,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), MtlsError> {
        let key = certified_key(cert_pem, key_pem)?;
        self.resolver.install(key);
        Ok(())
    }

    /// A handle for the listener to accept connections with.
    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

/// A connection accepted by [`MixedListener`], TLS or cleartext.
pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A connection after protocol detection. It holds an active-connection
/// permit for its whole lifetime and applies an idle read/write timeout after
/// the handshake, so a client cannot send one byte and then park forever.
pub struct MixedStream {
    inner: MaybeTlsStream,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    idle_started: bool,
    _active: OwnedSemaphorePermit,
}

impl MixedStream {
    fn new(inner: MaybeTlsStream, active: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            idle: Box::pin(tokio::time::sleep(CONNECTION_IDLE_TIMEOUT)),
            idle_timeout: CONNECTION_IDLE_TIMEOUT,
            // Start the clock on the first actual I/O poll, not while the
            // connection is waiting in the ready queue or between future
            // polls.
            idle_started: false,
            _active: active,
        }
    }

    fn arm_idle(&mut self) {
        self.idle
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle_timeout);
        self.idle_started = true;
    }

    fn poll_idle(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if !self.idle_started {
            self.arm_idle();
        }
        self.idle.as_mut().poll(cx)
    }

    fn timed_out() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "control-plane connection idle timeout",
        )
    }

    /// Whether this connection negotiated TLS.
    pub fn is_tls(&self) -> bool {
        matches!(self.inner, MaybeTlsStream::Tls(_))
    }
}

impl AsyncRead for MixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.arm_idle();
                Poll::Ready(result)
            },
            Poll::Pending => match this.poll_idle(cx) {
                Poll::Ready(()) => Poll::Ready(Err(Self::timed_out())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for MixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.arm_idle();
                Poll::Ready(result)
            },
            Poll::Pending => match this.poll_idle(cx) {
                Poll::Ready(()) => Poll::Ready(Err(Self::timed_out())),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.arm_idle();
                Poll::Ready(result)
            },
            Poll::Pending => match this.poll_idle(cx) {
                Poll::Ready(()) => Poll::Ready(Err(Self::timed_out())),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => {
                this.arm_idle();
                Poll::Ready(result)
            },
            Poll::Pending => match this.poll_idle(cx) {
                Poll::Ready(()) => Poll::Ready(Err(Self::timed_out())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// Accepts TLS and cleartext HTTP on a single port.
///
/// The first byte decides: a TLS record starts with `0x16` (handshake), and
/// no HTTP request line does — methods are ASCII letters — so the split is
/// unambiguous for anything a browser, curl or a container probe sends.
///
/// Protocol detection and the TLS handshake happen in per-connection tasks,
/// never in the accept loop. A silent or half-open client therefore cannot
/// stop the listener from accepting the next connection (the 9080 incident
/// happened because the old implementation did both inline).
pub struct MixedListener {
    receiver: mpsc::Receiver<(MixedStream, SocketAddr)>,
    local_addr: SocketAddr,
    accept_task: JoinHandle<()>,
    // Read by the test-only capacity assertion; the accept loop owns the
    // production counter through `ConnectionLimits`.
    #[allow(dead_code)]
    dropped: Arc<AtomicU64>,
}

impl MixedListener {
    /// Binds the listener and starts its dedicated accept task.
    ///
    /// The returned listener is only a receiver for completed handshakes;
    /// dropping it aborts the accept task and therefore closes the socket.
    pub fn new(
        listener: TcpListener,
        acceptor: TlsAcceptor,
    ) -> io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let (sender, receiver) = mpsc::channel(READY_QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let limits = ConnectionLimits {
            pending: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
            pending_loopback: Arc::new(Semaphore::new(MAX_PENDING_LOOPBACK)),
            active: Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS)),
            active_loopback: Arc::new(Semaphore::new(MAX_ACTIVE_LOOPBACK)),
            dropped: dropped.clone(),
        };
        let accept_task =
            tokio::spawn(accept_loop(listener, acceptor, sender, limits));
        Ok(Self {
            receiver,
            local_addr,
            accept_task,
            dropped,
        })
    }
}

impl Listener for MixedListener {
    type Io = MixedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let mut logged_closed = false;
        loop {
            if let Some(connection) = self.receiver.recv().await {
                return connection;
            }
            if !logged_closed {
                tracing::error!(
                    "control-plane accept task closed; no further connections will be served"
                );
                logged_closed = true;
            }
            // The accept task only closes when the listener is dropped; do
            // not busy-spin if shutdown races this future. There is no
            // recoverable error in axum's Listener interface.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
impl MixedListener {
    fn dropped_connections(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for MixedListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// The four independent limits and the rejection counter shared by the
/// accept loop. Loopback pools are separate so a local health probe cannot be
/// starved by remote clients.
struct ConnectionLimits {
    pending: Arc<Semaphore>,
    pending_loopback: Arc<Semaphore>,
    active: Arc<Semaphore>,
    active_loopback: Arc<Semaphore>,
    dropped: Arc<AtomicU64>,
}

/// Loopback check that also handles IPv4-mapped IPv6 peers on a dual-stack
/// `[::]:9080` listener. Without the mapping, `::ffff:127.0.0.1` would be
/// treated as a public client and lose the reserved health-probe pool.
fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        },
    }
}

/// Accepts sockets and hands each one to a bounded pre-handshake task.
async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    sender: mpsc::Sender<(MixedStream, SocketAddr)>,
    limits: ConnectionLimits,
) {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::error!(error = %err, "control-plane accept failed");
                // Mirroring axum: an accept error is usually a transient
                // resource shortage (e.g. EMFILE), so pause instead of
                // spinning.
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            },
        };
        let _ = stream.set_nodelay(true);
        let loopback = is_loopback(&addr);
        let pending_pool = if loopback {
            limits.pending_loopback.clone()
        } else {
            limits.pending.clone()
        };
        let active_pool = if loopback {
            limits.active_loopback.clone()
        } else {
            limits.active.clone()
        };

        let permit = match pending_pool.try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let count = limits.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if count == 1 || count.is_multiple_of(1024) {
                    tracing::warn!(
                        %addr,
                        dropped = count,
                        "control-plane pre-handshake limit reached; dropping connections"
                    );
                }
                // Drop the TCP connection rather than letting the kernel
                // accept queue grow behind a saturated handshake pool.
                drop(stream);
                continue;
            },
        };
        let active_permit = match active_pool.try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let count = limits.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if count == 1 || count.is_multiple_of(1024) {
                    tracing::warn!(
                        %addr,
                        dropped = count,
                        "control-plane active-connection limit reached; dropping connections"
                    );
                }
                drop(stream);
                continue;
            },
        };

        let sender = sender.clone();
        let acceptor = acceptor.clone();
        let dropped = limits.dropped.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let is_tls = match tokio::time::timeout(
                PROTOCOL_PEEK_TIMEOUT,
                looks_like_tls(&stream),
            )
            .await
            {
                Ok(Ok(is_tls)) => is_tls,
                Ok(Err(err)) => {
                    tracing::debug!(%addr, error = %err, "cannot read from the new connection");
                    return;
                },
                Err(_) => {
                    tracing::debug!(%addr, "control-plane protocol detection timed out");
                    return;
                },
            };

            let io = if is_tls {
                match tokio::time::timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(tls)) => MaybeTlsStream::Tls(Box::new(tls)),
                    Ok(Err(err)) => {
                        // A client that does not trust the certificate drops
                        // the handshake; that is routine, not an outage.
                        tracing::debug!(%addr, error = %err, "TLS handshake failed");
                        return;
                    },
                    Err(_) => {
                        tracing::debug!(%addr, "control-plane TLS handshake timed out");
                        return;
                    },
                }
            } else {
                MaybeTlsStream::Plain(stream)
            };

            let io = MixedStream::new(io, active_permit);
            if sender.try_send((io, addr)).is_err() {
                let count = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if count == 1 || count.is_multiple_of(1024) {
                    tracing::warn!(
                        %addr,
                        dropped = count,
                        "control-plane ready queue is full; dropping a completed handshake"
                    );
                }
            }
        });
    }
}

/// Peeks the first byte to tell a TLS handshake from a cleartext request.
///
/// `peek` does not consume the byte, so the protocol handler still sees it.
async fn looks_like_tls(stream: &TcpStream) -> io::Result<bool> {
    let mut first = [0u8; 1];
    match stream.peek(&mut first).await? {
        // The peer hung up before saying anything; hand it to the HTTP side,
        // which reports the empty request the same way it always has.
        0 => Ok(false),
        _ => Ok(first[0] == TLS_HANDSHAKE_RECORD),
    }
}

/// Per-connection facts the request middleware reads through `ConnectInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnInfo {
    /// Whether the connection arrived through the TLS half of the listener.
    pub tls: bool,
    /// The TCP peer address, used by the self-protection IP allowlist and the
    /// access log. Forwarding headers are deliberately ignored: only the
    /// socket address cannot be spoofed by the caller.
    pub peer_addr: SocketAddr,
}

impl Connected<IncomingStream<'_, MixedListener>> for ConnInfo {
    fn connect_info(stream: IncomingStream<'_, MixedListener>) -> Self {
        Self {
            tls: stream.io().is_tls(),
            peer_addr: *stream.remote_addr(),
        }
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for ConnInfo {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        // A plain `TcpListener` only ever serves cleartext.
        Self {
            tls: false,
            peer_addr: *stream.remote_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::tls::{generate_self_signed, parse_chain};
    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    fn test_certificate() -> (String, String) {
        let material =
            generate_self_signed("PingWAF", &["localhost".to_string()], 30)
                .unwrap();
        (material.cert_pem, material.key_pem.unwrap())
    }

    #[test]
    fn ipv4_mapped_ipv6_loopback_is_treated_as_local() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:9080".parse().unwrap();
        assert!(is_loopback(&mapped));
        let public: SocketAddr = "203.0.113.10:9080".parse().unwrap();
        assert!(!is_loopback(&public));
    }

    #[test]
    fn activate_installs_the_certificate_and_rejects_a_bad_pair() {
        let tls = ControlPlaneTls::new(true);
        assert!(!tls.has_certificate());
        assert!(tls.is_enabled());

        let (cert_pem, key_pem) = test_certificate();
        tls.activate(&cert_pem, &key_pem).unwrap();
        assert!(tls.has_certificate());

        // An unrelated key must not replace a working certificate.
        let other =
            generate_self_signed("Other", &["localhost".to_string()], 30)
                .unwrap();
        assert!(tls
            .activate(&cert_pem, other.key_pem.as_deref().unwrap())
            .is_err());
        assert!(tls.has_certificate());
    }

    #[test]
    fn resolver_serves_the_installed_key_and_nothing_before() {
        let resolver = ReloadableResolver::default();
        assert!(resolver.loaded().is_none());

        let (cert_pem, key_pem) = test_certificate();
        resolver.install(certified_key(&cert_pem, &key_pem).unwrap());
        let loaded = resolver.loaded().unwrap();
        assert_eq!(loaded.cert.len(), 1);
    }

    /// A client that connects but sends no first byte must not hold up the
    /// next connection. This is the regression for the 9080 accept-queue
    /// wedge: the old serial `peek` blocked the only accept loop forever.
    #[tokio::test]
    async fn silent_client_does_not_block_a_later_plain_request() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener =
            MixedListener::new(listener, tls.acceptor()).unwrap();

        let _silent = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"PING").await.unwrap();

        let (mut io, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        )
        .await
        .expect("a silent connection must not block the next accept");
        assert!(!io.is_tls());
        let mut ping = [0u8; 4];
        io.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"PING");
        io.write_all(b"PONG").await.unwrap();
        io.flush().await.unwrap();
    }

    /// Once a connection is handed to the HTTP layer, a client that sends one
    /// byte and then goes silent must be closed by the idle timeout instead of
    /// holding an active connection indefinitely.
    #[tokio::test]
    async fn plain_connection_idle_read_times_out() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener =
            MixedListener::new(listener, tls.acceptor()).unwrap();

        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"G").await.unwrap();
        let (mut io, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        )
        .await
        .expect("a plain connection should be accepted");
        assert!(!io.is_tls());
        let mut first = [0u8; 1];
        io.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"G");

        let reader = tokio::spawn(async move { io.read(&mut [0u8; 1]).await });
        tokio::time::sleep(
            CONNECTION_IDLE_TIMEOUT + Duration::from_millis(100),
        )
        .await;
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), reader)
                .await
                .expect("idle timeout must fire")
                .expect("reader task must not panic");
        assert_eq!(
            result.expect_err("idle read must fail").kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(plain);
    }

    /// The TLS branch has the same head-of-line risk as the peek branch: a
    /// client that sends a TLS record header and then stalls must time out
    /// without preventing the next plain request from being served.
    #[tokio::test]
    async fn stalled_tls_handshake_does_not_block_a_later_plain_request() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener =
            MixedListener::new(listener, tls.acceptor()).unwrap();

        let mut stalled = TcpStream::connect(addr).await.unwrap();
        stalled.write_all(&[TLS_HANDSHAKE_RECORD]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"PING").await.unwrap();

        let (mut io, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        )
        .await
        .expect("a stalled TLS handshake must not block the next accept");
        assert!(!io.is_tls());
        let mut ping = [0u8; 4];
        io.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"PING");

        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT + Duration::from_millis(300),
            stalled.read(&mut byte),
        )
        .await
        .expect("stalled TLS handshake must be closed");
        assert!(matches!(closed, Ok(0) | Err(_)));
    }

    /// More silent clients than the pre-handshake budget must not grow the
    /// task set without bound; after their timeouts expire the listener serves
    /// a normal request again.
    #[tokio::test]
    async fn excess_slow_connections_are_bounded_and_recover() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener =
            MixedListener::new(listener, tls.acceptor()).unwrap();

        let mut slow = Vec::new();
        for _ in 0..MAX_PENDING_HANDSHAKES + 4 {
            slow.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            listener.dropped_connections(),
            4,
            "the excess four connections must be rejected"
        );
        tokio::time::sleep(PROTOCOL_PEEK_TIMEOUT + Duration::from_millis(100))
            .await;

        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"PING").await.unwrap();
        let (mut io, _) =
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect(
                    "the listener must recover after slow connections time out",
                );
        assert!(!io.is_tls());
        let mut ping = [0u8; 4];
        io.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"PING");

        drop(slow);
    }

    /// Drives a real TCP connection through both halves of the listener: a
    /// cleartext client and a TLS client trusting the generated certificate.
    #[tokio::test]
    async fn mixed_listener_dispatches_both_protocols() {
        let (cert_pem, key_pem) = test_certificate();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener =
            MixedListener::new(listener, tls.acceptor()).unwrap();
        assert_eq!(listener.local_addr().unwrap(), addr);

        let server = tokio::spawn(async move {
            let mut replies = Vec::new();
            for _ in 0..2 {
                let (mut io, _) = listener.accept().await;
                let tls = io.is_tls();
                let mut ping = [0u8; 4];
                io.read_exact(&mut ping).await.unwrap();
                assert_eq!(&ping, b"PING");
                io.write_all(if tls { b"TLS" } else { b"PLAIN" })
                    .await
                    .unwrap();
                io.flush().await.unwrap();
                replies.push(tls);
            }
            replies
        });

        // Cleartext: the first byte is 'P', not a TLS record.
        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 5];
        plain.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"PLAIN");

        // TLS: the client verifies the self-signed certificate by name.
        let mut roots = RootCertStore::empty();
        roots
            .add(parse_chain(&cert_pem).unwrap().remove(0))
            .unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(
            crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let name = ServerName::try_from("localhost").unwrap();
        let mut secure = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        secure.write_all(b"PING").await.unwrap();
        let mut reply = [0u8; 3];
        secure.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"TLS");

        let mut handshakes: Vec<bool> = server.await.unwrap();
        handshakes.sort_unstable();
        assert_eq!(handshakes, vec![false, true]);
    }
}
