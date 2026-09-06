//! TLS configuration for iroh.
//!
//! Currently there is one mechanism available:
//! - Raw Public Keys, using the TLS extension described in [RFC 7250]
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use std::sync::Arc;

use iroh_base::SecretKey;
use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tracing::warn;

use self::resolver::ResolveRawPublicKeyCert;

pub(crate) mod misc;
pub(crate) mod name;
mod resolver;
mod verifier;

#[allow(deprecated)] // Re-export of backwards-compatibility item
pub use iroh_relay::tls::CaRootsConfig;
pub use iroh_relay::tls::CaTlsConfig;
#[cfg(with_crypto_provider)]
pub use iroh_relay::tls::default_provider;

/// Maximum amount of TLS tickets we will cache (by default) for 0-RTT connection
/// establishment.
///
/// 8 tickets per remote endpoint, 32 different endpoints would max out the required storage:
/// ~200 bytes per session + certificates (which are ~387 bytes)
/// So 8 * 32 * (200 + 387) = 150.272 bytes, assuming pointers to certificates
/// are never aliased pointers (they're Arc'ed).
/// I think 150KB is an acceptable default upper limit for such a cache.
pub(crate) const DEFAULT_MAX_TLS_TICKETS: usize = 8 * 32;

/// Configuration for TLS.
///
/// The main point of this struct is to keep state that should be kept the same
/// over multiple TLS sessions the same.
/// E.g. the `server_verifier` and `client_verifier` Arc pointers are checked to be
/// the same between different TLS session calls with 0-RTT data in rustls.
/// This makes sure that's the case.
#[derive(Debug)]
pub(crate) struct TlsConfig {
    pub(crate) secret_key: SecretKey,
    cert_resolver: Arc<ResolveRawPublicKeyCert>,
    server_verifier: Arc<verifier::ServerCertificateVerifier>,
    client_verifier: Arc<verifier::ClientCertificateVerifier>,
    session_store: Arc<dyn rustls::client::ClientSessionStore>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl TlsConfig {
    pub(crate) fn new(
        secret_key: SecretKey,
        max_tls_tickets: usize,
        crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            cert_resolver: Arc::new(ResolveRawPublicKeyCert::new(&secret_key)),
            server_verifier: Arc::new(verifier::ServerCertificateVerifier),
            client_verifier: Arc::new(verifier::ClientCertificateVerifier),
            session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(
                max_tls_tickets,
            )),
            crypto_provider,
            secret_key,
        }
    }

    /// Create a TLS client configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_client_config(
        &self,
        keylog: bool,
    ) -> Result<QuicClientConfig, TlsConfigError> {
        let mut crypto = rustls::ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_protocol_versions(verifier::PROTOCOL_VERSIONS)?
            .dangerous()
            .with_custom_certificate_verifier(self.server_verifier.clone())
            .with_client_cert_resolver(self.cert_resolver.clone());

        // Resumption tickets are kept (psk_dhe_ke keeps the key exchange), but
        // 0-RTT is off: early application data is replayable by design and a
        // CNSA 2.0 TLS profile (draft-becker-cnsa2-tls-profile) forbids
        // `early_data`. `Connecting::into_0rtt` therefore always returns the
        // 1-RTT path. Complear fork, branch complear/v1.0.2-cnsa-quic.
        crypto.resumption = rustls::client::Resumption::store(self.session_store.clone());
        crypto.enable_early_data = false;

        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let quic = match initial_suite(&self.crypto_provider) {
            Some(initial) => QuicClientConfig::with_initial(Arc::new(crypto), initial)?,
            None => QuicClientConfig::try_from(crypto)?,
        };
        Ok(quic)
    }

    /// Create a TLS server configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_server_config(
        &self,
        keylog: bool,
    ) -> Result<QuicServerConfig, TlsConfigError> {
        let mut crypto = rustls::ServerConfig::builder_with_provider(self.crypto_provider.clone())
            .with_protocol_versions(verifier::PROTOCOL_VERSIONS)?
            .with_client_cert_verifier(self.client_verifier.clone())
            .with_cert_resolver(self.cert_resolver.clone());
        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        // must be u32::MAX or 0 (the default). Any other value panics with QUIC
        // This is specified in RFC 9001: https://www.rfc-editor.org/rfc/rfc9001#section-4.6.1
        //
        // 0: no early data is accepted, for the reason given in
        // `make_client_config`. Complear fork, branch complear/v1.0.2-cnsa-quic.
        crypto.max_early_data_size = 0;
        let quic = match initial_suite(&self.crypto_provider) {
            Some(initial) => QuicServerConfig::with_initial(Arc::new(crypto), initial)?,
            None => QuicServerConfig::try_from(crypto)?,
        };
        Ok(quic)
    }
}

/// See [`iroh_relay::quic::initial_suite`]: the RFC 9001 Initial suite,
/// supplied explicitly so the negotiated suite list can exclude AES-128.
use iroh_relay::quic::initial_suite;

#[allow(missing_docs)]
#[n0_error::stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum TlsConfigError {
    #[error(
        "The configured crypto provider is missing support for TLS13_AES_128_GCM_SHA256, which is required for QUIC initial packets."
    )]
    CryptoProviderNoInitialCipherSuite {
        #[error(std_err)]
        source: noq::crypto::rustls::NoInitialCipherSuite,
    },
    #[error("The configured crypto provider is incompatible with iroh and QUIC encryption")]
    CryptoProviderIncompatible {
        #[error(std_err)]
        source: rustls::Error,
    },
}
