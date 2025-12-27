//! # High-Level Node API
//!
//! This module provides the main entry point for using Korium. A [`Node`] combines
//! all the underlying components (DHT, PubSub, Relay) into a single
//! unified interface.
//!
//! ## Quick Start
//!
//! ```ignore
//! // Create a new node on a random port
//! let node = Node::bind("0.0.0.0:0").await?;
//!
//! // Bootstrap by connecting to a known peer
//! node.add_peer(&bootstrap_contact).await?;
//!
//! // Subscribe to a topic and publish messages
//! node.subscribe("my-topic").await?;
//! node.publish("my-topic", b"hello world").await?;
//!
//! // Receive messages via the messages() receiver
//! let mut rx = node.messages().await?;
//! while let Some(msg) = rx.recv().await {
//!     println!("Got message: {:?}", msg);
//! }
//! ```
//!
//! ## Component Integration
//!
//! The Node orchestrates these components:
//! - **SmartSock**: Multi-path transport (direct UDP, relay tunnels)
//! - **RpcNode**: QUIC-based RPC for all protocol messages
//! - **DhtNode**: Kademlia DHT for peer/value lookup
//! - **GossipSub**: Epidemic broadcast for PubSub
//! - **RelayClient**: NAT traversal via relay servers

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use tracing::{debug, info, warn};

#[cfg(feature = "spiffe")]
use crate::crypto::{SpiffeConfig, generate_ed25519_cert_with_spiffe};
use crate::crypto::{create_client_config, create_server_config, generate_ed25519_cert};
use crate::dht::{DEFAULT_ALPHA, DEFAULT_K, DhtNode, TelemetrySnapshot};
use crate::gossipsub::{GossipSub, GossipSubConfig, ReceivedMessage, RelaySignal};
use crate::identity::Contact;
use crate::messages::{Message, RelayResponse};
use crate::protocols::{PlainRpc, RelayRpc};
use crate::relay::{
    IncomingConnection, MeshSignalOut, NatStatus, Relay, RelayClient, generate_session_id,
};
use crate::rpc::{self, RpcNode};
use crate::transport::{DIRECT_CONNECT_TIMEOUT, SmartSock};

/// Timeout for relay operations (session requests and relay-assisted connections).
/// SECURITY: Prevents hangs if a relay is unresponsive during handshake or RPC.
const RELAY_TIMEOUT: Duration = Duration::from_secs(15);

/// A receiver that can be taken exactly once via `.take()`.
/// Used for message receivers that should only have one consumer.
type TakeOnce<T> = tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<T>>>;

/// Request tuple type for request-response pattern.
type RequestTuple = (Identity, Vec<u8>, tokio::sync::oneshot::Sender<Vec<u8>>);

// Re-export Identity and PoW types for public API consumers
pub use crate::identity::{
    Identity, IdentityProof, Keypair, NAMESPACE_HASH_LEN, NamespaceConfig, POW_DIFFICULTY, PoWError,
};

// Re-export Threshold CA types for public API consumers
// Note: DKG types (DkgCoordinator, DkgRound1Secret, etc.) are internal.
// Users should generate SignerState via external tooling or the korium CLI.
#[cfg(feature = "spiffe")]
pub use crate::thresholdca::{CaPublicKey, SignerState, ThresholdCaConfig, ThresholdCaError};
// CaRequestConfig is defined in this module, not thresholdca

pub struct Node {
    keypair: Keypair,
    endpoint: Endpoint,
    smartsock: Arc<SmartSock>,
    contact: Contact,
    dhtnode: DhtNode<RpcNode>,
    rpcnode: RpcNode,
    gossipsub: GossipSub<RpcNode>,
    relay_client: Arc<RelayClient>,
    gossipsub_receiver: TakeOnce<ReceivedMessage>,
    request_handler_rx: TakeOnce<RequestTuple>,
    listener: tokio::task::JoinHandle<Result<()>>,
}

impl Node {
    /// Create a new node with a fresh identity (includes PoW generation).
    ///
    /// This generates a new Ed25519 keypair and computes a Proof-of-Work
    /// for Sybil resistance. PoW computation takes ~1-4 seconds.
    ///
    /// # Errors
    /// Returns error if PoW generation fails (astronomically unlikely) or socket binding fails.
    pub async fn bind(addr: &str) -> Result<Self> {
        let (keypair, pow_proof) =
            Keypair::generate_with_pow().map_err(|e| anyhow::anyhow!("{e}"))?;
        Self::create(addr, keypair, pow_proof).await
    }

    /// Create a new node with an existing keypair.
    ///
    /// **WARNING**: The keypair must have a valid PoW proof, otherwise
    /// this node's contacts will be rejected by other nodes.
    /// Use `bind_with_keypair_and_pow` for production.
    pub async fn bind_with_keypair(addr: &str, keypair: Keypair) -> Result<Self> {
        // No PoW proof - contacts from this node will be rejected
        Self::create(addr, keypair, IdentityProof::empty()).await
    }

    /// Create a new node with an existing keypair and its PoW proof.
    pub async fn bind_with_keypair_and_pow(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
    ) -> Result<Self> {
        Self::create_internal(addr, keypair, pow_proof, None).await
    }

    /// Create a builder for configuring a new node.
    ///
    /// The builder pattern allows configuring optional features like SPIFFE
    /// before creating the node.
    ///
    /// # Example
    /// ```ignore
    /// // Without SPIFFE (default)
    /// let node = Node::builder("0.0.0.0:4433").build().await?;
    ///
    /// // With SPIFFE (requires spiffe feature)
    /// let node = Node::builder("0.0.0.0:4433")
    ///     .spiffe_trust_domain("example.org")
    ///     .spiffe_workload_path("payment-svc")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn builder(addr: &str) -> NodeBuilder {
        NodeBuilder::new(addr)
    }

    #[cfg(not(feature = "spiffe"))]
    async fn create(addr: &str, keypair: Keypair, pow_proof: IdentityProof) -> Result<Self> {
        Self::create_internal(addr, keypair, pow_proof, None).await
    }

    #[cfg(not(feature = "spiffe"))]
    async fn create_with_namespace(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        namespace_config: Option<NamespaceConfig>,
    ) -> Result<Self> {
        Self::create_internal_with_namespace(addr, keypair, pow_proof, None, namespace_config).await
    }

    #[cfg(feature = "spiffe")]
    async fn create(addr: &str, keypair: Keypair, pow_proof: IdentityProof) -> Result<Self> {
        Self::create_internal(addr, keypair, pow_proof, None).await
    }

    #[cfg(feature = "spiffe")]
    async fn create_with_spiffe(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        spiffe_config: Option<&SpiffeConfig>,
    ) -> Result<Self> {
        Self::create_internal(addr, keypair, pow_proof, spiffe_config).await
    }

    #[cfg(feature = "spiffe")]
    async fn create_with_spiffe_and_namespace(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        spiffe_config: Option<&SpiffeConfig>,
        namespace_config: Option<NamespaceConfig>,
    ) -> Result<Self> {
        Self::create_internal_with_namespace(
            addr,
            keypair,
            pow_proof,
            spiffe_config,
            namespace_config,
        )
        .await
    }

    #[cfg(feature = "spiffe")]
    async fn create_internal(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        spiffe_config: Option<&SpiffeConfig>,
    ) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid socket address")?;

        let identity = keypair.identity();

        // Generate certificates with optional SPIFFE SAN
        let (server_certs, server_key) = match spiffe_config {
            Some(cfg) => generate_ed25519_cert_with_spiffe(&keypair, Some(cfg))?,
            None => generate_ed25519_cert(&keypair)?,
        };
        let (client_certs, client_key) = match spiffe_config {
            Some(cfg) => generate_ed25519_cert_with_spiffe(&keypair, Some(cfg))?,
            None => generate_ed25519_cert(&keypair)?,
        };

        let server_config = create_server_config(server_certs, server_key)?;
        let client_config = create_client_config(client_certs, client_key)?;

        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;

        // Create contact with PoW proof for Sybil resistance
        let mut contact = Contact::single(identity, local_addr.to_string());
        contact.pow_proof = pow_proof;

        Self::create_from_components(keypair, endpoint, smartsock, contact, client_config).await
    }

    #[cfg(feature = "spiffe")]
    async fn create_internal_with_namespace(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        spiffe_config: Option<&SpiffeConfig>,
        namespace_config: Option<NamespaceConfig>,
    ) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid socket address")?;

        let identity = keypair.identity();

        // Generate certificates with optional SPIFFE SAN
        let (server_certs, server_key) = match spiffe_config {
            Some(cfg) => generate_ed25519_cert_with_spiffe(&keypair, Some(cfg))?,
            None => generate_ed25519_cert(&keypair)?,
        };
        let (client_certs, client_key) = match spiffe_config {
            Some(cfg) => generate_ed25519_cert_with_spiffe(&keypair, Some(cfg))?,
            None => generate_ed25519_cert(&keypair)?,
        };

        let server_config = create_server_config(server_certs, server_key)?;
        let client_config = create_client_config(client_certs, client_key)?;

        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;

        // Create contact with PoW proof for Sybil resistance
        let mut contact = Contact::single(identity, local_addr.to_string());
        contact.pow_proof = pow_proof;

        Self::create_from_components_with_namespace(
            keypair,
            endpoint,
            smartsock,
            contact,
            client_config,
            namespace_config,
        )
        .await
    }

    #[cfg(not(feature = "spiffe"))]
    async fn create_internal(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        _spiffe_config: Option<()>,
    ) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid socket address")?;

        let identity = keypair.identity();

        let (server_certs, server_key) = generate_ed25519_cert(&keypair)?;
        let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;

        let server_config = create_server_config(server_certs, server_key)?;
        let client_config = create_client_config(client_certs, client_key)?;

        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;

        // Create contact with PoW proof for Sybil resistance
        let mut contact = Contact::single(identity, local_addr.to_string());
        contact.pow_proof = pow_proof;

        Self::create_from_components(keypair, endpoint, smartsock, contact, client_config).await
    }

    #[cfg(not(feature = "spiffe"))]
    async fn create_internal_with_namespace(
        addr: &str,
        keypair: Keypair,
        pow_proof: IdentityProof,
        _spiffe_config: Option<()>,
        namespace_config: Option<NamespaceConfig>,
    ) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("invalid socket address")?;

        let identity = keypair.identity();

        let (server_certs, server_key) = generate_ed25519_cert(&keypair)?;
        let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;

        let server_config = create_server_config(server_certs, server_key)?;
        let client_config = create_client_config(client_certs, client_key)?;

        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;

        // Create contact with PoW proof for Sybil resistance
        let mut contact = Contact::single(identity, local_addr.to_string());
        contact.pow_proof = pow_proof;

        Self::create_from_components_with_namespace(
            keypair,
            endpoint,
            smartsock,
            contact,
            client_config,
            namespace_config,
        )
        .await
    }

    async fn create_from_components(
        keypair: Keypair,
        endpoint: Endpoint,
        smartsock: Arc<SmartSock>,
        contact: Contact,
        client_config: quinn::ClientConfig,
    ) -> Result<Self> {
        Self::create_from_components_with_namespace(
            keypair,
            endpoint,
            smartsock,
            contact,
            client_config,
            None,
        )
        .await
    }

    async fn create_from_components_with_namespace(
        keypair: Keypair,
        endpoint: Endpoint,
        smartsock: Arc<SmartSock>,
        contact: Contact,
        client_config: quinn::ClientConfig,
        namespace_config: Option<NamespaceConfig>,
    ) -> Result<Self> {
        let identity = keypair.identity();
        let our_pubkey = *identity.as_bytes();
        let local_addr = endpoint.local_addr()?;

        // Wrap namespace config in Arc for sharing
        let namespace_config = namespace_config.map(Arc::new);

        let mut rpcnode =
            RpcNode::with_identity(endpoint.clone(), contact.clone(), client_config, identity)
                .with_smartsock(smartsock.clone());

        // Add namespace config to RpcNode for payload encryption
        if let Some(ref ns_config) = namespace_config {
            rpcnode = rpcnode.with_namespace_config(ns_config.clone());
        }

        let dhtnode = DhtNode::new(
            identity,
            contact.clone(),
            rpcnode.clone(),
            DEFAULT_K,
            DEFAULT_ALPHA,
        );

        // Create channel for relay server → mesh signaling (outbound signals)
        let (mesh_out_tx, mut mesh_out_rx) = tokio::sync::mpsc::channel::<MeshSignalOut>(32);

        // Initialize relay server (shares socket with SmartSock, uses mesh-only signaling)
        let relay = Relay::with_socket(smartsock.inner_socket().clone(), mesh_out_tx);
        smartsock.set_udprelay(relay);
        info!(
            "UDP relay server sharing port {} (mesh-only signaling)",
            local_addr
        );

        // Create relay client for NAT traversal (before GossipSub so we can wire up mesh signaling)
        let relay_client = RelayClient::new(
            Arc::new(rpcnode.clone()),
            dhtnode.clone(),
            keypair.clone(),
            local_addr,
        );

        // Create channel for mesh-mediated relay signaling (inbound signals to RelayClient)
        let (relay_signal_tx, mut relay_signal_rx) = tokio::sync::mpsc::channel::<RelaySignal>(32);

        // GossipSub with DHT and relay signaling integration
        let (gossipsub, gossipsub_rx) = GossipSub::spawn(
            Arc::new(rpcnode.clone()),
            keypair.clone(),
            GossipSubConfig::default(),
            dhtnode.clone(),
            relay_signal_tx,
        );
        let gossipsub_receiver = tokio::sync::Mutex::new(Some(gossipsub_rx));

        // Wrap relay_client in Arc for sharing with mesh signaling task
        let relay_client = Arc::new(relay_client);

        // Wire up mesh signaling: forward RelaySignal messages from GossipSub to RelayClient
        {
            let relay_client = relay_client.clone();
            tokio::spawn(async move {
                while let Some(signal) = relay_signal_rx.recv().await {
                    if let Err(e) = relay_client
                        .receive_mesh_signal(
                            signal.from_peer,
                            signal.session_id,
                            signal.relay_data_addr,
                        )
                        .await
                    {
                        debug!("failed to process mesh relay signal: {}", e);
                    }
                }
            });
        }

        // Wire up mesh signaling: forward MeshSignalOut from RelayServer to GossipSub
        // When the relay server needs to signal a NAT peer, it sends via the mesh network.
        {
            let gossipsub_clone = gossipsub.clone();
            tokio::spawn(async move {
                while let Some(signal) = mesh_out_rx.recv().await {
                    if let Err(e) = gossipsub_clone
                        .send_relay_signal(
                            signal.target,
                            signal.from_peer,
                            signal.session_id,
                            signal.relay_data_addr,
                        )
                        .await
                    {
                        debug!("failed to send relay signal via mesh: {}", e);
                    }
                }
            });
        }

        let listener = {
            let endpoint = endpoint.clone();
            let dhtnode = dhtnode.clone();
            let smartsock = smartsock.clone();
            let gossipsub = gossipsub.clone();
            let ns_config = namespace_config.clone();

            // Channel for request-response pattern
            let (request_tx, request_rx) = tokio::sync::mpsc::channel::<(
                Identity,
                Vec<u8>,
                tokio::sync::oneshot::Sender<Vec<u8>>,
            )>(256);
            let request_handler_rx = tokio::sync::Mutex::new(Some(request_rx));

            let listen = tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let node = dhtnode.clone();
                    let gossipsub = Some(gossipsub.clone());
                    let ss = Some(smartsock.clone());
                    let request_tx = Some(request_tx.clone());
                    let ns = ns_config.clone();
                    let pk = our_pubkey;
                    tokio::spawn(async move {
                        if let Err(e) = rpc::handle_connection_with_namespace(
                            node, gossipsub, ss, incoming, request_tx, ns, pk,
                        )
                        .await
                        {
                            warn!("connection error: {:?}", e);
                        }
                    });
                }
                Ok(())
            });

            (listen, request_handler_rx)
        };

        info!("Node {}/{}", local_addr, hex::encode(identity));

        Ok(Self {
            keypair,
            endpoint,
            smartsock,
            contact,
            dhtnode,
            rpcnode,
            gossipsub,
            relay_client,
            gossipsub_receiver,
            request_handler_rx: listener.1,
            listener: listener.0,
        })
    }

    /// Returns the node's identity as a hex-encoded string.
    pub fn identity(&self) -> String {
        self.keypair.identity().to_hex()
    }

    /// Returns the node's identity as an Identity struct.
    pub fn peer_identity(&self) -> Identity {
        self.keypair.identity()
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to get local address")
    }

    /// Returns routable addresses for this node.
    ///
    /// When bound to a specific IP (e.g., `192.168.1.10:8000`), returns that address.
    /// When bound to `0.0.0.0` or `::`, enumerates all local network interfaces
    /// and returns their addresses with the bound port.
    ///
    /// # Returns
    /// A vector of routable socket address strings.
    ///
    /// # Example
    /// ```ignore
    /// // Bound to 0.0.0.0:8000 on a machine with eth0=192.168.1.10 and lo=127.0.0.1
    /// let addrs = node.routable_addresses();
    /// // Returns: ["192.168.1.10:8000", "127.0.0.1:8000"]
    /// ```
    pub fn routable_addresses(&self) -> Vec<String> {
        let local = match self.endpoint.local_addr() {
            Ok(addr) => addr,
            Err(_) => return Vec::new(),
        };

        let ip = local.ip();
        let port = local.port();

        // Check if bound to unspecified (0.0.0.0 or ::)
        if ip.is_unspecified() {
            // Enumerate all local network interfaces
            Self::enumerate_local_addresses(port, ip.is_ipv4())
        } else {
            vec![local.to_string()]
        }
    }

    /// Enumerate all local network interface addresses.
    ///
    /// Uses a pure-Rust approach that doesn't shell out to external commands.
    /// This avoids potential issues with missing `hostname` command on some systems
    /// and eliminates subprocess overhead.
    fn enumerate_local_addresses(port: u16, ipv4_only: bool) -> Vec<String> {
        let mut addresses = Vec::new();

        // Probe method: bind to 0.0.0.0 then connect to public DNS to discover local IP.
        // This works reliably across platforms without shelling out.
        // We try multiple targets for robustness.
        let probe_targets = [
            "8.8.8.8:53", // Google DNS
            "1.1.1.1:53", // Cloudflare DNS
            "9.9.9.9:53", // Quad9 DNS
        ];

        for target in probe_targets {
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0")
                && socket.connect(target).is_ok()
                && let Ok(local) = socket.local_addr()
            {
                let ip = local.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    let addr_str = SocketAddr::new(ip, port).to_string();
                    if !addresses.contains(&addr_str) {
                        // Filter by IP version if requested
                        if ipv4_only && !ip.is_ipv4() {
                            continue;
                        }
                        addresses.push(addr_str);
                    }
                }
            }
        }

        // Also try IPv6 probe if not ipv4_only
        if !ipv4_only {
            // Use IPv6 DNS targets
            let ipv6_targets = [
                "[2001:4860:4860::8888]:53", // Google DNS IPv6
                "[2606:4700:4700::1111]:53", // Cloudflare DNS IPv6
            ];
            for target in ipv6_targets {
                if let Ok(socket) = std::net::UdpSocket::bind("[::]:0")
                    && socket.connect(target).is_ok()
                    && let Ok(local) = socket.local_addr()
                {
                    let ip = local.ip();
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        let addr_str = SocketAddr::new(ip, port).to_string();
                        if !addresses.contains(&addr_str) {
                            addresses.push(addr_str);
                        }
                    }
                }
            }
        }

        // Always include loopback as fallback
        let loopback = if ipv4_only {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        };

        // Add loopback if not already present
        let loopback_str = SocketAddr::new(loopback, port).to_string();
        if !addresses.iter().any(|a| a == &loopback_str) {
            addresses.push(loopback_str);
        }

        // If no addresses found, return just loopback
        if addresses.is_empty() {
            addresses.push(SocketAddr::new(loopback, port).to_string());
        }

        addresses
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn peer_endpoint(&self) -> &Contact {
        &self.contact
    }

    pub fn quic_endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn smartsock(&self) -> &Arc<SmartSock> {
        &self.smartsock
    }

    /// Check if communication with a peer is currently routed through a relay.
    ///
    /// Returns `true` if the peer is registered in SmartSock and using a relay path,
    /// `false` if using direct path or peer is not registered.
    ///
    /// # Arguments
    /// * `identity` - The peer's identity to check
    #[cfg(test)]
    pub async fn is_peer_relayed(&self, identity: &Identity) -> bool {
        self.smartsock.is_peer_relayed(identity).await
    }

    /// Get the active relay session ID for a peer, if using relay path.
    ///
    /// Returns `Some(session_id)` if the peer is using a relay path,
    /// `None` if using direct path or peer is not registered.
    ///
    /// # Arguments
    /// * `identity` - The peer's identity to check
    #[cfg(test)]
    pub async fn peer_relay_session(&self, identity: &Identity) -> Option<[u8; 16]> {
        self.smartsock.peer_relay_session(identity).await
    }

    /// Get the relay handle for this node.
    ///
    /// All nodes run an embedded relay server that shares the QUIC socket.
    /// Use this to access relay telemetry, session counts, or to check
    /// if the relay is operational.
    ///
    /// # Returns
    /// The Relay handle, or `None` if the relay hasn't been initialized.
    pub fn relay(&self) -> Option<crate::relay::Relay> {
        self.smartsock.relay()
    }

    pub async fn publish_address(&self, addresses: Vec<String>) -> Result<()> {
        // Warn if any address is unroutable (0.0.0.0 or ::)
        for addr in &addresses {
            if let Ok(socket_addr) = addr.parse::<SocketAddr>()
                && socket_addr.ip().is_unspecified()
            {
                warn!(
                    "publishing unroutable address '{}' - use routable_addresses() or provide explicit IPs",
                    addr
                );
            }
        }
        self.dhtnode.publish_address(&self.keypair, addresses).await
    }

    pub async fn relay_endpoint(&self) -> Option<Contact> {
        let local_addr = self.endpoint.local_addr().ok()?;

        Some(Contact::single(
            self.keypair.identity(),
            local_addr.to_string(),
        ))
    }

    /// Register with a relay node for incoming connection notifications.
    ///
    /// NAT-bound nodes should call this to maintain a signaling channel with
    /// their relay. When other peers want to connect via the relay, the node
    /// receives `IncomingConnection` notifications through the returned receiver.
    ///
    /// The relay's address is resolved via DHT lookup.
    ///
    /// # Arguments
    /// * `relay_identity` - Hex-encoded identity of the relay node
    ///
    /// # Returns
    /// A receiver that yields incoming connection notifications. Each notification
    /// contains the connecting peer's identity and a session_id to use when
    /// completing the relay connection.
    ///
    /// # Example
    /// ```ignore
    /// let mut rx = node.register_with_relay("abc123...").await?;
    /// while let Some(notification) = rx.recv().await {
    ///     match notification {
    ///         IncomingConnection { from_peer, session_id, relay_data_addr } => {
    ///             // Complete the relay connection...
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn register_with_relay(
        &self,
        relay_identity: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<IncomingConnection>> {
        let relay_id = Identity::from_hex(relay_identity)
            .context("invalid relay identity: must be 64 hex characters")?;

        let record = self
            .resolve(&relay_id)
            .await?
            .context("relay not found in DHT")?;

        let relay_contact = Contact::unsigned(relay_id, record.addrs);

        self.relay_client
            .register_with_relay(&relay_contact)
            .await?;

        self.relay_client
            .take_incoming_receiver()
            .await
            .context("incoming receiver not available")
    }

    /// Accept an incoming relay connection from a peer.
    ///
    /// When a NAT-bound node receives an `IncomingConnection` notification
    /// (from the receiver returned by `register_with_relay`), call this method
    /// to complete the relay handshake and establish the tunnel.
    ///
    /// After this returns successfully, the SmartSock is configured to route
    /// traffic to/from `from_peer` through the relay tunnel. The connecting
    /// peer's QUIC connection will arrive through the normal server accept loop.
    ///
    /// # Flow
    /// 1. Peer A calls `connect(B)` → triggers relay session
    /// 2. B receives `IncomingConnection` notification
    /// 3. B calls `accept_incoming()` → configures tunnel, sends probe
    /// 4. A's pending QUIC handshake now completes through the relay
    /// 5. B receives A's connection via the server accept loop (RPC handler)
    ///
    /// # Example
    /// ```ignore
    /// let mut rx = node.register_with_relay("relay_id").await?;
    /// tokio::spawn(async move {
    ///     while let Some(incoming) = rx.recv().await {
    ///         node.accept_incoming(&incoming).await?;
    ///         // A's connection will arrive via the server - nothing more to do
    ///     }
    /// });
    /// ```
    pub async fn accept_incoming(&self, incoming: &IncomingConnection) -> Result<()> {
        self.relay_client.accept_incoming(incoming).await
    }

    /// Enable mesh-mediated signaling for relay connections.
    ///
    /// This is an alternative to `register_with_relay()` that doesn't require
    /// maintaining a dedicated signaling connection to the relay. Instead,
    /// relay signals are forwarded through the GossipSub mesh.
    ///
    /// **Benefits:**
    /// - Reduces connection overhead for NAT-bound nodes
    /// - Works as long as you have mesh peers (no relay connectivity needed)
    /// - Signals can be forwarded by any mesh peer who receives them
    ///
    /// **Trade-offs:**
    /// - Slightly higher latency (goes through mesh peers)
    /// - Requires active GossipSub participation
    /// - Signals may not reach if mesh is partitioned
    ///
    /// # Returns
    /// A receiver that yields incoming connection notifications, same as
    /// `register_with_relay()`. Handle them with `accept_incoming()`.
    ///
    /// # Example
    /// ```ignore
    /// let mut rx = node.enable_mesh_signaling().await;
    /// while let Some(notification) = rx.recv().await {
    ///     node.accept_incoming(&notification).await?;
    /// }
    /// ```
    pub async fn enable_mesh_signaling(&self) -> tokio::sync::mpsc::Receiver<IncomingConnection> {
        self.relay_client.enable_mesh_signaling().await
    }

    /// Resolve identity to contact, trying local cache first, then network.
    /// Prefers signed contacts over unsigned ones.
    pub async fn resolve(&self, identity: &Identity) -> Result<Option<Contact>> {
        // Fast path: local routing table (only if signed)
        if let Some(contact) = self.dhtnode.lookup_contact(identity).await {
            if !contact.signature.is_empty() {
                return Ok(Some(contact));
            }
            // Unsigned contact found locally, try DHT for a signed version
            if let Ok(Some(dht_contact)) = self.dhtnode.resolve_peer(identity).await {
                return Ok(Some(dht_contact));
            }
            // Fall back to unsigned if DHT lookup fails
            return Ok(Some(contact));
        }
        // Slow path: DHT network lookup
        self.dhtnode.resolve_peer(identity).await
    }

    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dhtnode.iterative_find_node(target).await
    }

    /// Find mesh peers that can act as relays (opportunistic mesh relay).
    ///
    /// In the mesh-first relay model, any mesh peer that is reachable by both
    /// parties can act as a relay. Returns all mesh peers except ourselves.
    async fn find_mesh_relays(&self) -> Vec<Contact> {
        let our_id = self.keypair.identity();
        let mesh_peers = self.gossipsub.mesh_peers().await;

        let relays: Vec<Contact> = mesh_peers
            .into_iter()
            .filter(|c| c.identity != our_id && c.has_direct_addrs())
            .collect();

        debug!(
            mesh_relay_count = relays.len(),
            "found mesh peers for relay"
        );

        relays
    }

    pub async fn add_peer(&self, endpoint: Contact) {
        // SECURITY: Require PoW for externally-provided contacts.
        // The contact must have a valid PoW proof to be added to routing table.
        self.dhtnode.observe_contact(endpoint).await;
    }

    pub async fn bootstrap(&self, identity: &str, addr: &str) -> Result<()> {
        let peer_identity =
            Identity::from_hex(identity).context("invalid identity: must be 64 hex characters")?;

        let contact = Contact::single(peer_identity, addr.to_string());

        // SECURITY: Bootstrap contacts are NOT added to routing table without PoW.
        // Instead, we pass the seed contact directly to the lookup.
        // Once we successfully connect via mTLS, the peer will be added
        // to routing via observe_direct_peer in the RPC layer.
        let self_identity = self.keypair.identity();
        self.dhtnode.bootstrap(contact, self_identity).await?;

        Ok(())
    }

    /// Connect to a peer by identity using DHT-based address resolution.
    ///
    /// This resolves the peer's published `Contact` from the DHT and uses
    /// smart connection logic: tries direct connection first, then falls back to
    /// relay-assisted connection if the peer has designated relays.
    ///
    /// # Arguments
    /// * `identity` - Hex-encoded 32-byte identity of the peer
    ///
    /// # Returns
    /// A QUIC connection to the peer.
    ///
    /// # Errors
    /// - If the identity is invalid (not 64 hex characters)
    /// - If the peer is not found in the DHT
    /// - If connection fails (direct and relay)
    pub async fn connect(&self, identity: &str) -> Result<Connection> {
        let peer_id =
            Identity::from_hex(identity).context("invalid identity: must be 64 hex characters")?;

        let contact = self.resolve(&peer_id).await?.context("peer not found")?;

        debug!(
            peer = %identity,
            addrs = ?contact.addrs,
            "resolved peer endpoint, attempting connection"
        );

        // Try direct connection first
        if !contact.addrs.is_empty() {
            debug!(peer = ?peer_id, addrs = ?contact.addrs, "trying direct connection");

            let direct_result = tokio::time::timeout(
                DIRECT_CONNECT_TIMEOUT,
                self.rpcnode.connect_to_peer(&peer_id, &contact.addrs),
            )
            .await;

            match direct_result {
                Ok(Ok(conn)) => {
                    debug!(peer = ?peer_id, "direct connection successful");

                    let addrs: Vec<std::net::SocketAddr> = contact
                        .addrs
                        .iter()
                        .filter_map(|a| a.parse().ok())
                        .collect();
                    self.smartsock.register_peer(peer_id, addrs).await;
                    debug!(peer = ?peer_id, "registered peer with SmartSock (direct)");

                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    debug!(peer = ?peer_id, error = %e, "direct connection failed");
                }
                Err(_) => {
                    debug!(peer = ?peer_id, "direct connection timed out");
                }
            }
        }

        // Try mesh peers as opportunistic relays (mesh-first relay model)
        let mesh_relays = self.find_mesh_relays().await;
        if !mesh_relays.is_empty() {
            debug!(
                peer = ?peer_id,
                mesh_relay_count = mesh_relays.len(),
                "attempting connection via mesh relay"
            );

            let direct_addrs = &contact.addrs;
            if direct_addrs.is_empty() {
                anyhow::bail!("cannot use relay without at least one target address");
            }

            let our_peer_id = self.keypair.identity();

            for mesh_relay in mesh_relays {
                let session_id = match generate_session_id() {
                    Ok(id) => id,
                    Err(_) => continue,
                };

                debug!(
                    peer = ?peer_id,
                    mesh_relay = ?mesh_relay.identity,
                    "attempting mesh relay"
                );

                let mesh_result = tokio::time::timeout(
                    RELAY_TIMEOUT,
                    self.rpcnode
                        .request_mesh_relay(&mesh_relay, our_peer_id, peer_id, session_id),
                )
                .await;

                let (session_id, relay_data_addr) = match mesh_result {
                    Ok(Ok(RelayResponse::MeshRelayOffer {
                        session_id,
                        relay_data_addr,
                    })) => {
                        debug!(
                            peer = ?peer_id,
                            mesh_relay = ?mesh_relay.identity,
                            session = hex::encode(session_id),
                            "mesh relay session offered"
                        );
                        (session_id, relay_data_addr)
                    }
                    Ok(Ok(RelayResponse::Rejected { reason })) => {
                        debug!(
                            mesh_relay = ?mesh_relay.identity,
                            reason = %reason,
                            "mesh relay rejected, trying next"
                        );
                        continue;
                    }
                    Ok(Ok(other)) => {
                        debug!(
                            mesh_relay = ?mesh_relay.identity,
                            response = ?other,
                            "unexpected mesh relay response, trying next"
                        );
                        continue;
                    }
                    Ok(Err(e)) => {
                        debug!(
                            mesh_relay = ?mesh_relay.identity,
                            error = %e,
                            "mesh relay request failed, trying next"
                        );
                        continue;
                    }
                    Err(_) => {
                        debug!(
                            mesh_relay = ?mesh_relay.identity,
                            "mesh relay request timed out, trying next"
                        );
                        continue;
                    }
                };

                // Configure relay path through mesh peer
                if let Err(e) = self
                    .rpcnode
                    .configure_relay_path_for_peer(
                        peer_id,
                        direct_addrs,
                        session_id,
                        &relay_data_addr,
                    )
                    .await
                {
                    debug!(
                        mesh_relay = ?mesh_relay.identity,
                        error = %e,
                        "failed to configure mesh relay path, trying next"
                    );
                    continue;
                }

                // Try to connect through the mesh relay
                let peer_conn_result = tokio::time::timeout(
                    RELAY_TIMEOUT,
                    self.rpcnode.connect_to_peer(&peer_id, direct_addrs),
                )
                .await;

                match peer_conn_result {
                    Ok(Ok(conn)) => {
                        info!(
                            peer = ?peer_id,
                            mesh_relay = ?mesh_relay.identity,
                            "connection successful via mesh relay"
                        );
                        return Ok(conn);
                    }
                    Ok(Err(e)) => {
                        self.smartsock
                            .remove_relay_tunnel(&peer_id, &session_id)
                            .await;
                        debug!(
                            mesh_relay = ?mesh_relay.identity,
                            error = %e,
                            "mesh relay connect failed, trying next"
                        );
                        continue;
                    }
                    Err(_) => {
                        self.smartsock
                            .remove_relay_tunnel(&peer_id, &session_id)
                            .await;
                        debug!(
                            mesh_relay = ?mesh_relay.identity,
                            "mesh relay connect timed out, trying next"
                        );
                        continue;
                    }
                }
            }
        }

        anyhow::bail!(
            "connection failed: direct, designated relays, and mesh relays all exhausted"
        );
    }

    /// Send a request to a peer and receive a response.
    ///
    /// # Arguments
    /// * `identity` - The peer's identity as a 64-character hex string
    /// * `request` - The request data to send
    ///
    /// # Returns
    /// The response data from the peer
    pub async fn send(&self, identity: &str, request: Vec<u8>) -> Result<Vec<u8>> {
        let peer_identity =
            Identity::from_hex(identity).context("invalid identity: must be 64 hex characters")?;

        let contact = self
            .resolve(&peer_identity)
            .await?
            .context("peer not found")?;

        self.rpcnode.send(&contact, request).await
    }

    /// Set a request handler to process incoming requests.
    ///
    /// The handler receives requests and must provide responses. Each request
    /// expects a response.
    ///
    /// # Arguments
    /// * `handler` - A function that takes (sender_identity_hex, request_data) and returns response_data
    ///
    /// # Example
    /// ```ignore
    /// node.set_request_handler(|from, request| {
    ///     // Echo the request back
    ///     request
    /// }).await?;
    /// ```
    pub async fn set_request_handler<F>(&self, handler: F) -> Result<()>
    where
        F: Fn(String, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
    {
        let mut guard = self.request_handler_rx.lock().await;
        let mut internal_rx = guard.take().context("request handler already set")?;

        tokio::spawn(async move {
            while let Some((from, request_data, response_tx)) = internal_rx.recv().await {
                let from_hex = hex::encode(from.as_bytes());
                let response = handler(from_hex, request_data);
                // Send response back (ignore error if caller dropped)
                let _ = response_tx.send(response);
            }
        });

        Ok(())
    }

    /// Get a receiver for incoming requests that allows async response handling.
    ///
    /// Each received item is (sender_identity_hex, request_data, response_sender).
    /// You MUST send a response via the response_sender or the request will timeout.
    ///
    /// This is the low-level API. For simpler cases, use `set_request_handler`.
    pub async fn incoming_requests(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<(String, Vec<u8>, tokio::sync::oneshot::Sender<Vec<u8>>)>>
    {
        let mut guard = self.request_handler_rx.lock().await;
        let internal_rx = guard.take().context("request handler already taken")?;

        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            let mut internal_rx = internal_rx;
            while let Some((from, request_data, response_tx)) = internal_rx.recv().await {
                let from_hex = hex::encode(from.as_bytes());
                if tx
                    .send((from_hex, request_data, response_tx))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(rx)
    }

    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        self.gossipsub.subscribe(topic).await
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        self.gossipsub.publish(topic, data).await?;
        Ok(())
    }

    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        self.gossipsub.unsubscribe(topic).await?;
        Ok(())
    }

    pub async fn subscriptions(&self) -> Result<Vec<String>> {
        Ok(self.gossipsub.subscriptions().await)
    }

    pub async fn messages(&self) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let mut guard = self.gossipsub_receiver.lock().await;
        let internal_rx = guard.take().context("message receiver already taken")?;

        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            let mut internal_rx = internal_rx;
            while let Some(msg) = internal_rx.recv().await {
                let public_msg = Message {
                    topic: msg.topic,
                    from: hex::encode(msg.source.as_bytes()),
                    data: msg.data,
                };
                if tx.send(public_msg).await.is_err() {
                    break;
                }
            }
        });

        Ok(rx)
    }

    pub async fn shutdown(&self) {
        // Abort the server first to stop accepting new connections
        self.listener.abort();

        // Shutdown actors in reverse dependency order
        self.gossipsub.quit().await;
        self.dhtnode.quit().await;
        self.rpcnode.quit().await;

        // Shutdown the relay actor if present
        if let Some(relay) = self.smartsock.relay() {
            relay.quit().await;
        }
    }

    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dhtnode.telemetry_snapshot().await
    }

    // =========================================================================
    // NAT Detection and Relay Configuration
    // =========================================================================

    /// Check if this node is publicly reachable by asking a peer to connect back.
    ///
    /// This performs a "self-probe" by requesting `helper` to attempt a connection
    /// to our local address. Returns `true` if we are publicly reachable.
    ///
    /// The helper's address is resolved via DHT lookup.
    ///
    /// # Arguments
    /// * `helper_identity` - Hex-encoded identity of a known peer to help with the probe
    ///
    /// # Returns
    /// * `Ok(true)` - We are publicly reachable (can serve as relay)
    /// * `Ok(false)` - We are behind NAT (need to use a relay)
    /// * `Err(_)` - Could not complete the probe (helper unreachable, etc.)
    pub async fn probe_reachability(&self, helper_identity: &str) -> Result<bool> {
        let helper_id = Identity::from_hex(helper_identity)
            .context("invalid helper identity: must be 64 hex characters")?;

        let record = self
            .resolve(&helper_id)
            .await?
            .context("helper not found in DHT")?;

        self.relay_client.probe_reachability(&record).await
    }

    /// Discover peers that can serve as relays.
    ///
    /// Uses a **mesh-first** strategy: any mesh peer with direct addresses
    /// can potentially relay traffic between NAT-bound peers. The mesh-based
    /// relay model means we don't need pre-declared relay nodes - any reachable
    /// mesh peer that both parties can connect to can serve as a relay.
    ///
    /// Falls back to DHT discovery if no suitable mesh peers are found.
    ///
    /// # Returns
    /// A list of contacts that can serve as relays.
    pub async fn discover_relays(&self) -> Result<Vec<Contact>> {
        let our_id = self.keypair.identity();

        // Check mesh peers first (zero network overhead, already connected)
        let mesh_peers = self.gossipsub.mesh_peers().await;
        debug!(
            mesh_peer_count = mesh_peers.len(),
            "checking mesh peers for relay capability"
        );

        let relays: Vec<Contact> = mesh_peers
            .into_iter()
            .filter(|c| c.identity != our_id && c.has_direct_addrs())
            .collect();

        if !relays.is_empty() {
            debug!(
                relay_count = relays.len(),
                "discovered relays from mesh peers (mesh-first)"
            );
            return Ok(relays);
        }

        // Fall back to DHT discovery if no mesh peers available
        debug!("no mesh peers available, falling back to DHT discovery");
        self.relay_client.discover_relays().await
    }

    /// Select the best relay from a list by measuring RTT.
    ///
    /// Pings each relay and returns the one with the lowest round-trip time.
    ///
    /// # Arguments
    /// * `candidates` - List of potential relay contacts
    ///
    /// # Returns
    /// The relay with the lowest RTT, or `None` if all candidates are unreachable.
    pub async fn select_best_relay(&self, candidates: &[Contact]) -> Option<Contact> {
        self.relay_client.select_best_relay(candidates).await
    }

    /// Automatically configure NAT traversal for this node.
    ///
    /// This performs the complete NAT configuration flow:
    /// 1. Probe reachability via a helper peer
    /// 2. If publicly reachable: publish address (can serve as relay for others)
    /// 3. If NAT-bound: discover relays, select best one, register, and publish
    ///
    /// The helper's address is resolved via DHT lookup.
    ///
    /// # Arguments
    /// * `helper_identity` - Hex-encoded identity of a known peer to use for the reachability probe
    /// * `addresses` - Our addresses to publish in the DHT
    ///
    /// # Returns
    /// Configuration result indicating our NAT status and relay (if applicable).
    pub async fn configure_nat(
        &self,
        helper_identity: &str,
        addresses: Vec<String>,
    ) -> Result<(
        bool,
        Option<Identity>,
        Option<tokio::sync::mpsc::Receiver<IncomingConnection>>,
    )> {
        let helper_id = Identity::from_hex(helper_identity)
            .context("invalid helper identity: must be 64 hex characters")?;

        let helper = self
            .resolve(&helper_id)
            .await?
            .context("helper not found in DHT")?;

        let status = self.relay_client.configure(&helper, addresses).await?;

        match status {
            NatStatus::Public => Ok((true, None, None)),
            NatStatus::NatBound { relay } => {
                let incoming_rx = self.relay_client.take_incoming_receiver().await;
                Ok((false, Some(relay), incoming_rx))
            }
            NatStatus::Unknown => {
                anyhow::bail!("NAT configuration failed: status unknown")
            }
        }
    }

    /// Get the current NAT status.
    pub async fn nat_status(&self) -> NatStatus {
        self.relay_client.status().await
    }

    /// Check if the registered relay is healthy (recently communicated with).
    ///
    /// This uses mesh traffic to prove relay liveness: if we're subscribed to
    /// topics and sending GossipSub messages to our relay, it proves the relay
    /// is alive without dedicated health probes.
    ///
    /// # Returns
    /// * `true` - Relay recently responded to traffic (healthy)
    /// * `false` - No recent communication (may need failover)
    pub async fn is_relay_healthy(&self) -> bool {
        self.relay_client.is_relay_healthy().await
    }

    /// Update relay health by checking if the relay is in our mesh.
    ///
    /// Call this periodically (e.g., from heartbeat) to update relay health
    /// based on mesh activity. If the registered relay is a mesh peer and
    /// we're actively sending to it, this proves liveness.
    pub async fn update_relay_health_from_mesh(&self) {
        let relay_identity = match self.relay_client.registered_relay_identity().await {
            Some(id) => id,
            None => return, // No registered relay
        };

        // Check if relay is in our mesh peers
        let mesh_peers = self.gossipsub.mesh_peers().await;
        for peer in mesh_peers {
            if peer.identity == relay_identity {
                // Relay is a mesh peer - record it as alive
                self.relay_client.record_relay_alive(&relay_identity).await;
                return;
            }
        }
    }

    /// Get access to the relay client for advanced NAT management.
    pub fn relay_client(&self) -> &RelayClient {
        &self.relay_client
    }

    /// Start the CA signer background task.
    ///
    /// This subscribes to the `csr` topic and responds to certificate signing
    /// requests via RPC. The protocol is:
    ///
    /// 1. Requester broadcasts CSR on `csr` GossipSub topic
    /// 2. Signer generates commitment and sends via RPC to requester
    /// 3. Requester collects K commitments, then sends sign-request via RPC to each signer
    /// 4. Signer produces share and responds via RPC
    ///
    /// # Arguments
    /// * `signer_state` - The signer state from DKG
    ///
    /// # Returns
    /// A `JoinHandle` for the background task.
    #[cfg(feature = "spiffe")]
    pub async fn start_ca_signer(
        &self,
        signer_state: crate::thresholdca::SignerState,
    ) -> Result<tokio::task::JoinHandle<()>> {
        use crate::identity::Identity;
        use crate::thresholdca::{
            CA_SIGN_REQUEST_MAGIC, CA_SIGN_REQUEST_MAGIC_LEN, CaCommitmentResponse, CaSignRequest,
            CaSignResponse, SigningRequest, generate_signing_commitment, sign_with_share,
        };
        use lru::LruCache;
        use std::num::NonZeroUsize;
        use std::time::Instant;

        const CSR_TOPIC: &str = "csr";
        /// Maximum pending signing requests to prevent OOM.
        const MAX_PENDING_REQUESTS: usize = 1000;
        /// Timeout for pending requests (30 seconds).
        const PENDING_TIMEOUT_SECS: u64 = 30;
        /// Cleanup interval for expired pending requests.
        const CLEANUP_INTERVAL_SECS: u64 = 10;

        // Subscribe to CSR topic
        self.subscribe(CSR_TOPIC).await?;

        let mut gossip_rx = self.messages().await?;
        let mut rpc_rx = self.incoming_requests().await?;
        let rpcnode = self.rpcnode.clone();
        let dhtnode = self.dhtnode.clone();
        let my_frost_id = signer_state.identifier();

        // Type alias for pending request data: (tbs, nonce, commitment, created_at, requester)
        type PendingRequest = (
            Vec<u8>,
            crate::thresholdca::SigningNonce,
            Vec<u8>,
            Instant,
            Identity,
        );

        let handle = tokio::spawn(async move {
            // Track pending requests with bounded capacity and timestamps
            let mut pending: LruCache<[u8; 32], PendingRequest> = LruCache::new(
                NonZeroUsize::new(MAX_PENDING_REQUESTS)
                    .expect("MAX_PENDING_REQUESTS must be non-zero"),
            );

            let mut cleanup_interval =
                tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));

            loop {
                tokio::select! {
                    // Periodic cleanup of expired pending requests
                    _ = cleanup_interval.tick() => {
                        let now = Instant::now();
                        let timeout = std::time::Duration::from_secs(PENDING_TIMEOUT_SECS);

                        // Collect expired keys (can't modify while iterating)
                        let expired: Vec<[u8; 32]> = pending
                            .iter()
                            .filter(|(_, (_, _, _, created_at, _))| now.duration_since(*created_at) > timeout)
                            .map(|(k, _)| *k)
                            .collect();

                        for key in &expired {
                            pending.pop(key);
                        }

                        if !expired.is_empty() {
                            debug!(count = expired.len(), "Cleaned up expired pending requests");
                        }
                    }
                    // Handle CSR from GossipSub
                    Some(msg) = gossip_rx.recv() => {
                        if msg.topic != CSR_TOPIC {
                            continue;
                        }

                        // Parse signing request with size bounds
                        // SECURITY: Use deserialize_bounded to prevent OOM from oversized payloads
                        let request: SigningRequest = match crate::messages::deserialize_bounded(&msg.data) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("Invalid signing request: {}", e);
                                continue;
                            }
                        };

                        // SECURITY: Validate TBS certificate size
                        if request.tbs_certificate.len() > crate::thresholdca::MAX_TBS_CERTIFICATE_SIZE {
                            warn!(
                                tbs_size = request.tbs_certificate.len(),
                                max = crate::thresholdca::MAX_TBS_CERTIFICATE_SIZE,
                                "CSR rejected: TBS certificate too large"
                            );
                            continue;
                        }

                        // SECURITY: Validate that msg.from matches request.requester
                        // Prevents impersonation attacks where attacker sends CSR with victim's identity.
                        // NOTE: msg.from is derived from msg.source which is cryptographically signed
                        // by the GossipSub signature (verified in verify_gossipsub_signature()).
                        let msg_sender = match Identity::from_hex(&msg.from) {
                            Ok(id) => id,
                            Err(_) => {
                                warn!("Invalid sender identity in GossipSub message");
                                continue;
                            }
                        };
                        if msg_sender != request.requester {
                            warn!(
                                msg_from = %msg.from,
                                request_requester = %request.requester,
                                "CSR requester mismatch - possible impersonation attempt"
                            );
                            continue;
                        }

                        // SECURITY: Skip duplicate request_ids to prevent nonce reuse
                        if pending.contains(&request.request_id) {
                            debug!(
                                request_id = hex::encode(&request.request_id[..8]),
                                "Duplicate request_id - skipping"
                            );
                            continue;
                        }

                        // Generate commitment and nonce
                        let (nonce, commitment_bytes) = match generate_signing_commitment(&signer_state) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("Failed to generate commitment: {}", e);
                                continue;
                            }
                        };

                        // Store for later signing (with timestamp and requester identity for validation)
                        pending.put(
                            request.request_id,
                            (request.tbs_certificate.clone(), nonce, commitment_bytes.clone(), Instant::now(), request.requester),
                        );

                        // Resolve requester's contact
                        let requester_contact = match dhtnode.resolve_peer(&request.requester).await {
                            Ok(Some(c)) => c,
                            Ok(None) => {
                                warn!(requester = %request.requester, "Requester not found in DHT");
                                pending.pop(&request.request_id);
                                continue;
                            }
                            Err(e) => {
                                warn!("DHT lookup failed: {}", e);
                                pending.pop(&request.request_id);
                                continue;
                            }
                        };

                        // Send commitment via RPC (fire and forget - requester will RPC back for signing)
                        let response = CaCommitmentResponse {
                            request_id: request.request_id,
                            frost_id: my_frost_id,
                            commitment: commitment_bytes,
                        };

                        if let Ok(data) = bincode::serialize(&response) {
                            if let Err(e) = rpcnode.send(&requester_contact, data).await {
                                warn!("Failed to send commitment to requester: {}", e);
                                pending.pop(&request.request_id);
                            } else {
                                debug!(
                                    request_id = hex::encode(&request.request_id[..8]),
                                    "Sent commitment to requester"
                                );
                            }
                        }
                    }

                    // Handle sign requests via RPC
                    Some((from_hex, request_data, response_tx)) = rpc_rx.recv() => {
                        // Check if this is a CA sign request (4-byte magic prefix)
                        if request_data.len() < CA_SIGN_REQUEST_MAGIC_LEN
                            || &request_data[..CA_SIGN_REQUEST_MAGIC_LEN] != CA_SIGN_REQUEST_MAGIC
                        {
                            // Not for us, send empty response
                            let _ = response_tx.send(vec![]);
                            continue;
                        }

                        // Parse sign request (skip magic prefix)
                        // SECURITY: Use deserialize_bounded to prevent OOM from oversized payloads
                        let sign_request: CaSignRequest = match crate::messages::deserialize_bounded(&request_data[CA_SIGN_REQUEST_MAGIC_LEN..]) {
                            Ok(r) => r,
                            Err(_) => {
                                let _ = response_tx.send(vec![]);
                                continue;
                            }
                        };

                        // Look up our pending state
                        let (tbs, nonce, _our_commitment, _created_at, requester_identity) = match pending.pop(&sign_request.request_id) {
                            Some(p) => p,
                            None => {
                                warn!("No pending request for sign request");
                                let _ = response_tx.send(vec![]);
                                continue;
                            }
                        };

                        // SECURITY: Validate that RPC sender matches the original requester
                        let rpc_sender = match Identity::from_hex(&from_hex) {
                            Ok(id) => id,
                            Err(_) => {
                                warn!("Invalid RPC sender identity");
                                let _ = response_tx.send(vec![]);
                                continue;
                            }
                        };
                        if rpc_sender != requester_identity {
                            warn!(
                                rpc_sender = %rpc_sender,
                                original_requester = %requester_identity,
                                "Sign request sender mismatch - possible hijacking attempt"
                            );
                            let _ = response_tx.send(vec![]);
                            continue;
                        }

                        // Produce signature share
                        match sign_with_share(&signer_state, nonce, &tbs, &sign_request.commitments) {
                            Ok(share_bytes) => {
                                let response = CaSignResponse {
                                    request_id: sign_request.request_id,
                                    frost_id: my_frost_id,
                                    share: share_bytes,
                                };

                                if let Ok(data) = bincode::serialize(&response) {
                                    let _ = response_tx.send(data);
                                    debug!(
                                        request_id = hex::encode(&sign_request.request_id[..8]),
                                        "Sent signature share"
                                    );
                                } else {
                                    let _ = response_tx.send(vec![]);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to produce signature share: {}", e);
                                let _ = response_tx.send(vec![]);
                            }
                        }
                    }

                    else => break,
                }
            }
        });

        info!("CA signer task started");
        Ok(handle)
    }

    /// Request a CA-signed certificate from the threshold CA.
    ///
    /// This broadcasts a CSR to the signer committee and collects enough
    /// partial signatures to produce a valid CA-signed certificate.
    ///
    /// **Important:** The node must be bootstrapped into a mesh with responsive
    /// signers before calling this method.
    ///
    /// # Arguments
    /// * `trust_domain` - SPIFFE trust domain for the certificate
    /// * `workload_path` - Optional workload path suffix
    /// * `config` - CA request configuration
    ///
    /// # Returns
    /// DER-encoded X.509 certificate signed by the threshold CA.
    ///
    /// # Example
    /// ```ignore
    /// // First bootstrap into the mesh
    /// node.bootstrap(&bootstrap_identity, &bootstrap_addr).await?;
    ///
    /// // Then request CA certificate
    /// let config = CaRequestConfig {
    ///     signer_identities: vec![...],
    ///     min_signers: 3,
    ///     ca_public_key,
    ///     timeout: Duration::from_secs(30),
    /// };
    /// let cert_der = node.request_ca_certificate("example.org", Some("api-gw"), &config).await?;
    /// ```
    #[cfg(feature = "spiffe")]
    pub async fn request_ca_certificate_from_mesh(
        &self,
        trust_domain: &str,
        workload_path: Option<&str>,
        config: &CaRequestConfig,
    ) -> Result<Vec<u8>> {
        request_ca_certificate(self, &self.keypair, trust_domain, workload_path, config).await
    }
}

// ============================================================================
// CA Certificate Request Flow
// ============================================================================

/// Request a CA-signed certificate from the threshold CA signers.
///
/// Protocol flow:
/// 1. Broadcast CSR on `csr` GossipSub topic
/// 2. Receive commitments via RPC from signers
/// 3. Send sign-request (with all commitments) via RPC to each signer
/// 4. Receive signature shares via RPC responses
/// 5. Aggregate shares into final signature
#[cfg(feature = "spiffe")]
async fn request_ca_certificate(
    node: &Node,
    keypair: &Keypair,
    trust_domain: &str,
    workload_path: Option<&str>,
    config: &CaRequestConfig,
) -> Result<Vec<u8>> {
    use crate::thresholdca::{
        CA_SIGN_REQUEST_MAGIC, CaCommitmentResponse, CaSignRequest, CaSignResponse, SigningRequest,
        aggregate_signatures, generate_csr,
    };

    const CSR_TOPIC: &str = "csr";
    const CERT_VALIDITY_SECS: u64 = 86400 * 365; // 1 year

    // Generate CSR with SPIFFE SAN
    let csr = generate_csr(keypair, trust_domain, workload_path, CERT_VALIDITY_SECS)
        .map_err(|e| anyhow::anyhow!("CSR generation failed: {}", e))?;

    // Create signing request with unique ID
    let request = SigningRequest::new(csr.tbs_der.clone(), keypair.identity());
    let request_id = request.request_id;

    // Broadcast CSR on GossipSub
    let request_data = bincode::serialize(&request)
        .map_err(|e| anyhow::anyhow!("Failed to serialize request: {}", e))?;
    node.publish(CSR_TOPIC, request_data).await?;

    info!(
        request_id = hex::encode(&request_id[..8]),
        "Broadcast CSR to signers"
    );

    // Collect commitments via RPC from signers
    // Signers will send their commitments directly to us after seeing the CSR
    let mut rpc_rx = node.incoming_requests().await?;
    let mut commitments: Vec<(frost_ed25519::Identifier, Vec<u8>)> = Vec::new();
    let mut signer_contacts: Vec<(frost_ed25519::Identifier, String)> = Vec::new(); // frost_id -> identity_hex

    let deadline = tokio::time::Instant::now() + config.timeout;

    // Phase 1: Collect commitments
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, rpc_rx.recv()).await {
            Ok(Some((from_hex, data, response_tx))) => {
                // Try to parse as commitment response
                // SECURITY: Use deserialize_bounded to prevent OOM from malicious signers
                if let Ok(commitment) =
                    crate::messages::deserialize_bounded::<CaCommitmentResponse>(&data)
                    && commitment.request_id == request_id
                    && !commitments.iter().any(|(id, _)| *id == commitment.frost_id)
                {
                    commitments.push((commitment.frost_id, commitment.commitment));
                    signer_contacts.push((commitment.frost_id, from_hex.clone()));
                    debug!(
                        frost_id = ?commitment.frost_id,
                        count = commitments.len(),
                        "Received commitment"
                    );
                }
                // Ack the RPC (empty response for commitment phase)
                let _ = response_tx.send(vec![]);

                // Check if we have enough commitments
                if commitments.len() >= config.min_signers as usize {
                    info!(
                        commitments = commitments.len(),
                        threshold = config.min_signers,
                        "Collected sufficient commitments"
                    );
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break, // Timeout
        }
    }

    if commitments.len() < config.min_signers as usize {
        return Err(anyhow::anyhow!(
            "Insufficient commitments: got {}, need {}",
            commitments.len(),
            config.min_signers
        ));
    }

    // Phase 2: Send sign request to each signer and collect shares
    let sign_request = CaSignRequest {
        request_id,
        commitments: commitments.clone(),
    };

    // Prepend 4-byte magic prefix
    let mut sign_request_data = CA_SIGN_REQUEST_MAGIC.to_vec();
    sign_request_data.extend(
        bincode::serialize(&sign_request)
            .map_err(|e| anyhow::anyhow!("Failed to serialize sign request: {}", e))?,
    );

    let mut shares: Vec<(frost_ed25519::Identifier, Vec<u8>)> = Vec::new();

    for (frost_id, identity_hex) in &signer_contacts {
        match node.send(identity_hex, sign_request_data.clone()).await {
            Ok(response_data) => {
                // SECURITY: Use deserialize_bounded to prevent OOM from malicious signers
                if let Ok(response) =
                    crate::messages::deserialize_bounded::<CaSignResponse>(&response_data)
                    && response.request_id == request_id
                    && response.frost_id == *frost_id
                {
                    shares.push((response.frost_id, response.share));
                    debug!(
                        frost_id = ?frost_id,
                        count = shares.len(),
                        "Received signature share"
                    );
                }
            }
            Err(e) => {
                warn!(frost_id = ?frost_id, "Failed to get signature share: {}", e);
            }
        }

        if shares.len() >= config.min_signers as usize {
            break;
        }
    }

    // Aggregate signatures
    if shares.len() < config.min_signers as usize {
        return Err(anyhow::anyhow!(
            "Insufficient signatures: got {}, need {}",
            shares.len(),
            config.min_signers
        ));
    }

    let pubkey_package = config
        .ca_public_key
        .pubkey_package()
        .map_err(|e| anyhow::anyhow!("Invalid CA public key: {}", e))?;

    let signature = aggregate_signatures(&pubkey_package, &csr.tbs_der, &commitments, &shares)
        .map_err(|e| anyhow::anyhow!("Signature aggregation failed: {}", e))?;

    // Assemble final certificate
    let cert_der = crate::thresholdca::assemble_certificate(&csr.tbs_der, &signature)
        .map_err(|e| anyhow::anyhow!("Certificate assembly failed: {}", e))?;

    info!(
        spiffe_id = csr.spiffe_id,
        "Successfully obtained CA-signed certificate"
    );

    Ok(cert_der)
}

// ============================================================================
// NodeBuilder - Fluent Configuration API
// ============================================================================

/// Builder for configuring a Korium node before creation.
///
/// Provides a fluent API for configuring optional features like SPIFFE
/// trust domains before binding the node to a socket.
///
/// # Example
/// ```ignore
/// // Basic usage (no SPIFFE)
/// let node = Node::builder("0.0.0.0:4433")
///     .build()
///     .await?;
///
/// // With SPIFFE (requires `spiffe` feature)
/// let node = Node::builder("0.0.0.0:4433")
///     .spiffe_trust_domain("example.org")
///     .spiffe_workload_path("payment-svc")
///     .build()
///     .await?;
///
/// // With existing keypair
/// let node = Node::builder("0.0.0.0:4433")
///     .keypair(keypair)
///     .pow_proof(pow_proof)
///     .build()
///     .await?;
/// ```
pub struct NodeBuilder {
    addr: String,
    keypair: Option<Keypair>,
    pow_proof: Option<IdentityProof>,
    /// Namespace for identity isolation.
    /// When set, the node will only accept application connections from peers
    /// in the same namespace. DHT routing and relay remain global.
    namespace: Option<String>,
    /// Pre-computed namespace hash (alternative to string namespace).
    /// Takes precedence over `namespace` if both are set.
    namespace_hash: Option<[u8; NAMESPACE_HASH_LEN]>,
    /// Full namespace configuration with master secret for challenge-response.
    /// Takes precedence over `namespace` and `namespace_hash` if set.
    namespace_config: Option<NamespaceConfig>,
    #[cfg(feature = "spiffe")]
    spiffe_trust_domain: Option<String>,
    #[cfg(feature = "spiffe")]
    spiffe_workload_path: Option<String>,
    #[cfg(feature = "spiffe")]
    signer_state: Option<crate::thresholdca::SignerState>,
    #[cfg(feature = "spiffe")]
    ca_request_config: Option<CaRequestConfig>,
}

/// Configuration for requesting a CA-signed certificate at startup.
#[cfg(feature = "spiffe")]
#[derive(Clone)]
pub struct CaRequestConfig {
    /// Identities of the CA signers (from DKG).
    pub signer_identities: Vec<Identity>,
    /// Minimum number of signers required (K threshold).
    pub min_signers: u16,
    /// CA public key for verification.
    pub ca_public_key: crate::thresholdca::CaPublicKey,
    /// Timeout for collecting signatures.
    pub timeout: Duration,
}

impl NodeBuilder {
    /// Create a new builder for the given bind address.
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            keypair: None,
            pow_proof: None,
            namespace: None,
            namespace_hash: None,
            #[cfg(feature = "spiffe")]
            spiffe_trust_domain: None,
            #[cfg(feature = "spiffe")]
            spiffe_workload_path: None,
            #[cfg(feature = "spiffe")]
            signer_state: None,
            #[cfg(feature = "spiffe")]
            ca_request_config: None,
            namespace_config: None,
        }
    }

    /// Set an existing keypair instead of generating a new one.
    ///
    /// If you have an existing keypair from persistent storage, use this
    /// to reuse the same identity across restarts.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set the Proof-of-Work proof for the keypair.
    ///
    /// Required for production use - contacts without valid PoW will be
    /// rejected by other nodes.
    pub fn pow_proof(mut self, proof: IdentityProof) -> Self {
        self.pow_proof = Some(proof);
        self
    }

    /// Set full namespace configuration with master secret.
    ///
    /// This is the recommended way to configure namespace isolation. The master
    /// secret enables challenge-response authentication which is more secure than
    /// just using a namespace hash.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Create namespace config with a random secret
    /// let mut secret = [0u8; 32];
    /// getrandom::getrandom(&mut secret).unwrap();
    /// let ns_config = NamespaceConfig::new(secret);
    ///
    /// let node = Node::builder("0.0.0.0:0")
    ///     .namespace_config(ns_config)
    ///     .build()
    ///     .await?;
    /// ```
    pub fn namespace_config(mut self, config: NamespaceConfig) -> Self {
        self.namespace_config = Some(config);
        self
    }

    /// Set the namespace for identity isolation.
    ///
    /// When configured, the node will:
    /// - Generate identity with PoW bound to this namespace (if generating new keypair)
    /// - Verify that incoming application connections are from peers in the same namespace
    /// - Reject GossipSub messages from peers in different namespaces (on scoped topics)
    ///
    /// DHT routing and relay operations remain global, allowing cross-namespace:
    /// - Peer discovery via DHT
    /// - NAT traversal via relay servers
    ///
    /// The namespace string becomes a cryptographic trust anchor - identities
    /// generated for one namespace cannot be reused in another.
    ///
    /// # Arguments
    /// * `namespace` - The namespace identifier (e.g., "acme-corp", "production")
    ///
    /// # Example
    /// ```ignore
    /// // All nodes in "acme-corp" can connect to each other
    /// let node = Node::builder("0.0.0.0:4433")
    ///     .namespace("acme-corp")
    ///     .build()
    ///     .await?;
    ///
    /// // Nodes in different namespaces can still relay for each other
    /// let relay_node = Node::builder("0.0.0.0:4434")
    ///     .namespace("public-relay")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Set the namespace using raw bytes (e.g., a BLAKE3 hash or random secret).
    ///
    /// Use this for **maximum privacy** - the namespace cannot be guessed since
    /// there's no string to brute-force.
    ///
    /// # Example
    /// ```ignore
    /// // Generate a namespace secret (share out-of-band with peers)
    /// let secret = blake3::hash(b"my-secret-seed");
    ///
    /// let node = Node::builder("0.0.0.0:4433")
    ///     .namespace_bytes(secret.as_bytes())
    ///     .build()
    ///     .await?;
    /// ```
    pub fn namespace_bytes(mut self, bytes: &[u8]) -> Self {
        self.namespace_hash = Some(IdentityProof::namespace_hash_from_bytes(bytes));
        self
    }

    /// Set the namespace using a pre-computed 8-byte hash directly.
    ///
    /// Use this when you already have the namespace hash and don't want to
    /// derive it from a string or bytes.
    pub fn namespace_hash(mut self, hash: [u8; NAMESPACE_HASH_LEN]) -> Self {
        self.namespace_hash = Some(hash);
        self
    }

    /// Set the SPIFFE trust domain for certificate generation.
    ///
    /// When set, the node's X.509 certificate will include a SPIFFE ID
    /// as a URI Subject Alternative Name, enabling interoperability with
    /// SPIFFE-aware systems (Envoy, Istio, AWS IAM Roles Anywhere, etc.).
    ///
    /// The SPIFFE ID format will be:
    /// `spiffe://{trust_domain}/{identity_hex}[/{workload_path}]`
    ///
    /// # Arguments
    /// * `trust_domain` - The trust domain (e.g., "example.org", "korium.mesh")
    ///
    /// # Example
    /// ```ignore
    /// Node::builder("0.0.0.0:4433")
    ///     .spiffe_trust_domain("example.org")
    ///     .build()
    ///     .await?;
    /// // Certificate SAN: spiffe://example.org/abc123...
    /// ```
    #[cfg(feature = "spiffe")]
    pub fn spiffe_trust_domain(mut self, trust_domain: impl Into<String>) -> Self {
        self.spiffe_trust_domain = Some(trust_domain.into());
        self
    }

    /// Set the SPIFFE workload path suffix.
    ///
    /// Optional refinement to the SPIFFE ID that identifies the workload
    /// role within the trust domain. If set, appended to the SPIFFE ID:
    /// `spiffe://{trust_domain}/{identity_hex}/{workload_path}`
    ///
    /// # Arguments
    /// * `path` - The workload path (e.g., "relay", "validator", "payment-svc")
    ///
    /// # Example
    /// ```ignore
    /// Node::builder("0.0.0.0:4433")
    ///     .spiffe_trust_domain("example.org")
    ///     .spiffe_workload_path("payment-svc")
    ///     .build()
    ///     .await?;
    /// // Certificate SAN: spiffe://example.org/abc123.../payment-svc
    /// ```
    #[cfg(feature = "spiffe")]
    pub fn spiffe_workload_path(mut self, path: impl Into<String>) -> Self {
        self.spiffe_workload_path = Some(path.into());
        self
    }

    /// Configure this node as a threshold CA signer.
    ///
    /// When set, the node will listen on the `ca/sign/request` GossipSub topic
    /// and automatically respond to certificate signing requests with partial
    /// signatures.
    ///
    /// # Arguments
    /// * `state` - The signer state from DKG (contains private key share)
    ///
    /// # Security
    /// The signer state contains sensitive key material. It should be:
    /// - Loaded from encrypted storage
    /// - Never logged or serialized without encryption
    ///
    /// # Example
    /// ```ignore
    /// let signer_state = SignerState::deserialize(&encrypted_state)?;
    ///
    /// let node = Node::builder("0.0.0.0:4433")
    ///     .spiffe_trust_domain("example.org")
    ///     .as_ca_signer(signer_state)
    ///     .build()
    ///     .await?;
    /// // Node now responds to CSR requests on ca/sign/request
    /// ```
    #[cfg(feature = "spiffe")]
    pub fn as_ca_signer(mut self, state: crate::thresholdca::SignerState) -> Self {
        self.signer_state = Some(state);
        self
    }

    /// Request a CA-signed certificate at startup.
    ///
    /// When configured, the node will:
    /// 1. Generate a CSR with SPIFFE SAN
    /// 2. Broadcast to signers on `ca/sign/request`
    /// 3. Collect K partial signatures
    /// 4. Aggregate into valid CA-signed certificate
    /// 5. Use CA-signed cert for TLS (instead of self-signed)
    ///
    /// This requires the mesh to already have K responsive signers.
    ///
    /// # Arguments
    /// * `config` - CA request configuration (signers, threshold, CA public key)
    ///
    /// # Example
    /// ```ignore
    /// let ca_config = CaRequestConfig {
    ///     signer_identities: vec![signer1, signer2, signer3],
    ///     min_signers: 2,
    ///     ca_public_key,
    ///     timeout: Duration::from_secs(30),
    /// };
    ///
    /// let node = Node::builder("0.0.0.0:4433")
    ///     .spiffe_trust_domain("example.org")
    ///     .request_ca_cert(ca_config)
    ///     .build()
    ///     .await?;
    /// // Node now has CA-signed certificate
    /// ```
    #[cfg(feature = "spiffe")]
    pub fn request_ca_cert(mut self, config: CaRequestConfig) -> Self {
        self.ca_request_config = Some(config);
        self
    }

    /// Build and start the node.
    ///
    /// This will:
    /// 1. Generate a new keypair with PoW (if not provided)
    /// 2. Generate TLS certificates (with optional SPIFFE SAN)
    /// 3. Bind to the specified socket address
    /// 4. Start the DHT, GossipSub, and relay components
    /// 5. Start CA signer task (if configured)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Socket binding fails
    /// - PoW generation fails (astronomically unlikely)
    /// - Certificate generation fails
    #[cfg(feature = "spiffe")]
    pub async fn build(self) -> Result<Node> {
        // Determine namespace config: prefer explicit config, then derive from hash/string
        let namespace_config = if let Some(config) = self.namespace_config.clone() {
            Some(config)
        } else if let Some(hash) = self.namespace_hash {
            // Create config from hash (user must have the secret elsewhere for challenge-response)
            // This is a fallback - for full security, use namespace_config()
            None // No challenge-response without the secret
        } else if let Some(ref ns) = self.namespace {
            if ns.is_empty() {
                None
            } else {
                // Create config from passphrase (less secure, guessable)
                Some(NamespaceConfig::from_passphrase(ns))
            }
        } else {
            None
        };

        // Determine namespace hash for PoW binding
        let namespace_hash = if let Some(ref config) = namespace_config {
            if config.is_global() {
                None
            } else {
                Some(config.namespace_hash())
            }
        } else if let Some(hash) = self.namespace_hash {
            Some(hash)
        } else if let Some(ref ns) = self.namespace {
            if ns.is_empty() {
                None
            } else {
                Some(IdentityProof::namespace_hash_from_string(ns))
            }
        } else {
            None
        };

        let (keypair, pow_proof) = match self.keypair {
            Some(kp) => {
                // Use provided keypair; if pow_proof not provided, assume global namespace
                let proof = self.pow_proof.unwrap_or_else(IdentityProof::empty);
                // Validate namespace matches proof if specified
                if let Some(ref expected_hash) = namespace_hash {
                    if !proof.matches_namespace_hash(expected_hash) {
                        return Err(anyhow::anyhow!(
                            "provided keypair's PoW proof was generated for a different namespace"
                        ));
                    }
                }
                (kp, proof)
            }
            None => {
                // Generate new keypair with namespace-bound PoW
                let (kp, proof) = if let Some(hash) = namespace_hash {
                    Keypair::generate_with_pow_for_namespace_hash(hash)
                        .map_err(|e| anyhow::anyhow!("{}", e))?
                } else {
                    Keypair::generate_with_pow().map_err(|e| anyhow::anyhow!("{}", e))?
                };
                (kp, self.pow_proof.unwrap_or(proof))
            }
        };

        let spiffe_config = self.spiffe_trust_domain.as_ref().map(|td| {
            let mut config = SpiffeConfig::new(td.clone());
            if let Some(ref path) = self.spiffe_workload_path {
                config = config.with_workload_path(path.clone());
            }
            config
        });

        let node = Node::create_with_spiffe_and_namespace(
            &self.addr,
            keypair,
            pow_proof,
            spiffe_config.as_ref(),
            namespace_config,
        )
        .await?;

        // Start CA signer task if configured
        if let Some(signer_state) = self.signer_state {
            node.start_ca_signer(signer_state).await?;
            info!("Node configured as threshold CA signer");
        }

        // Note: CA certificate request (self.ca_request_config) requires the node to first
        // bootstrap into a mesh with responsive signers. This must be done post-build via
        // a separate method since we can't bootstrap during build() without peer addresses.
        // Users should call node.request_ca_certificate() after bootstrapping.
        if self.ca_request_config.is_some() {
            warn!(
                "CA certificate request configured but cannot execute during build(). \
                 Call node.request_ca_certificate() after bootstrapping into the mesh."
            );
        }

        if namespace_hash.is_some() {
            if let Some(ref config) = self.namespace_config {
                if !config.is_global() {
                    info!("Node configured with namespace isolation (challenge-response enabled)");
                }
            } else if let Some(ref ns) = self.namespace {
                info!(
                    namespace = ns.as_str(),
                    "Node configured with namespace isolation"
                );
            } else {
                info!("Node configured with namespace isolation (bytes-based)");
            }
        }

        Ok(node)
    }

    /// Build and start the node (without SPIFFE support).
    #[cfg(not(feature = "spiffe"))]
    pub async fn build(self) -> Result<Node> {
        // Determine namespace config: prefer explicit config, then derive from hash/string
        let namespace_config = if let Some(config) = self.namespace_config.clone() {
            Some(config)
        } else if self.namespace_hash.is_some() {
            // No challenge-response without the secret
            None
        } else if let Some(ref ns) = self.namespace {
            if ns.is_empty() {
                None
            } else {
                Some(NamespaceConfig::from_passphrase(ns))
            }
        } else {
            None
        };

        // Determine namespace hash for PoW binding
        let namespace_hash = if let Some(ref config) = namespace_config {
            if config.is_global() {
                None
            } else {
                Some(config.namespace_hash())
            }
        } else if let Some(hash) = self.namespace_hash {
            Some(hash)
        } else if let Some(ref ns) = self.namespace {
            if ns.is_empty() {
                None
            } else {
                Some(IdentityProof::namespace_hash_from_string(ns))
            }
        } else {
            None
        };

        let (keypair, pow_proof) = if let Some(kp) = self.keypair {
            // Use provided keypair; if pow_proof not provided, assume global namespace
            let proof = self.pow_proof.unwrap_or_else(IdentityProof::empty);
            // Validate namespace matches proof if specified
            if let Some(ref expected_hash) = namespace_hash
                && !proof.matches_namespace_hash(expected_hash) {
                    return Err(anyhow::anyhow!(
                        "provided keypair's PoW proof was generated for a different namespace"
                    ));
                }
            (kp, proof)
        } else {
            // Generate new keypair with namespace-bound PoW
            let (kp, proof) = if let Some(hash) = namespace_hash {
                Keypair::generate_with_pow_for_namespace_hash(hash)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            } else {
                Keypair::generate_with_pow().map_err(|e| anyhow::anyhow!("{e}"))?
            };
            (kp, self.pow_proof.unwrap_or(proof))
        };

        if namespace_hash.is_some() {
            if let Some(ref config) = self.namespace_config {
                if !config.is_global() {
                    info!("Node configured with namespace isolation (challenge-response enabled)");
                }
            } else if let Some(ref ns) = self.namespace {
                info!(
                    namespace = ns.as_str(),
                    "Node configured with namespace isolation"
                );
            } else {
                info!("Node configured with namespace isolation (bytes-based)");
            }
        }

        Node::create_with_namespace(&self.addr, keypair, pow_proof, namespace_config).await
    }
}
