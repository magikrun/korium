# Korium

[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/korium.svg)](https://crates.io/crates/korium)
[![Documentation](https://docs.rs/korium/badge.svg)](https://docs.rs/korium)

**Batteries-included adaptive networking fabric**

Korium is a high-performance, secure, and adaptive networking library written in Rust. It provides a robust foundation for building decentralized applications, scale-out fabrics, and distributed services with built-in NAT traversal, efficient PubSub, and a cryptographic identity system.

## Why Korium?

- **Zero Configuration** — Self-organizing mesh with automatic peer discovery
- **NAT Traversal** — Built-in relay infrastructure and path probing via SmartSock
- **Secure by Default** — Ed25519 identities with mutual TLS on every connection
- **Adaptive Performance** — Latency-tiered DHT with automatic path optimization
- **Complete Stack** — PubSub messaging, request-response, direct connections, and membership management
- **SPIFFE Compatible** — Optional X.509 URI SAN extensions for enterprise identity interoperability

## Quick Start

Add Korium to your `Cargo.toml`:

```toml
[dependencies]
korium = "0.2"
tokio = { version = "1", features = ["full"] }
```

### Create a Node

```rust
use korium::Node;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Bind to any available port
    let node = Node::bind("0.0.0.0:0").await?;
    
    println!("Node identity: {}", node.identity());
    println!("Listening on: {}", node.local_addr()?);
    
    // Bootstrap from an existing peer
    node.bootstrap("peer_identity_hex", "192.168.1.100:4433").await?;
    
    Ok(())
}
```

### PubSub Messaging

```rust
// Subscribe to a topic
node.subscribe("events/alerts").await?;

// Publish messages (signed with your identity)
node.publish("events/alerts", b"System update available".to_vec()).await?;

// Receive messages
let mut rx = node.messages().await?;
while let Some(msg) = rx.recv().await {
    println!("[{}] from {}: {:?}", msg.topic, &msg.from[..16], msg.data);
}
```

### Request-Response

```rust
// Set up a request handler (echo server)
node.set_request_handler(|from, request| {
    println!("Request from {}: {:?}", &from[..16], request);
    request  // Echo back the request as response
}).await?;

// Send a request and get a response
let response = node.send("peer_identity_hex", b"Hello!".to_vec()).await?;
println!("Response: {:?}", response);

// Or use the low-level API for async handling
let mut requests = node.incoming_requests().await?;
while let Some((from, request, response_tx)) = requests.recv().await {
    // Process request asynchronously
    let response = process_request(request);
    response_tx.send(response).ok();
}
```

### Peer Discovery

```rust
// Find peers near a target identity
let peers = node.find_peers(target_identity).await?;

// Resolve a peer's published contact record
let contact = node.resolve(&peer_identity).await?;

// Publish your address for others to discover
node.publish_address(vec!["192.168.1.100:4433".to_string()]).await?;
```

### NAT Traversal

```rust
// Automatic NAT configuration (helper is a known peer identity in the DHT)
let helper_identity = "abc123..."; // hex-encoded peer identity
let (is_public, relay, incoming_rx) = node.configure_nat(helper_identity, addresses).await?;

if is_public {
    println!("Publicly reachable - can serve as relay");
} else {
    println!("Behind NAT - using relay: {:?}", relay);
    
    // Handle incoming relay connections via mesh signaling
    if let Some(mut rx) = incoming_rx {
        while let Some(incoming) = rx.recv().await {
            node.accept_incoming(&incoming).await?;
        }
    }
}

// Alternative: Enable mesh-mediated signaling (no dedicated relay connection)
let mut rx = node.enable_mesh_signaling().await;
while let Some(incoming) = rx.recv().await {
    node.accept_incoming(&incoming).await?;
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              Node                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │  GossipSub  │  │   Crypto    │  │     DHT     │  │   Relay    │  │
│  │   (PubSub)  │  │ (Identity)  │  │ (Discovery) │  │  (Client)  │  │
│  └──────┬──────┘  └─────────────┘  └──────┬──────┘  └─────┬──────┘  │
│         │                                 │                │        │
│  ┌──────┴─────────────────────────────────┴────────────────┴──────┐ │
│  │                          RpcNode                               │ │
│  │            (Connection pooling, request routing)               │ │
│  └────────────────────────────┬───────────────────────────────────┘ │
│  ┌────────────────────────────┴───────────────────────────────────┐ │
│  │                         SmartSock                              │ │
│  │  (Path probing, relay tunnels, virtual addressing, QUIC mux)   │ │
│  └────────────────────────────┬───────────────────────────────────┘ │
│  ┌────────────────────────────┴───────────────────────────────────┐ │
│  │                       QUIC (Quinn)                             │ │
│  └────────────────────────────┬───────────────────────────────────┘ │
│  ┌────────────────────────────┴───────────────────────────────────┐ │
│  │                   UDP Socket + Relay Server                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```
### Module Overview

| Module | Description |
|--------|-------------|
| `node` | High-level facade exposing the complete public API |
| `transport` | SmartSock with path probing, relay tunnels, and virtual addresses |
| `rpc` | Connection pooling, RPC dispatch, and actor-based state management |
| `dht` | Kademlia-style DHT with latency tiering, adaptive parameters, and peer discovery |
| `gossipsub` | GossipSub v1.1/v1.2 epidemic broadcast with peer scoring |
| `relay` | UDP relay server and client with mesh-mediated signaling for NAT traversal |
| `crypto` | Ed25519 certificates, identity verification, custom TLS |
| `identity` | Keypairs, endpoint records, and signed address publication |
| `protocols` | Protocol trait definitions (DhtNodeRpc, GossipSubRpc, RelayRpc, PlainRpc) |
| `messages` | Protocol message types and bounded serialization |
| `thresholdca` | FROST threshold CA (K-of-N signing) — requires `spiffe` feature |

## Core Concepts

### Identity (Ed25519 Public Keys)

Every node has a cryptographic identity derived from an Ed25519 keypair:

```rust
let node = Node::bind("0.0.0.0:0").await?;
let identity: String = node.identity();  // 64 hex characters (32 bytes)
let keypair = node.keypair();            // Access for signing
```

Identities are:
- **Self-certifying** — The identity IS the public key
- **Collision-resistant** — 256-bit space makes collisions infeasible
- **Verifiable** — Every connection verifies peer identity via mTLS

### Contact

A `Contact` represents a reachable peer:

```rust
pub struct Contact {
    pub identity: Identity,   // Ed25519 public key
    pub addrs: Vec<String>,   // List of addresses (IP:port)
}
```

### SmartAddr (Virtual Addressing)

SmartSock maps identities to virtual IPv6 addresses in the `fd00:c0f1::/32` range:

```
Identity (32 bytes) → blake3 hash → fd00:c0f1:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
```

This enables:
- **Transparent path switching** — QUIC sees stable addresses while SmartSock handles path changes
- **Relay abstraction** — Applications use identity-based addressing regardless of NAT status

### SmartConnect

Automatic connection establishment with fallback:

1. **Try direct connection** to published addresses
2. **If direct fails**, use peer's designated relays
3. **Configure relay tunnel** and establish QUIC connection through relay

```rust
// SmartConnect handles all complexity internally
let conn = node.connect("target_identity_hex").await?;
```

## NAT Traversal

### Mesh-First Relay Model

Korium uses a **mesh-first** relay model where any reachable mesh peer can act as a relay:

1. **No dedicated relay servers** — Any publicly reachable node serves as a relay
2. **Mesh-mediated signaling** — Relay signals forwarded through GossipSub mesh
3. **Opportunistic relaying** — Connection attempts try mesh peers as relays
4. **Zero configuration** — Works automatically when mesh peers are available

### How SmartSock Works

SmartSock implements transparent NAT traversal:

1. **Path Probing** — Periodic probes measure RTT to all known paths
2. **Path Selection** — Best path chosen (direct preferred, relay as fallback)
3. **Relay Tunnels** — UDP packets wrapped in CRLY frames through relay
4. **Automatic Upgrade** — Switch from relay to direct when hole-punch succeeds

### Protocol Headers

**Path Probe (SMPR)**
```
┌──────────┬──────────┬──────────┬──────────────┐
│  Magic   │   Type   │  Tx ID   │  Timestamp   │
│  4 bytes │  1 byte  │  8 bytes │   8 bytes    │
└──────────┴──────────┴──────────┴──────────────┘
```

**Relay Frame (CRLY)**
```
┌──────────┬──────────────┬──────────────────────┐
│  Magic   │  Session ID  │    QUIC Payload      │
│  4 bytes │   16 bytes   │     (variable)       │
└──────────┴──────────────┴──────────────────────┘
```

### Path Selection Algorithm

```
if direct_path.rtt + 10ms < current_path.rtt:
    switch to direct_path
elif relay_path.rtt + 50ms < direct_path.rtt:
    switch to relay_path (relay gets 50ms handicap)
```

## DHT (Distributed Hash Table)

### Kademlia Implementation

The DHT is used internally for peer discovery and address publication:

- **256 k-buckets** with configurable k (default: 20, adaptive: 10-30)
- **Iterative lookups** with configurable α (default: 3, adaptive: 2-5)
- **S/Kademlia PoW**: Identity generation requires Proof-of-Work for Sybil resistance

### Key Operations

```rust
// Find peers near a target identity
let peers = node.find_peers(target_identity).await?;

// Resolve peer's published contact record
let contact = node.resolve(&peer_id).await?;

// Publish your address for discovery
node.publish_address(vec!["192.168.1.100:4433".to_string()]).await?;
```

### Latency Tiering

The DHT implements Coral-inspired latency tiering:

- **RTT samples** collected per /16 IP prefix (IPv4) or /32 prefix (IPv6)
- **K-means clustering** groups prefixes into 1-7 latency tiers
- **Tiered lookups** prefer faster prefixes for lower latency
- **LRU-bounded** — tracks up to 10,000 active prefixes (~1MB memory)

## Scalability (10M+ Nodes)

Korium is designed to scale to millions of concurrent peers. Key design decisions enable efficient operation at scale:

### Memory Efficiency (Per-Node at 10M Network)

Each node uses constant memory regardless of network size:

| Component | Memory | Design |
|-----------|--------|--------|
| **Routing table** | ~640 KB | 256 buckets × 20 contacts |
| **RTT tiering** | ~1 MB | /16 prefix-based (not per-peer) |
| **Passive view** | ~13 KB | 100 recovery candidates |
| **Connection cache** | ~200 KB | 1,000 LRU connections |
| **Peer scoring** | ~1 MB | 10K active peers scored |
| **Message dedup** | ~2 MB | 10K source sequence windows |
| **Total** | **~5 MB** | Bounded, scales to 10M+ nodes |

### DHT Performance

| Metric | Value | Notes |
|--------|-------|-------|
| **Lookup hops** | O(log₂ N) ≈ 23 | Standard Kademlia complexity |
| **Parallel queries (α)** | 2-5 adaptive | Reduces under congestion |
| **Bucket size (k)** | 10-30 adaptive | Increases with churn |
| **Routing contacts** | ~5,120 max | 256 buckets × 20 |

### Korium vs Standard Kademlia

| Feature | Standard Kademlia | Korium | Benefit |
|---------|------------------|--------|---------|
| **Bucket size** | Fixed k=20 | Adaptive 10-30 | Handles churn spikes |
| **Concurrency** | Fixed α=3 | Adaptive 2-5 | Load shedding |
| **RTT optimization** | ❌ None | /16 prefix tiering | Lower latency paths |
| **Sybil protection** | ❌ Basic | S/Kademlia PoW + per-peer limits | Eclipse resistant |
| **Gossip layer** | ❌ None | GossipSub v1.1/v1.2 | Fast broadcast, scoring |
| **NAT traversal** | ❌ None | SmartSock + mesh relays | Works behind NAT |
| **Identity** | SHA-1 node IDs | Ed25519 + PoW | Self-certifying, Sybil-resistant |

### Scaling Boundaries (Per-Node)

These limits are per-node, not network-wide. With 10M nodes, the network's aggregate capacity scales linearly:

| Parameter | Per-Node Limit | At 10M Nodes | Notes |
|-----------|----------------|--------------|-------|
| **Routing contacts** | ~5,120 | N/A | O(log N) = 23 hops at 10M |
| **Contact records** | 100K entries | 1 trillion | Distributed across DHT |
| **Scored peers** | 10,000 | 100 billion | Per-node active peer set |
| **PubSub topics** | 10,000 | 100 billion | Topics span multiple nodes |
| **Peers per topic** | 1,000 | N/A | Gossip efficiency bound |
| **Relay sessions** | 10,000 | 100 billion | Per-relay server |

### Key Design Decisions

1. **Prefix-based RTT** — Tracking RTT per /16 IP prefix instead of per-peer reduces memory from O(N) to O(65K) while maintaining routing quality through statistical sampling.

2. **Adaptive parameters** — k and α automatically adjust based on observed churn rate, preventing cascade failures during network instability.

3. **Bounded data structures** — All caches use LRU eviction with fixed caps, ensuring memory stays constant regardless of network size.

## GossipSub (PubSub)

### GossipSub v1.1/v1.2 Implementation

Korium implements the full GossipSub v1.1 specification with v1.2 extensions:

- **Peer Scoring (P1-P7)**: Time in mesh, message delivery, invalid messages, IP colocation
- **Adaptive Gossip**: D_score mesh quotas, Opportunistic Grafting, Flood Publishing
- **IDontWant (v1.2)**: Bandwidth optimization for large messages
- **Mesh Management**: D, D_lo, D_hi, D_out, D_score parameters
- **Prune Backoff**: Exponential backoff for pruned peers

### Epidemic Broadcast

GossipSub implements efficient topic-based publish/subscribe:
- **Mesh overlay** — Each topic maintains a mesh of connected peers
- **Eager push** — Messages forwarded immediately to mesh peers
- **Flood publishing** — Publishers send to all peers above publish threshold
- **Gossip protocol** — IHave/IWant metadata exchange for reliability
- **Relay signaling** — NAT traversal signals forwarded through mesh peers

### Message Flow

```
Publisher → Mesh Push → Subscribers
              ↓
         Gossip (IHave)
              ↓
         IWant requests
              ↓
         Message delivery
```

### Message Authentication

All published messages include Ed25519 signatures:

```rust
// Messages are signed with publisher's keypair
node.publish("topic", data).await?;

// Signatures verified on receipt (invalid messages rejected)
let msg = rx.recv().await?;  // msg.from is verified sender
```

### Rate Limiting

| Limit | Value |
|-------|-------|
| Publish rate | 100/sec |
| Per-peer receive rate | 50/sec |
| Max message size | 64 KB |
| Max topics | 10,000 |
| Max peers per topic | 1,000 |

## Security

### Defense Layers

| Layer | Protection |
|-------|------------|
| **Identity** | Ed25519 keypairs, identity = public key |
| **Transport** | Mutual TLS on all QUIC connections |
| **RPC** | Identity verification on every request |
| **Storage** | Per-peer quotas, rate limiting, content validation |
| **Routing** | Rate-limited insertions, ping verification, S/Kademlia PoW |
| **PubSub** | Message signatures, replay detection, peer scoring (P1-P7), IP colocation (P6) |

### Security Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_VALUE_SIZE` | 1 MB | DHT value limit |
| `MAX_RESPONSE_SIZE` | 1 MB | RPC response limit |
| `MAX_SESSIONS` | 10,000 | Relay session limit |
| `MAX_SESSIONS_PER_IP` | 50 | Per-IP relay rate limit |
| `PER_PEER_STORAGE_QUOTA` | 1 MB | DHT storage per peer |
| `PER_PEER_ENTRY_LIMIT` | 100 | DHT entries per peer |
| `MAX_CONCURRENT_STREAMS` | 64 | QUIC streams per connection |
| `POW_DIFFICULTY` | 24 bits | Identity PoW (Sybil resistance) |

## SPIFFE Compatibility (Optional)

Korium supports [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) as an **optional interoperability layer**. This enables Korium nodes to present SPIFFE-compliant X.509 certificates for integration with enterprise service meshes and identity-aware proxies.

The `spiffe` feature includes:
- **SPIFFE ID generation** — X.509 URI SAN extensions with trust domain/workload identifiers
- **Threshold CA** — Distributed K-of-N certificate signing using FROST signatures

### Architecture

**Important:** SPIFFE compatibility is additive—it does NOT replace Korium's native Ed25519 self-certifying identity model. The SPIFFE ID is embedded as a URI SAN (Subject Alternative Name) in X.509 certificates and is cryptographically bound to the node's identity.

```
SPIFFE ID Format:
spiffe://{trust_domain}/{identity_hex}[/{workload_path}]

Example:
spiffe://production.example.com/d4f5a6b7c8.../api-gateway
```

### Enabling SPIFFE

Add the feature flag to your `Cargo.toml`:

```toml
[dependencies]
korium = { version = "0.2", features = ["spiffe"] }
```

### Creating a Node with SPIFFE

```rust
use korium::Node;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node = Node::builder("0.0.0.0:0")
        .spiffe_trust_domain("production.example.com")
        .spiffe_workload_path("api-gateway")
        .build()
        .await?;
    
    println!("Node identity: {}", node.identity());
    // Certificate now contains URI SAN: spiffe://production.example.com/{identity}/api-gateway
    
    Ok(())
}
```

### SPIFFE API

| Method | Description |
|--------|-------------|
| `NodeBuilder::spiffe_trust_domain(domain)` | Set the SPIFFE trust domain |
| `NodeBuilder::spiffe_workload_path(path)` | Set optional workload path suffix |

Certificates with SPIFFE URI SANs are generated automatically when building a node with `spiffe_trust_domain()` set.

### Verification Without a CA

Korium does **not** use a central Certificate Authority. Instead, verification relies on the self-certifying property of Ed25519 identities:

```
Standard SPIFFE:
  SPIRE CA signs SVID → Verifier trusts CA → Trusts workload identity

Korium (Self-Certifying):
  TLS handshake proves key possession → Public key IS the identity
  → SPIFFE ID is metadata bound to verified key
```

**Verification Flow:**

1. **TLS Handshake** — Peer must prove possession of the private key (cryptographic proof)
2. **Extract Public Key** — Verifier extracts Ed25519 public key from the X.509 certificate
3. **Identity = Key** — The 32-byte public key IS the canonical identity (no trust delegation)
4. **SPIFFE ID Validation** — If SPIFFE ID present, verify the identity hex in the URI path matches the certificate's public key

```rust
// Verification pseudocode
let cert_pubkey = extract_pubkey_from_cert(&peer_cert);  // From TLS handshake
let expected_identity = Identity(cert_pubkey);           // Identity = Public Key

if let Some(spiffe_id) = extract_spiffe_id_from_cert(&peer_cert)? {
    // Validate SPIFFE ID is bound to the same identity
    let spiffe_identity = validate_spiffe_id(&spiffe_id, "my-trust-domain")?;
    assert_eq!(spiffe_identity, expected_identity);  // Cryptographic binding
}
```

**Why This Works:**

| Property | Standard SPIFFE | Korium |
|----------|----------------|--------|
| Trust anchor | CA certificate | None (self-certifying) |
| Identity proof | CA signature | TLS key possession |
| Revocation | CA-managed | Peer scoring / DHT expiry |
| SPIFFE ID role | Primary identity | Interoperability metadata |

### Security Considerations

- **Cryptographic Binding:** The identity hex is embedded in the SPIFFE URI path, ensuring the SPIFFE ID cannot be forged independently of the Ed25519 keypair
- **No Central Authority:** Unlike standard SPIFFE deployments, Korium nodes self-issue certificates—the SPIFFE ID provides format compatibility, not centralized trust
- **Zero Runtime Cost:** When the `spiffe` feature is disabled, no SPIFFE code is compiled
- **No Revocation Infrastructure:** Without a CA, certificate revocation relies on DHT record expiry and GossipSub peer scoring—nodes with bad behavior are deprioritized, not revoked

## Threshold CA

For enterprise integrations requiring CA-backed certificates, the `spiffe` feature includes a **distributed threshold CA** using FROST (Flexible Round-Optimized Schnorr Threshold) signatures. This enables K-of-N signing without any single party holding the complete CA private key.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Threshold CA Architecture                         │
│                                                                      │
│  1. DKG (one-time setup):                                           │
│     - N signers run 3-round protocol via GossipSub                  │
│     - Each signer gets KeyPackage (private share)                   │
│     - All get combined CA public key                                │
│                                                                      │
│  2. Signing (per certificate):                                       │
│     - Requester broadcasts CSR to signers                           │
│     - K signers validate and produce partial signatures             │
│     - Requester combines into valid FROST signature                 │
│                                                                      │
│  Trust Model:                                                        │
│     - Verifier trusts CA_pubkey (32 bytes)                          │
│     - CA_pubkey created by committee via DKG                        │
│     - Any K honest signers can produce valid signatures             │
└─────────────────────────────────────────────────────────────────────┘
```

### Running DKG (Key Generation Ceremony)

```rust
use korium::{ThresholdCaConfig, DkgCoordinator, SignerState};

// Configure 5 signers, require 3 to sign (Byzantine fault tolerant)
let config = ThresholdCaConfig::new(5, 3, "make.run")?;

// Each signer creates a coordinator with all signer identities
let coordinator = DkgCoordinator::new(config, all_signer_identities, my_identity)?;

// Round 1: Generate and broadcast commitment
let (round1_secret, round1_msg) = coordinator.round1()?;
broadcast(round1_msg);  // Send via GossipSub

// Round 2: Process received commitments, generate shares
let (round2_secret, round2_msgs) = coordinator.round2(round1_secret, &received_round1)?;
for msg in round2_msgs {
    send_to_recipient(msg);  // Per-recipient packages
}

// Round 3: Finalize - produces SignerState with key share
let signer_state: SignerState = coordinator.round3(
    &round2_secret,
    &all_round1_msgs,
    &my_round2_msgs,
)?;

// Persist signer_state (contains private key share - encrypt at rest!)
let serialized = signer_state.serialize()?;
```

### Node Integration

For automatic signing, configure nodes as signers using `NodeBuilder`:

```rust
use korium::{Node, CaRequestConfig, SignerState};

// === Signer Node ===
// Load signer state from encrypted storage (from DKG ceremony)
let signer_state = SignerState::deserialize(&encrypted_state)?;

let signer_node = Node::builder("0.0.0.0:4433")
    .spiffe_trust_domain("example.org")
    .as_ca_signer(signer_state)
    .build()
    .await?;
// Node now automatically responds to CSR requests:
// 1. Listens on GossipSub `csr` topic for CSR broadcasts
// 2. Sends commitment via RPC to requester
// 3. Receives sign-request via RPC with all commitments
// 4. Responds with signature share via RPC

// === Requesting Node ===
let node = Node::builder("0.0.0.0:4433")
    .spiffe_trust_domain("example.org")
    .build()
    .await?;

// First bootstrap into the mesh
node.bootstrap(&bootstrap_identity, &bootstrap_addr).await?;

// Then request CA certificate
let config = CaRequestConfig {
    signer_identities: vec![signer1, signer2, signer3],
    min_signers: 2,
    ca_public_key,
    timeout: Duration::from_secs(30),
};
let cert_der = node.request_ca_certificate_from_mesh("example.org", Some("api-gw"), &config).await?;
// cert_der is a valid X.509 certificate signed by the threshold CA
```

### Threshold CA Protocol

```text
┌─────────────┐   GossipSub: csr    ┌─────────────┐
│  Requester  │ ─────────────────▶  │   Signers   │
│             │                     │  (K of N)   │
│             │ ◀─────────────────  │             │
│             │  RPC: commitment    └─────────────┘
│             │                           │
│             │  ─────────────────▶       │
│             │  RPC: sign-request        │
│             │  (all commitments)        │
│             │ ◀─────────────────        │
│             │  RPC: signature share     │
└─────────────┘                           │
      │ aggregate K shares                │
      ▼                                   │
   [CA-signed X.509 cert]                 │
```

### Threshold CA API

| Type/Function | Description |
|---------------|-------------|
| `SignerState` | Holds private key share (generated externally, serialize for persistence) |
| `CaPublicKey` | Distributable CA public key |
| `CaRequestConfig` | Configuration for requesting CA-signed certificates |
| `ThresholdCaConfig` | Configuration (N signers, K threshold, trust domain) |
| `ThresholdCaError` | Error type for threshold CA operations |
| `NodeBuilder::as_ca_signer()` | Configure node as CA signer |
| `Node::request_ca_certificate_from_mesh()` | Request CA-signed certificate |

> **Note:** DKG (Distributed Key Generation) is an internal implementation detail. Generate `SignerState` via external tooling or the Korium CLI.

### Security Properties

| Property | Value |
|----------|-------|
| **Byzantine Tolerance** | Survives up to N-K malicious signers |
| **No Trusted Dealer** | DKG ensures no party sees complete key |
| **Identifiable Aborts** | Misbehaving signers can be detected |
| **Key Shares** | Must be stored encrypted at rest |
| **Signature Algorithm** | FROST (RFC 9591) over Ed25519 |

### GossipSub Topics (Threshold CA)

| Topic | Purpose |
|-------|--------|
| `csr` | Certificate signing request broadcast |

> **Note:** Commitments and signature shares are exchanged via RPC (point-to-point), not GossipSub, for privacy and efficiency.

## CLI Usage

### Running a Node

```bash
# Start a node on a random port
cargo run

# Start with specific bind address
cargo run -- --bind 0.0.0.0:4433

# Bootstrap from existing peer
cargo run -- --bootstrap 192.168.1.100:4433/abc123...def456

# With debug logging
RUST_LOG=debug cargo run
```

### Chatroom Example

```bash
# Terminal 1: Start first node
cargo run --example chatroom -- --name Alice --room dev

# Terminal 2: Join with bootstrap (copy the bootstrap string from Terminal 1)
cargo run --example chatroom -- --name Bob --room dev --bootstrap <bootstrap_string>
```

The chatroom demonstrates:
- PubSub messaging (`/room` messages)
- Direct messaging (`/dm <identity> <message>`)
- Peer discovery (`/peers`)

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_smart_addr

# Run integration tests
cargo test --test node_public_api

# Run relay tests
cargo test --test relay_infrastructure

# Run SPIFFE compatibility tests
cargo test --features "spiffe" spiffe

# Run Threshold CA tests
cargo test --features "spiffe,test-pow" thresholdca

# Spawn local cluster (7 nodes)
./scripts/spawn_cluster.sh
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `quinn` | QUIC implementation |
| `tokio` | Async runtime |
| `ed25519-dalek` | Ed25519 signatures |
| `blake3` | Fast cryptographic hashing |
| `rustls` | TLS implementation |
| `bincode` | Binary serialization |
| `lru` | LRU caches |
| `tracing` | Structured logging |
| `rcgen` | X.509 certificate generation (URI SAN for SPIFFE) |
| `x509-parser` | Certificate parsing (SPIFFE ID extraction) |
| `frost-ed25519` | FROST threshold signatures (optional, spiffe feature) |

## References

### NAT Traversal with QUIC

- **Liang, J., et al.** (2024). *Implementing NAT Hole Punching with QUIC*. VTC2024-Fall. [arXiv:2408.01791](https://arxiv.org/abs/2408.01791)
  
  Demonstrates QUIC hole punching advantages and connection migration saving 2 RTTs.

### Distributed Hash Tables

- **Freedman, M. J., et al.** (2004). *Democratizing Content Publication with Coral*. NSDI '04. [PDF](https://www.cs.princeton.edu/~mfreed/docs/coral-nsdi04.pdf)

  Introduced "sloppy" DHT with latency-based clustering—inspiration for Korium's tiering system.

- **Baumgart, I. & Mies, S.** (2007). *S/Kademlia: A Practicable Approach Towards Secure Key-Based Routing*. ICPP '07.

  The S/Kademlia specification that Korium implements for Sybil-resistant identity generation via Proof-of-Work.

### GossipSub / PlumTree

- **Vyzovitis, D., et al.** (2020). *GossipSub: Attack-Resilient Message Propagation in the Filecoin and ETH2.0 Networks*.

  The GossipSub v1.1 specification that Korium's PubSub implementation follows, including peer scoring (P1-P7), Adaptive Gossip, and mesh management.

- **Leitão, J., Pereira, J., & Rodrigues, L.** (2007). *Epidemic Broadcast Trees*. SRDS '07.

  The PlumTree paper that influenced GossipSub's design, combining gossip reliability with efficient message propagation.

## License

MIT License - see [LICENSE](LICENSE) for details.
