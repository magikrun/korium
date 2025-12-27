//! # Korium - Distributed Mesh Networking Library
//!
//! Korium provides a secure, decentralized mesh networking stack built on:
//!
//! - **Identity**: Ed25519-based cryptographic identities (32-byte public keys)
//! - **DHT**: Kademlia-style distributed hash table for peer discovery and data storage
//! - **PubSub**: GossipSub epidemic broadcast for reliable message dissemination
//! - **Transport**: SmartSock with automatic path selection (direct/relay)
//! - **NAT Traversal**: UDP relay infrastructure for NAT-bound nodes
//!
//! ## Architecture
//!
//! The codebase uses the **Actor Pattern** extensively for safe concurrent state:
//! - Each component (DHT, GossipSub, Relay) has a public Handle and private Actor
//! - Handles are cheap to clone and communicate via async channels
//! - Actors own all mutable state and process commands sequentially
//!
//! ## Security Model
//!
//! - All peer connections use mutual TLS with Ed25519 certificates
//! - Identity = Public Key (no separate identity layer)
//! - All stored data is content-addressed or cryptographically signed
//! - Rate limiting and bounded data structures prevent resource exhaustion
//! - **S/Kademlia PoW**: Identity generation requires Proof-of-Work (Sybil resistance)
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|--------|
//! | `node` | High-level API combining all components |
//! | `identity` | Keypairs, Identities, signed Contacts |
//! | `crypto` | TLS certificate generation and verification |
//! | `dht` | Kademlia DHT with adaptive parameters, XOR-metric routing, and storage |
//! | `gossipsub` | Epidemic broadcast for PubSub |
//! | `relay` | UDP relay server/client for NAT traversal |
//! | `transport` | SmartSock multi-path transport layer |
//! | `protocols` | Protocol trait definitions (DhtNodeRpc, etc.) |
//! | `rpc` | QUIC-based RPC layer implementing protocols |
//! | `messages` | Serialization types for all wire protocols |

mod crypto;
mod dht;
mod gossipsub;
mod identity;
mod messages;
mod node;
mod protocols;
mod relay;
mod rpc;
mod transport;

#[cfg(feature = "spiffe")]
mod thresholdca;

pub use node::{
    Identity, IdentityProof, Keypair, NAMESPACE_HASH_LEN, Node, NodeBuilder, POW_DIFFICULTY,
    PoWError,
};

// SPIFFE and Threshold CA types are accessed through Node's public API:
// - Node::builder().spiffe_trust_domain() / .spiffe_workload_path()
// - Node::builder().as_ca_signer(signer_state)
// - Node::request_ca_certificate_from_mesh()
// DKG types are internal - generate SignerState via external tooling.
#[cfg(feature = "spiffe")]
pub use node::{CaPublicKey, CaRequestConfig, SignerState, ThresholdCaConfig, ThresholdCaError};
