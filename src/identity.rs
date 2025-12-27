//! # Identity and Cryptographic Primitives
//!
//! This module defines the core identity types used throughout Korium:
//!
//! - [`Keypair`]: Ed25519 signing keypair (secret + public key)
//! - [`Identity`]: 32-byte public key serving as the peer's unique identifier
//! - [`Contact`]: Signed endpoint record containing addresses and relay information
//!
//! ## Identity Model
//!
//! Korium uses a simple identity model: **Identity = Ed25519 Public Key**.
//! This provides:
//!
//! - **Sybil resistance**: Creating identities requires Proof-of-Work (crypto puzzle)
//! - **Self-certifying**: No external CA needed; possession of private key proves identity
//! - **XOR-metric routing**: Identities can be used directly in Kademlia-style DHT
//!
//! ## Proof-of-Work (S/Kademlia Compliance)
//!
//! To prevent Sybil attacks, identity generation requires solving a crypto puzzle:
//! `BLAKE3(public_key || nonce)` must have `POW_DIFFICULTY` leading zero bits.
//!
//! This makes bulk identity generation computationally expensive while keeping
//! verification O(1). See [`IdentityProof`] and [`Keypair::generate_with_pow`].
//!
//! ## Contact Records
//!
//! A [`Contact`] is a signed record containing:
//! - The peer's identity (public key)
//! - Network addresses (IP:port)
//! - Relay identities for NAT-bound nodes
//! - Timestamp and signature for freshness verification
//!
//! Contacts are stored in the DHT under key = identity bytes, allowing
//! any peer to discover how to reach a given identity.
//!
//! ## Namespace Isolation
//!
//! Korium supports namespace isolation via cryptographic binding:
//! - Identities can be bound to a namespace string (e.g., "acme-corp")
//! - The namespace is hashed and included in the PoW challenge
//! - Peers verify namespace membership during application-layer auth
//! - DHT routing and relay remain global (cross-namespace)
//!
//! See [`IdentityProof`] for namespace-related methods.
//!
//! ## Security Invariants
//!
//! - P1: `Identity::from_bytes(bytes).as_bytes() == bytes` (round-trip preservation)
//! - P2: XOR distance is symmetric and satisfies triangle inequality
//! - P3: Only valid Ed25519 points are accepted as identities
//! - P4: Contact signatures bind addresses to identity cryptographically
//! - P5: Timestamps prevent replay of stale contact records
//! - P6: Identity generation requires Proof-of-Work (Sybil resistance)
//! - P7: Namespace is cryptographically bound to identity via PoW hash

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

use crate::crypto::{CONTACT_SIGNATURE_DOMAIN, SignatureError};

// ============================================================================
// Network Provenance (IP-based locality detection)
// ============================================================================

/// Network provenance for colocation detection and locality-based operations.
///
/// Extracts a coarse identifier representing the peer's network origin:
/// - **IPv4**: `/16` prefix (first two octets) — ISP/regional level
/// - **IPv6**: `/32` prefix (first two segments) — similar regional scope
///
/// # Use Cases
///
/// - **GossipSub P6**: Detect peers in same datacenter → colocation penalty (Sybil resistance)
/// - **DHT Tiering**: Group peers by network region → latency estimation
/// - **Rate Limiting**: Bound requests per network block → abuse prevention
///
/// # Design Rationale
///
/// - `/16` catches datacenter co-tenancy (AWS, GCP share /16 blocks)
/// - Coarser than `/24` to detect VPS in same datacenter
/// - Matches statistical assumption: same /16 ≈ similar latency
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Provenance(u16);

impl Provenance {
    /// Extract provenance from a socket address.
    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::from_ip(addr.ip())
    }

    /// Extract provenance from an IP address.
    #[inline]
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // /16: first two octets
                Self((u16::from(octets[0]) << 8) | u16::from(octets[1]))
            }
            IpAddr::V6(v6) => {
                // /32: first two segments (ISP-level granularity)
                let segs = v6.segments();
                Self(segs[0].wrapping_add(segs[1]))
            }
        }
    }

    /// Parse from "host:port" string format.
    ///
    /// Handles:
    /// - IPv4: "192.168.1.1:8080"
    /// - IPv6: "[::1]:8080"
    /// - Host only: "192.168.1.1"
    pub fn from_addr_str(addr: &str) -> Option<Self> {
        // Try parsing as SocketAddr first (most common case)
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            return Some(Self::from_socket_addr(socket_addr));
        }

        // Fall back to manual parsing for "host:port" or just "host"
        let host = if let Some(bracket_end) = addr.find(']') {
            // IPv6: [::1]:port
            &addr[1..bracket_end]
        } else if let Some(colon_pos) = addr.rfind(':') {
            // IPv4 or hostname:port - take part before last colon
            &addr[..colon_pos]
        } else {
            addr
        };

        host.parse::<IpAddr>().ok().map(Self::from_ip)
    }
}

// ============================================================================
// Proof-of-Work Constants (S/Kademlia Sybil Resistance)
// ============================================================================

/// Number of leading zero bits required in PoW hash.
///
/// Production (difficulty 24):
/// - Average attempts: 2^24 = ~16 million
/// - Time on modern CPU: ~1-4 seconds
///
/// Tests with `test-pow` feature (difficulty 8):
/// - Average attempts: 2^8 = ~256
/// - Time: <1ms
/// - Exercises full PoW validation code path
///
/// SECURITY: Production difficulty makes Sybil attacks expensive.
/// An attacker generating 1000 identities needs ~3-5 hours of CPU time.
#[cfg(not(any(test, feature = "test-pow")))]
pub const POW_DIFFICULTY: u32 = 24;

#[cfg(any(test, feature = "test-pow"))]
pub const POW_DIFFICULTY: u32 = 8;

/// Maximum nonce value before giving up (prevents infinite loops).
/// With difficulty 24, success is virtually guaranteed within 2^32 attempts.
const POW_MAX_NONCE: u64 = 1 << 36;

/// Maximum keypair regeneration attempts before panic.
/// If inner loop (POW_MAX_NONCE attempts) fails, regenerate keypair.
/// Exhausting this limit requires P < 10^(-1780) per keypair, making
/// this bound purely defensive against hypothetical CSPRNG failures.
const POW_MAX_KEYPAIR_ATTEMPTS: u32 = 16;

/// Domain separation prefix for PoW hashing.
/// Prevents cross-protocol hash reuse.
const POW_HASH_DOMAIN: &[u8] = b"korium-pow-v1:";

/// Length of namespace hash stored in IdentityProof.
/// 8 bytes = 64 bits provides ~10^19 collision resistance between namespaces.
/// SECURITY: Larger values increase collision resistance at the cost of storage.
pub const NAMESPACE_HASH_LEN: usize = 8;

/// The empty namespace hash (all zeros) used for global/legacy namespace.
const EMPTY_NAMESPACE_HASH: [u8; NAMESPACE_HASH_LEN] = [0u8; NAMESPACE_HASH_LEN];

/// Error type for Proof-of-Work generation failures.
///
/// This error indicates a catastrophic failure in the random number generator
/// or an unreasonable difficulty setting. In practice, this should never occur
/// with a functioning CSPRNG and reasonable difficulty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoWError {
    /// Number of keypairs attempted before giving up.
    pub keypairs_tried: u32,
    /// Number of nonces tried per keypair.
    pub nonces_per_keypair: u64,
    /// The difficulty level that was requested.
    pub difficulty: u32,
}

impl std::fmt::Display for PoWError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PoW generation failed after {} keypairs with {} nonces each (difficulty={}). \
             This indicates a CSPRNG failure or unreasonable difficulty.",
            self.keypairs_tried, self.nonces_per_keypair, self.difficulty
        )
    }
}

impl std::error::Error for PoWError {}

/// Error type for namespace encryption/decryption failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceEncryptionError {
    /// Encryption operation failed (should never happen with valid input).
    EncryptionFailed,
    /// Ciphertext is too short to contain nonce + tag.
    CiphertextTooShort,
    /// Decryption failed - wrong key, tampered data, or epoch mismatch.
    DecryptionFailed,
}

impl std::fmt::Display for NamespaceEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "namespace encryption failed"),
            Self::CiphertextTooShort => write!(f, "ciphertext too short"),
            Self::DecryptionFailed => {
                write!(f, "namespace decryption failed (wrong key or tampered)")
            }
        }
    }
}

impl std::error::Error for NamespaceEncryptionError {}

/// Returns current time as milliseconds since Unix epoch.
/// Used for timestamp generation in signed records.
#[inline]
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new keypair WITHOUT Proof-of-Work.
    ///
    /// **WARNING**: This creates an identity that will be rejected by DHT nodes
    /// enforcing PoW verification. Use [`generate_with_pow`] for production.
    ///
    /// Use cases:
    /// - Testing and development
    /// - Ephemeral connections that don't need DHT routing
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Generate a new keypair WITH Proof-of-Work (S/Kademlia compliant).
    ///
    /// Creates an identity in the **global namespace** (empty namespace).
    /// For namespace-specific identities, use [`generate_with_pow_for_namespace`].
    ///
    /// This iterates through random keypairs until finding one where:
    /// `BLAKE3(POW_HASH_DOMAIN || public_key || nonce)` has `POW_DIFFICULTY` leading zeros.
    ///
    /// Returns `Ok((Keypair, IdentityProof))` - the proof must be included in Contact
    /// records for DHT acceptance.
    ///
    /// # Performance
    /// - Expected time: 50-200ms on modern CPU (difficulty 16)
    /// - Parallelizable across cores if needed
    ///
    /// # Errors
    /// Returns `Err(PoWError)` if no valid proof is found within the bounded attempts.
    /// This is astronomically unlikely (probability < 10^(-28000)) with a functioning CSPRNG.
    pub fn generate_with_pow() -> Result<(Self, IdentityProof), PoWError> {
        Self::generate_with_pow_for_namespace("")
    }

    /// Generate a new keypair WITH Proof-of-Work bound to a namespace.
    ///
    /// The namespace string becomes a cryptographic trust anchor:
    /// - The identity proof is bound to this namespace via PoW hash
    /// - The proof cannot be reused across namespaces
    /// - Peers can verify namespace membership during mTLS
    ///
    /// # Namespace Model
    ///
    /// - Empty string ("") = global namespace (default, backwards compatible)
    /// - Named namespace (e.g., "acme-corp") = isolated namespace
    ///
    /// Nodes in different namespaces can still route traffic and act as relays,
    /// but cannot establish authenticated application connections.
    ///
    /// # Example
    /// ```ignore
    /// let (keypair, proof) = Keypair::generate_with_pow_for_namespace("acme-corp")?;
    /// assert!(keypair.identity().verify_pow(&proof));
    /// assert!(proof.matches_namespace("acme-corp"));
    /// ```
    ///
    /// # Errors
    /// Returns `Err(PoWError)` if no valid proof is found within the bounded attempts.
    pub fn generate_with_pow_for_namespace(
        namespace: &str,
    ) -> Result<(Self, IdentityProof), PoWError> {
        let namespace_hash = IdentityProof::namespace_hash_from_string(namespace);
        Self::generate_with_pow_for_namespace_hash(namespace_hash)
    }

    /// Generate a new keypair WITH Proof-of-Work bound to a namespace hash.
    ///
    /// Use this when your namespace is a raw secret (bytes) rather than a string.
    /// This provides **stronger privacy** since the namespace cannot be guessed.
    ///
    /// # Example
    /// ```ignore
    /// // Generate a random namespace secret (share out-of-band with peers)
    /// let namespace_secret = blake3::hash(b"my-secret-seed");
    /// let ns_hash = IdentityProof::namespace_hash_from_bytes(namespace_secret.as_bytes());
    ///
    /// let (keypair, proof) = Keypair::generate_with_pow_for_namespace_hash(ns_hash)?;
    /// ```
    ///
    /// # Errors
    /// Returns `Err(PoWError)` if no valid proof is found within the bounded attempts.
    pub fn generate_with_pow_for_namespace_hash(
        namespace_hash: [u8; NAMESPACE_HASH_LEN],
    ) -> Result<(Self, IdentityProof), PoWError> {
        Self::generate_with_pow_internal_hash(POW_DIFFICULTY, namespace_hash)
    }

    /// Generate a keypair with custom PoW difficulty in global namespace.
    ///
    /// Useful for testing (difficulty=0) or high-security deployments.
    ///
    /// # Errors
    /// Returns `Err(PoWError)` if difficulty > 0 and no valid proof is found.
    pub fn generate_with_pow_difficulty(
        difficulty: u32,
    ) -> Result<(Self, IdentityProof), PoWError> {
        Self::generate_with_pow_internal_hash(difficulty, EMPTY_NAMESPACE_HASH)
    }

    /// Internal PoW generation with pre-computed namespace hash.
    fn generate_with_pow_internal_hash(
        difficulty: u32,
        namespace_hash: [u8; NAMESPACE_HASH_LEN],
    ) -> Result<(Self, IdentityProof), PoWError> {
        if difficulty == 0 {
            let keypair = Self::generate();
            return Ok((keypair, IdentityProof::with_namespace(0, namespace_hash)));
        }

        #[allow(unused_variables)]
        for keypair_attempt in 0..POW_MAX_KEYPAIR_ATTEMPTS {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key().to_bytes();

            for nonce in 0..POW_MAX_NONCE {
                if verify_pow_hash_with_namespace(&public_key, nonce, &namespace_hash, difficulty) {
                    let keypair = Self { signing_key };
                    let proof = IdentityProof::with_namespace(nonce, namespace_hash);
                    return Ok((keypair, proof));
                }
            }
            // Exhausted nonce space for this keypair, try another.
            // This branch is astronomically unlikely (P < 10^(-1780)).
            #[cfg(debug_assertions)]
            eprintln!(
                "PoW: exhausted nonce space on keypair attempt {}/{} (difficulty={}), regenerating",
                keypair_attempt + 1,
                POW_MAX_KEYPAIR_ATTEMPTS,
                difficulty
            );
        }
        Err(PoWError {
            keypairs_tried: POW_MAX_KEYPAIR_ATTEMPTS,
            nonces_per_keypair: POW_MAX_NONCE,
            difficulty,
        })
    }

    pub fn from_secret_key_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn identity(&self) -> Identity {
        Identity::from_bytes(self.public_key_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key
            .verifying_key()
            .verify(message, signature)
            .is_ok()
    }

    /// Create a signed endpoint record WITHOUT PoW proof.
    ///
    /// **WARNING**: Contacts created this way will be rejected by DHT nodes
    /// enforcing PoW. Use [`create_contact_with_pow`] for production.
    pub fn create_contact(&self, addrs: Vec<String>) -> Contact {
        self.create_contact_with_pow(addrs, IdentityProof::empty())
    }

    /// Create a signed endpoint record WITH PoW proof (S/Kademlia compliant).
    ///
    /// The `pow_proof` should be obtained from [`generate_with_pow`] and stored
    /// persistently alongside the keypair.
    pub fn create_contact_with_pow(&self, addrs: Vec<String>, pow_proof: IdentityProof) -> Contact {
        let identity = self.identity();
        let timestamp = now_ms();

        // Build the payload to sign (without domain prefix - that's added by sign_with_domain)
        let payload = Contact::build_signed_payload(&identity, &addrs, timestamp);

        // Sign with domain separation
        let signature = crate::crypto::sign_with_domain(self, CONTACT_SIGNATURE_DOMAIN, &payload);

        Contact {
            identity,
            addrs,
            timestamp,
            signature,
            pow_proof,
        }
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("identity", &hex::encode(self.identity().as_bytes()))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Identity([u8; 32]);

impl Identity {
    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let identity = Self(bytes);

        debug_assert_eq!(
            identity.0, bytes,
            "P1 violation: Identity must preserve bytes exactly"
        );

        identity
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn xor_distance(&self, other: &Identity) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = self.0[i] ^ other.0[i];
        }
        out
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Check if this identity is valid.
    ///
    /// Validates that the identity:
    /// 1. Is not all zeros or all 0xFF (trivially invalid)
    /// 2. Represents a valid Ed25519 public key point
    ///
    /// This ensures the identity can be used for cryptographic operations
    /// such as signature verification.
    #[inline]
    pub fn is_valid(&self) -> bool {
        // Fast-path rejection for trivially invalid identities
        if self.0.iter().all(|&b| b == 0) {
            return false;
        }
        if self.0.iter().all(|&b| b == 0xFF) {
            return false;
        }
        // Validate it's a valid Ed25519 public key point
        VerifyingKey::try_from(self.0.as_slice()).is_ok()
    }

    /// Verify that a Proof-of-Work is valid for this identity.
    ///
    /// Validates that `BLAKE3(POW_HASH_DOMAIN || [namespace_hash] || identity || nonce)`
    /// has at least `POW_DIFFICULTY` leading zero bits.
    ///
    /// The namespace_hash from the proof is included in the hash, ensuring
    /// that proofs cannot be reused across namespaces.
    ///
    /// This is O(1) verification of the work done during identity generation.
    #[inline]
    pub fn verify_pow(&self, proof: &IdentityProof) -> bool {
        verify_pow_hash_with_namespace(&self.0, proof.nonce, &proof.namespace_hash, POW_DIFFICULTY)
    }

    /// Verify PoW with custom difficulty (for testing or migration).
    #[inline]
    pub fn verify_pow_with_difficulty(&self, proof: &IdentityProof, difficulty: u32) -> bool {
        verify_pow_hash_with_namespace(&self.0, proof.nonce, &proof.namespace_hash, difficulty)
    }
}

// ============================================================================
// Proof-of-Work Infrastructure (S/Kademlia)
// ============================================================================

/// Proof-of-Work for identity generation with optional namespace binding.
///
/// Contains the nonce that, when hashed with the public key and namespace,
/// produces a hash with sufficient leading zeros. This proof must be included
/// in Contact records for DHT routing table acceptance.
///
/// ## Namespace Trust Model
///
/// The `namespace_hash` field cryptographically binds an identity to a namespace:
/// - **Global namespace** (`namespace_hash = [0; 8]`): Legacy/default behavior
/// - **Named namespace**: Hash of the namespace string (e.g., "acme-corp")
///
/// Identities in different namespaces can still:
/// - Discover each other via DHT (global routing)
/// - Relay traffic for each other
///
/// But they CANNOT:
/// - Establish direct mTLS connections (namespace mismatch rejection)
/// - Exchange GossipSub messages on scoped topics
///
/// ## Verification
/// ```ignore
/// let (keypair, proof) = Keypair::generate_with_pow_for_namespace("acme-corp")?;
/// assert!(keypair.identity().verify_pow(&proof));
/// assert!(proof.matches_namespace("acme-corp"));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IdentityProof {
    /// Nonce that produces a valid PoW hash with the identity.
    pub nonce: u64,
    /// Truncated BLAKE3 hash of the namespace secret.
    /// All zeros = global namespace (backwards compatible).
    ///
    /// SECURITY: This field is NEVER serialized (skipped during serde).
    /// The namespace hash is bound to the PoW but not transmitted in Contact records.
    /// Peers prove namespace membership via challenge-response at runtime.
    ///
    /// This prevents attackers from copying the namespace_hash from DHT Contact
    /// records and forging identities in the same namespace.
    #[serde(skip, default)]
    pub namespace_hash: [u8; NAMESPACE_HASH_LEN],
}

impl IdentityProof {
    /// Create a new proof with the given nonce (global namespace).
    pub fn new(nonce: u64) -> Self {
        Self {
            nonce,
            namespace_hash: EMPTY_NAMESPACE_HASH,
        }
    }

    /// Create a new proof with nonce and namespace.
    pub fn with_namespace(nonce: u64, namespace_hash: [u8; NAMESPACE_HASH_LEN]) -> Self {
        Self {
            nonce,
            namespace_hash,
        }
    }

    /// Create an empty/invalid proof (for unsigned contacts).
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            namespace_hash: EMPTY_NAMESPACE_HASH,
        }
    }

    /// Derive namespace hash from a string identifier.
    ///
    /// The namespace is hashed using BLAKE3 and truncated to `NAMESPACE_HASH_LEN` bytes.
    /// Empty string maps to all-zeros (global namespace).
    ///
    /// # Examples
    /// ```ignore
    /// let hash = IdentityProof::namespace_hash_from_string("acme-corp");
    /// let global = IdentityProof::namespace_hash_from_string("");
    /// assert_eq!(global, [0u8; 8]);
    /// ```
    #[inline]
    pub fn namespace_hash_from_string(namespace: &str) -> [u8; NAMESPACE_HASH_LEN] {
        if namespace.is_empty() {
            return EMPTY_NAMESPACE_HASH;
        }
        let hash = blake3::hash(namespace.as_bytes());
        let mut result = [0u8; NAMESPACE_HASH_LEN];
        result.copy_from_slice(&hash.as_bytes()[..NAMESPACE_HASH_LEN]);
        result
    }

    /// Derive namespace hash from raw bytes (e.g., a BLAKE3 hash or random secret).
    ///
    /// Use this when you want a namespace that **cannot be brute-forced**.
    /// The input bytes are hashed and truncated to `NAMESPACE_HASH_LEN` bytes.
    ///
    /// # Security
    ///
    /// Unlike string-based namespaces, bytes-based namespaces cannot be guessed:
    /// - Use a 32-byte BLAKE3 hash of a secret
    /// - Use a 32-byte random value
    /// - Share the secret out-of-band with authorized peers
    ///
    /// # Examples
    /// ```ignore
    /// // Generate a random namespace secret
    /// let mut secret = [0u8; 32];
    /// getrandom::getrandom(&mut secret).unwrap();
    ///
    /// // Derive namespace hash from secret
    /// let ns_hash = IdentityProof::namespace_hash_from_bytes(&secret);
    ///
    /// // Or use a BLAKE3 hash directly
    /// let hash = blake3::hash(b"my-secret-seed");
    /// let ns_hash = IdentityProof::namespace_hash_from_bytes(hash.as_bytes());
    /// ```
    #[inline]
    pub fn namespace_hash_from_bytes(bytes: &[u8]) -> [u8; NAMESPACE_HASH_LEN] {
        if bytes.is_empty() {
            return EMPTY_NAMESPACE_HASH;
        }
        // Hash the input to ensure uniform distribution and handle any length
        let hash = blake3::hash(bytes);
        let mut result = [0u8; NAMESPACE_HASH_LEN];
        result.copy_from_slice(&hash.as_bytes()[..NAMESPACE_HASH_LEN]);
        result
    }

    /// Use a pre-computed namespace hash directly.
    ///
    /// Use this when you already have an 8-byte namespace hash and don't need
    /// to derive it from a string or bytes.
    ///
    /// # Examples
    /// ```ignore
    /// let ns_hash = [0x4a, 0x7b, 0x2c, 0x91, 0x3f, 0xe8, 0x0d, 0x55];
    /// let proof = IdentityProof::with_namespace(nonce, ns_hash);
    /// ```
    #[inline]
    pub fn namespace_hash_raw(hash: [u8; NAMESPACE_HASH_LEN]) -> [u8; NAMESPACE_HASH_LEN] {
        hash
    }

    /// Check if this proof is for the same namespace as another.
    ///
    /// Two proofs are in the same namespace if their `namespace_hash` fields match.
    /// This is the primary check used during mTLS connection establishment.
    #[inline]
    pub fn same_namespace(&self, other: &IdentityProof) -> bool {
        self.namespace_hash == other.namespace_hash
    }

    /// Check if this proof matches a given namespace string.
    ///
    /// Computes `BLAKE3(namespace)[0..8]` and compares to `self.namespace_hash`.
    #[inline]
    pub fn matches_namespace(&self, namespace: &str) -> bool {
        self.namespace_hash == Self::namespace_hash_from_string(namespace)
    }

    /// Check if this proof matches a namespace derived from raw bytes.
    ///
    /// Use this when your namespace is a secret byte array rather than a string.
    #[inline]
    pub fn matches_namespace_bytes(&self, bytes: &[u8]) -> bool {
        self.namespace_hash == Self::namespace_hash_from_bytes(bytes)
    }

    /// Check if this proof matches a pre-computed namespace hash directly.
    #[inline]
    pub fn matches_namespace_hash(&self, hash: &[u8; NAMESPACE_HASH_LEN]) -> bool {
        self.namespace_hash == *hash
    }

    /// Check if this is the global (legacy) namespace.
    #[inline]
    pub fn is_global_namespace(&self) -> bool {
        self.namespace_hash == EMPTY_NAMESPACE_HASH
    }

    /// Compute a PoW proof for an existing identity in the global namespace.
    ///
    /// This finds a nonce where `BLAKE3(domain || public_key || nonce)` has
    /// the specified number of leading zero bits.
    ///
    /// # Use Cases
    /// - Computing PoW for an imported keypair
    /// - Test helpers that need valid PoW for deterministic identities
    ///
    /// # Panics
    /// Panics if no valid nonce is found within `POW_MAX_NONCE` attempts.
    pub fn compute_for_identity(identity: &Identity, difficulty: u32) -> Self {
        Self::compute_for_identity_in_namespace(identity, difficulty, "")
    }

    /// Compute a PoW proof for an existing identity in a specific namespace.
    ///
    /// # Panics
    /// Panics if no valid nonce is found within `POW_MAX_NONCE` attempts.
    pub fn compute_for_identity_in_namespace(
        identity: &Identity,
        difficulty: u32,
        namespace: &str,
    ) -> Self {
        let public_key = identity.as_bytes();
        let namespace_hash = Self::namespace_hash_from_string(namespace);
        for nonce in 0..POW_MAX_NONCE {
            if verify_pow_hash_with_namespace(public_key, nonce, &namespace_hash, difficulty) {
                return Self {
                    nonce,
                    namespace_hash,
                };
            }
        }
        panic!(
            "PoW computation failed: no valid nonce found within {POW_MAX_NONCE} attempts"
        );
    }
}

/// Verify PoW hash with namespace support.
///
/// Backwards compatible: empty namespace_hash produces the same hash as legacy.
///
/// Hash format: BLAKE3(domain || [namespace_hash if non-empty] || public_key || nonce)
#[inline]
fn verify_pow_hash_with_namespace(
    public_key: &[u8; 32],
    nonce: u64,
    namespace_hash: &[u8; NAMESPACE_HASH_LEN],
    difficulty: u32,
) -> bool {
    let hash = compute_pow_hash_with_namespace(public_key, nonce, namespace_hash);
    count_leading_zeros(&hash) >= difficulty
}

/// Compute PoW hash with namespace support.
///
/// For backwards compatibility with legacy identities:
/// - If namespace_hash is all zeros (empty), it's NOT included in the hash
/// - If namespace_hash is non-zero, it IS included in the hash
///
/// This ensures old identities (generated before namespace support) still verify.
#[inline]
fn compute_pow_hash_with_namespace(
    public_key: &[u8; 32],
    nonce: u64,
    namespace_hash: &[u8; NAMESPACE_HASH_LEN],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POW_HASH_DOMAIN);
    // SECURITY: Only include namespace if non-empty for backwards compatibility.
    // Old identities with empty namespace_hash will verify with the legacy hash format.
    if *namespace_hash != EMPTY_NAMESPACE_HASH {
        hasher.update(namespace_hash);
    }
    hasher.update(public_key);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Legacy verify_pow_hash for global namespace (backwards compatibility).
#[inline]
#[allow(dead_code)]
fn verify_pow_hash(public_key: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    verify_pow_hash_with_namespace(public_key, nonce, &EMPTY_NAMESPACE_HASH, difficulty)
}

/// Legacy compute_pow_hash for global namespace.
#[inline]
#[allow(dead_code)]
fn compute_pow_hash(public_key: &[u8; 32], nonce: u64) -> [u8; 32] {
    compute_pow_hash_with_namespace(public_key, nonce, &EMPTY_NAMESPACE_HASH)
}

/// Count leading zero bits in a hash.
#[inline]
fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0u32;
    for byte in hash {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

/// Compare two XOR distances lexicographically.
///
/// Used to determine which of two identities is closer to a target
/// in the Kademlia XOR metric space.
///
/// # Example
/// ```ignore
/// let dist_a = target.xor_distance(&a);
/// let dist_b = target.xor_distance(&b);
/// if distance_cmp(&dist_a, &dist_b) == Ordering::Less {
///     // a is closer to target than b
/// }
/// ```
#[inline]
pub fn distance_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return std::cmp::Ordering::Less;
        } else if a[i] > b[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
}

// ============================================================================
// Namespace Isolation (Challenge-Response Protocol)
// ============================================================================

/// Length of namespace challenge nonce.
pub const NAMESPACE_CHALLENGE_LEN: usize = 32;

/// Length of namespace challenge response.
pub const NAMESPACE_RESPONSE_LEN: usize = 32;

/// Domain separation prefix for namespace challenge-response.
const NAMESPACE_CHALLENGE_DOMAIN: &[u8] = b"korium-ns-challenge-v1:";

/// Domain separation prefix for session secret derivation.
const NAMESPACE_SESSION_DOMAIN: &[u8] = b"korium-ns-session-v1:";

/// Domain separation prefix for encryption key derivation.
const NAMESPACE_ENCRYPTION_DOMAIN: &[u8] = b"korium-ns-encrypt-v1:";

/// Default epoch duration for session secret rotation (24 hours).
pub const DEFAULT_EPOCH_DURATION_SECS: u64 = 86400;

/// Default number of grace epochs (1 = accept current + 1 previous).
pub const DEFAULT_GRACE_EPOCHS: u64 = 1;

/// Namespace configuration for challenge-response authentication.
///
/// The namespace provides cryptographic isolation between groups of nodes:
/// - Nodes with the same namespace secret can authenticate each other
/// - Nodes with different namespaces can still relay/route but cannot authenticate
/// - The namespace secret is NEVER transmitted over the wire
///
/// # Two-Layer Design
///
/// 1. **Master Secret (permanent)**: Used to bind PoW and derive session secrets
/// 2. **Session Secret (rotating)**: Derived from master secret + epoch, used for challenges
///
/// This provides:
/// - Stable identity (PoW never invalidated by rotation)
/// - Limited blast radius (compromised session → one epoch only)
/// - Forward secrecy (old sessions can't derive future secrets)
///
/// # Example
///
/// ```ignore
/// // Create with a 32-byte secret
/// let secret: [u8; 32] = rand::random();
/// let config = NamespaceConfig::new(secret);
///
/// // Or from a passphrase (less secure, guessable)
/// let config = NamespaceConfig::from_passphrase("my-secret-namespace");
///
/// // Use with NodeBuilder
/// Node::builder("0.0.0.0:0")
///     .namespace_config(config)
///     .build()
///     .await?;
/// ```
#[derive(Clone)]
pub struct NamespaceConfig {
    /// Master secret (32 bytes). NEVER transmitted.
    master_secret: [u8; 32],
    /// Duration of each epoch in seconds.
    epoch_duration_secs: u64,
    /// Number of previous epochs to accept (for clock skew tolerance).
    grace_epochs: u64,
}

impl NamespaceConfig {
    /// Create a new namespace config with a 32-byte master secret.
    ///
    /// # Security
    ///
    /// The master secret should be:
    /// - At least 32 bytes of cryptographically random data
    /// - Shared securely with all nodes in the namespace
    /// - Never transmitted over the network
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut secret = [0u8; 32];
    /// getrandom::getrandom(&mut secret).unwrap();
    /// let config = NamespaceConfig::new(secret);
    /// ```
    pub fn new(master_secret: [u8; 32]) -> Self {
        Self {
            master_secret,
            epoch_duration_secs: DEFAULT_EPOCH_DURATION_SECS,
            grace_epochs: DEFAULT_GRACE_EPOCHS,
        }
    }

    /// Create a namespace config from a passphrase.
    ///
    /// # Security Warning
    ///
    /// Passphrases are vulnerable to dictionary attacks. An attacker who
    /// can observe your namespace hash could attempt to guess the passphrase.
    ///
    /// For maximum security, use `new()` with random bytes instead.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let hash = blake3::hash(passphrase.as_bytes());
        Self::new(*hash.as_bytes())
    }

    /// Set the epoch duration for session secret rotation.
    ///
    /// Shorter durations provide better forward secrecy at the cost of
    /// requiring tighter clock synchronization between nodes.
    pub fn with_epoch_duration(mut self, duration: std::time::Duration) -> Self {
        self.epoch_duration_secs = duration.as_secs().max(1);
        self
    }

    /// Set the number of grace epochs to accept.
    ///
    /// This allows for clock skew between nodes. A value of 1 means
    /// the current epoch and the previous epoch are both accepted.
    pub fn with_grace_epochs(mut self, epochs: u64) -> Self {
        self.grace_epochs = epochs;
        self
    }

    /// Get the namespace hash (for PoW binding).
    ///
    /// This is derived from the master secret and is stable across epochs.
    #[inline]
    pub fn namespace_hash(&self) -> [u8; NAMESPACE_HASH_LEN] {
        IdentityProof::namespace_hash_from_bytes(&self.master_secret)
    }

    /// Get the current epoch number.
    #[inline]
    pub fn current_epoch(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now / self.epoch_duration_secs
    }

    /// Derive session secret for a specific epoch.
    ///
    /// Session secrets are used for challenge-response authentication.
    /// They rotate each epoch, limiting the blast radius of compromise.
    #[inline]
    pub fn session_secret(&self, epoch: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(NAMESPACE_SESSION_DOMAIN);
        hasher.update(&self.master_secret);
        hasher.update(&epoch.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Get the current session secret.
    #[inline]
    pub fn current_session_secret(&self) -> [u8; 32] {
        self.session_secret(self.current_epoch())
    }

    /// Compute challenge response for proving namespace membership.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Random challenge nonce from the verifier
    /// * `our_pubkey` - Our public key (32 bytes)
    /// * `peer_pubkey` - Peer's public key (32 bytes)
    ///
    /// The response binds the session secret, nonce, and both identities.
    pub fn compute_response(
        &self,
        nonce: &[u8; NAMESPACE_CHALLENGE_LEN],
        our_pubkey: &[u8; 32],
        peer_pubkey: &[u8; 32],
    ) -> [u8; NAMESPACE_RESPONSE_LEN] {
        self.compute_response_for_epoch(nonce, our_pubkey, peer_pubkey, self.current_epoch())
    }

    /// Compute challenge response for a specific epoch.
    fn compute_response_for_epoch(
        &self,
        nonce: &[u8; NAMESPACE_CHALLENGE_LEN],
        our_pubkey: &[u8; 32],
        peer_pubkey: &[u8; 32],
        epoch: u64,
    ) -> [u8; NAMESPACE_RESPONSE_LEN] {
        let session = self.session_secret(epoch);
        let mut hasher = blake3::Hasher::new();
        hasher.update(NAMESPACE_CHALLENGE_DOMAIN);
        hasher.update(&session);
        hasher.update(nonce);
        hasher.update(our_pubkey);
        hasher.update(peer_pubkey);
        *hasher.finalize().as_bytes()
    }

    /// Verify a challenge response from a peer.
    ///
    /// Checks the response against the current epoch and grace epochs.
    /// Returns true if the response is valid for any accepted epoch.
    pub fn verify_response(
        &self,
        nonce: &[u8; NAMESPACE_CHALLENGE_LEN],
        peer_pubkey: &[u8; 32],
        our_pubkey: &[u8; 32],
        response: &[u8; NAMESPACE_RESPONSE_LEN],
    ) -> bool {
        let current = self.current_epoch();

        // Check current epoch and grace epochs
        for offset in 0..=self.grace_epochs {
            if offset > current {
                break; // Don't underflow
            }
            let epoch = current - offset;
            let expected = self.compute_response_for_epoch(nonce, peer_pubkey, our_pubkey, epoch);
            if constant_time_eq(&expected, response) {
                return true;
            }
        }

        false
    }

    /// Check if this config represents the global (no isolation) namespace.
    #[inline]
    pub fn is_global(&self) -> bool {
        self.master_secret == [0u8; 32]
    }

    /// Derive an encryption key for the current epoch.
    ///
    /// This key is used for ChaCha20-Poly1305 authenticated encryption
    /// of GossipSub and Plain payloads.
    #[inline]
    pub fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key_for_epoch(self.current_epoch())
    }

    /// Derive an encryption key for a specific epoch.
    fn encryption_key_for_epoch(&self, epoch: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(NAMESPACE_ENCRYPTION_DOMAIN);
        hasher.update(&self.master_secret);
        hasher.update(&epoch.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Encrypt a payload using the namespace session key.
    ///
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    ///
    /// Uses ChaCha20-Poly1305 authenticated encryption with a random nonce.
    /// The ciphertext is bound to the current epoch - decryption will fail
    /// with a different epoch's key.
    ///
    /// # Errors
    /// Returns error if encryption fails (should never happen with valid input).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, NamespaceEncryptionError> {
        if self.is_global() {
            // Global namespace: no encryption, return plaintext as-is
            return Ok(plaintext.to_vec());
        }

        let key = self.encryption_key();
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| NamespaceEncryptionError::EncryptionFailed)?;

        // Format: nonce || ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a payload using the namespace session key.
    ///
    /// Expects format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    ///
    /// Tries current epoch first, then grace epochs for clock skew tolerance.
    ///
    /// # Errors
    /// Returns error if:
    /// - Ciphertext is too short (< 28 bytes for nonce + min ciphertext + tag)
    /// - Authentication fails (wrong key, tampered data, or wrong epoch)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NamespaceEncryptionError> {
        if self.is_global() {
            // Global namespace: no encryption, return as-is
            return Ok(ciphertext.to_vec());
        }

        // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
        if ciphertext.len() < 28 {
            return Err(NamespaceEncryptionError::CiphertextTooShort);
        }

        let nonce_bytes = &ciphertext[..12];
        let encrypted = &ciphertext[12..];
        let nonce = GenericArray::from_slice(nonce_bytes);

        let current = self.current_epoch();

        // Try current epoch and grace epochs
        for offset in 0..=self.grace_epochs {
            if offset > current {
                break;
            }
            let epoch = current - offset;
            let key = self.encryption_key_for_epoch(epoch);
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));

            if let Ok(plaintext) = cipher.decrypt(nonce, encrypted) {
                return Ok(plaintext);
            }
        }

        Err(NamespaceEncryptionError::DecryptionFailed)
    }
}

impl std::fmt::Debug for NamespaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak the master secret in debug output
        f.debug_struct("NamespaceConfig")
            .field("namespace_hash", &hex::encode(self.namespace_hash()))
            .field("epoch_duration_secs", &self.epoch_duration_secs)
            .field("grace_epochs", &self.grace_epochs)
            .finish()
    }
}

/// Global namespace config (no isolation).
///
/// Nodes with this config accept any peer, regardless of namespace.
impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            master_secret: [0u8; 32],
            epoch_duration_secs: DEFAULT_EPOCH_DURATION_SECS,
            grace_epochs: DEFAULT_GRACE_EPOCHS,
        }
    }
}

/// Constant-time comparison to prevent timing attacks.
#[inline]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Generate a random challenge nonce.
///
/// # Panics
///
/// Panics if the system random number generator fails.
pub fn generate_challenge_nonce() -> [u8; NAMESPACE_CHALLENGE_LEN] {
    let mut nonce = [0u8; NAMESPACE_CHALLENGE_LEN];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    nonce
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Identity {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Identity> for [u8; 32] {
    fn from(identity: Identity) -> Self {
        identity.0
    }
}

impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub identity: Identity,
    pub addrs: Vec<String>,
    /// Timestamp when record was created (0 = unsigned/ephemeral).
    pub timestamp: u64,
    /// Ed25519 signature (empty = unsigned/ephemeral).
    pub signature: Vec<u8>,
    /// Proof-of-Work for Sybil resistance (S/Kademlia).
    /// Default is 0 for backwards compatibility; nodes enforcing PoW will reject contacts
    /// where `identity.verify_pow(&proof)` fails.
    #[serde(default)]
    pub pow_proof: IdentityProof,
}

/// Reasons a Contact record may fail freshness verification.
///
/// This structured error enables differentiated logging and metrics:
/// - Signature failures indicate tampering or corruption
/// - Clock skew failures may indicate infrastructure issues
/// - Stale records are normal expiry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessError {
    /// Cryptographic signature verification failed.
    SignatureInvalid,
    /// Record timestamp is too far in the future (clock skew detected).
    /// Contains: (record_timestamp_ms, local_time_ms, drift_ms)
    ClockSkewFuture {
        record_ts: u64,
        local_ts: u64,
        drift_ms: u64,
    },
    /// Record has expired (older than max_age).
    /// Contains: (record_timestamp_ms, local_time_ms, age_ms)
    Stale {
        record_ts: u64,
        local_ts: u64,
        age_ms: u64,
    },
}

impl Contact {
    /// Create an unsigned endpoint record (lightweight peer reference).
    /// Unsigned records have timestamp=0, empty signature, and no PoW proof.
    pub fn unsigned(identity: Identity, addrs: Vec<String>) -> Self {
        Self {
            identity,
            addrs,
            timestamp: 0,
            signature: vec![],
            pow_proof: IdentityProof::empty(),
        }
    }

    /// Create an unsigned endpoint record with a single address.
    pub fn single(identity: Identity, addr: impl Into<String>) -> Self {
        Self::unsigned(identity, vec![addr.into()])
    }

    /// Get the primary address (first in the list).
    pub fn primary_addr(&self) -> Option<&str> {
        self.addrs.first().map(std::string::String::as_str)
    }

    /// Get the network provenance of this contact's primary address.
    ///
    /// Returns the coarse network origin identifier used for:
    /// - P6 IP colocation scoring (Sybil resistance)
    /// - RTT-based latency tiering
    /// - Per-prefix rate limiting
    ///
    /// Returns `None` if no primary address or address cannot be parsed.
    #[inline]
    pub(crate) fn provenance(&self) -> Option<Provenance> {
        self.primary_addr().and_then(Provenance::from_addr_str)
    }

    /// Verify the cryptographic signature of this Contact record.
    ///
    /// This verifies that:
    /// 1. The record has both timestamp and signature
    /// 2. The signature was created by the identity's private key
    /// 3. The signature covers: domain_prefix + identity + addresses + timestamp
    ///
    /// SECURITY: Signature verification ensures addresses are bound to the identity.
    /// An attacker cannot forge a Contact pointing to their own address.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(SignatureError)` otherwise.
    pub fn verify(&self) -> Result<(), SignatureError> {
        // Unsigned records (empty signature or zero timestamp) cannot be verified
        if self.signature.is_empty() {
            return Err(SignatureError::Missing);
        }
        if self.timestamp == 0 {
            return Err(SignatureError::Missing);
        }

        // Reconstruct the signed payload
        let payload = Self::build_signed_payload(&self.identity, &self.addrs, self.timestamp);

        // Verify with domain separation
        crate::crypto::verify_with_domain(
            &self.identity,
            CONTACT_SIGNATURE_DOMAIN,
            &payload,
            &self.signature,
        )
    }

    /// Build the canonical payload for Contact signatures.
    ///
    /// This is the data that gets signed (domain prefix is added by crypto layer).
    /// Format: identity(32) || addr_count(4) || [addr_len(4) || addr]* || timestamp(8)
    #[doc(hidden)]
    pub fn build_signed_payload(identity: &Identity, addrs: &[String], timestamp: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&timestamp.to_le_bytes());
        data
    }

    /// Verify the signature AND freshness of this Contact record.
    ///
    /// SECURITY: This is the recommended verification method for DHT records.
    /// It prevents replay attacks by rejecting records older than max_age_secs.
    ///
    /// Rejects records that are:
    /// - Not cryptographically valid (via verify())
    /// - Older than max_age_secs (stale)
    /// - More than FUTURE_TOLERANCE_MS in the future (clock skew tolerance)
    ///
    /// ## Clock Synchronization Requirements
    ///
    /// This function assumes nodes have reasonably synchronized clocks (within 5s).
    /// Nodes with severely drifted clocks may reject valid Contact records or
    /// accept stale ones. Operators SHOULD ensure NTP synchronization is active.
    ///
    /// ## Security Properties
    ///
    /// - **Pre-dating Attack Resistance**: Future tolerance is kept tight (5s) to
    ///   minimize the window where an attacker with clock control can create records
    ///   that remain valid longer than intended. The effective maximum age of any
    ///   record is `max_age_secs + FUTURE_TOLERANCE_MS/1000` (i.e., max_age + 5s).
    ///
    /// - **Replay Attack Resistance**: Stale records are rejected based on the
    ///   timestamp embedded in the signed payload, preventing replay of old addresses.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the record is valid and fresh
    /// - `Err(FreshnessError)` with structured reason for rejection
    pub fn verify_fresh(&self, max_age_secs: u64) -> Result<(), FreshnessError> {
        if self.verify().is_err() {
            return Err(FreshnessError::SignatureInvalid);
        }

        // timestamp is already validated as non-zero by verify()
        let current_time = now_ms();

        let max_age_ms = max_age_secs * 1000;

        // SECURITY: Future tolerance is intentionally tight (5s) to limit pre-dating attacks.
        // An attacker who can manipulate their clock could create Contact records with
        // future timestamps that remain "fresh" for max_age + tolerance. By keeping this
        // window small, we bound the attack surface while accommodating minor NTP drift.
        //
        // Trade-off: Nodes with >5s clock drift will have their Contact records rejected.
        // This is acceptable as such severe drift indicates misconfiguration and NTP-synced
        // systems typically maintain sub-second accuracy.
        const FUTURE_TOLERANCE_MS: u64 = 5_000;
        if self.timestamp > current_time.saturating_add(FUTURE_TOLERANCE_MS) {
            let drift = self.timestamp.saturating_sub(current_time);
            return Err(FreshnessError::ClockSkewFuture {
                record_ts: self.timestamp,
                local_ts: current_time,
                drift_ms: drift,
            });
        }

        // Reject stale records to prevent replay of old addresses.
        // Note: A record timestamped at current_time + FUTURE_TOLERANCE_MS will be
        // considered valid for up to max_age_secs + 5s from now. This is the maximum
        // effective lifetime and is documented as a security property above.
        let age_ms = current_time.saturating_sub(self.timestamp);
        if age_ms > max_age_ms {
            return Err(FreshnessError::Stale {
                record_ts: self.timestamp,
                local_ts: current_time,
                age_ms,
            });
        }

        Ok(())
    }

    pub fn has_direct_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    /// Verify the Proof-of-Work for this Contact's identity.
    ///
    /// SECURITY: This is required for DHT routing table acceptance.
    /// Contacts without valid PoW should be rejected to prevent Sybil attacks.
    ///
    /// # Returns
    /// `true` if the PoW proof is valid for the identity.
    #[inline]
    pub fn verify_pow(&self) -> bool {
        self.identity.verify_pow(&self.pow_proof)
    }

    /// Verify PoW with custom difficulty.
    #[inline]
    pub fn verify_pow_with_difficulty(&self, difficulty: u32) -> bool {
        self.identity
            .verify_pow_with_difficulty(&self.pow_proof, difficulty)
    }

    /// Validate the structural integrity of a Contact record.
    ///
    /// SECURITY: This validates bounds and format, NOT cryptographic signatures or PoW.
    /// Always call `verify()` or `verify_fresh()` for untrusted data.
    /// For DHT routing, also call `verify_pow()`.
    ///
    /// Checks:
    /// - Address count ≤ MAX_ADDRS (16)
    /// - Each address ≤ MAX_ADDR_LEN (256) and non-empty
    /// - Signature length is exactly 64 bytes if non-empty (signed)
    pub fn validate_structure(&self) -> bool {
        // SECURITY: These limits prevent memory exhaustion attacks when
        // deserializing untrusted Contact records from the network.
        const MAX_ADDRS: usize = 16;
        const MAX_ADDR_LEN: usize = 256;

        if self.addrs.len() > MAX_ADDRS {
            return false;
        }

        for addr in &self.addrs {
            if addr.len() > MAX_ADDR_LEN || addr.is_empty() {
                return false;
            }
        }

        // If signed (non-empty signature), must be exactly 64 bytes
        if !self.signature.is_empty() && self.signature.len() != 64 {
            return false;
        }

        true
    }
}

impl PartialEq for Contact {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for Contact {}

impl std::hash::Hash for Contact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();

        assert_ne!(kp1.identity(), kp2.identity());
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = Keypair::generate();
        let message = b"hello world";

        let signature = kp.sign(message);
        assert!(kp.verify(message, &signature));

        assert!(!kp.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_identity_xor_distance() {
        let a = Identity::from_bytes([0xFF; 32]);
        let b = Identity::from_bytes([0x00; 32]);
        let c = Identity::from_bytes([0xFF; 32]);

        assert_eq!(a.xor_distance(&a), [0u8; 32]);

        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));

        assert_eq!(a.xor_distance(&b), [0xFF; 32]);

        assert_eq!(a.xor_distance(&c), [0u8; 32]);
    }

    #[test]
    fn test_contact_verify_fresh_accepts_recent() {
        let kp = Keypair::generate();
        let record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);

        assert!(record.verify_fresh(3600).is_ok());
    }

    #[test]
    fn test_contact_verify_fresh_rejects_old() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - (2 * 60 * 60 * 1000);

        // Signature is now invalid (timestamp changed), so we get SignatureInvalid
        assert!(matches!(
            record.verify_fresh(3600),
            Err(FreshnessError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_contact_verify_fresh_rejects_future() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + (5 * 60 * 1000);

        // Signature is now invalid (timestamp changed), so we get SignatureInvalid
        assert!(matches!(
            record.verify_fresh(3600),
            Err(FreshnessError::SignatureInvalid)
        ));
    }

    #[test]
    fn test_contact_verify_fresh_future_tolerance_boundary() {
        // SECURITY: Verify that the 5-second future tolerance is correctly enforced.
        // Records just within tolerance should pass, records just outside should fail.
        let kp = Keypair::generate();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // 3 seconds in the future: should be accepted (within 5s tolerance)
        let mut record_within = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        record_within.timestamp = now_ms + 3_000;
        // Re-sign with the new timestamp
        let payload = Contact::build_signed_payload(
            &kp.identity(),
            &record_within.addrs,
            record_within.timestamp,
        );
        record_within.signature =
            crate::crypto::sign_with_domain(&kp, crate::crypto::CONTACT_SIGNATURE_DOMAIN, &payload);
        assert!(
            record_within.verify_fresh(3600).is_ok(),
            "record 3s in future should be accepted"
        );

        // 7 seconds in the future: should be rejected (outside 5s tolerance)
        let mut record_outside = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        record_outside.timestamp = now_ms + 7_000;
        // Re-sign with the new timestamp
        let payload = Contact::build_signed_payload(
            &kp.identity(),
            &record_outside.addrs,
            record_outside.timestamp,
        );
        record_outside.signature =
            crate::crypto::sign_with_domain(&kp, crate::crypto::CONTACT_SIGNATURE_DOMAIN, &payload);
        assert!(
            matches!(
                record_outside.verify_fresh(3600),
                Err(FreshnessError::ClockSkewFuture { .. })
            ),
            "record 7s in future should be rejected with ClockSkewFuture"
        );
    }

    #[test]
    fn test_contact_validate_structure_valid() {
        let kp = Keypair::generate();
        let record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);

        assert!(record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_too_many_addrs() {
        let kp = Keypair::generate();
        let addrs: Vec<String> = (0..20).map(|i| format!("192.168.1.{}:8080", i)).collect();
        let record = kp.create_contact(addrs);

        assert!(!record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_empty_addr() {
        let kp = Keypair::generate();
        let record = kp.create_contact(vec!["".to_string()]);

        assert!(!record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_addr_too_long() {
        let kp = Keypair::generate();
        let long_addr = "x".repeat(300);
        let record = kp.create_contact(vec![long_addr]);

        assert!(!record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_bad_signature_length() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.signature = vec![0u8; 32];
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_p1_identity_equals_public_key() {
        for _ in 0..100 {
            let kp = Keypair::generate();
            let public_key = kp.public_key_bytes();
            let identity = kp.identity();

            assert_eq!(
                *identity.as_bytes(),
                public_key,
                "P1 violation: Identity must equal PublicKey exactly"
            );

            let recovered = Identity::from_bytes(*identity.as_bytes());
            assert_eq!(
                recovered, identity,
                "P1 violation: Identity roundtrip must be lossless"
            );
        }
    }

    #[test]
    fn test_p2_xor_distance_on_raw_bytes() {
        for _ in 0..100 {
            let a = Keypair::generate().identity();
            let b = Keypair::generate().identity();

            let mut expected = [0u8; 32];
            for (i, byte) in expected.iter_mut().enumerate() {
                *byte = a.as_bytes()[i] ^ b.as_bytes()[i];
            }

            assert_eq!(
                a.xor_distance(&b),
                expected,
                "P2 violation: XOR distance must operate on raw Identity bytes"
            );
        }
    }

    #[test]
    fn test_p2_xor_distance_properties() {
        let a = Keypair::generate().identity();
        let b = Keypair::generate().identity();

        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));

        assert_eq!(a.xor_distance(&a), [0u8; 32]);
    }

    #[test]
    fn test_p4_sybil_protection() {
        for _ in 0..100 {
            let kp1 = Keypair::generate();
            let kp2 = Keypair::generate();

            let identity_1 = kp1.identity();
            let public_key_1 = kp1.public_key_bytes();
            let public_key_2 = kp2.public_key_bytes();

            assert_eq!(
                *identity_1.as_bytes(),
                public_key_1,
                "P4 violation: valid Identity-PublicKey binding rejected"
            );

            assert_ne!(
                *identity_1.as_bytes(),
                public_key_2,
                "P4 violation: Sybil attack - wrong public key accepted for Identity"
            );
        }
    }

    #[test]
    fn test_identity_hex_roundtrip_formal() {
        for _ in 0..100 {
            let kp = Keypair::generate();
            let identity = kp.identity();

            let hex = identity.to_hex();
            let recovered = Identity::from_hex(&hex).expect("hex decode failed");

            assert_eq!(
                identity, recovered,
                "Hex roundtrip invariant violated: from_hex(to_hex(id)) != id"
            );

            assert_eq!(hex.len(), 64, "Hex encoding should be 64 characters");
            assert!(
                hex.chars().all(|c| c.is_ascii_hexdigit()),
                "Hex should be valid hex"
            );
        }
    }

    #[test]
    fn test_p5_contact_binding() {
        let kp = Keypair::generate();
        let addrs = vec!["192.168.1.1:8080".to_string()];
        let record = kp.create_contact(addrs);

        assert!(
            record.verify().is_ok(),
            "P5 violation: valid record rejected"
        );

        let mut tampered = record.clone();
        let mut tampered_bytes = *tampered.identity.as_bytes();
        tampered_bytes[0] ^= 1;
        tampered.identity = Identity::from_bytes(tampered_bytes);
        assert!(
            tampered.verify().is_err(),
            "P5 violation: identity tampering not detected"
        );

        let mut tampered = record.clone();
        tampered.addrs[0] = "10.0.0.1:9999".to_string();
        assert!(
            tampered.verify().is_err(),
            "P5 violation: address tampering not detected"
        );

        let mut tampered = record.clone();
        tampered.timestamp += 1;
        assert!(
            tampered.verify().is_err(),
            "P5 violation: timestamp tampering not detected"
        );

        let mut tampered = record.clone();
        tampered.signature[0] ^= 1;
        assert!(
            tampered.verify().is_err(),
            "P5 violation: signature tampering not detected"
        );
    }

    #[test]
    fn keypair_collision_resistance() {
        use std::collections::HashSet;
        let mut identities = HashSet::new();

        for _ in 0..1000 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            assert!(
                identities.insert(identity),
                "Identity collision detected - this should be astronomically unlikely"
            );
        }
    }

    #[test]
    fn identity_deterministic_derivation() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key_bytes();

        let identity_1 = keypair.identity();
        let identity_2 = keypair.identity();

        assert_eq!(identity_1, identity_2);
        assert_eq!(identity_1.as_bytes(), &public_key);
    }

    #[test]
    fn keypair_reconstruction_preserves_identity() {
        let original = Keypair::generate();
        let secret = original.secret_key_bytes();

        let reconstructed = Keypair::from_secret_key_bytes(&secret);

        assert_eq!(
            original.public_key_bytes(),
            reconstructed.public_key_bytes()
        );
        assert_eq!(original.identity(), reconstructed.identity());

        let message = b"test message";
        let sig1 = original.sign(message);
        let sig2 = reconstructed.sign(message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn identity_verification_security() {
        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let public_key = keypair.public_key_bytes();

        assert_eq!(*identity.as_bytes(), public_key);

        let other_keypair = Keypair::generate();
        assert_ne!(*identity.as_bytes(), other_keypair.public_key_bytes());

        let mut bad_bytes = *identity.as_bytes();
        bad_bytes[0] ^= 0xFF;
        let bad_identity = Identity::from_bytes(bad_bytes);
        assert_ne!(*bad_identity.as_bytes(), public_key);
    }

    #[test]
    fn signature_unforgeability() {
        let keypair = Keypair::generate();
        let message = b"important message";
        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));

        let modified_message = b"modified message";
        assert!(!keypair.verify(modified_message, &signature));

        let other_keypair = Keypair::generate();
        assert!(!other_keypair.verify(message, &signature));
    }

    #[test]
    fn identity_hex_rejects_invalid() {
        assert!(Identity::from_hex("abcd").is_err());
        let long_hex = "a".repeat(70);
        assert!(Identity::from_hex(&long_hex).is_err());
        assert!(Identity::from_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn valid_record_verifies() {
        let keypair = Keypair::generate();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let record = keypair.create_contact(addrs);

        assert!(record.verify().is_ok());
        assert!(record.verify_fresh(3600).is_ok());
    }

    #[test]
    fn record_with_multiple_addrs_verifies() {
        let keypair = Keypair::generate();

        let record = keypair.create_contact(vec![
            "192.168.1.1:8080".to_string(),
            "10.0.0.1:8080".to_string(),
        ]);

        assert!(record.verify().is_ok());
        assert!(record.has_direct_addrs());
    }

    #[test]
    fn tampered_addresses_fail_verification() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.addrs = vec!["attacker.com:8080".to_string()];

        assert!(record.verify().is_err());
    }

    #[test]
    fn wrong_signer_fails_verification() {
        let keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();

        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        let attacker_record = attacker_keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);
        record.signature = attacker_record.signature;

        assert!(record.verify().is_err());
    }

    #[test]
    fn replay_attack_prevention() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let old_timestamp = now_ms - (2 * 60 * 60 * 1000); // 2 hours ago

        // Build the payload and sign with domain separation
        let payload = Contact::build_signed_payload(&identity, &addrs, old_timestamp);
        let signature = crate::crypto::sign_with_domain(
            &keypair,
            crate::crypto::CONTACT_SIGNATURE_DOMAIN,
            &payload,
        );

        let old_record = Contact {
            identity,
            addrs,
            timestamp: old_timestamp,
            signature,
            pow_proof: IdentityProof::empty(),
        };

        // Signature should be valid (cryptographically correct)
        assert!(old_record.verify().is_ok());
        // But freshness check should fail (record is stale)
        assert!(matches!(
            old_record.verify_fresh(3600),
            Err(FreshnessError::Stale { .. })
        ));
    }

    #[test]
    fn future_dated_records_rejected() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let future_timestamp = now_ms + (2 * 60 * 60 * 1000); // 2 hours in future

        // Build the payload and sign with domain separation
        let payload = Contact::build_signed_payload(&identity, &addrs, future_timestamp);
        let signature = crate::crypto::sign_with_domain(
            &keypair,
            crate::crypto::CONTACT_SIGNATURE_DOMAIN,
            &payload,
        );

        let future_record = Contact {
            identity,
            addrs,
            timestamp: future_timestamp,
            signature,
            pow_proof: IdentityProof::empty(),
        };

        // Future-dated record should fail freshness check
        assert!(matches!(
            future_record.verify_fresh(3600),
            Err(FreshnessError::ClockSkewFuture { .. })
        ));
    }

    #[test]
    fn structure_validation_limits() {
        let keypair = Keypair::generate();

        let too_many_addrs: Vec<String> = (0..20).map(|i| format!("10.0.0.{}:8080", i)).collect();
        let record = keypair.create_contact(too_many_addrs);
        assert!(!record.validate_structure());

        let long_addr = "a".repeat(300);
        let record = keypair.create_contact(vec![long_addr]);
        assert!(!record.validate_structure());

        let record = keypair.create_contact(vec!["".to_string()]);
        assert!(!record.validate_structure());
    }

    #[test]
    fn invalid_signature_length_rejected() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.signature = record.signature[..32].to_vec();

        assert!(!record.validate_structure());
        assert!(record.verify().is_err());
    }

    #[test]
    fn address_concatenation_attack_prevented() {
        let keypair = Keypair::generate();

        let record1 = keypair.create_contact(vec!["192.168.1.1".to_string(), ":8080".to_string()]);

        let record2 = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        assert_ne!(record1.signature, record2.signature);

        assert!(record1.verify().is_ok());
        assert!(record2.verify().is_ok());
    }

    #[test]
    fn identity_must_match_public_key() {
        let keypair = Keypair::generate();
        let correct_identity = keypair.identity();
        let public_key = keypair.public_key_bytes();

        let attacker_claimed_id = Identity::from_bytes([0xFF; 32]);

        assert_ne!(*attacker_claimed_id.as_bytes(), public_key);
        assert_eq!(*correct_identity.as_bytes(), public_key);
    }

    #[test]
    fn signature_malleability_resistance() {
        let keypair = Keypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();

        let mut modified_sig = sig_bytes;
        modified_sig[0] ^= 0x01;

        let modified = ed25519_dalek::Signature::from_bytes(&modified_sig);

        assert_ne!(modified.to_bytes(), sig_bytes);
        assert!(!keypair.verify(message, &modified));
        assert!(keypair.verify(message, &signature));
    }

    #[test]
    fn cross_identity_replay_prevention() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let message = b"important transaction";
        let alice_signature = alice.sign(message);

        assert!(!bob.verify(message, &alice_signature));
        assert!(alice.verify(message, &alice_signature));
    }

    #[test]
    fn special_identity_edge_cases() {
        let all_zeros = Identity::from_bytes([0u8; 32]);
        let all_ones = Identity::from_bytes([0xFF; 32]);

        let keypair = Keypair::generate();

        assert_ne!(
            *all_zeros.as_bytes(),
            keypair.public_key_bytes(),
            "All-zeros Identity should not match any real keypair"
        );
        assert_ne!(
            *all_ones.as_bytes(),
            keypair.public_key_bytes(),
            "All-ones Identity should not match any real keypair"
        );
    }

    #[test]
    fn is_valid_rejects_invalid_ed25519_points() {
        // All zeros - trivially invalid
        let all_zeros = Identity::from_bytes([0u8; 32]);
        assert!(!all_zeros.is_valid());

        // All 0xFF - trivially invalid
        let all_ones = Identity::from_bytes([0xFF; 32]);
        assert!(!all_ones.is_valid());

        // Random bytes that aren't valid Ed25519 curve points
        // Most random 32-byte arrays won't be valid curve points
        let invalid_point = Identity::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ]);
        assert!(
            !invalid_point.is_valid(),
            "should fail Ed25519 point validation"
        );

        // Valid keypair identity should pass
        let keypair = Keypair::generate();
        let valid_identity = keypair.identity();
        assert!(valid_identity.is_valid());
    }

    // ========================================================================
    // Proof-of-Work (S/Kademlia) Tests
    // ========================================================================

    #[test]
    fn test_pow_generation_produces_valid_proof() {
        // Use lower difficulty for faster test
        let (keypair, proof) =
            Keypair::generate_with_pow_difficulty(8).expect("PoW generation failed");
        let identity = keypair.identity();

        assert!(
            identity.verify_pow_with_difficulty(&proof, 8),
            "P6 violation: generate_with_pow must produce valid proof"
        );
    }

    #[test]
    fn test_pow_verification_rejects_invalid_nonce() {
        let (keypair, proof) =
            Keypair::generate_with_pow_difficulty(8).expect("PoW generation failed");
        let identity = keypair.identity();

        // Valid proof works
        assert!(identity.verify_pow_with_difficulty(&proof, 8));

        // Wrong nonce fails
        let bad_proof = IdentityProof::new(proof.nonce.wrapping_add(1));
        assert!(
            !identity.verify_pow_with_difficulty(&bad_proof, 8),
            "PoW should reject invalid nonce"
        );
    }

    #[test]
    fn test_pow_verification_rejects_wrong_identity() {
        let (keypair1, proof1) =
            Keypair::generate_with_pow_difficulty(8).expect("PoW generation failed");
        let keypair2 = Keypair::generate();

        // Proof from keypair1 shouldn't work for keypair2's identity
        assert!(
            !keypair2.identity().verify_pow_with_difficulty(&proof1, 8),
            "PoW proof should be bound to specific identity"
        );

        // But should work for its own identity
        assert!(keypair1.identity().verify_pow_with_difficulty(&proof1, 8));
    }

    #[test]
    fn test_pow_difficulty_zero_always_passes() {
        let keypair = Keypair::generate();
        let proof = IdentityProof::new(0);

        // Difficulty 0 means no leading zeros required
        assert!(
            keypair.identity().verify_pow_with_difficulty(&proof, 0),
            "Difficulty 0 should always pass"
        );
    }

    #[test]
    fn test_contact_with_pow_serialization_roundtrip() {
        let (keypair, proof) =
            Keypair::generate_with_pow_difficulty(8).expect("PoW generation failed");
        let contact = keypair.create_contact_with_pow(vec!["192.168.1.1:8080".to_string()], proof);

        // Verify PoW before serialization
        assert!(contact.verify_pow_with_difficulty(8));

        // Serialize and deserialize
        let serialized = bincode::serialize(&contact).unwrap();
        let deserialized: Contact = bincode::deserialize(&serialized).unwrap();

        // Verify PoW after deserialization
        assert!(
            deserialized.verify_pow_with_difficulty(8),
            "PoW proof must survive serialization roundtrip"
        );
        assert_eq!(deserialized.pow_proof.nonce, proof.nonce);
    }

    #[test]
    fn test_contact_without_pow_fails_verification() {
        let keypair = Keypair::generate();
        let contact = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        // Contact created without PoW should fail verification at any non-zero difficulty
        // (unless astronomically lucky, which won't happen in practice)
        // Note: nonce=0 might occasionally pass for very low bits, so we check difficulty 8+
        assert!(
            !contact.verify_pow_with_difficulty(16),
            "Contact without PoW should fail verification at production difficulty"
        );
    }

    #[test]
    fn test_pow_helper_functions() {
        // Test count_leading_zeros
        assert_eq!(count_leading_zeros(&[0x00; 32]), 256);
        assert_eq!(count_leading_zeros(&[0xFF; 32]), 0);
        assert_eq!(
            count_leading_zeros(&[
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]),
            23
        );
        assert_eq!(
            count_leading_zeros(&[
                0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]),
            8
        );
    }

    #[test]
    fn test_identity_proof_default() {
        let proof = IdentityProof::default();
        assert_eq!(proof.nonce, 0);

        let empty = IdentityProof::empty();
        assert_eq!(empty.nonce, 0);
    }

    #[test]
    fn test_pow_generation_timing() {
        use std::time::Instant;

        // Benchmark PoW generation at production difficulty (24)
        // Note: Use lower difficulty (8) in debug mode to avoid slow tests
        let difficulty = if cfg!(debug_assertions) {
            8
        } else {
            POW_DIFFICULTY
        };

        let start = Instant::now();
        let (keypair, proof) =
            Keypair::generate_with_pow_difficulty(difficulty).expect("PoW generation failed");
        let elapsed = start.elapsed();

        // Verify the proof is valid
        assert!(
            keypair
                .identity()
                .verify_pow_with_difficulty(&proof, difficulty)
        );

        // Print timing for visibility (run with --nocapture)
        println!(
            "\nPoW generation at difficulty {}: {:?}",
            difficulty, elapsed
        );
        println!("  Nonce found: {}", proof.nonce);

        // Sanity check: should complete in reasonable time
        // Debug mode (diff 8): < 1 second
        // Release mode (diff 24): < 60 seconds (allows for variance)
        let max_secs = if cfg!(debug_assertions) { 5 } else { 60 };
        assert!(
            elapsed.as_secs() < max_secs,
            "PoW took too long: {:?}",
            elapsed
        );
    }

    // ========================================================================
    // Namespace Tests
    // ========================================================================

    #[test]
    fn test_namespace_hash_from_string() {
        // Empty string maps to all zeros
        let empty_hash = IdentityProof::namespace_hash_from_string("");
        assert_eq!(empty_hash, [0u8; NAMESPACE_HASH_LEN]);

        // Non-empty strings produce non-zero hashes
        let acme_hash = IdentityProof::namespace_hash_from_string("acme-corp");
        assert_ne!(acme_hash, [0u8; NAMESPACE_HASH_LEN]);

        // Different strings produce different hashes
        let other_hash = IdentityProof::namespace_hash_from_string("other-org");
        assert_ne!(acme_hash, other_hash);

        // Same string produces same hash (deterministic)
        let acme_hash2 = IdentityProof::namespace_hash_from_string("acme-corp");
        assert_eq!(acme_hash, acme_hash2);
    }

    #[test]
    fn test_identity_proof_namespace_methods() {
        let global_proof = IdentityProof::empty();
        assert!(global_proof.is_global_namespace());
        assert!(global_proof.matches_namespace(""));
        assert!(!global_proof.matches_namespace("acme-corp"));

        let ns_hash = IdentityProof::namespace_hash_from_string("acme-corp");
        let ns_proof = IdentityProof::with_namespace(12345, ns_hash);

        assert!(!ns_proof.is_global_namespace());
        assert!(!ns_proof.matches_namespace(""));
        assert!(ns_proof.matches_namespace("acme-corp"));
        assert!(!ns_proof.matches_namespace("other-org"));
    }

    #[test]
    fn test_same_namespace_comparison() {
        let ns1 = IdentityProof::namespace_hash_from_string("acme-corp");
        let ns2 = IdentityProof::namespace_hash_from_string("acme-corp");
        let ns3 = IdentityProof::namespace_hash_from_string("other-org");

        let proof1 = IdentityProof::with_namespace(1, ns1);
        let proof2 = IdentityProof::with_namespace(2, ns2);
        let proof3 = IdentityProof::with_namespace(3, ns3);
        let global = IdentityProof::empty();

        // Same namespace (different nonces)
        assert!(proof1.same_namespace(&proof2));

        // Different namespaces
        assert!(!proof1.same_namespace(&proof3));
        assert!(!proof2.same_namespace(&proof3));

        // Global vs named
        assert!(!global.same_namespace(&proof1));

        // Global vs global
        let global2 = IdentityProof::empty();
        assert!(global.same_namespace(&global2));
    }

    #[test]
    fn test_namespace_bound_pow_generation() {
        let namespace = "test-namespace";

        // Generate keypair with namespace
        let (keypair, proof) = Keypair::generate_with_pow_for_namespace(namespace)
            .expect("namespace PoW generation failed");

        // Proof should match the namespace
        assert!(proof.matches_namespace(namespace));
        assert!(!proof.matches_namespace(""));
        assert!(!proof.matches_namespace("other-namespace"));

        // Identity should verify with this proof
        assert!(keypair.identity().verify_pow(&proof));
    }

    #[test]
    fn test_namespace_pow_cannot_be_reused_across_namespaces() {
        // Generate identity for namespace A
        let (keypair_a, proof_a) =
            Keypair::generate_with_pow_for_namespace("namespace-a").expect("PoW generation failed");

        // Proof is valid for this identity in namespace A
        assert!(keypair_a.identity().verify_pow(&proof_a));
        assert!(proof_a.matches_namespace("namespace-a"));

        // Create a fake proof claiming to be for namespace B but with same nonce
        let ns_b_hash = IdentityProof::namespace_hash_from_string("namespace-b");
        let fake_proof = IdentityProof::with_namespace(proof_a.nonce, ns_b_hash);

        // The fake proof should NOT verify for this identity
        // (because the PoW was computed for namespace A, not B)
        assert!(
            !keypair_a.identity().verify_pow(&fake_proof),
            "PoW proof should not be reusable across namespaces"
        );
    }

    #[test]
    fn test_global_namespace_backwards_compatibility() {
        // Generate keypair in global namespace
        let (keypair, proof) = Keypair::generate_with_pow().expect("PoW generation failed");

        // Should be in global namespace
        assert!(proof.is_global_namespace());
        assert!(proof.matches_namespace(""));

        // Should verify correctly
        assert!(keypair.identity().verify_pow(&proof));

        // Generate with explicit empty string should be equivalent
        let (keypair2, proof2) =
            Keypair::generate_with_pow_for_namespace("").expect("PoW generation failed");

        assert!(proof2.is_global_namespace());
        assert!(keypair2.identity().verify_pow(&proof2));
    }

    #[test]
    fn test_compute_pow_for_existing_identity_with_namespace() {
        // Generate a keypair without PoW
        let keypair = Keypair::generate();
        let identity = keypair.identity();

        // Compute PoW for global namespace
        let global_proof = IdentityProof::compute_for_identity(&identity, POW_DIFFICULTY);
        assert!(identity.verify_pow(&global_proof));
        assert!(global_proof.is_global_namespace());

        // Compute PoW for named namespace
        let ns_proof = IdentityProof::compute_for_identity_in_namespace(
            &identity,
            POW_DIFFICULTY,
            "my-namespace",
        );
        assert!(identity.verify_pow(&ns_proof));
        assert!(ns_proof.matches_namespace("my-namespace"));

        // The two proofs should be different (different nonces due to different hashes)
        // Note: Theoretically they COULD have the same nonce if the random keypair
        // happens to satisfy both constraints, but this is astronomically unlikely.
        // We test the namespace_hash difference which is guaranteed.
        assert_ne!(global_proof.namespace_hash, ns_proof.namespace_hash);
    }

    #[test]
    fn test_namespace_serialization_privacy() {
        // SECURITY: namespace_hash is intentionally NOT serialized to prevent
        // attackers from learning the namespace from DHT records.
        // Namespace membership is verified via challenge-response protocol.
        let ns_hash = IdentityProof::namespace_hash_from_string("serialization-test");
        let original = IdentityProof::with_namespace(42424242, ns_hash);

        // Serialize
        let bytes = bincode::serialize(&original).expect("serialization failed");

        // Deserialize
        let restored: IdentityProof = bincode::deserialize(&bytes).expect("deserialization failed");

        // Nonce is preserved (needed for PoW verification)
        assert_eq!(original.nonce, restored.nonce);

        // SECURITY: namespace_hash should be zeroed after deserialization
        // This prevents attackers from learning namespace from DHT
        assert_eq!(
            restored.namespace_hash, [0u8; 8],
            "namespace_hash must not be transmitted"
        );

        // The original still has the correct hash locally
        assert!(original.matches_namespace("serialization-test"));
    }

    #[test]
    fn test_contact_with_namespace_serialization() {
        // SECURITY: This test verifies that namespace_hash is hidden from
        // serialized contact records. Only the PoW nonce is transmitted.
        // Namespace verification happens via challenge-response, not by hash.
        let namespace = "contact-ns-test";
        let (keypair, proof) =
            Keypair::generate_with_pow_for_namespace(namespace).expect("PoW generation failed");

        // Create contact with namespace-bound proof
        let contact = keypair.create_contact_with_pow(vec!["192.168.1.1:8080".to_string()], proof);

        // Verify the contact's PoW proof has the namespace BEFORE serialization
        assert!(contact.pow_proof.matches_namespace(namespace));
        // PoW verification works locally because we have the namespace_hash
        assert!(contact.identity.verify_pow(&contact.pow_proof));

        // Serialize and deserialize
        let bytes = bincode::serialize(&contact).expect("serialization failed");
        let restored: Contact = bincode::deserialize(&bytes).expect("deserialization failed");

        // SECURITY: After deserialization, namespace_hash is zeroed
        // This is intentional - namespace is verified via challenge-response
        assert_eq!(
            restored.pow_proof.namespace_hash, [0u8; 8],
            "namespace_hash must not be transmitted in DHT"
        );

        // SECURITY: PoW verification FAILS for namespace-bound proofs after
        // deserialization because the receiver doesn't have the namespace secret.
        // This is intentional! The receiver can still:
        // 1. Accept the contact for routing (DHT/Relay work across namespaces)
        // 2. Verify namespace membership via challenge-response at stream level
        //
        // If PoW was computed with a namespace, a receiver who doesn't know
        // the namespace CANNOT verify the PoW - they'd need the secret.
        assert!(
            !restored.identity.verify_pow(&restored.pow_proof),
            "namespace-bound PoW should NOT verify without namespace secret"
        );

        // Basic identity verification still works (signature, not PoW)
        assert!(restored.identity.is_valid());
    }

    #[test]
    fn test_namespace_encryption_roundtrip() {
        // SECURITY: Verify that encryption/decryption works correctly
        // and that ciphertext is not equal to plaintext.
        let master_secret = [0x42u8; 32];
        let config = NamespaceConfig::new(master_secret);

        let plaintext = b"Hello, encrypted namespace!";

        // Encrypt
        let ciphertext = config.encrypt(plaintext).expect("encryption failed");

        // Ciphertext should be different from plaintext
        assert_ne!(
            &ciphertext[12..],
            plaintext,
            "ciphertext should differ from plaintext"
        );

        // Ciphertext should include nonce (12) + plaintext + tag (16)
        assert_eq!(ciphertext.len(), 12 + plaintext.len() + 16);

        // Decrypt
        let decrypted = config.decrypt(&ciphertext).expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_namespace_encryption_epoch_tolerance() {
        // SECURITY: Verify that decryption works across epoch boundaries
        // using the grace period mechanism.
        let master_secret = [0x42u8; 32];
        let config = NamespaceConfig::new(master_secret);

        // Encrypt at current epoch
        let current_epoch = config.current_epoch();
        let plaintext = b"Cross-epoch message";
        let ciphertext = config.encrypt(plaintext).expect("encryption failed");

        // Create a config that simulates being one epoch behind
        // (decryption should still work due to grace period)
        let encryption_key_current = config.encryption_key_for_epoch(current_epoch);
        let encryption_key_prev = config.encryption_key_for_epoch(current_epoch.saturating_sub(1));

        // Keys for different epochs should be different
        if current_epoch > 0 {
            assert_ne!(
                encryption_key_current, encryption_key_prev,
                "different epochs should have different keys"
            );
        }

        // Decryption should still succeed (tries current + grace epochs)
        let decrypted = config
            .decrypt(&ciphertext)
            .expect("decryption with grace period failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_namespace_encryption_wrong_key_fails() {
        // SECURITY: Verify that decryption fails with wrong key.
        let master_secret_1 = [0x42u8; 32];
        let master_secret_2 = [0x43u8; 32];

        let config1 = NamespaceConfig::new(master_secret_1);
        let config2 = NamespaceConfig::new(master_secret_2);

        let plaintext = b"Secret message";
        let ciphertext = config1.encrypt(plaintext).expect("encryption failed");

        // Decryption with wrong key should fail
        let result = config2.decrypt(&ciphertext);
        assert!(result.is_err(), "decryption with wrong key should fail");
        assert!(matches!(
            result.unwrap_err(),
            NamespaceEncryptionError::DecryptionFailed
        ));
    }

    #[test]
    fn test_namespace_encryption_tampered_ciphertext_fails() {
        // SECURITY: Verify that tampered ciphertext is detected (AEAD property).
        let master_secret = [0x42u8; 32];
        let config = NamespaceConfig::new(master_secret);

        let plaintext = b"Authenticated message";
        let mut ciphertext = config.encrypt(plaintext).expect("encryption failed");

        // Tamper with ciphertext (flip a bit in the middle)
        let tamper_pos = ciphertext.len() / 2;
        ciphertext[tamper_pos] ^= 0xFF;

        // Decryption should fail due to authentication check
        let result = config.decrypt(&ciphertext);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail decryption"
        );
    }

    #[test]
    fn test_namespace_encryption_short_ciphertext_fails() {
        // SECURITY: Verify that short/malformed ciphertext is rejected.
        let master_secret = [0x42u8; 32];
        let config = NamespaceConfig::new(master_secret);

        // Too short - less than nonce + tag overhead
        let short_ciphertext = vec![0u8; 10];
        let result = config.decrypt(&short_ciphertext);
        assert!(result.is_err(), "short ciphertext should fail");
        assert!(matches!(
            result.unwrap_err(),
            NamespaceEncryptionError::CiphertextTooShort
        ));
    }

    #[test]
    fn test_namespace_encryption_empty_plaintext() {
        // Verify that empty plaintext encrypts and decrypts correctly.
        let master_secret = [0x42u8; 32];
        let config = NamespaceConfig::new(master_secret);

        let plaintext = b"";
        let ciphertext = config
            .encrypt(plaintext)
            .expect("encryption of empty plaintext failed");

        // Should have nonce (12) + tag (16) overhead
        assert_eq!(ciphertext.len(), 12 + 16);

        let decrypted = config
            .decrypt(&ciphertext)
            .expect("decryption of empty plaintext failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_namespace_encryption_nonce_uniqueness() {
        // SECURITY: Verify that each encryption produces a unique nonce.
        let master_secret = [0x42u8; 32];
        let config = NamespaceConfig::new(master_secret);

        let plaintext = b"Same message";

        // Encrypt the same message multiple times
        let ciphertext1 = config.encrypt(plaintext).expect("encryption 1 failed");
        let ciphertext2 = config.encrypt(plaintext).expect("encryption 2 failed");
        let ciphertext3 = config.encrypt(plaintext).expect("encryption 3 failed");

        // All ciphertexts should be different (random nonces)
        assert_ne!(
            ciphertext1, ciphertext2,
            "ciphertexts should differ due to unique nonces"
        );
        assert_ne!(
            ciphertext2, ciphertext3,
            "ciphertexts should differ due to unique nonces"
        );
        assert_ne!(
            ciphertext1, ciphertext3,
            "ciphertexts should differ due to unique nonces"
        );

        // But all should decrypt to the same plaintext
        assert_eq!(config.decrypt(&ciphertext1).unwrap(), plaintext);
        assert_eq!(config.decrypt(&ciphertext2).unwrap(), plaintext);
        assert_eq!(config.decrypt(&ciphertext3).unwrap(), plaintext);
    }
}
