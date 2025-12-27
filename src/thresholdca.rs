//! Threshold CA using FROST (Flexible Round-Optimized Schnorr Threshold) signatures.
//!
//! This module implements a distributed Certificate Authority using K-of-N threshold
//! signatures. Any K signers from a committee of N can collaboratively sign certificates
//! without any single party holding the complete CA private key.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Threshold CA Overview                             │
//! │                                                                      │
//! │  1. DKG (one-time setup):                                           │
//! │     - N signers run 3-round protocol                                │
//! │     - Each signer gets KeyPackage (private share)                   │
//! │     - All get PublicKeyPackage (combined CA pubkey)                 │
//! │                                                                      │
//! │  2. Signing (per certificate):                                       │
//! │     - Requester broadcasts CSR                                       │
//! │     - K signers produce partial signatures                          │
//! │     - Requester combines into valid signature                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! - **Byzantine Fault Tolerance**: Requires K honest signers (typically K = N/2 + 1)
//! - **No Trusted Dealer**: DKG ensures no party ever sees the complete private key
//! - **Identifiable Aborts**: Misbehaving signers can be detected
//! - **Key Shares**: MUST be stored encrypted at rest
//!
//! # Protocol Constants
//!
//! | Constant | Value | Rationale |
//! |----------|-------|-----------|
//! | `MIN_SIGNERS` | 3 | Minimum for meaningful threshold |
//! | `MAX_SIGNERS` | 255 | FROST identifier limit |
//! | `DKG_ROUND_TIMEOUT` | 30s | Network latency allowance |
//! | `SIGNING_TIMEOUT` | 10s | Per-request timeout |

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost_ed25519::Identifier;
use serde::{Deserialize, Serialize};

use crate::identity::Identity;

// ============================================================================
// Protocol Constants
// ============================================================================

/// Minimum number of signers for a meaningful threshold.
pub const MIN_SIGNERS: u16 = 3;

/// Maximum number of signers (FROST identifier limit).
pub const MAX_SIGNERS: u16 = 255;

/// Timeout for each DKG round.
#[allow(dead_code)]
pub(crate) const DKG_ROUND_TIMEOUT_SECS: u64 = 30;

/// Timeout for collecting signature shares.
#[allow(dead_code)]
pub(crate) const SIGNING_TIMEOUT_SECS: u64 = 10;

/// GossipSub topic for CSR broadcast.
#[allow(dead_code)]
pub(crate) const TOPIC_CSR: &str = "csr";

/// RPC magic prefix for CA sign requests.
/// Using 4 bytes to avoid collision with application payloads.
pub const CA_SIGN_REQUEST_MAGIC: &[u8; 4] = b"CASN";

/// Length of the CA sign request magic prefix.
pub const CA_SIGN_REQUEST_MAGIC_LEN: usize = 4;

/// Maximum size of a TBS (To-Be-Signed) certificate.
/// X.509 certificates are typically <4KB; 16KB provides generous headroom.
/// SECURITY: Prevents memory exhaustion from oversized CSR payloads.
pub const MAX_TBS_CERTIFICATE_SIZE: usize = 16 * 1024;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during threshold CA operations.
#[derive(Debug, Clone)]
pub enum ThresholdCaError {
    /// Invalid configuration parameters.
    InvalidConfig(String),
    /// DKG protocol error.
    DkgFailed(String),
    /// Signing protocol error.
    SigningFailed(String),
    /// Not enough signers responded.
    InsufficientSigners { required: u16, received: u16 },
    /// Signature verification failed.
    InvalidSignature,
    /// Signer not part of committee.
    NotASigner,
    /// Timeout waiting for responses.
    Timeout,
    /// Serialization error.
    Serialization(String),
    /// Certificate generation error.
    CertificateError(String),
}

impl std::fmt::Display for ThresholdCaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::DkgFailed(msg) => write!(f, "DKG failed: {msg}"),
            Self::SigningFailed(msg) => write!(f, "signing failed: {msg}"),
            Self::InsufficientSigners { required, received } => {
                write!(f, "insufficient signers: need {required}, got {received}")
            }
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::NotASigner => write!(f, "not a signer in the committee"),
            Self::Timeout => write!(f, "timeout waiting for responses"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
            Self::CertificateError(msg) => write!(f, "certificate error: {msg}"),
        }
    }
}

impl std::error::Error for ThresholdCaError {}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for threshold CA operations.
#[derive(Debug, Clone)]
pub struct ThresholdCaConfig {
    /// Total number of signers in the committee (N).
    pub max_signers: u16,
    /// Minimum signers required to produce a signature (K).
    pub min_signers: u16,
    /// Trust domain for SPIFFE URIs (e.g., "make.run").
    pub trust_domain: String,
    /// Certificate validity period in seconds.
    pub cert_validity_secs: u64,
}

impl ThresholdCaConfig {
    /// Create a new threshold CA configuration.
    ///
    /// # Arguments
    ///
    /// * `max_signers` - Total number of signers (N), must be >= 3 and <= 255
    /// * `min_signers` - Threshold (K), must be > N/2 for Byzantine fault tolerance
    /// * `trust_domain` - SPIFFE trust domain
    ///
    /// # Errors
    ///
    /// Returns error if parameters are invalid.
    pub fn new(
        max_signers: u16,
        min_signers: u16,
        trust_domain: impl Into<String>,
    ) -> Result<Self, ThresholdCaError> {
        if max_signers < MIN_SIGNERS {
            return Err(ThresholdCaError::InvalidConfig(format!(
                "max_signers must be >= {MIN_SIGNERS}"
            )));
        }
        if max_signers > MAX_SIGNERS {
            return Err(ThresholdCaError::InvalidConfig(format!(
                "max_signers must be <= {MAX_SIGNERS}"
            )));
        }
        if min_signers < 2 {
            return Err(ThresholdCaError::InvalidConfig(
                "min_signers must be >= 2".into(),
            ));
        }
        if min_signers > max_signers {
            return Err(ThresholdCaError::InvalidConfig(
                "min_signers must be <= max_signers".into(),
            ));
        }
        // Recommend K > N/2 for Byzantine fault tolerance
        if min_signers <= max_signers / 2 {
            tracing::warn!(
                "min_signers ({}) <= max_signers/2 ({}) - vulnerable to Byzantine failures",
                min_signers,
                max_signers / 2
            );
        }

        Ok(Self {
            max_signers,
            min_signers,
            trust_domain: trust_domain.into(),
            cert_validity_secs: 3600, // 1 hour default
        })
    }

    /// Set certificate validity period.
    #[must_use]
    pub fn with_validity(mut self, secs: u64) -> Self {
        self.cert_validity_secs = secs;
        self
    }
}

// ============================================================================
// Signer Identity Mapping
// ============================================================================

/// Maps between Korium Identity and FROST Identifier.
///
/// FROST uses u16-based identifiers (1..=N), while Korium uses Ed25519 public keys.
/// This mapping is established during DKG setup and must be consistent across all signers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRegistry {
    /// Maps FROST identifier to Korium identity.
    pub frost_to_identity: BTreeMap<u16, Identity>,
    /// Maps Korium identity to FROST identifier.
    #[serde(skip)]
    identity_to_frost: BTreeMap<Identity, u16>,
}

impl SignerRegistry {
    /// Create a new signer registry from a list of identities.
    ///
    /// Identities are sorted and assigned sequential FROST identifiers starting from 1.
    pub fn from_identities(mut identities: Vec<Identity>) -> Self {
        // Sort for deterministic ordering across all participants
        identities.sort();
        identities.dedup();

        let mut frost_to_identity = BTreeMap::new();
        let mut identity_to_frost = BTreeMap::new();

        for (idx, identity) in identities.into_iter().enumerate() {
            let frost_id = (idx + 1) as u16; // FROST identifiers are 1-indexed
            frost_to_identity.insert(frost_id, identity);
            identity_to_frost.insert(identity, frost_id);
        }

        Self {
            frost_to_identity,
            identity_to_frost,
        }
    }

    /// Get the FROST identifier for a Korium identity.
    pub fn get_frost_id(&self, identity: &Identity) -> Option<Identifier> {
        self.identity_to_frost
            .get(identity)
            .and_then(|&id| id.try_into().ok())
    }

    /// Get the Korium identity for a FROST identifier.
    pub fn get_identity(&self, frost_id: Identifier) -> Option<&Identity> {
        // FROST identifiers serialize to their scalar representation
        // We need to extract the u16 index from the serialized form
        let serialized = frost_id.serialize();
        if serialized.len() < 2 {
            return None;
        }
        // FROST scalar serialization is little-endian
        let id = u16::from_le_bytes([serialized[0], serialized[1]]);
        self.frost_to_identity.get(&id)
    }

    /// Number of signers in the registry.
    pub fn len(&self) -> usize {
        self.frost_to_identity.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.frost_to_identity.is_empty()
    }

    /// Rebuild the reverse mapping after deserialization.
    pub fn rebuild_reverse_mapping(&mut self) {
        self.identity_to_frost.clear();
        for (&frost_id, identity) in &self.frost_to_identity {
            self.identity_to_frost.insert(*identity, frost_id);
        }
    }
}

// ============================================================================
// DKG Protocol Messages
// ============================================================================

/// Message types for DKG protocol.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DkgMessage {
    /// Round 1: Commitment broadcast (same to all participants).
    Round1 {
        /// Sender's Korium identity.
        sender: Identity,
        /// Serialized round1::Package.
        package: Vec<u8>,
    },
    /// Round 2: Secret share (specific per recipient).
    Round2 {
        /// Sender's Korium identity.
        sender: Identity,
        /// Recipient's Korium identity.
        recipient: Identity,
        /// Serialized round2::Package.
        package: Vec<u8>,
    },
}

// ============================================================================
// Signing Protocol Messages
// ============================================================================

/// A request to sign a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    /// Unique request identifier (blake3 hash of CSR).
    pub request_id: [u8; 32],
    /// The certificate data to sign (TBS = To Be Signed).
    pub tbs_certificate: Vec<u8>,
    /// Requester's identity (for audit/logging).
    pub requester: Identity,
    /// SPIFFE workload path (optional).
    pub workload_path: Option<String>,
    /// Request timestamp (for replay protection).
    pub timestamp_ms: u64,
}

impl SigningRequest {
    /// Create a new signing request.
    pub fn new(tbs_certificate: Vec<u8>, requester: Identity) -> Self {
        let request_id = blake3::hash(&tbs_certificate).into();
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            request_id,
            tbs_certificate,
            requester,
            workload_path: None,
            timestamp_ms,
        }
    }

    /// Set the SPIFFE workload path.
    #[allow(dead_code)]
    #[must_use]
    pub fn with_workload_path(mut self, path: impl Into<String>) -> Self {
        self.workload_path = Some(path.into());
        self
    }
}

/// A partial signature share from a signer (legacy GossipSub format).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignatureShare {
    /// Request ID this share is for.
    pub request_id: [u8; 32],
    /// Signer's Korium identity.
    pub signer: Identity,
    /// Signer's FROST identifier.
    pub frost_identifier: Identifier,
    /// Serialized SigningCommitments.
    pub commitment: Vec<u8>,
    /// Serialized SignatureShare.
    pub share: Vec<u8>,
}

// ============================================================================
// RPC Protocol Messages
// ============================================================================

/// Signer's commitment response (sent via RPC to requester).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaCommitmentResponse {
    /// Request ID this commitment is for.
    pub request_id: [u8; 32],
    /// Signer's FROST identifier.
    pub frost_id: Identifier,
    /// Serialized SigningCommitments.
    pub commitment: Vec<u8>,
}

/// Request for signers to produce signature shares (sent via RPC from requester).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaSignRequest {
    /// Request ID to sign.
    pub request_id: [u8; 32],
    /// All collected commitments from participating signers.
    pub commitments: Vec<(Identifier, Vec<u8>)>,
}

/// Signer's signature share response (sent via RPC to requester).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaSignResponse {
    /// Request ID this share is for.
    pub request_id: [u8; 32],
    /// Signer's FROST identifier.
    pub frost_id: Identifier,
    /// Serialized SignatureShare.
    pub share: Vec<u8>,
}

// ============================================================================
// Signer State
// ============================================================================

/// State held by a threshold CA signer.
///
/// This contains the signer's private key share and must be stored securely.
#[derive(Clone)]
pub struct SignerState {
    /// This signer's FROST key package (contains private share).
    key_package: frost::keys::KeyPackage,
    /// Public key package (shared by all signers).
    pubkey_package: frost::keys::PublicKeyPackage,
    /// Signer registry for identity mapping.
    registry: SignerRegistry,
    /// Configuration.
    config: ThresholdCaConfig,
}

impl SignerState {
    /// Get this signer's FROST identifier.
    pub fn identifier(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// Get the combined CA public key (verifying key).
    pub fn ca_public_key(&self) -> &frost::VerifyingKey {
        self.pubkey_package.verifying_key()
    }

    /// Get the CA public key as bytes (32 bytes).
    pub fn ca_public_key_bytes(&self) -> [u8; 32] {
        self.ca_public_key()
            .serialize()
            .ok()
            .and_then(|v| v.as_slice().try_into().ok())
            .unwrap_or([0u8; 32])
    }

    /// Get the signer registry.
    pub fn registry(&self) -> &SignerRegistry {
        &self.registry
    }

    /// Get the configuration.
    pub fn config(&self) -> &ThresholdCaConfig {
        &self.config
    }

    /// Serialize the signer state for persistent storage.
    ///
    /// # Security
    ///
    /// The returned bytes contain the private key share and MUST be encrypted
    /// before storing to disk.
    pub fn serialize(&self) -> Result<Vec<u8>, ThresholdCaError> {
        // Serialize key_package and pubkey_package using FROST's serialization
        let key_package_bytes = self
            .key_package
            .serialize()
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        let pubkey_package_bytes = self
            .pubkey_package
            .serialize()
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        let registry_bytes = bincode::serialize(&self.registry)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        let config_bytes = bincode::serialize(&(
            self.config.max_signers,
            self.config.min_signers,
            &self.config.trust_domain,
            self.config.cert_validity_secs,
        ))
        .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

        // Pack lengths and data
        let mut out = Vec::new();
        out.extend_from_slice(&(key_package_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&key_package_bytes);
        out.extend_from_slice(&(pubkey_package_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&pubkey_package_bytes);
        out.extend_from_slice(&(registry_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&registry_bytes);
        out.extend_from_slice(&(config_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&config_bytes);

        Ok(out)
    }

    /// Deserialize signer state from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ThresholdCaError> {
        let mut cursor = 0;

        let read_chunk = |cursor: &mut usize, data: &[u8]| -> Result<Vec<u8>, ThresholdCaError> {
            if *cursor + 4 > data.len() {
                return Err(ThresholdCaError::Serialization("truncated data".into()));
            }
            let len = u32::from_le_bytes(data[*cursor..*cursor + 4].try_into().unwrap()) as usize;
            *cursor += 4;
            if *cursor + len > data.len() {
                return Err(ThresholdCaError::Serialization("truncated data".into()));
            }
            let chunk = data[*cursor..*cursor + len].to_vec();
            *cursor += len;
            Ok(chunk)
        };

        let key_package_bytes = read_chunk(&mut cursor, data)?;
        let pubkey_package_bytes = read_chunk(&mut cursor, data)?;
        let registry_bytes = read_chunk(&mut cursor, data)?;
        let config_bytes = read_chunk(&mut cursor, data)?;

        let key_package = frost::keys::KeyPackage::deserialize(&key_package_bytes)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        let pubkey_package = frost::keys::PublicKeyPackage::deserialize(&pubkey_package_bytes)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        let mut registry: SignerRegistry = bincode::deserialize(&registry_bytes)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        registry.rebuild_reverse_mapping();

        let (max_signers, min_signers, trust_domain, cert_validity_secs): (u16, u16, String, u64) =
            bincode::deserialize(&config_bytes)
                .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

        Ok(Self {
            key_package,
            pubkey_package,
            registry,
            config: ThresholdCaConfig {
                max_signers,
                min_signers,
                trust_domain,
                cert_validity_secs,
            },
        })
    }
}

// ============================================================================
// DKG Coordinator
// ============================================================================

/// Coordinates the Distributed Key Generation protocol.
///
/// This is used during the one-time setup phase to generate key shares
/// without any single party seeing the complete private key.
#[allow(dead_code)]
pub(crate) struct DkgCoordinator {
    config: ThresholdCaConfig,
    registry: SignerRegistry,
    my_identifier: Identifier,
    my_identity: Identity,
}

#[allow(dead_code)]
impl DkgCoordinator {
    /// Create a new DKG coordinator.
    ///
    /// # Arguments
    ///
    /// * `config` - Threshold CA configuration
    /// * `signers` - List of all signer identities (must include self)
    /// * `my_identity` - This participant's identity
    pub fn new(
        config: ThresholdCaConfig,
        signers: Vec<Identity>,
        my_identity: Identity,
    ) -> Result<Self, ThresholdCaError> {
        if signers.len() != config.max_signers as usize {
            return Err(ThresholdCaError::InvalidConfig(format!(
                "expected {} signers, got {}",
                config.max_signers,
                signers.len()
            )));
        }

        let registry = SignerRegistry::from_identities(signers);

        let my_identifier = registry
            .get_frost_id(&my_identity)
            .ok_or(ThresholdCaError::NotASigner)?;

        Ok(Self {
            config,
            registry,
            my_identifier,
            my_identity,
        })
    }

    /// Execute DKG Round 1: Generate commitment.
    ///
    /// Returns the secret package (keep private) and the public package (broadcast to all).
    pub fn round1(&self) -> Result<(DkgRound1Secret, DkgMessage), ThresholdCaError> {
        let rng = rand::rngs::OsRng;

        let (secret_package, round1_package) = frost::keys::dkg::part1(
            self.my_identifier,
            self.config.max_signers,
            self.config.min_signers,
            rng,
        )
        .map_err(|e| ThresholdCaError::DkgFailed(e.to_string()))?;

        let package_bytes = round1_package
            .serialize()
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

        let message = DkgMessage::Round1 {
            sender: self.my_identity,
            package: package_bytes,
        };

        Ok((DkgRound1Secret(secret_package), message))
    }

    /// Execute DKG Round 2: Process received Round 1 packages and generate shares.
    ///
    /// # Arguments
    ///
    /// * `secret` - Secret from Round 1
    /// * `received` - Round 1 packages received from other participants
    ///
    /// Returns the secret package and a map of per-recipient packages.
    pub fn round2(
        &self,
        secret: DkgRound1Secret,
        received: &[DkgMessage],
    ) -> Result<(DkgRound2Secret, Vec<DkgMessage>), ThresholdCaError> {
        // Parse received Round 1 packages
        let mut round1_packages = BTreeMap::new();

        for msg in received {
            if let DkgMessage::Round1 { sender, package } = msg {
                let frost_id = self
                    .registry
                    .get_frost_id(sender)
                    .ok_or_else(|| ThresholdCaError::DkgFailed("unknown sender".into()))?;

                // Skip our own package
                if frost_id == self.my_identifier {
                    continue;
                }

                let parsed = frost::keys::dkg::round1::Package::deserialize(package)
                    .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

                round1_packages.insert(frost_id, parsed);
            }
        }

        // Verify we have enough participants
        let expected = self.config.max_signers as usize - 1; // Exclude self
        if round1_packages.len() < expected {
            return Err(ThresholdCaError::InsufficientSigners {
                required: expected as u16,
                received: round1_packages.len() as u16,
            });
        }

        // Execute Round 2
        let (secret_package, round2_packages) = frost::keys::dkg::part2(secret.0, &round1_packages)
            .map_err(|e| ThresholdCaError::DkgFailed(e.to_string()))?;

        // Create messages for each recipient
        let mut messages = Vec::new();
        for (recipient_id, package) in round2_packages {
            let recipient = *self
                .registry
                .get_identity(recipient_id)
                .ok_or_else(|| ThresholdCaError::DkgFailed("unknown recipient".into()))?;

            let package_bytes = package
                .serialize()
                .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

            messages.push(DkgMessage::Round2 {
                sender: self.my_identity,
                recipient,
                package: package_bytes,
            });
        }

        Ok((DkgRound2Secret(secret_package), messages))
    }

    /// Execute DKG Round 3: Finalize and produce key shares.
    ///
    /// # Arguments
    ///
    /// * `secret` - Secret from Round 2
    /// * `round1_packages` - All Round 1 packages (for verification)
    /// * `round2_packages` - Round 2 packages addressed to us
    pub fn round3(
        &self,
        secret: &DkgRound2Secret,
        round1_messages: &[DkgMessage],
        round2_messages: &[DkgMessage],
    ) -> Result<SignerState, ThresholdCaError> {
        // Parse Round 1 packages
        let mut round1_packages = BTreeMap::new();
        for msg in round1_messages {
            if let DkgMessage::Round1 { sender, package } = msg {
                let frost_id = self
                    .registry
                    .get_frost_id(sender)
                    .ok_or_else(|| ThresholdCaError::DkgFailed("unknown sender".into()))?;

                if frost_id == self.my_identifier {
                    continue;
                }

                let parsed = frost::keys::dkg::round1::Package::deserialize(package)
                    .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

                round1_packages.insert(frost_id, parsed);
            }
        }

        // Parse Round 2 packages addressed to us
        let mut round2_packages = BTreeMap::new();
        for msg in round2_messages {
            if let DkgMessage::Round2 {
                sender,
                recipient,
                package,
            } = msg
            {
                // Only process packages addressed to us
                if recipient != &self.my_identity {
                    continue;
                }

                let frost_id = self
                    .registry
                    .get_frost_id(sender)
                    .ok_or_else(|| ThresholdCaError::DkgFailed("unknown sender".into()))?;

                let parsed = frost::keys::dkg::round2::Package::deserialize(package)
                    .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

                round2_packages.insert(frost_id, parsed);
            }
        }

        // Verify we have enough Round 2 packages
        let expected = self.config.max_signers as usize - 1;
        if round2_packages.len() < expected {
            return Err(ThresholdCaError::InsufficientSigners {
                required: expected as u16,
                received: round2_packages.len() as u16,
            });
        }

        // Execute Round 3 (finalization)
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(&secret.0, &round1_packages, &round2_packages)
                .map_err(|e| ThresholdCaError::DkgFailed(e.to_string()))?;

        Ok(SignerState {
            key_package,
            pubkey_package,
            registry: self.registry.clone(),
            config: self.config.clone(),
        })
    }
}

/// Secret state from DKG Round 1 (must not be shared).
#[allow(dead_code)]
pub(crate) struct DkgRound1Secret(frost::keys::dkg::round1::SecretPackage);

/// Secret state from DKG Round 2 (must not be shared).
#[allow(dead_code)]
pub(crate) struct DkgRound2Secret(frost::keys::dkg::round2::SecretPackage);

// ============================================================================
// Signing Operations
// ============================================================================

/// Generate a signing commitment and nonce.
///
/// Returns the commitment (to broadcast) and nonce (keep private).
pub fn generate_signing_commitment(
    signer: &SignerState,
) -> Result<(SigningNonce, Vec<u8>), ThresholdCaError> {
    let mut rng = rand::rngs::OsRng;

    let (nonces, commitments) = frost::round1::commit(signer.key_package.signing_share(), &mut rng);

    let commitment_bytes = commitments
        .serialize()
        .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

    Ok((SigningNonce(nonces), commitment_bytes))
}

/// Sign a message using the signer's key share.
///
/// # Arguments
///
/// * `signer` - Signer state with key package
/// * `nonce` - Nonce from `generate_signing_commitment`
/// * `message` - Message to sign (TBS certificate)
/// * `commitments` - All signers' commitments
pub fn sign_with_share(
    signer: &SignerState,
    nonce: SigningNonce,
    message: &[u8],
    commitments: &[(Identifier, Vec<u8>)],
) -> Result<Vec<u8>, ThresholdCaError> {
    // Parse commitments
    let mut commitment_map = BTreeMap::new();
    for (id, bytes) in commitments {
        let parsed = frost::round1::SigningCommitments::deserialize(bytes)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        commitment_map.insert(*id, parsed);
    }

    // Create signing package
    let signing_package = frost::SigningPackage::new(commitment_map, message);

    // Generate signature share
    let share = frost::round2::sign(&signing_package, &nonce.0, &signer.key_package)
        .map_err(|e| ThresholdCaError::SigningFailed(e.to_string()))?;

    Ok(share.serialize())
}

/// Aggregate signature shares into a complete signature.
///
/// # Arguments
///
/// * `pubkey_package` - Public key package from DKG
/// * `message` - Message that was signed
/// * `commitments` - All signers' commitments
/// * `shares` - Signature shares from K signers
pub fn aggregate_signatures(
    pubkey_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
    commitments: &[(Identifier, Vec<u8>)],
    shares: &[(Identifier, Vec<u8>)],
) -> Result<Vec<u8>, ThresholdCaError> {
    // Parse commitments
    let mut commitment_map = BTreeMap::new();
    for (id, bytes) in commitments {
        let parsed = frost::round1::SigningCommitments::deserialize(bytes)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        commitment_map.insert(*id, parsed);
    }

    // Parse signature shares
    let mut share_map = BTreeMap::new();
    for (id, bytes) in shares {
        let parsed = frost::round2::SignatureShare::deserialize(bytes)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        share_map.insert(*id, parsed);
    }

    // Create signing package
    let signing_package = frost::SigningPackage::new(commitment_map, message);

    // Aggregate
    let signature = frost::aggregate(&signing_package, &share_map, pubkey_package)
        .map_err(|e| ThresholdCaError::SigningFailed(e.to_string()))?;

    signature
        .serialize()
        .map_err(|e| ThresholdCaError::Serialization(e.to_string()))
}

/// Verify a signature against the CA public key.
#[allow(dead_code)]
pub fn verify_ca_signature(
    pubkey_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, ThresholdCaError> {
    let sig = frost::Signature::deserialize(signature)
        .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

    Ok(pubkey_package.verifying_key().verify(message, &sig).is_ok())
}

/// Nonce for signing (must not be reused).
pub struct SigningNonce(frost::round1::SigningNonces);

// ============================================================================
// CA Public Key Distribution
// ============================================================================

/// Serialized CA public key for distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaPublicKey {
    /// Serialized PublicKeyPackage.
    pub package: Vec<u8>,
    /// Trust domain this CA serves.
    pub trust_domain: String,
    /// Configuration parameters.
    pub max_signers: u16,
    pub min_signers: u16,
}

impl CaPublicKey {
    /// Create from a signer state.
    pub fn from_signer_state(signer: &SignerState) -> Result<Self, ThresholdCaError> {
        let package = signer
            .pubkey_package
            .serialize()
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

        Ok(Self {
            package,
            trust_domain: signer.config.trust_domain.clone(),
            max_signers: signer.config.max_signers,
            min_signers: signer.config.min_signers,
        })
    }

    /// Parse the public key package.
    pub fn pubkey_package(&self) -> Result<frost::keys::PublicKeyPackage, ThresholdCaError> {
        frost::keys::PublicKeyPackage::deserialize(&self.package)
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))
    }

    /// Get the verifying key bytes (32 bytes).
    pub fn verifying_key_bytes(&self) -> Result<[u8; 32], ThresholdCaError> {
        let pkg = self.pubkey_package()?;
        let serialized = pkg
            .verifying_key()
            .serialize()
            .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;
        serialized
            .as_slice()
            .try_into()
            .map_err(|_| ThresholdCaError::Serialization("invalid key length".into()))
    }
}

// ============================================================================
// Certificate Generation
// ============================================================================

/// Result of CSR generation containing all data needed for threshold signing.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CertificateSigningRequest {
    /// DER-encoded TBSCertificate (the data to be signed).
    pub tbs_der: Vec<u8>,
    /// Certificate parameters for final assembly.
    pub params: CertificateParamsData,
    /// The node's public key bytes (for embedding in the certificate).
    pub subject_public_key: [u8; 32],
    /// SPIFFE ID embedded in the certificate.
    pub spiffe_id: String,
}

/// Serializable certificate parameters for reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateParamsData {
    /// Common Name
    pub common_name: String,
    /// SPIFFE URI SAN
    pub spiffe_uri: String,
    /// Validity start (Unix timestamp seconds)
    pub not_before: u64,
    /// Validity end (Unix timestamp seconds)
    pub not_after: u64,
    /// Serial number (random)
    pub serial_number: [u8; 20],
}

/// Generate a certificate signing request (CSR) with SPIFFE SAN.
///
/// This creates the DER-encoded TBSCertificate data that will be
/// signed by the threshold CA. The result can be used with `assemble_certificate()`
/// after collecting threshold signatures.
///
/// # Returns
///
/// A `CertificateSigningRequest` containing:
/// - `tbs_der`: The DER-encoded TBSCertificate to be signed
/// - `params`: Certificate parameters for final assembly
/// - `subject_public_key`: The node's Ed25519 public key
/// - `spiffe_id`: The SPIFFE URI embedded in the certificate
pub fn generate_csr(
    keypair: &crate::identity::Keypair,
    trust_domain: &str,
    workload_path: Option<&str>,
    validity_secs: u64,
) -> Result<CertificateSigningRequest, ThresholdCaError> {
    use std::time::Duration;

    let identity = keypair.identity();
    let identity_hex = hex::encode(identity.as_bytes());
    let subject_public_key = keypair.public_key_bytes();

    // Build SPIFFE ID
    let spiffe_id = if let Some(path) = workload_path {
        format!("spiffe://{}/{}/{}", trust_domain, identity_hex, path)
    } else {
        format!("spiffe://{}/{}", trust_domain, identity_hex)
    };

    // Generate random serial number (required for X.509)
    let mut serial_number = [0u8; 20];
    getrandom::getrandom(&mut serial_number).map_err(|e| {
        ThresholdCaError::CertificateError(format!("failed to generate serial: {e}"))
    })?;
    // Ensure positive (set high bit to 0)
    serial_number[0] &= 0x7F;

    // Calculate validity timestamps
    let now = std::time::SystemTime::now();
    let not_before = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_after = (now + Duration::from_secs(validity_secs))
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let common_name = format!("korium-node-{}", &identity_hex[..16]);

    let params = CertificateParamsData {
        common_name: common_name.clone(),
        spiffe_uri: spiffe_id.clone(),
        not_before,
        not_after,
        serial_number,
    };

    // Build DER-encoded TBSCertificate
    let tbs_der = build_tbs_certificate_der(&params, &subject_public_key)?;

    Ok(CertificateSigningRequest {
        tbs_der,
        params,
        subject_public_key,
        spiffe_id,
    })
}

/// Build a DER-encoded TBSCertificate structure per RFC 5280.
///
/// This produces a valid X.509 TBSCertificate that can be signed by the threshold CA.
/// The structure follows RFC 5280 Section 4.1:
///
/// ```text
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT INTEGER DEFAULT v1,
///     serialNumber         INTEGER,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     extensions      [3] EXPLICIT Extensions OPTIONAL
/// }
/// ```
fn build_tbs_certificate_der(
    params: &CertificateParamsData,
    subject_public_key: &[u8; 32],
) -> Result<Vec<u8>, ThresholdCaError> {
    // We'll build the DER structure manually to ensure correctness.
    // This is more reliable than depending on rcgen's internal serialization.

    let mut tbs = Vec::with_capacity(512);

    // Build inner content first, then wrap in SEQUENCE
    let mut content = Vec::with_capacity(400);

    // Version [0] EXPLICIT INTEGER (v3 = 2)
    // Tag: A0 (context-specific, constructed, tag 0)
    // Content: INTEGER 02 01 02
    content.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

    // SerialNumber INTEGER
    let serial_der = encode_integer(&params.serial_number);
    content.extend_from_slice(&serial_der);

    // Signature AlgorithmIdentifier (Ed25519 = 1.3.101.112)
    // SEQUENCE { OID 1.3.101.112 }
    content.extend_from_slice(&[
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, // OID, length 3
        0x2B, 0x65, 0x70, // 1.3.101.112 (Ed25519)
    ]);

    // Issuer Name (CN=Korium Threshold CA)
    let issuer = encode_rdn("Korium Threshold CA");
    content.extend_from_slice(&issuer);

    // Validity SEQUENCE { notBefore, notAfter }
    let validity = encode_validity(params.not_before, params.not_after)?;
    content.extend_from_slice(&validity);

    // Subject Name (CN=<common_name>)
    let subject = encode_rdn(&params.common_name);
    content.extend_from_slice(&subject);

    // SubjectPublicKeyInfo SEQUENCE { algorithm, publicKey }
    let spki = encode_ed25519_spki(subject_public_key);
    content.extend_from_slice(&spki);

    // Extensions [3] EXPLICIT SEQUENCE
    let extensions = encode_extensions(&params.spiffe_uri)?;
    content.extend_from_slice(&extensions);

    // Wrap in SEQUENCE
    let content_len = content.len();
    tbs.push(0x30); // SEQUENCE tag
    encode_length(content_len, &mut tbs);
    tbs.extend_from_slice(&content);

    Ok(tbs)
}

/// Encode an INTEGER in DER format.
fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len() + 4);
    result.push(0x02); // INTEGER tag

    // Skip leading zeros but keep at least one byte
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }

    // If high bit is set, prepend a 0x00
    let needs_padding = bytes[start] & 0x80 != 0;
    let content_len = bytes.len() - start + if needs_padding { 1 } else { 0 };

    encode_length(content_len, &mut result);
    if needs_padding {
        result.push(0x00);
    }
    result.extend_from_slice(&bytes[start..]);

    result
}

/// Encode DER length.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Encode a relative distinguished name (single CN attribute).
fn encode_rdn(common_name: &str) -> Vec<u8> {
    let cn_bytes = common_name.as_bytes();

    // AttributeTypeAndValue: SEQUENCE { OID, UTF8String }
    // OID for CN = 2.5.4.3 = 55 04 03
    let mut atv = Vec::new();
    atv.push(0x30); // SEQUENCE
    let atv_content_len = 5 + cn_bytes.len() + if cn_bytes.len() < 128 { 0 } else { 1 };
    encode_length(atv_content_len, &mut atv);
    atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // OID CN
    atv.push(0x0C); // UTF8String
    encode_length(cn_bytes.len(), &mut atv);
    atv.extend_from_slice(cn_bytes);

    // RDN: SET { AttributeTypeAndValue }
    let mut rdn = Vec::new();
    rdn.push(0x31); // SET
    encode_length(atv.len(), &mut rdn);
    rdn.extend_from_slice(&atv);

    // Name: SEQUENCE { RDN }
    let mut name = Vec::new();
    name.push(0x30); // SEQUENCE
    encode_length(rdn.len(), &mut name);
    name.extend_from_slice(&rdn);

    name
}

/// Encode Validity (notBefore, notAfter as GeneralizedTime).
fn encode_validity(not_before: u64, not_after: u64) -> Result<Vec<u8>, ThresholdCaError> {
    let before_str = unix_to_generalized_time(not_before)?;
    let after_str = unix_to_generalized_time(not_after)?;

    let mut content = Vec::new();

    // notBefore GeneralizedTime
    content.push(0x18); // GeneralizedTime tag
    encode_length(before_str.len(), &mut content);
    content.extend_from_slice(before_str.as_bytes());

    // notAfter GeneralizedTime
    content.push(0x18); // GeneralizedTime tag
    encode_length(after_str.len(), &mut content);
    content.extend_from_slice(after_str.as_bytes());

    // Wrap in SEQUENCE
    let mut validity = Vec::new();
    validity.push(0x30); // SEQUENCE
    encode_length(content.len(), &mut validity);
    validity.extend_from_slice(&content);

    Ok(validity)
}

/// Convert Unix timestamp to GeneralizedTime format (YYYYMMDDHHMMSSZ).
fn unix_to_generalized_time(timestamp: u64) -> Result<String, ThresholdCaError> {
    use std::time::{Duration, UNIX_EPOCH};

    let time = UNIX_EPOCH + Duration::from_secs(timestamp);
    let datetime: chrono::DateTime<chrono::Utc> = time.into();
    Ok(datetime.format("%Y%m%d%H%M%SZ").to_string())
}

/// Encode Ed25519 SubjectPublicKeyInfo.
fn encode_ed25519_spki(public_key: &[u8; 32]) -> Vec<u8> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    // AlgorithmIdentifier for Ed25519: SEQUENCE { OID 1.3.101.112 }

    let mut content = Vec::new();

    // AlgorithmIdentifier
    content.extend_from_slice(&[
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, // OID, length 3
        0x2B, 0x65, 0x70, // 1.3.101.112 (Ed25519)
    ]);

    // BIT STRING (public key)
    // BIT STRING has a leading byte for unused bits (0 in our case)
    content.push(0x03); // BIT STRING tag
    content.push(0x21); // length 33 (1 + 32)
    content.push(0x00); // 0 unused bits
    content.extend_from_slice(public_key);

    // Wrap in SEQUENCE
    let mut spki = Vec::new();
    spki.push(0x30); // SEQUENCE
    encode_length(content.len(), &mut spki);
    spki.extend_from_slice(&content);

    spki
}

/// Encode X.509 v3 Extensions including Subject Alternative Name.
fn encode_extensions(spiffe_uri: &str) -> Result<Vec<u8>, ThresholdCaError> {
    // Build SAN extension
    // Extension ::= SEQUENCE { extnID, critical, extnValue }
    // SAN OID = 2.5.29.17

    // GeneralName for URI
    let uri_bytes = spiffe_uri.as_bytes();
    let mut general_name = Vec::new();
    general_name.push(0x86); // Context-specific tag 6 (URI)
    encode_length(uri_bytes.len(), &mut general_name);
    general_name.extend_from_slice(uri_bytes);

    // GeneralNames SEQUENCE
    let mut general_names = Vec::new();
    general_names.push(0x30); // SEQUENCE
    encode_length(general_name.len(), &mut general_names);
    general_names.extend_from_slice(&general_name);

    // extnValue OCTET STRING
    let mut extn_value = Vec::new();
    extn_value.push(0x04); // OCTET STRING
    encode_length(general_names.len(), &mut extn_value);
    extn_value.extend_from_slice(&general_names);

    // Extension SEQUENCE { OID, BOOLEAN (critical), OCTET STRING }
    let mut extension = Vec::new();
    extension.push(0x30); // SEQUENCE
    let ext_content_len = 4 + extn_value.len(); // OID(4) + extnValue
    encode_length(ext_content_len, &mut extension);
    extension.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x11]); // OID 2.5.29.17 (SAN)
    // Note: critical is optional and defaults to FALSE, so we omit it
    extension.extend_from_slice(&extn_value);

    // Extensions SEQUENCE
    let mut extensions = Vec::new();
    extensions.push(0x30); // SEQUENCE
    encode_length(extension.len(), &mut extensions);
    extensions.extend_from_slice(&extension);

    // [3] EXPLICIT wrapper
    let mut explicit = Vec::new();
    explicit.push(0xA3); // Context-specific, constructed, tag 3
    encode_length(extensions.len(), &mut explicit);
    explicit.extend_from_slice(&extensions);

    Ok(explicit)
}

/// Assemble a complete X.509 certificate from TBS and signature.
///
/// # Arguments
///
/// * `tbs_der` - The DER-encoded TBSCertificate
/// * `signature` - The FROST signature over the TBS
///
/// # Returns
///
/// DER-encoded X.509 Certificate that can be used for TLS.
pub fn assemble_certificate(tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, ThresholdCaError> {
    // Certificate ::= SEQUENCE {
    //   tbsCertificate       TBSCertificate,
    //   signatureAlgorithm   AlgorithmIdentifier,
    //   signature            BIT STRING
    // }

    let mut content = Vec::with_capacity(tbs_der.len() + signature.len() + 20);

    // TBSCertificate (already DER-encoded)
    content.extend_from_slice(tbs_der);

    // SignatureAlgorithm (Ed25519)
    content.extend_from_slice(&[
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, // OID, length 3
        0x2B, 0x65, 0x70, // 1.3.101.112 (Ed25519)
    ]);

    // Signature BIT STRING
    content.push(0x03); // BIT STRING tag
    encode_length(signature.len() + 1, &mut content);
    content.push(0x00); // 0 unused bits
    content.extend_from_slice(signature);

    // Wrap in SEQUENCE
    let mut cert = Vec::new();
    cert.push(0x30); // SEQUENCE
    encode_length(content.len(), &mut cert);
    cert.extend_from_slice(&content);

    Ok(cert)
}

/// Verify that a TBS certificate was signed by the threshold CA.
#[allow(dead_code)]
pub fn verify_tbs_signature(
    tbs: &[u8],
    signature: &[u8],
    ca_public_key: &CaPublicKey,
) -> Result<bool, ThresholdCaError> {
    let pubkey_package = ca_public_key.pubkey_package()?;

    let frost_sig = frost::Signature::deserialize(signature)
        .map_err(|e| ThresholdCaError::Serialization(e.to_string()))?;

    Ok(pubkey_package
        .verifying_key()
        .verify(tbs, &frost_sig)
        .is_ok())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_identities(count: usize) -> Vec<Identity> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        (0..count)
            .map(|_| {
                let signing_key = SigningKey::generate(&mut OsRng);
                Identity::from_bytes(signing_key.verifying_key().to_bytes())
            })
            .collect()
    }

    #[test]
    fn test_config_validation() {
        // Valid config
        assert!(ThresholdCaConfig::new(5, 3, "test.domain").is_ok());

        // Invalid: too few signers
        assert!(ThresholdCaConfig::new(2, 2, "test.domain").is_err());

        // Invalid: min > max
        assert!(ThresholdCaConfig::new(5, 6, "test.domain").is_err());

        // Invalid: min < 2
        assert!(ThresholdCaConfig::new(5, 1, "test.domain").is_err());
    }

    #[test]
    fn test_signer_registry() {
        let identities = generate_test_identities(5);
        let registry = SignerRegistry::from_identities(identities.clone());

        assert_eq!(registry.len(), 5);

        // All identities should have FROST IDs
        for identity in &identities {
            assert!(registry.get_frost_id(identity).is_some());
        }

        // FROST IDs should be 1..=5
        for i in 1u16..=5 {
            let frost_id: Identifier = i.try_into().unwrap();
            assert!(registry.get_identity(frost_id).is_some());
        }
    }

    #[test]
    fn test_full_dkg_and_signing() {
        // This test simulates the full DKG and signing protocol locally
        let identities = generate_test_identities(5);
        let config = ThresholdCaConfig::new(5, 3, "test.domain").unwrap();

        // Create coordinators for each participant
        let coordinators: Vec<_> = identities
            .iter()
            .map(|id| DkgCoordinator::new(config.clone(), identities.clone(), id.clone()).unwrap())
            .collect();

        // Round 1: Generate commitments
        let mut round1_secrets: Vec<Option<DkgRound1Secret>> = Vec::new();
        let mut round1_messages = Vec::new();

        for coord in &coordinators {
            let (secret, msg) = coord.round1().unwrap();
            round1_secrets.push(Some(secret));
            round1_messages.push(msg);
        }

        // Round 2: Generate shares
        let mut round2_secrets = Vec::new();
        let mut round2_messages = Vec::new();

        for (i, coord) in coordinators.iter().enumerate() {
            let secret = round1_secrets[i].take().unwrap();
            let (secret2, msgs) = coord.round2(secret, &round1_messages).unwrap();
            round2_secrets.push(secret2);
            round2_messages.extend(msgs);
        }

        // Round 3: Finalize
        let mut signer_states = Vec::new();

        for (i, coord) in coordinators.iter().enumerate() {
            let state = coord
                .round3(&round2_secrets[i], &round1_messages, &round2_messages)
                .unwrap();
            signer_states.push(state);
        }

        // Verify all signers have the same CA public key
        let ca_pubkey_bytes = signer_states[0].ca_public_key_bytes();
        for state in &signer_states[1..] {
            assert_eq!(state.ca_public_key_bytes(), ca_pubkey_bytes);
        }

        // Test signing with 3 signers (threshold)
        let message = b"test certificate data";

        // Generate commitments from first 3 signers
        let mut nonces: Vec<Option<SigningNonce>> = Vec::new();
        let mut commitments = Vec::new();

        for state in signer_states.iter().take(3) {
            let (nonce, commitment) = generate_signing_commitment(state).unwrap();
            nonces.push(Some(nonce));
            commitments.push((state.identifier(), commitment));
        }

        // Generate signature shares
        let mut shares = Vec::new();

        for (i, state) in signer_states.iter().take(3).enumerate() {
            let nonce = nonces[i].take().unwrap();
            let share = sign_with_share(state, nonce, message, &commitments).unwrap();
            shares.push((state.identifier(), share));
        }

        // Aggregate signatures
        let signature = aggregate_signatures(
            &signer_states[0].pubkey_package,
            message,
            &commitments,
            &shares,
        )
        .unwrap();

        // Verify signature
        let valid =
            verify_ca_signature(&signer_states[0].pubkey_package, message, &signature).unwrap();
        assert!(valid);

        // Verify with different message fails
        let invalid = verify_ca_signature(
            &signer_states[0].pubkey_package,
            b"different message",
            &signature,
        )
        .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_signer_state_serialization() {
        let identities = generate_test_identities(3);
        let config = ThresholdCaConfig::new(3, 2, "test.domain").unwrap();

        // Run minimal DKG
        let coordinators: Vec<_> = identities
            .iter()
            .map(|id| DkgCoordinator::new(config.clone(), identities.clone(), id.clone()).unwrap())
            .collect();

        let mut round1_secrets: Vec<Option<DkgRound1Secret>> = Vec::new();
        let mut round1_messages = Vec::new();
        for coord in &coordinators {
            let (secret, msg) = coord.round1().unwrap();
            round1_secrets.push(Some(secret));
            round1_messages.push(msg);
        }

        let mut round2_secrets = Vec::new();
        let mut round2_messages = Vec::new();
        for (i, coord) in coordinators.iter().enumerate() {
            let secret = round1_secrets[i].take().unwrap();
            let (secret2, msgs) = coord.round2(secret, &round1_messages).unwrap();
            round2_secrets.push(secret2);
            round2_messages.extend(msgs);
        }

        let state = coordinators[0]
            .round3(&round2_secrets[0], &round1_messages, &round2_messages)
            .unwrap();

        // Serialize and deserialize
        let serialized = state.serialize().unwrap();
        let deserialized = SignerState::deserialize(&serialized).unwrap();

        // Verify CA public key matches
        assert_eq!(
            state.ca_public_key_bytes(),
            deserialized.ca_public_key_bytes()
        );
    }

    #[test]
    fn test_generate_csr_produces_valid_der() {
        use crate::identity::Keypair;

        let keypair = Keypair::generate();
        let csr = generate_csr(&keypair, "test.domain", Some("workload"), 86400).unwrap();

        // Verify TBS DER structure starts with SEQUENCE
        assert!(!csr.tbs_der.is_empty());
        assert_eq!(csr.tbs_der[0], 0x30, "TBS must start with SEQUENCE tag");

        // Verify we can parse the length
        let len_byte = csr.tbs_der[1];
        if len_byte < 0x80 {
            // Short form length
            assert!(csr.tbs_der.len() >= (2 + len_byte as usize));
        } else if len_byte == 0x81 {
            // Long form, 1 byte length
            assert!(csr.tbs_der.len() >= 3);
            let actual_len = csr.tbs_der[2] as usize;
            assert_eq!(csr.tbs_der.len(), 3 + actual_len);
        } else if len_byte == 0x82 {
            // Long form, 2 byte length
            assert!(csr.tbs_der.len() >= 4);
            let actual_len = ((csr.tbs_der[2] as usize) << 8) | (csr.tbs_der[3] as usize);
            assert_eq!(csr.tbs_der.len(), 4 + actual_len);
        }

        // Verify SPIFFE ID is embedded
        assert!(csr.spiffe_id.starts_with("spiffe://test.domain/"));
        assert!(csr.spiffe_id.contains("/workload"));

        // Verify params are populated
        assert!(csr.params.common_name.starts_with("korium-node-"));
        assert!(csr.params.not_after > csr.params.not_before);

        // Verify public key is set
        assert_eq!(csr.subject_public_key, keypair.public_key_bytes());
    }

    #[test]
    fn test_assemble_certificate_produces_valid_der() {
        use crate::identity::Keypair;

        let keypair = Keypair::generate();
        let csr = generate_csr(&keypair, "test.domain", None, 3600).unwrap();

        // Create a mock signature (64 bytes for Ed25519)
        let mock_signature = [0u8; 64];

        let cert = assemble_certificate(&csr.tbs_der, &mock_signature).unwrap();

        // Verify certificate structure
        assert!(!cert.is_empty());
        assert_eq!(cert[0], 0x30, "Certificate must start with SEQUENCE tag");

        // Verify TBS is embedded at the start of the certificate content
        // Skip the outer SEQUENCE header to find TBS
        let tbs_offset = if cert[1] < 0x80 {
            2
        } else if cert[1] == 0x81 {
            3
        } else {
            4
        };
        assert_eq!(
            &cert[tbs_offset..tbs_offset + 10],
            &csr.tbs_der[..10],
            "TBS should be at start of certificate content"
        );

        // Certificate should be longer than TBS (adds signature algorithm + signature)
        assert!(cert.len() > csr.tbs_der.len() + 64);
    }
}
