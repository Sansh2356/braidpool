use crate::committed_metadata::CommittedMetadata;
use crate::config::PoolNetwork;
use crate::uncommitted_metadata::UnCommittedMetadata;
use crate::utils::BeadHash;
use async_trait::async_trait;
use bitcoin::block::Header as BlockHeader;
use bitcoin::block::Version as BlockVersion;
use bitcoin::consensus::encode::Decodable;
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};

/// Collection of beads.
///
/// Newtype wrapper around `Vec<Bead>` that provides Bitcoin consensus encoding/decoding
/// and convenient iteration methods. Used to work around Rust's orphan rule.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Beads(pub Vec<Bead>);
impl_vec_wrapper!(Beads, Bead);

/// Collection of bead hashes.
///
/// Newtype wrapper around `Vec<BeadHash>` that provides Bitcoin consensus encoding/decoding
/// and convenient iteration methods. Used for requesting and responding with bead identifiers.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BeadHashes(pub Vec<BeadHash>);
impl_vec_wrapper!(BeadHashes, BeadHash);

/// A bead in the Braidpool DAG structure.
///
/// A bead represents a weak share in the Braidpool mining protocol. It combines a Bitcoin
/// block header with metadata about the mining process and network topology.
///
/// **Fields:**
/// - `block_header`: Standard Bitcoin block header with proof-of-work
/// - `committed_metadata`: Metadata committed to the block (parents, timestamps, transactions)
/// - `uncommitted_metadata`: Metadata not part of the hash (signature, broadcast time)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Bead {
    pub block_header: BlockHeader,
    pub committed_metadata: CommittedMetadata,
    pub uncommitted_metadata: UnCommittedMetadata,
}
impl Bead {
    /// Returns the plain Bitcoin hash of this bead's block header.
    pub fn hash(&self) -> BeadHash {
        self.block_header.block_hash()
    }

    /// Returns the predefined genesis bead of `network`, the single root every braid starts from.
    pub fn genesis(network: PoolNetwork) -> Bead {
        use crate::utils::timestamp::MicrosecondTimestamp;
        use crate::{TimeVec, TxIdVec};

        // 2026-01-01T00:00:00Z
        const GENESIS_TIME_SECS: u32 = 1_767_225_600;
        const GENESIS_TARGET: u32 = 0x1d00ffff;
        const GENESIS_PUBKEY: &str =
            "020202020202020202020202020202020202020202020202020202020202020202";
        const GENESIS_SIGNATURE: &str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";

        let genesis_time = MicrosecondTimestamp::from_secs(GENESIS_TIME_SECS);
        // The constants above are valid encodings; `genesis_is_deterministic` checks them.
        let comm_pub_key = GENESIS_PUBKEY
            .parse::<bitcoin::PublicKey>()
            .expect("genesis public key is a valid compressed key");
        let signature_der = hex::decode(GENESIS_SIGNATURE).expect("genesis signature is valid hex");
        let signature = bitcoin::ecdsa::Signature {
            signature: bitcoin::secp256k1::ecdsa::Signature::from_der(&signature_der)
                .expect("genesis signature is valid DER"),
            sighash_type: bitcoin::sighash::EcdsaSighashType::All,
        };

        Bead {
            block_header: BlockHeader {
                version: BlockVersion::ONE,
                prev_blockhash: network.genesis_block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: GENESIS_TIME_SECS,
                bits: CompactTarget::from_consensus(GENESIS_TARGET),
                nonce: 0,
            },
            committed_metadata: CommittedMetadata {
                transaction_ids: TxIdVec(Vec::new()),
                parents: Vec::new(),
                parent_bead_timestamps: TimeVec(Vec::new()),
                payout_address: "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97"
                    .to_string(),
                start_timestamp: genesis_time,
                comm_pub_key,
                min_target: CompactTarget::from_consensus(GENESIS_TARGET),
                weak_target: CompactTarget::from_consensus(GENESIS_TARGET),
                miner_ip: "system".to_string(),
            },
            uncommitted_metadata: UnCommittedMetadata {
                extra_nonce_1: 0,
                extra_nonce_2: 0,
                broadcast_timestamp: genesis_time,
                signature,
            },
        }
    }
}
impl_consensus_encoding!(Bead, block_header, committed_metadata, uncommitted_metadata);

impl Default for Bead {
    fn default() -> Self {
        let empty_merkle_bytes: [u8; 32] = [0; 32];
        Self {
            block_header: BlockHeader {
                bits: CompactTarget::from_consensus(1),
                merkle_root: TxMerkleNode::from_byte_array(empty_merkle_bytes),
                nonce: 0,
                prev_blockhash: BlockHash::all_zeros(),
                time: 0,
                version: BlockVersion::TWO,
            },
            committed_metadata: CommittedMetadata::default(),
            uncommitted_metadata: UnCommittedMetadata::default(),
        }
    }
}

braidpool_protocol! {
    /// Request types for bead synchronization protocol.
    ///
    /// Used in the request-response protocol to request beads from remote peers.
    /// Each variant maps to a specific opcode for network encoding.
    ///
    /// **Variants:**
    /// - `GetBeads(BeadHashes)`: Request specific beads by their hashes
    /// - `GetTips`: Request the current DAG tips
    /// - `GetGenesis`: Request the genesis bead(s)
    /// - `GetAllBeads`: Request all beads (for IBD)
    /// - `GetBeadsAfter(BeadHashes)`: Request all beads after specified hashes (for sync)
    pub enum BeadRequest {
        GetBeads(BeadHashes)        = 0,
        GetTips                     = 1,
        GetGenesis                  = 2,
        GetAllBeads                 = 3,
        GetBeadsAfter(BeadHashes)   = 4,
    }
}

braidpool_protocol! {
    /// Response types for bead synchronization protocol.
    ///
    /// Responses to `BeadRequest` messages. Contains either the requested data
    /// or an error explaining why the request couldn't be fulfilled.
    ///
    /// **Variants:**
    /// - `Beads(Beads)`: Response containing requested beads
    /// - `Tips(BeadHashes)`: Response containing current DAG tip hashes
    /// - `Genesis(BeadHashes)`: Response containing genesis bead hash(es)
    /// - `GetAllBeads(Beads)`: Response containing all beads (for IBD)
    /// - `GetBeadsAfter(BeadHashes)`: Response containing beads after specified hashes
    /// - `Error(BeadSyncError)`: Error response indicating why request failed
    pub enum BeadResponse {
        Beads(Beads)                = 0,
        Tips(BeadHashes)            = 1,
        Genesis(BeadHashes)         = 2,
        GetAllBeads(Beads)          = 3,
        GetBeadsAfter(BeadHashes)   = 4,
        Error(BeadSyncError)        = 5,
    }
}

braidpool_protocol! {
    /// Errors that can occur during bead synchronization.
    ///
    /// These errors are returned in `BeadResponse::Error` to indicate
    /// why a bead request could not be fulfilled.
    ///
    /// **Variants:**
    /// - `GenesisMismatch`: The peers' genesis beads differ
    /// - `BeadHashNotFound`: Requested bead hash not found in local store
    pub enum BeadSyncError {
        GenesisMismatch     = 0,
        BeadHashNotFound    = 1,
    }
}

/// Codec for encoding/decoding bead sync messages over libp2p.
///
/// Implements the `libp2p::request_response::Codec` trait to handle serialization
/// of `BeadRequest` and `BeadResponse` messages using Bitcoin consensus encoding.
#[derive(Clone, Default)]
pub struct BeadCodec;

#[async_trait]
impl Codec for BeadCodec {
    type Protocol = StreamProtocol;
    type Request = BeadRequest;
    type Response = BeadResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> IoResult<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        BeadRequest::consensus_decode(&mut buf.as_slice())
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> IoResult<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        BeadResponse::consensus_decode(&mut buf.as_slice())
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> IoResult<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut buf = Vec::new();
        request
            .consensus_encode(&mut buf)
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
        io.write_all(&buf)
            .await
            .map_err(|e| IoError::new(ErrorKind::Other, e))
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> IoResult<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut buf = Vec::new();
        response
            .consensus_encode(&mut buf)
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
        io.write_all(&buf)
            .await
            .map_err(|e| IoError::new(ErrorKind::Other, e))
    }
}

#[cfg(test)]
mod tests;
