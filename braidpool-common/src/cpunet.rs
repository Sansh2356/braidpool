//! Cpunet implementation
//!
//! Provides cpunet-specific functionality including:
//! - Block hash computation (appending "cpunet\0" before double-SHA256)
//! - Bech32 address encoding/decoding with "tc" HRP
//! - Consensus parameters
//!
//! Referenced: https://github.com/braidpool/rust-bitcoin/tree/cpunet

use bitcoin::{
    bech32,
    block::Header as BlockHeader,
    hashes::{sha256d, Hash, HashEngine},
    BlockHash, ScriptBuf, Target, WitnessProgram,
};
use core::fmt;
use std::str::FromStr;

/// Human-readable part for cpunet bech32 addresses: "tc"
pub const CPUNET_HRP: &str = "tc";

/// The core-arg name along with that the actual network name as string-slice
pub const CPUNET_NAME: &str = "cpunet";

/// Error type for parsing cpunet from string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCpunetError(pub String);

impl fmt::Display for ParseCpunetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse '{}' as cpunet", self.0)
    }
}

impl std::error::Error for ParseCpunetError {}

/// Error type for cpunet address operations.
#[derive(Debug, Clone)]
pub enum CpunetAddressError {
    /// Bech32 decoding error
    Bech32(bech32::segwit::DecodeError),
    /// Wrong network HRP
    WrongNetwork { expected: String, found: String },
    /// Invalid witness version
    InvalidWitnessVersion(u8),
    /// Invalid witness program
    InvalidProgram(String),
}

impl fmt::Display for CpunetAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bech32(e) => write!(f, "bech32 decode error: {}", e),
            Self::WrongNetwork { expected, found } => {
                write!(
                    f,
                    "wrong network: expected '{}', found '{}'",
                    expected, found
                )
            }
            Self::InvalidWitnessVersion(v) => write!(f, "invalid witness version: {}", v),
            Self::InvalidProgram(e) => write!(f, "invalid witness program: {}", e),
        }
    }
}

impl std::error::Error for CpunetAddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bech32(e) => Some(e),
            _ => None,
        }
    }
}

/// Cpunet consensus parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpunetParams {
    /// BIP16 activation time
    pub bip16_time: u32,
    /// BIP34 activation height
    pub bip34_height: u32,
    /// BIP65 activation height
    pub bip65_height: u32,
    /// BIP66 activation height
    pub bip66_height: u32,
    /// Whether to enforce BIP94 (testnet4 rules)
    pub enforce_bip94: bool,
    /// Threshold for rule change activation (75% = 1512 of 2016)
    pub rule_change_activation_threshold: u32,
    /// Miner confirmation window for soft forks
    pub miner_confirmation_window: u32,
    /// Maximum proof-of-work target (minimum difficulty)
    pub pow_limit: Target,
    /// Maximum attainable target value
    pub max_attainable_target: Target,
    /// Target block spacing in seconds (10 minutes)
    pub pow_target_spacing: u32,
    /// Target timespan for difficulty adjustment (2 weeks)
    pub pow_target_timespan: u32,
    /// Whether minimum difficulty blocks are allowed
    pub allow_min_difficulty_blocks: bool,
    /// Whether PoW retargeting is disabled
    pub no_pow_retargeting: bool,
}

impl Default for CpunetParams {
    fn default() -> Self {
        Self::new()
    }
}

impl CpunetParams {
    pub const fn new() -> Self {
        Self {
            bip16_time: 1333238400, // Apr 1 2012
            bip34_height: 1,
            bip65_height: 1,
            bip66_height: 1,
            enforce_bip94: false,
            rule_change_activation_threshold: 1512, // 75%
            miner_confirmation_window: 2016,
            pow_limit: Target::MAX_ATTAINABLE_MAINNET,
            max_attainable_target: Target::MAX_ATTAINABLE_MAINNET,
            pow_target_spacing: 10 * 60,            // 10 minutes
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            allow_min_difficulty_blocks: false,
            no_pow_retargeting: false,
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub const fn difficulty_adjustment_interval(&self) -> u32 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

/// Implementation of Cpunet specific `Network` and `Address` decoding/encoding functionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cpunet;

impl Cpunet {
    #[inline]
    pub const fn bech32_hrp() -> &'static str {
        CPUNET_HRP
    }

    #[inline]
    pub const fn name() -> &'static str {
        CPUNET_NAME
    }

    #[inline]
    pub fn is_cpunet_name(name: &str) -> bool {
        matches!(name.to_lowercase().as_str(), "cpunet")
    }

    #[inline]
    pub fn is_cpunet_hrp(hrp: &str) -> bool {
        hrp.eq_ignore_ascii_case(CPUNET_HRP)
    }

    /// Encodes a witness program as a cpunet bech32m or bech32 address depending upon
    /// `WitnessVersion` for non-taproot and taproot specific addresses.
    pub fn encode_bech32_address(program: &WitnessProgram) -> String {
        let hrp = bech32::Hrp::parse(CPUNET_HRP).unwrap();
        let version = bech32::Fe32::try_from(program.version().to_num())
            .expect("witness version is valid fe32");
        bech32::segwit::encode(hrp, version, program.program().as_bytes())
            .expect("valid witness program encodes successfully")
    }

    /// Decodes a cpunet bech32 address string.
    ///
    /// Returns the script pubkey (ScriptBuf) for the decoded address.
    pub fn decode_bech32_address(address: &str) -> Result<ScriptBuf, CpunetAddressError> {
        let (hrp, version, data) =
            bech32::segwit::decode(address).map_err(CpunetAddressError::Bech32)?;

        // Verify HRP is cpunet
        if !hrp.as_str().eq_ignore_ascii_case(CPUNET_HRP) {
            return Err(CpunetAddressError::WrongNetwork {
                expected: CPUNET_HRP.to_string(),
                found: hrp.to_string(),
            });
        }

        let witness_version = bitcoin::WitnessVersion::try_from(version.to_u8())
            .map_err(|_| CpunetAddressError::InvalidWitnessVersion(version.to_u8()))?;
        let witness_program = WitnessProgram::new(witness_version, &data)
            .map_err(|e| CpunetAddressError::InvalidProgram(e.to_string()))?;

        Ok(ScriptBuf::new_witness_program(&witness_program))
    }

    /// Returns the cpunet-specific block hash.
    ///
    /// Cpunet block hash is computed by appending "cpunet\0" to the serialized header
    /// before performing double-SHA256.
    pub fn block_hash(header: BlockHeader) -> BlockHash {
        let mut engine = sha256d::Hash::engine();
        engine.input(&header.version.to_consensus().to_le_bytes());
        engine.input(header.prev_blockhash.as_byte_array());
        engine.input(header.merkle_root.as_byte_array());
        engine.input(&header.time.to_le_bytes());
        engine.input(&header.bits.to_consensus().to_le_bytes());
        engine.input(&header.nonce.to_le_bytes());
        engine.input("cpunet\0".as_bytes());

        BlockHash::from_byte_array(sha256d::Hash::from_engine(engine).to_byte_array())
    }
}

impl fmt::Display for Cpunet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", CPUNET_NAME)
    }
}

impl FromStr for Cpunet {
    type Err = ParseCpunetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Cpunet::is_cpunet_name(s) {
            Ok(Cpunet)
        } else {
            Err(ParseCpunetError(s.to_owned()))
        }
    }
}

/// Utility function to compute block hash according to the network type.
///
/// For cpunet, uses the cpunet-specific hash algorithm (appending "cpunet\0").
/// For all other networks, uses the standard Bitcoin block hash.
///
/// # Arguments
/// * `block_header` - The block header to hash
/// * `network_type` - Network name string ("cpunet", "mainnet", "testnet4", etc.)
///
/// # Returns
/// The computed block hash appropriate for the network.
pub fn compute_block_hash(block_header: &BlockHeader, network_type: &str) -> BlockHash {
    if network_type == "cpunet" {
        Cpunet::block_hash(*block_header)
    } else {
        block_header.block_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::WitnessVersion;

    #[test]
    fn cpunet_hrp_check() {
        assert!(Cpunet::is_cpunet_hrp("tc"));
        assert!(Cpunet::is_cpunet_hrp("TC"));
        assert!(!Cpunet::is_cpunet_hrp("bc"));
        assert!(!Cpunet::is_cpunet_hrp("tb"));
    }

    #[test]
    fn cpunet_from_str() {
        assert!(Cpunet::from_str("cpunet").is_ok());
        assert!(Cpunet::from_str("mainnet").is_err());
    }

    #[test]
    fn cpunet_address_roundtrip() {
        let program_bytes = [0u8; 20];
        let program =
            WitnessProgram::new(WitnessVersion::V0, &program_bytes).expect("valid witness program");

        let address = Cpunet::encode_bech32_address(&program);
        assert!(address.starts_with("tc1"));

        let decoded_script = Cpunet::decode_bech32_address(&address).expect("should decode");
        assert!(decoded_script.is_witness_program());
        let expected_script = bitcoin::ScriptBuf::new_witness_program(&program);
        assert_eq!(decoded_script, expected_script);
    }

    #[test]
    fn cpunet_wrong_network_address() {
        let mainnet_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = Cpunet::decode_bech32_address(mainnet_addr);
        assert!(matches!(
            result,
            Err(CpunetAddressError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn compute_block_hash_cpunet_vs_standard() {
        use bitcoin::block::{Header, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::{CompactTarget, TxMerkleNode};

        let header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        };

        let cpunet_hash = compute_block_hash(&header, "cpunet");
        let mainnet_hash = compute_block_hash(&header, "mainnet");

        // Cpunet and mainnet hashes should be different due to "cpunet\0" suffix
        assert_ne!(cpunet_hash, mainnet_hash);

        // Verify cpunet hash matches Cpunet::block_hash
        assert_eq!(cpunet_hash, Cpunet::block_hash(header));

        // Verify mainnet hash matches standard block_hash
        assert_eq!(mainnet_hash, header.block_hash());
    }
}
