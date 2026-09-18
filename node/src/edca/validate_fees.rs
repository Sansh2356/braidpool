use crate::bead::Bead;
use crate::config::PoolNetwork;
use crate::error::FeeProofError;
use bitcoin::blockdata::block::Block;
use bitcoin::{Amount, FeeRate, Network, OutPoint, Transaction, TxMerkleNode, TxOut, Txid, Weight};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Block subsidy at height zero or genesis block in satoshis .
const INITIAL_SUBSIDY_SATS: u64 = 5_000_000_000;

/// Returns the number of blocks between subsidy halvings on `network`.
pub fn subsidy_halving_interval(network: PoolNetwork) -> u64 {
    match network {
        PoolNetwork::Bitcoin(Network::Regtest) => 150,
        PoolNetwork::Cpunet | PoolNetwork::Bitcoin(_) => 210_000,
    }
}

/// Returns the block subsidy at `height` on `network`, in satoshis.
pub fn block_subsidy_sats(height: u64, network: PoolNetwork) -> u64 {
    let halvings = height / subsidy_halving_interval(network);
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY_SATS >> halvings
}

/// The fee claim of a bead, checked against its coinbase and proof of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeCommitment {
    /// Block height committed in the coinbase under BIP34.
    pub height: u64,
    /// The block subsidy at `height`, in satoshis.
    pub subsidy_sats: u64,
    /// Sum of the coinbase outputs, in satoshis.
    pub coinbase_value_sats: u64,
    /// The committed fee total `F_i`, equal to
    /// `(coinbase_value_sats - subsidy_sats)`.
    pub fee_total_sats: u64,
}

/// Checks that the bead's claimed fee total is committed to by its proof of work.
pub fn verify_fee_commitment(
    bead: &Bead,
    coinbase: &Transaction,
    network: PoolNetwork,
) -> Result<FeeCommitment, FeeProofError> {
    if !coinbase.is_coinbase() {
        return Err(FeeProofError::NotCoinbase);
    }

    let transaction_ids = &bead.committed_metadata.transaction_ids.0;
    let committed_coinbase_txid = transaction_ids
        .first()
        .copied()
        .ok_or(FeeProofError::NoTransactions)?;
    let coinbase_txid = coinbase.compute_txid();
    if coinbase_txid != committed_coinbase_txid {
        return Err(FeeProofError::CoinbaseTxidMismatch {
            committed: committed_coinbase_txid,
            computed: coinbase_txid,
        });
    }

    // A valid block never repeats a txid.
    let mut seen: HashSet<&Txid> = HashSet::with_capacity(transaction_ids.len());
    if let Some(duplicate) = transaction_ids.iter().find(|txid| !seen.insert(*txid)) {
        return Err(FeeProofError::DuplicateTxid { txid: *duplicate });
    }

    let computed_root = bitcoin::merkle_tree::calculate_root(
        transaction_ids
            .iter()
            .map(|txid| TxMerkleNode::from_raw_hash(txid.to_raw_hash())),
    )
    .ok_or(FeeProofError::NoTransactions)?;
    if computed_root != bead.block_header.merkle_root {
        return Err(FeeProofError::MerkleRootMismatch {
            header: bead.block_header.merkle_root,
            computed: computed_root,
        });
    }

    let height = Block {
        header: bead.block_header,
        txdata: vec![coinbase.clone()],
    }
    .bip34_block_height()
    .map_err(|error| FeeProofError::InvalidBip34Height {
        error: error.to_string(),
    })?;
    let subsidy_sats = block_subsidy_sats(height, network);

    let coinbase_value_sats = coinbase
        .output
        .iter()
        .try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat())
        })
        .filter(|total| *total <= Amount::MAX_MONEY.to_sat())
        .ok_or(FeeProofError::CoinbaseValueOverflow)?;

    let derived_fee_sats = coinbase_value_sats.checked_sub(subsidy_sats).ok_or(
        FeeProofError::CoinbaseBelowSubsidy {
            coinbase_value_sats,
            subsidy_sats,
        },
    )?;
    let claimed_fee_sats = bead.committed_metadata.fee_total_sats;
    if derived_fee_sats != claimed_fee_sats {
        return Err(FeeProofError::FeeCommitmentMismatch {
            claimed_fee_sats,
            derived_fee_sats,
        });
    }

    Ok(FeeCommitment {
        height,
        subsidy_sats,
        coinbase_value_sats,
        fee_total_sats: claimed_fee_sats,
    })
}

/// Fees of transactions the verifying node has validated itself.
pub trait TxFeeSource {
    /// Returns the fee paid by `txid` in satoshis, or `None` if the transaction
    /// is unknown to this node.
    fn fee_sats(&self, txid: &Txid) -> Option<u64>;
}

impl TxFeeSource for HashMap<Txid, u64> {
    fn fee_sats(&self, txid: &Txid) -> Option<u64> {
        self.get(txid).copied()
    }
}

impl TxFeeSource for BTreeMap<Txid, u64> {
    fn fee_sats(&self, txid: &Txid) -> Option<u64> {
        self.get(txid).copied()
    }
}

impl TxFeeSource for HashMap<Txid, TransactionFee> {
    fn fee_sats(&self, txid: &Txid) -> Option<u64> {
        self.get(txid).map(|fee| fee.fee.to_sat())
    }
}

/// Outputs a transaction spends, as the verifier's node knows them.
pub trait PrevoutSource {
    /// Returns the output `outpoint` spends, or `None` if this node does not
    /// know it.
    fn prevout(&self, outpoint: &OutPoint) -> Option<TxOut>;
}

impl PrevoutSource for HashMap<OutPoint, TxOut> {
    fn prevout(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.get(outpoint).cloned()
    }
}

impl PrevoutSource for BTreeMap<OutPoint, TxOut> {
    fn prevout(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.get(outpoint).cloned()
    }
}

/// The fee a single transaction pays, with the weight it pays it over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionFee {
    /// `sum(inputs) - sum(outputs)`.
    pub fee: Amount,
    /// Consensus weight of the transaction, for its fee rate.
    pub weight: Weight,
}

impl TransactionFee {
    /// Returns the fee rate .
    pub fn fee_rate(&self) -> Option<FeeRate> {
        self.fee
            .to_sat()
            .checked_mul(1_000)
            .and_then(|scaled| scaled.checked_div(self.weight.to_wu()))
            .map(FeeRate::from_sat_per_kwu)
    }
}

/// Computes the fee a transaction pays as `sum(inputs) - sum(outputs)`.
pub fn transaction_fee(
    transaction: &Transaction,
    prevouts: &dyn PrevoutSource,
) -> Result<TransactionFee, FeeProofError> {
    if transaction.is_coinbase() {
        return Err(FeeProofError::CoinbaseHasNoFee);
    }
    let txid = transaction.compute_txid();
    let max_money = Amount::MAX_MONEY.to_sat();

    let mut input_sats: u64 = 0;
    for input in &transaction.input {
        let prevout =
            prevouts
                .prevout(&input.previous_output)
                .ok_or(FeeProofError::MissingPrevout {
                    txid,
                    outpoint: input.previous_output,
                })?;
        input_sats = input_sats
            .checked_add(prevout.value.to_sat())
            .filter(|total| *total <= max_money)
            .ok_or(FeeProofError::FeeOutOfRange { txid })?;
    }

    let mut output_sats: u64 = 0;
    for output in &transaction.output {
        output_sats = output_sats
            .checked_add(output.value.to_sat())
            .filter(|total| *total <= max_money)
            .ok_or(FeeProofError::FeeOutOfRange { txid })?;
    }

    let fee_sats = input_sats
        .checked_sub(output_sats)
        .ok_or(FeeProofError::NegativeFee {
            txid,
            input_sats,
            output_sats,
        })?;

    Ok(TransactionFee {
        fee: Amount::from_sat(fee_sats),
        weight: transaction.weight(),
    })
}

/// Computes the fee of every non-coinbase transaction in a block or template.
pub fn compute_block_fees(
    block: &Block,
    prevouts: &dyn PrevoutSource,
) -> Result<HashMap<Txid, TransactionFee>, FeeProofError> {
    let transactions = block.txdata.get(1..).unwrap_or_default();
    let mut fees: HashMap<Txid, TransactionFee> = HashMap::with_capacity(transactions.len());
    // Outputs the block creates, minus the ones it has already spent.
    let mut in_block: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut spent: HashSet<OutPoint> = HashSet::new();

    for (index, transaction) in block.txdata.iter().enumerate() {
        let txid = transaction.compute_txid();

        if index > 0 {
            for input in &transaction.input {
                if !spent.insert(input.previous_output) {
                    return Err(FeeProofError::DuplicateSpend {
                        txid,
                        outpoint: input.previous_output,
                    });
                }
            }
            let inter_val = IntermediateState {
                in_block: &in_block,
                prevouts,
            };
            fees.insert(txid, transaction_fee(transaction, &inter_val)?);
        }

        for (vout, output) in transaction.output.iter().enumerate() {
            in_block.insert(
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                output.clone(),
            );
        }
    }

    Ok(fees)
}

/// Outputs created earlier in the block being summed, layered over the node's
/// own prevouts.
struct IntermediateState<'a> {
    in_block: &'a HashMap<OutPoint, TxOut>,
    prevouts: &'a dyn PrevoutSource,
}

impl PrevoutSource for IntermediateState<'_> {
    fn prevout(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.in_block
            .get(outpoint)
            .cloned()
            .or_else(|| self.prevouts.prevout(outpoint))
    }
}

/// Result of checking a committed fee total against known transaction fees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeBound {
    /// The known fees cover the claimed fee total, so the claim is proven.
    Proven {
        /// Sum of the fees the verifier knows, in satoshis.
        computed_fees: u64,
    },
    /// Some transactions are unknown and the known fees do not cover the
    /// claim, so it can be neither proven nor refuted yet.
    Undecided {
        /// Sum of the fees the verifier knows, in satoshis.
        computed_fees: u64,
        /// Committed transactions whose fee the verifier does not know.
        missing: Vec<Txid>,
    },
}

/// Checks that a committed fee total does not exceed the fees of the bead's
/// transactions.
pub fn verify_fee_bound(
    bead: &Bead,
    commitment: &FeeCommitment,
    fees: &dyn TxFeeSource,
) -> Result<FeeBound, FeeProofError> {
    let mut computed_fees: u64 = 0;
    let mut missing: Vec<Txid> = Vec::new();

    // Index 0 is the coinbase, which pays no fee.
    for txid in bead.committed_metadata.transaction_ids.0.iter().skip(1) {
        match fees.fee_sats(txid) {
            Some(fee) => computed_fees = computed_fees.saturating_add(fee),
            None => missing.push(*txid),
        }
        // Fees are never negative, so the claim is proven the moment the known
        // fees cover it.
        if computed_fees >= commitment.fee_total_sats {
            return Ok(FeeBound::Proven { computed_fees });
        }
    }

    if computed_fees >= commitment.fee_total_sats {
        Ok(FeeBound::Proven { computed_fees })
    } else if missing.is_empty() {
        Err(FeeProofError::FeeExceedsTransactions {
            claimed_fee_sats: commitment.fee_total_sats,
            actual_fee_sats: computed_fees,
        })
    } else {
        Ok(FeeBound::Undecided {
            computed_fees,
            missing,
        })
    }
}
