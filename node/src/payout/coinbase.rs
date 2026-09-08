//! Turns an EDCA settlement into Bitcoin coinbase outputs.
//!
//! [`crate::payout`] is deliberately free of any Bitcoin address handling: it
//! works in payout-address strings and satoshis and nothing else. This module
//! is the boundary where those strings become spendable `scriptPubKey`s, and
//! where the two constraints the base layer imposes on the settlement are
//! applied:
//!
//! * **An address must be resolvable for this chain.** A payout address is
//!   copied verbatim out of a bead's committed metadata and ultimately from a
//!   miner's `mining.submit` worker name, so it is untrusted input. One
//!   malformed address must not be able to stop the pool from producing a
//!   template.
//! * **A coinbase cannot carry unlimited outputs.** Beyond
//!   [`MAX_PAYOUT_OUTPUTS`] the transaction starts costing meaningful block
//!   weight, so only the heaviest miners are paid directly.
//!
//! In both cases the excluded miner is dropped from the weight map *before*
//! the reward is divided, via [`EdcaPayout::settle_weights`]. That renormalises
//! the survivors rather than destroying the excluded value — the same treatment
//! the paper gives sub-dust outputs in section VI.C.

use super::{EdcaPayout, PayoutShare, Settlement};
use crate::config::PoolNetwork;
use crate::error::EdcaError;
use bitcoin::{Address, Amount, ScriptBuf, TxOut};
use braidpool_common::cpunet::Cpunet;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::str::FromStr;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

/// Maximum number of miner payout outputs placed in a single coinbase.
///
/// Each output costs roughly 30-40 bytes of block space, so this caps the
/// payout roster's contribution at about 1.5 kB. Miners past the cap are
/// treated exactly like sub-dust miners: their weight leaves the pool for this
/// block, and their claim is untouched in the UHPO state for the next one.
pub const MAX_PAYOUT_OUTPUTS: usize = 64;

/// A settled payout roster, ready to be spliced into a coinbase transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutDistribution {
    /// One output per qualifying miner, ordered by descending value so that
    /// the largest contributors sit at the front of the coinbase.
    pub outputs: Vec<TxOut>,
    /// The underlying EDCA settlement, retained for logging and for the RPC
    /// surface that reports why a miner was or was not paid.
    pub settlement: Settlement,
    /// Miners dropped before settlement because their payout address could not
    /// be resolved for this chain.
    pub unresolved: Vec<String>,
    /// Miners dropped before settlement because the coinbase output budget was
    /// already full.
    pub over_budget: Vec<String>,
}

impl PayoutDistribution {
    /// Returns the total value carried by the payout outputs.
    ///
    /// # Returns
    /// The sum of every output's value, which equals the reward the
    /// distribution was built for.
    pub fn total_value(&self) -> Amount {
        // Saturating rather than checked: `Amount`'s `Add` panics past
        // `MAX_MONEY`, and a diagnostic accessor must never be the thing that
        // brings the node down.
        let satoshis = self.outputs.iter().fold(0u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        Amount::from_sat(satoshis.min(Amount::MAX_MONEY.to_sat()))
    }
}

/// Resolves a payout address string to a `scriptPubKey` for `network`.
///
/// # Arguments
/// * `payout_address` - Address string committed to by a bead.
/// * `network` - The chain the address must be valid for.
///
/// # Returns
/// The output script, or `None` if the address is malformed or belongs to a
/// different chain. Cross-chain addresses are rejected rather than coerced:
/// paying a testnet address on mainnet would burn the miner's reward.
pub fn resolve_payout_script(payout_address: &str, network: PoolNetwork) -> Option<ScriptBuf> {
    match network {
        PoolNetwork::Cpunet => Cpunet::decode_bech32_address(payout_address).ok(),
        PoolNetwork::Bitcoin(bitcoin_network) => Address::from_str(payout_address)
            .ok()?
            .require_network(bitcoin_network)
            .ok()
            .map(|address| address.script_pubkey()),
    }
}

/// Builds the coinbase payout roster for a block reward.
///
/// Applies, in order: address resolution, the output budget, then the EDCA
/// settlement of section VI.C over whatever weight survives. The returned
/// outputs sum to exactly `total_reward`, so they can replace the template's
/// single pool output without altering the coinbase's value.
///
/// # Arguments
/// * `payout` - The active UHPO state to settle against.
/// * `total_reward` - The full coinbase value `A_total` to distribute.
/// * `network` - The chain payout addresses must be valid for.
/// * `max_outputs` - Coinbase output budget; see [`MAX_PAYOUT_OUTPUTS`].
///
/// # Returns
/// The [`PayoutDistribution`] to splice into the coinbase.
///
/// # Errors
/// Returns [`EdcaError::EmptyPool`] when no miner has a resolvable address or
/// the state carries no weight, and [`EdcaError::NoQualifyingMiners`] when no
/// miner's share reaches the dust limit. Both mean "there is nobody to pay
/// yet"; the caller is expected to fall back to the pool's own address.
pub fn build_payout_distribution(
    payout: &EdcaPayout,
    total_reward: Amount,
    network: PoolNetwork,
    max_outputs: usize,
) -> Result<PayoutDistribution, EdcaError> {
    let mut resolved: Vec<(String, u128, ScriptBuf)> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();

    for (address, weight) in payout.weights() {
        match resolve_payout_script(&address, network) {
            Some(script) => resolved.push((address, weight, script)),
            None => {
                warn!(
                    payout_address = %address,
                    network = %network,
                    "Dropping miner from payout roster - payout address is not valid for this chain"
                );
                unresolved.push(address);
            }
        }
    }

    // Heaviest first, address as a deterministic tie-break, so the output
    // budget always keeps the same miners on every node.
    resolved.sort_by(|left, right| (Reverse(left.1), &left.0).cmp(&(Reverse(right.1), &right.0)));

    let mut over_budget: Vec<String> = Vec::new();
    if resolved.len() > max_outputs {
        for (address, _, _) in resolved.drain(max_outputs..) {
            debug!(
                payout_address = %address,
                max_outputs,
                "Deferring miner payout - coinbase output budget is full"
            );
            over_budget.push(address);
        }
        over_budget.sort();
    }

    let scripts: BTreeMap<String, ScriptBuf> = resolved
        .iter()
        .map(|(address, _, script)| (address.clone(), script.clone()))
        .collect();
    let weights: BTreeMap<String, u128> = resolved
        .into_iter()
        .map(|(address, weight, _)| (address, weight))
        .collect();

    let settlement = EdcaPayout::settle_weights(payout.params(), weights, total_reward)?;

    // Largest payout first; the settlement itself is ordered by address.
    let mut paid: Vec<&PayoutShare> = settlement.outputs.iter().collect();
    paid.sort_by(|left, right| {
        (Reverse(left.amount), &left.payout_address)
            .cmp(&(Reverse(right.amount), &right.payout_address))
    });

    let mut outputs = Vec::with_capacity(paid.len());
    for share in paid {
        let Some(script) = scripts.get(&share.payout_address) else {
            // Unreachable: every settled address was resolved above.
            return Err(EdcaError::UnresolvedPayoutAddress {
                payout_address: share.payout_address.clone(),
            });
        };
        outputs.push(TxOut {
            value: share.amount,
            script_pubkey: script.clone(),
        });
    }

    Ok(PayoutDistribution {
        outputs,
        settlement,
        unresolved,
        over_budget,
    })
}
