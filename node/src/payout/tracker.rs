//! Shared EDCA payout state for the running node.
//!
//! [`PayoutTracker`] is the seam between the two halves of the integration:
//!
//! * The **stratum submit path** records a bead the moment its share is
//!   accepted and the braid has been extended, via
//!   [`PayoutTracker::record_bead`].
//! * The **template creation path** reads the settled roster back out through
//!   [`PayoutTracker::payout_distribution`], and splices it into the coinbase.
//!
//! Cohort membership is taken from the braid rather than accumulated locally.
//! That matters: `Braid::extend` can re-shape existing cohorts when a bead
//! arrives that bridges two tips, so a locally accumulated cohort list would
//! drift out of agreement with consensus — and with every other node. Rebuilding
//! from the braid keeps the payout a pure function of the DAG, which is the
//! property the whole scheme rests on.

use super::coinbase::{build_payout_distribution, PayoutDistribution, MAX_PAYOUT_OUTPUTS};
use super::{BeadShare, EdcaParams, EdcaPayout};
use crate::braid::Braid;
use crate::config::PoolNetwork;
use crate::error::EdcaError;
use crate::utils::BeadHash;
use bitcoin::Amount;
use std::collections::{BTreeMap, HashMap};
use tokio::sync::RwLock;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

/// Mutable half of the tracker, guarded by a single lock.
#[derive(Debug)]
struct TrackerState {
    /// Total template reward `A_i` observed for a locally accepted bead.
    ///
    /// Only beads this node accepted through `mining.submit` have a known
    /// template value; a bead relayed by a peer carries only transaction ids,
    /// so its fees cannot be verified here and default to zero. The map is
    /// pruned against the braid on every rebuild so it stays bounded by the
    /// DAG rather than growing with submission volume.
    template_rewards: HashMap<BeadHash, Amount>,
    /// The active UHPO state, rebuilt from the braid on each accepted bead.
    payout: EdcaPayout,
}

/// Thread-safe handle to the node's EDCA payout state.
#[derive(Debug)]
pub struct PayoutTracker {
    /// Consensus parameters; immutable for the lifetime of the node.
    params: EdcaParams,
    /// Chain payout addresses are resolved against.
    network: PoolNetwork,
    /// Coinbase output budget applied when building a roster.
    max_payout_outputs: usize,
    /// Guarded mutable state.
    state: RwLock<TrackerState>,
}

impl PayoutTracker {
    /// Creates a tracker with the EDCA parameters for `network`.
    ///
    /// # Arguments
    /// * `network` - The chain this node mines against.
    ///
    /// # Returns
    /// An empty tracker holding no beads.
    ///
    /// # Errors
    /// Propagates any parameter validation failure from [`EdcaPayout::new`].
    pub fn new(network: PoolNetwork) -> Result<Self, EdcaError> {
        Self::with_params(
            EdcaParams::for_network(network),
            network,
            MAX_PAYOUT_OUTPUTS,
        )
    }

    /// Creates a tracker with explicit parameters.
    ///
    /// # Arguments
    /// * `params` - EDCA consensus parameters.
    /// * `network` - The chain payout addresses are resolved against.
    /// * `max_payout_outputs` - Coinbase output budget.
    ///
    /// # Returns
    /// An empty tracker holding no beads.
    ///
    /// # Errors
    /// Propagates any parameter validation failure from [`EdcaPayout::new`].
    pub fn with_params(
        params: EdcaParams,
        network: PoolNetwork,
        max_payout_outputs: usize,
    ) -> Result<Self, EdcaError> {
        let payout = EdcaPayout::new(params.clone())?;
        Ok(Self {
            params,
            network,
            max_payout_outputs,
            state: RwLock::new(TrackerState {
                template_rewards: HashMap::new(),
                payout,
            }),
        })
    }

    /// Records a bead accepted from a successful `mining.submit`.
    ///
    /// Called once the braid has already been extended, so the rebuild below
    /// sees the new bead in its cohort. `template_reward` is the total value of
    /// the coinbase the miner was working on — subsidy plus fees — which is the
    /// fee amplifier `A_i` of equation (3) directly.
    ///
    /// # Arguments
    /// * `braid` - The braid, already extended with this bead.
    /// * `bead_hash` - Hash of the accepted bead.
    /// * `template_reward` - Total coinbase value of the bead's template.
    ///
    /// # Returns
    /// `Ok(())` once the payout state reflects the new bead.
    ///
    /// # Errors
    /// Propagates any error from the rebuild; see
    /// [`PayoutTracker::refresh_from_braid`].
    pub async fn record_bead(
        &self,
        braid: &Braid,
        bead_hash: BeadHash,
        template_reward: Amount,
    ) -> Result<(), EdcaError> {
        let mut state = self.state.write().await;
        state.template_rewards.insert(bead_hash, template_reward);
        self.rebuild(&mut state, braid)
    }

    /// Rebuilds the payout state from the braid without recording a new bead.
    ///
    /// Used after the DAG changes for a reason other than a local submission —
    /// a bead relayed by a peer, or the end of initial block download.
    ///
    /// # Arguments
    /// * `braid` - The current braid.
    ///
    /// # Returns
    /// `Ok(())` once the payout state matches the braid.
    ///
    /// # Errors
    /// Returns [`EdcaError::ArithmeticOverflow`] or [`EdcaError::FeeOverflow`]
    /// if a bead's score cannot be represented.
    pub async fn refresh_from_braid(&self, braid: &Braid) -> Result<(), EdcaError> {
        let mut state = self.state.write().await;
        self.rebuild(&mut state, braid)
    }

    /// Recomputes the UHPO state from the braid's cohorts.
    ///
    /// The observed-reward map is pruned to beads the braid still indexes, so
    /// it cannot outgrow the DAG.
    fn rebuild(&self, state: &mut TrackerState, braid: &Braid) -> Result<(), EdcaError> {
        state
            .template_rewards
            .retain(|hash, _| braid.bead_index_mapping.contains_key(hash));

        let base_subsidy = self.params.base_subsidy;
        let rewards = &state.template_rewards;
        let payout = EdcaPayout::from_braid(self.params.clone(), braid, |bead| {
            // Equation (3) is stated as A_i = B_base + F_i, so a template's
            // total value is converted back into the fee component it implies.
            // A template worth less than the configured subsidy means the node
            // is configured for the wrong halving epoch; clamping to zero keeps
            // the bead scoreable instead of dropping it from the pool.
            let hash = braid.compute_bead_hash(bead);
            match rewards.get(&hash) {
                Some(reward) => reward.checked_sub(base_subsidy).unwrap_or_else(|| {
                    warn!(
                        bead = %hash,
                        template_reward = %reward,
                        base_subsidy = %base_subsidy,
                        "Template reward is below the configured subsidy - scoring the bead with zero fees"
                    );
                    Amount::ZERO
                }),
                // A bead relayed by a peer: its template fees are unverifiable
                // here, so it scores on the base subsidy alone.
                None => Amount::ZERO,
            }
        })?;

        state.payout = payout;
        Ok(())
    }

    /// Returns each miner's decayed weight `U_m`.
    ///
    /// # Returns
    /// A map from payout address to `U_m` in Q64.64 satoshis.
    pub async fn weights(&self) -> BTreeMap<String, u128> {
        self.state.read().await.payout.weights()
    }

    /// Returns the number of cohorts currently held in the active state.
    pub async fn retained_cohorts(&self) -> usize {
        self.state.read().await.payout.retained_cohorts()
    }

    /// Builds the coinbase payout roster for a block reward.
    ///
    /// # Arguments
    /// * `total_reward` - The full coinbase value to distribute.
    ///
    /// # Returns
    /// The [`PayoutDistribution`] whose outputs sum to `total_reward`.
    ///
    /// # Errors
    /// Returns [`EdcaError::EmptyPool`] before any bead has been recorded, and
    /// [`EdcaError::NoQualifyingMiners`] when no miner's share clears the dust
    /// limit. Both are expected early in a pool's life and mean the caller
    /// should fall back to the pool's own payout address.
    pub async fn payout_distribution(
        &self,
        total_reward: Amount,
    ) -> Result<PayoutDistribution, EdcaError> {
        let state = self.state.read().await;
        build_payout_distribution(
            &state.payout,
            total_reward,
            self.network,
            self.max_payout_outputs,
        )
    }

    /// Builds the coinbase payout outputs, or an empty roster if none exist.
    ///
    /// Convenience wrapper for the template path, where "nobody to pay yet" is
    /// a normal state rather than a failure: the caller falls back to a single
    /// pool output whenever this returns an empty vector.
    ///
    /// # Arguments
    /// * `total_reward` - The full coinbase value to distribute.
    ///
    /// # Returns
    /// The payout outputs, or an empty vector when the pool cannot be settled.
    pub async fn payout_outputs(&self, total_reward: Amount) -> Vec<bitcoin::TxOut> {
        match self.payout_distribution(total_reward).await {
            Ok(distribution) => {
                debug!(
                    miners = distribution.outputs.len(),
                    dust_swept = %distribution.settlement.dust_swept,
                    unresolved = distribution.unresolved.len(),
                    deferred = distribution.over_budget.len(),
                    "Built EDCA payout roster"
                );
                distribution.outputs
            }
            Err(EdcaError::EmptyPool) => {
                debug!("No EDCA payout weight yet - paying the pool address");
                Vec::new()
            }
            Err(error) => {
                warn!(error = %error, "EDCA payout unavailable - paying the pool address");
                Vec::new()
            }
        }
    }

    /// Builds a bead share at the tracker's parameters.
    ///
    /// Exposed for callers that need to score a hypothetical bead without
    /// mutating the tracker, such as the RPC surface.
    ///
    /// # Arguments
    /// * `payout_address` - Address the bead pays out to.
    /// * `template_reward` - Total coinbase value of the bead's template.
    ///
    /// # Returns
    /// The corresponding [`BeadShare`].
    pub fn share_for(&self, payout_address: &str, template_reward: Amount) -> BeadShare {
        BeadShare::new(
            payout_address,
            template_reward
                .checked_sub(self.params.base_subsidy)
                .unwrap_or(Amount::ZERO),
            self.params.bead_difficulty,
        )
    }
}
