//! Exponentially Decayed Cohort Average (EDCA) payout algorithm.
//!
//! This is a direct implementation of the scheme specified in `docs/EDCA.pdf`,
//! *EDCA: Mining Payouts in DAG Consensus*. EDCA replaces the sliding PPLNS
//! window — whose hard boundary lets miners hop in and out of a pool for free —
//! with a continuously damped decay curve anchored to the braid's **cohorts**
//! rather than to wall-clock time or a linear share index. Because every bead
//! in a cohort shares one topological age, concurrent beads that differ only by
//! network latency are weighted identically, which is what makes the curve
//! well-defined on a DAG at all.
//!
//! # The pipeline
//!
//! For each bead `i`, with `B_base` the block subsidy, `F_i` the fees in that
//! bead's committed template, `D_bp` the pool's global bead difficulty,
//! `D_network` the Bitcoin network difficulty and `r` the retention parameter:
//!
//! 1. **Fee amplifier** (eq. 3) — `A_i = B_base + F_i`. A bead's worth is tied
//!    to the mempool its miner actually committed to, so including high-value
//!    transactions is rewarded directly.
//! 2. **Raw score** (eq. 4) — `S_i = (D_bp / D_network) * A_i`. The ratio is the
//!    probability that the bead is also a valid Bitcoin block, making `S_i` the
//!    exact expected value of one unit of work.
//! 3. **EDCA weight** (eq. 5) — `W_i = S_i * r^{dc_i}`, where `dc_i` is the
//!    bead's topological age in elapsed cohorts.
//! 4. **Miner total** (eq. 6) — `U_m = sum of W_i over beads mined by m`.
//! 5. **Payout percentage** (eq. 7) — `P_m = U_m / U_total`.
//! 6. **Settlement** (eqs. 14-16) — `O_m = P_m * A_total`; outputs below the
//!    network dust limit are swept into a pool and redistributed pro-rata among
//!    the qualifying miners, so 100% of the reward lands on-chain.
//!
//! # Truncation
//!
//! A pure exponential never reaches zero, so an unbounded history would be a
//! memory-exhaustion vector. Section VI.A bounds the state instead of using an
//! arbitrary window: because the tail of a geometric series sums to
//! `W_decayed / (1 - r)`, an entire pruned history is unspendable as soon as
//! `W_decayed < L_dust * (1 - r)`. The oldest cohort is dropped once its
//! decayed aggregate crosses that line, holding the active state to `O(1)`.
//!
//! # Fixed difficulty
//!
//! Section III.B specifies a strict, uniform global bead difficulty `D_bp`
//! rather than per-miner vardiff: a larger miner submits proportionally *more*
//! beads, not mathematically heavier ones. Until difficulty adjustment lands,
//! [`TEST_BEAD_DIFFICULTY`] pins `D_bp` to a fixed ideal value for every bead,
//! which is exactly the regime the paper's own worked simulation uses.
//!
//! # Arithmetic
//!
//! Every quantity is an exact Q64.64 fixed-point integer; see
//! [`fixed_point`] for why floats are excluded from this path.

pub mod coinbase;
pub mod fixed_point;
pub mod tracker;

#[cfg(test)]
mod tests;

use crate::bead::Bead;
use crate::braid::Braid;
use crate::config::PoolNetwork;
use crate::error::EdcaError;
use bitcoin::{Amount, Network};
use fixed_point::{mul_div_floor, mul_shift, to_fixed, DecayTable};
use std::cmp::Reverse;
use std::collections::{BTreeMap, VecDeque};

/// Fixed global bead difficulty (`D_bp`) used while EDCA is under test.
///
/// The value matches the difficulty the paper's five-cohort simulation assigns
/// to every participant, so the worked example in Table I can be reproduced
/// exactly. This constant is the single seam where a real difficulty-adjustment
/// module will plug in: nothing else in this module assumes the value is
/// constant, only that all nodes agree on it.
pub const TEST_BEAD_DIFFICULTY: u64 = 500;

/// Numerator of the default retention parameter `r`.
pub const DEFAULT_RETENTION_NUMERATOR: u64 = 95;

/// Denominator of the default retention parameter `r`.
///
/// Together with [`DEFAULT_RETENTION_NUMERATOR`] this gives `r = 0.95`, the
/// value the paper names as a representative protocol constant. Section IV
/// notes that the `r = 0.80` used in its simulation is deliberately aggressive
/// for illustration and that a production pool should sit at `0.9` or above so
/// that miner history is not burned off too quickly.
pub const DEFAULT_RETENTION_DENOMINATOR: u64 = 100;

/// Default Bitcoin block subsidy (`B_base`) in satoshis: 3.125 BTC.
pub const DEFAULT_BASE_SUBSIDY_SATS: u64 = 312_500_000;

/// Block subsidy in force on regtest and cpunet, in satoshis: 50 BTC.
pub const REGTEST_BASE_SUBSIDY_SATS: u64 = 5_000_000_000;

/// Default Bitcoin network dust limit (`L_dust`) in satoshis.
///
/// 330 satoshis is the relay dust threshold for a P2WSH-sized output, and is
/// the figure the paper uses when deriving the truncation rule.
pub const DEFAULT_DUST_LIMIT_SATS: u64 = 330;

/// Hard ceiling on the number of retained cohorts.
///
/// The dust-derived truncation rule already bounds the active state, but this
/// cap makes the `O(1)` memory guarantee unconditional: it holds even for a
/// degenerate parameter set where the decayed aggregate would take an absurd
/// number of cohorts to cross the pruning threshold.
pub const DEFAULT_MAX_COHORT_HISTORY: usize = 4096;

/// Consensus parameters for an EDCA payout calculation.
///
/// Every node must be configured identically: the payout percentages are a pure
/// function of these parameters and the DAG topology, which is what allows each
/// node to settle a block without consulting a central operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdcaParams {
    /// Numerator of the retention parameter `r`.
    pub retention_numerator: u64,
    /// Denominator of the retention parameter `r`. Must exceed the numerator.
    pub retention_denominator: u64,
    /// Global bead difficulty `D_bp` applied to every bead.
    pub bead_difficulty: u64,
    /// Bitcoin network difficulty `D_network`.
    ///
    /// This factor is common to every bead and therefore cancels out of the
    /// payout ratio `P_m`; it is carried explicitly so that the intermediate
    /// score `S_i` is a true expected value in satoshis rather than an
    /// unnormalised weight.
    pub network_difficulty: u128,
    /// Fixed Bitcoin block subsidy `B_base`.
    pub base_subsidy: Amount,
    /// Bitcoin network dust limit `L_dust`, driving both the truncation rule
    /// and the on-chain dust sweep.
    pub dust_limit: Amount,
    /// Hard ceiling on retained cohorts; see [`DEFAULT_MAX_COHORT_HISTORY`].
    pub max_cohort_history: usize,
}

impl EdcaParams {
    /// Returns the parameter set used for testing EDCA against a live braid.
    ///
    /// `D_bp` is pinned to [`TEST_BEAD_DIFFICULTY`] and `D_network` to `1`, so
    /// a bead's raw score reduces to `D_bp * A_i`. Because `D_network` cancels
    /// out of `P_m`, this changes no payout percentage — it only keeps the
    /// intermediate scores in a range that is legible when debugging.
    ///
    /// # Returns
    /// An [`EdcaParams`] with `r = 0.95`, a 3.125 BTC subsidy and a 330 satoshi
    /// dust limit.
    pub fn testing() -> Self {
        Self {
            retention_numerator: DEFAULT_RETENTION_NUMERATOR,
            retention_denominator: DEFAULT_RETENTION_DENOMINATOR,
            bead_difficulty: TEST_BEAD_DIFFICULTY,
            network_difficulty: 1,
            base_subsidy: Amount::from_sat(DEFAULT_BASE_SUBSIDY_SATS),
            dust_limit: Amount::from_sat(DEFAULT_DUST_LIMIT_SATS),
            max_cohort_history: DEFAULT_MAX_COHORT_HISTORY,
        }
    }

    /// Returns the parameter set for a live pool on `network`.
    ///
    /// The subsidy is the one in force for that chain, so the fee amplifier
    /// `A_i = B_base + F_i` reconstructs a template's true total reward. The
    /// network difficulty is left at `1` because it cancels out of `P_m`
    /// entirely: carrying the real value would only rescale every score by a
    /// common factor while costing precision.
    ///
    /// # Arguments
    /// * `network` - The chain this node mines against.
    ///
    /// # Returns
    /// An [`EdcaParams`] with the chain's subsidy and the default retention,
    /// dust limit and history cap.
    pub fn for_network(network: PoolNetwork) -> Self {
        // Regtest and cpunet both start from the genesis subsidy schedule and
        // in practice never reach a halving during a test run.
        let base_subsidy = match network {
            PoolNetwork::Cpunet | PoolNetwork::Bitcoin(Network::Regtest) => {
                Amount::from_sat(REGTEST_BASE_SUBSIDY_SATS)
            }
            PoolNetwork::Bitcoin(_) => Amount::from_sat(DEFAULT_BASE_SUBSIDY_SATS),
        };
        Self {
            base_subsidy,
            ..Self::testing()
        }
    }

    /// Returns `1 - r` as an exact rational `(numerator, denominator)`.
    ///
    /// # Returns
    /// The complement of the retention parameter, used to scale the dust limit
    /// into the truncation threshold of equation (10).
    pub fn decay_complement(&self) -> (u64, u64) {
        (
            self.retention_denominator
                .saturating_sub(self.retention_numerator),
            self.retention_denominator,
        )
    }
}

/// A single bead's contribution to the EDCA state.
///
/// Fees are supplied by the caller rather than derived from the bead: a bead
/// commits only to the transaction ids of its template, so the fee total
/// `F_i` has to come from the node's view of those transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeadShare {
    /// The payout address committed to by the bead.
    pub payout_address: String,
    /// Total transaction fees `F_i` in the bead's committed block template.
    pub fees: Amount,
    /// The bead's difficulty `D_bp`.
    pub difficulty: u64,
}

impl BeadShare {
    /// Builds a share with an explicit difficulty.
    ///
    /// # Arguments
    /// * `payout_address` - Address the bead pays out to.
    /// * `fees` - Total fees in the bead's committed template.
    /// * `difficulty` - The bead's difficulty `D_bp`.
    ///
    /// # Returns
    /// The constructed [`BeadShare`].
    pub fn new(payout_address: impl Into<String>, fees: Amount, difficulty: u64) -> Self {
        Self {
            payout_address: payout_address.into(),
            fees,
            difficulty,
        }
    }

    /// Builds a share at the fixed test difficulty [`TEST_BEAD_DIFFICULTY`].
    ///
    /// # Arguments
    /// * `payout_address` - Address the bead pays out to.
    /// * `fees` - Total fees in the bead's committed template.
    ///
    /// # Returns
    /// The constructed [`BeadShare`].
    pub fn with_fixed_difficulty(payout_address: impl Into<String>, fees: Amount) -> Self {
        Self::new(payout_address, fees, TEST_BEAD_DIFFICULTY)
    }
}

/// One closed cohort's undecayed per-miner scores.
///
/// Raw scores are stored rather than decayed weights so that ageing a cohort is
/// a single multiply at read time instead of a rewrite of the whole history.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CohortScores {
    /// Sum of `S_i` per payout address, in Q64.64 satoshis.
    scores: BTreeMap<String, u128>,
    /// Cached sum of `scores`, used by the truncation rule.
    total: u128,
}

/// A miner's settled position in a payout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutShare {
    /// The miner's payout address.
    pub payout_address: String,
    /// The miner's decayed weight `U_m` in Q64.64 satoshis.
    pub weight: u128,
    /// The satoshi amount attributed to the miner.
    ///
    /// For an entry in [`Settlement::outputs`] this is the final adjusted
    /// payout `O'_m`; for an entry in [`Settlement::swept`] it is the nominal
    /// sub-dust amount `O_m` that was swept away.
    pub amount: Amount,
}

/// The result of settling a block reward against the active UHPO state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// Payable coinbase outputs, ordered by payout address. Their amounts sum
    /// exactly to the reward that was settled.
    pub outputs: Vec<PayoutShare>,
    /// Miners whose nominal output fell below the dust limit, carrying the
    /// amount that was swept from them. Ordered by payout address.
    pub swept: Vec<PayoutShare>,
    /// The aggregated dust pool `D_total` that was redistributed.
    pub dust_swept: Amount,
    /// The total active pool weight `U_total` the settlement was computed
    /// against.
    pub total_weight: u128,
}

/// The active Unspent Hash Power Output (UHPO) state.
///
/// Holds the retained cohorts, oldest first, and derives payout percentages
/// from them on demand. The struct is deliberately free of I/O and clocks: it
/// is a pure function of its parameters and the cohorts pushed into it, so two
/// nodes with the same DAG necessarily agree.
#[derive(Clone, Debug)]
pub struct EdcaPayout {
    /// Consensus parameters this state was built with.
    params: EdcaParams,
    /// Pre-computed `r^n` lookup table.
    decay: DecayTable,
    /// `L_dust * (1 - r)` in Q64.64 satoshis, from equation (10).
    prune_threshold: u128,
    /// Retained cohorts, oldest at the front.
    cohorts: VecDeque<CohortScores>,
    /// Count of cohorts dropped by the truncation rule, for diagnostics.
    pruned_cohorts: usize,
}

impl EdcaPayout {
    /// Creates an empty payout state.
    ///
    /// # Arguments
    /// * `params` - Consensus parameters; see [`EdcaParams`].
    ///
    /// # Returns
    /// The initialised state.
    ///
    /// # Errors
    /// Returns [`EdcaError::InvalidRetention`] unless
    /// `0 < retention_numerator < retention_denominator`,
    /// [`EdcaError::ZeroNetworkDifficulty`] if `D_network` is zero, and
    /// [`EdcaError::ArithmeticOverflow`] if the truncation threshold cannot be
    /// represented.
    pub fn new(params: EdcaParams) -> Result<Self, EdcaError> {
        if params.network_difficulty == 0 {
            return Err(EdcaError::ZeroNetworkDifficulty);
        }
        let decay = DecayTable::new(
            params.retention_numerator,
            params.retention_denominator,
            params.max_cohort_history,
        )
        .ok_or(EdcaError::InvalidRetention {
            numerator: params.retention_numerator,
            denominator: params.retention_denominator,
        })?;

        // Equation (10): a cohort is unspendable once its decayed aggregate
        // drops below `L_dust * (1 - r)`, because the whole geometric tail
        // behind it then sums to less than one dust output.
        let (complement, denominator) = params.decay_complement();
        let prune_threshold = mul_div_floor(
            to_fixed(params.dust_limit.to_sat()),
            complement as u128,
            denominator as u128,
        )
        .ok_or(EdcaError::ArithmeticOverflow {
            operation: "truncation threshold",
        })?;

        Ok(Self {
            params,
            decay,
            prune_threshold,
            cohorts: VecDeque::new(),
            pruned_cohorts: 0,
        })
    }

    /// Builds a payout state from every cohort currently in the braid.
    ///
    /// Cohorts are consumed oldest first, so the braid's newest cohort ends up
    /// at topological age zero.
    ///
    /// # Arguments
    /// * `params` - Consensus parameters; see [`EdcaParams`].
    /// * `braid` - The DAG to read cohorts and payout addresses from.
    /// * `bead_fees` - Resolves the total template fees `F_i` for a bead. The
    ///   braid stores only transaction ids, so fees must come from the node's
    ///   view of those transactions.
    ///
    /// # Returns
    /// A state containing every cohort that survives truncation.
    ///
    /// # Errors
    /// Propagates any error from [`EdcaPayout::new`] or
    /// [`EdcaPayout::push_cohort`].
    pub fn from_braid<F>(params: EdcaParams, braid: &Braid, bead_fees: F) -> Result<Self, EdcaError>
    where
        F: Fn(&Bead) -> Amount,
    {
        let difficulty = params.bead_difficulty;
        let mut payout = Self::new(params)?;

        for cohort in &braid.cohorts {
            // Cohort membership is a `HashSet`, whose iteration order is not
            // stable across runs. Sorting keeps the traversal deterministic
            // even though the score accumulation itself is order-independent.
            let mut bead_indices: Vec<usize> = cohort.0.iter().copied().collect();
            bead_indices.sort_unstable();

            let mut shares = Vec::with_capacity(bead_indices.len());
            for index in bead_indices {
                let Some(bead) = braid.beads.get(index) else {
                    continue;
                };
                shares.push(BeadShare::new(
                    bead.committed_metadata.payout_address.clone(),
                    bead_fees(bead),
                    difficulty,
                ));
            }
            payout.push_cohort(shares)?;
        }

        Ok(payout)
    }

    /// Closes a new cohort at topological age zero.
    ///
    /// Every previously retained cohort ages by exactly one, which is what
    /// applies the decay factor `r` uniformly to all of its beads. Truncation
    /// runs immediately afterwards.
    ///
    /// # Arguments
    /// * `beads` - The beads bounded by the closing graph cut.
    ///
    /// # Returns
    /// `Ok(())` once the cohort is recorded and the history re-truncated.
    ///
    /// # Errors
    /// Returns [`EdcaError::ArithmeticOverflow`] if a bead's raw score cannot
    /// be represented in Q64.64, or [`EdcaError::FeeOverflow`] if
    /// `B_base + F_i` exceeds [`Amount::MAX_MONEY`].
    pub fn push_cohort<I>(&mut self, beads: I) -> Result<(), EdcaError>
    where
        I: IntoIterator<Item = BeadShare>,
    {
        let mut scores: BTreeMap<String, u128> = BTreeMap::new();
        let mut total: u128 = 0;

        for share in beads {
            let score = self.raw_score(&share)?;
            total = total.saturating_add(score);
            scores
                .entry(share.payout_address)
                .and_modify(|existing| *existing = existing.saturating_add(score))
                .or_insert(score);
        }

        self.cohorts.push_back(CohortScores { scores, total });
        self.truncate();
        Ok(())
    }

    /// Computes a bead's raw score `S_i` in Q64.64 satoshis.
    ///
    /// Applies the fee amplifier of equation (3) and the expected-value scaling
    /// of equation (4) in a single exact `mul_div`, so the difficulty ratio is
    /// never materialised as a lossy reciprocal.
    fn raw_score(&self, share: &BeadShare) -> Result<u128, EdcaError> {
        // Equation (3): A_i = B_base + F_i.
        let amplified =
            self.params
                .base_subsidy
                .checked_add(share.fees)
                .ok_or(EdcaError::FeeOverflow {
                    fees: share.fees.to_sat(),
                })?;

        // Equation (4): S_i = (D_bp / D_network) * A_i.
        mul_div_floor(
            to_fixed(amplified.to_sat()),
            share.difficulty as u128,
            self.params.network_difficulty,
        )
        .ok_or(EdcaError::ArithmeticOverflow {
            operation: "raw bead score",
        })
    }

    /// Drops cohorts whose entire remaining geometric tail is unspendable.
    ///
    /// Implements equation (10): once the oldest cohort's decayed aggregate
    /// falls below `L_dust * (1 - r)`, that cohort and everything behind it sum
    /// to less than a single dust output and can be removed without altering
    /// any payable amount. The `max_cohort_history` cap is enforced in the same
    /// pass so the active state is bounded unconditionally.
    fn truncate(&mut self) {
        while let Some(oldest) = self.cohorts.front() {
            let age = self.cohorts.len() - 1;
            let decayed = mul_shift(oldest.total, self.decay.multiplier(age));
            let over_capacity = self.cohorts.len() > self.params.max_cohort_history;

            if decayed < self.prune_threshold || over_capacity {
                self.cohorts.pop_front();
                self.pruned_cohorts += 1;
            } else {
                break;
            }
        }
    }

    /// Returns the consensus parameters this state was built with.
    pub fn params(&self) -> &EdcaParams {
        &self.params
    }

    /// Returns the number of cohorts currently retained in the active state.
    pub fn retained_cohorts(&self) -> usize {
        self.cohorts.len()
    }

    /// Returns the number of cohorts dropped by the truncation rule so far.
    pub fn pruned_cohorts(&self) -> usize {
        self.pruned_cohorts
    }

    /// Computes each miner's decayed weight `U_m`.
    ///
    /// Implements equations (5) and (6): every retained cohort is scaled by the
    /// retention multiplier for its topological age and summed per address.
    ///
    /// # Returns
    /// A map from payout address to `U_m` in Q64.64 satoshis, ordered by
    /// address.
    pub fn weights(&self) -> BTreeMap<String, u128> {
        let mut weights: BTreeMap<String, u128> = BTreeMap::new();
        let newest = self.cohorts.len().saturating_sub(1);

        for (position, cohort) in self.cohorts.iter().enumerate() {
            // Position 0 is the oldest retained cohort, so its topological age
            // is the largest.
            let multiplier = self.decay.multiplier(newest - position);
            for (address, score) in &cohort.scores {
                let weight = mul_shift(*score, multiplier);
                weights
                    .entry(address.clone())
                    .and_modify(|existing| *existing = existing.saturating_add(weight))
                    .or_insert(weight);
            }
        }

        weights
    }

    /// Computes the total active pool weight `U_total`.
    ///
    /// # Returns
    /// The sum of every miner's `U_m`, in Q64.64 satoshis.
    pub fn total_weight(&self) -> u128 {
        self.weights()
            .values()
            .fold(0u128, |sum, weight| sum.saturating_add(*weight))
    }

    /// Computes each miner's payout percentage `P_m`, in parts per million.
    ///
    /// Implements equation (7). Parts per million is used instead of a float so
    /// that the reported percentage is itself reproducible.
    ///
    /// # Returns
    /// A map from payout address to `P_m` in ppm, ordered by address.
    ///
    /// # Errors
    /// Returns [`EdcaError::EmptyPool`] if no retained bead carries any weight.
    pub fn percentages_ppm(&self) -> Result<BTreeMap<String, u128>, EdcaError> {
        let weights = self.weights();
        let total = weights
            .values()
            .fold(0u128, |sum, weight| sum.saturating_add(*weight));
        if total == 0 {
            return Err(EdcaError::EmptyPool);
        }

        let mut percentages = BTreeMap::new();
        for (address, weight) in weights {
            let ppm =
                mul_div_floor(weight, 1_000_000, total).ok_or(EdcaError::ArithmeticOverflow {
                    operation: "payout percentage",
                })?;
            percentages.insert(address, ppm);
        }
        Ok(percentages)
    }

    /// Settles a block reward against the active UHPO state.
    ///
    /// Implements section VI.C. Nominal outputs `O_m = P_m * A_total` are
    /// computed first (eq. 14); every output below the network dust limit is
    /// stripped and aggregated into `D_total` (eq. 15), which is then
    /// redistributed among the qualifying miners in proportion to their
    /// existing consensus weight (eq. 16). The dust is never claimed as a fee
    /// by the block finder.
    ///
    /// Integer division floors at both stages, so a handful of satoshis can
    /// remain unassigned. Those are handed out one at a time to qualifying
    /// miners ordered by descending weight, breaking ties by address. This
    /// tie-break is deterministic, which is what preserves the zero-sum
    /// guarantee of the paper's second Lean proof under integer arithmetic:
    /// the outputs always sum to exactly `A_total`.
    ///
    /// # Arguments
    /// * `total_reward` - The full block reward `A_total` to distribute.
    ///
    /// # Returns
    /// The [`Settlement`], whose `outputs` sum exactly to `total_reward`.
    ///
    /// # Errors
    /// Returns [`EdcaError::EmptyPool`] if the active state carries no weight,
    /// [`EdcaError::NoQualifyingMiners`] if every nominal output is below the
    /// dust limit (leaving nobody to redistribute to), and
    /// [`EdcaError::ArithmeticOverflow`] on an unrepresentable intermediate.
    pub fn settle(&self, total_reward: Amount) -> Result<Settlement, EdcaError> {
        Self::settle_weights(&self.params, self.weights(), total_reward)
    }

    /// Settles a block reward against an explicit weight map.
    ///
    /// Identical to [`EdcaPayout::settle`] but driven by a caller-supplied
    /// `U_m` map rather than the full active state. This is what lets the
    /// coinbase builder drop miners it cannot pay — an unparseable payout
    /// address, or a miner beyond the coinbase output budget — before the
    /// reward is divided. Removing a miner from the map removes them from
    /// `U_total` too, so the survivors' proportions renormalise correctly
    /// instead of the dropped value being destroyed.
    ///
    /// # Arguments
    /// * `params` - Consensus parameters supplying the dust limit.
    /// * `weights` - Each payable miner's `U_m` in Q64.64 satoshis.
    /// * `total_reward` - The full block reward `A_total` to distribute.
    ///
    /// # Returns
    /// The [`Settlement`], whose `outputs` sum exactly to `total_reward`.
    ///
    /// # Errors
    /// As [`EdcaPayout::settle`].
    pub fn settle_weights(
        params: &EdcaParams,
        weights: BTreeMap<String, u128>,
        total_reward: Amount,
    ) -> Result<Settlement, EdcaError> {
        let total_weight = weights
            .values()
            .fold(0u128, |sum, weight| sum.saturating_add(*weight));
        if total_weight == 0 {
            return Err(EdcaError::EmptyPool);
        }

        let reward_sats = total_reward.to_sat();
        let dust_limit_sats = params.dust_limit.to_sat();

        // Equation (14): nominal output per miner. The Q64.64 scale is common
        // to both operands of the ratio and therefore cancels.
        let mut nominal: Vec<(String, u128, u64)> = Vec::with_capacity(weights.len());
        for (address, weight) in weights {
            let amount = mul_div_floor(weight, reward_sats as u128, total_weight).ok_or(
                EdcaError::ArithmeticOverflow {
                    operation: "nominal payout",
                },
            )?;
            let amount = u64::try_from(amount).map_err(|_| EdcaError::ArithmeticOverflow {
                operation: "nominal payout",
            })?;
            nominal.push((address, weight, amount));
        }

        // Equation (15): strip and aggregate the sub-dust outputs.
        let mut swept: Vec<PayoutShare> = Vec::new();
        let mut qualifying: Vec<(String, u128, u64)> = Vec::new();
        let mut dust_total: u64 = 0;
        for (address, weight, amount) in nominal {
            if amount < dust_limit_sats {
                dust_total = dust_total.saturating_add(amount);
                swept.push(PayoutShare {
                    payout_address: address,
                    weight,
                    amount: Amount::from_sat(amount),
                });
            } else {
                qualifying.push((address, weight, amount));
            }
        }

        if qualifying.is_empty() {
            return Err(EdcaError::NoQualifyingMiners {
                dust_limit: dust_limit_sats,
                total_reward: reward_sats,
            });
        }

        let qualifying_total: u64 = qualifying
            .iter()
            .fold(0u64, |sum, (_, _, amount)| sum.saturating_add(*amount));

        // Equation (16): redistribute the dust pool pro-rata across the
        // qualifying set.
        let mut outputs: Vec<PayoutShare> = Vec::with_capacity(qualifying.len());
        for (address, weight, amount) in qualifying {
            let bonus = mul_div_floor(amount as u128, dust_total as u128, qualifying_total as u128)
                .ok_or(EdcaError::ArithmeticOverflow {
                    operation: "dust redistribution",
                })?;
            let bonus = u64::try_from(bonus).map_err(|_| EdcaError::ArithmeticOverflow {
                operation: "dust redistribution",
            })?;
            outputs.push(PayoutShare {
                payout_address: address,
                weight,
                amount: Amount::from_sat(amount.saturating_add(bonus)),
            });
        }

        Self::assign_rounding_remainder(&mut outputs, reward_sats);
        outputs.sort_by(|left, right| left.payout_address.cmp(&right.payout_address));
        swept.sort_by(|left, right| left.payout_address.cmp(&right.payout_address));

        Ok(Settlement {
            outputs,
            swept,
            dust_swept: Amount::from_sat(dust_total),
            total_weight,
        })
    }

    /// Hands the satoshis lost to floor division back to the qualifying miners.
    ///
    /// Recipients are ordered by descending weight and then by address, so the
    /// assignment is a pure function of the DAG. The remainder is bounded by
    /// twice the number of qualifying miners — one satoshi per miner per
    /// division — so the loop is short.
    fn assign_rounding_remainder(outputs: &mut [PayoutShare], reward_sats: u64) {
        let assigned = outputs
            .iter()
            .fold(0u64, |sum, share| sum.saturating_add(share.amount.to_sat()));
        let mut remainder = reward_sats.saturating_sub(assigned);
        if remainder == 0 || outputs.is_empty() {
            return;
        }

        let mut order: Vec<usize> = (0..outputs.len()).collect();
        order.sort_by_key(|index| {
            (
                Reverse(outputs[*index].weight),
                outputs[*index].payout_address.clone(),
            )
        });

        let mut cursor = 0usize;
        while remainder > 0 {
            let target = order[cursor % order.len()];
            outputs[target].amount += Amount::from_sat(1);
            remainder -= 1;
            cursor += 1;
        }
    }
}
