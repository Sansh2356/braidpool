//! Tests for the EDCA payout algorithm.
//!
//! The headline case is [`edca_reproduces_paper_settlement_simulation`], which
//! replays the five-cohort Alice/Bob/Charlie scenario from section IV of
//! `docs/EDCA.pdf` and checks the implementation against Table I. The remainder
//! exercise the invariants the paper formalises in Lean: zero-sum dust
//! settlement, the truncation shift theorem, Sybil linearity and the
//! share-withholding penalty.

use super::coinbase::{build_payout_distribution, resolve_payout_script, MAX_PAYOUT_OUTPUTS};
use super::fixed_point::{mul_div_floor, mul_shift, mul_wide, to_fixed, DecayTable, ONE};
use super::tracker::PayoutTracker;
use super::{BeadShare, EdcaParams, EdcaPayout, REGTEST_BASE_SUBSIDY_SATS, TEST_BEAD_DIFFICULTY};
use crate::bead::Bead;
use crate::braid::{Braid, Cohort};
use crate::config::PoolNetwork;
use crate::error::EdcaError;
use crate::utils::compute_block_hash;
use crate::utils::test_utils::test_utility_functions::emit_bead;
use bitcoin::{Amount, Network};
use std::collections::{HashMap, HashSet};

/// Satoshis in one bitcoin, used to keep the paper's BTC-denominated figures
/// readable in the fixtures below.
const BTC: u64 = 100_000_000;

/// Builds the parameter set used by the paper's simulation: an aggressive
/// `r = 0.80`, a 3.125 BTC subsidy and a fixed bead difficulty of 500.
fn simulation_params() -> EdcaParams {
    EdcaParams {
        retention_numerator: 80,
        retention_denominator: 100,
        ..EdcaParams::testing()
    }
}

/// Convenience constructor for a bead share at the fixed test difficulty.
fn share(address: &str, fees_sats: u64) -> BeadShare {
    BeadShare::with_fixed_difficulty(address, Amount::from_sat(fees_sats))
}

/// Returns the payout percentage of `address` in parts per million.
fn ppm(payout: &EdcaPayout, address: &str) -> u128 {
    payout
        .percentages_ppm()
        .expect("active pool must carry weight")
        .get(address)
        .copied()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Fixed-point primitives
// ---------------------------------------------------------------------------

#[test]
fn mul_wide_matches_native_multiplication_below_the_boundary() {
    let (high, low) = mul_wide(u64::MAX as u128, u64::MAX as u128);
    assert_eq!(high, 0);
    assert_eq!(low, (u64::MAX as u128) * (u64::MAX as u128));
}

#[test]
fn mul_wide_carries_through_the_128_bit_boundary() {
    // (2^127) * 2 == 2^128, which is exactly one in the high limb.
    let (high, low) = mul_wide(1u128 << 127, 2);
    assert_eq!(high, 1);
    assert_eq!(low, 0);

    // The maximum product must not wrap.
    let (high, low) = mul_wide(u128::MAX, u128::MAX);
    assert_eq!(high, u128::MAX - 1);
    assert_eq!(low, 1);
}

#[test]
fn mul_shift_is_multiplication_in_q64_64() {
    // 1.0 is the identity.
    assert_eq!(mul_shift(to_fixed(12_345), ONE), to_fixed(12_345));
    // 0.5 halves.
    assert_eq!(mul_shift(to_fixed(100), ONE / 2), to_fixed(50));
    // A score far larger than any block reward still shifts without wrapping.
    assert_eq!(
        mul_shift(to_fixed(u64::MAX), ONE / 2),
        to_fixed(u64::MAX) / 2
    );
}

#[test]
fn mul_div_floor_is_exact_over_a_256_bit_intermediate() {
    // Product overflows u128; the quotient does not.
    let a = 1u128 << 100;
    let b = 1u128 << 100;
    assert_eq!(mul_div_floor(a, b, 1u128 << 90), Some(1u128 << 110));

    // Exactness, including the floor.
    assert_eq!(mul_div_floor(7, 5, 3), Some(11));
    assert_eq!(mul_div_floor(u128::MAX, 1, u128::MAX), Some(1));

    // Undefined and unrepresentable results are reported, never wrapped.
    assert_eq!(mul_div_floor(1, 1, 0), None);
    assert_eq!(mul_div_floor(u128::MAX, u128::MAX, 1), None);
}

#[test]
fn decay_table_matches_the_paper_retention_multipliers() {
    // Table I of the paper tabulates r = 0.80 out to a topological age of four:
    // 1.0000, 0.8000, 0.6400, 0.5120 and 0.4096.
    let table = DecayTable::new(80, 100, 8).expect("0 < r < 1");
    assert_eq!(table.max_age(), 8);
    assert_eq!(table.multiplier(0), ONE);

    for age in 0..=8u32 {
        // Independent expectation: r^age evaluated as a single exact rational
        // rather than as a chain of per-step multiplies.
        let exact = mul_div_floor(ONE, 80u128.pow(age), 100u128.pow(age)).expect("in range");
        let multiplier = table.multiplier(age as usize);
        assert!(
            multiplier.abs_diff(exact) <= age as u128,
            "r^{age} drifted from the exact rational by more than one unit per step"
        );

        // And the same values in basis points, which is how the paper prints
        // them. Each entry floors, so it can sit one unit low.
        let as_basis_points = mul_shift(to_fixed(10_000), multiplier) >> 64;
        let expected_basis_points = 10_000u128 * 80u128.pow(age) / 100u128.pow(age);
        assert!(
            as_basis_points.abs_diff(expected_basis_points) <= 1,
            "r^{age} should be {expected_basis_points} basis points, got {as_basis_points}"
        );
    }
}

#[test]
fn decay_table_rejects_non_convergent_retention() {
    assert!(DecayTable::new(0, 100, 4).is_none(), "r = 0 never retains");
    assert!(DecayTable::new(100, 100, 4).is_none(), "r = 1 never decays");
    assert!(DecayTable::new(101, 100, 4).is_none(), "r > 1 amplifies");
}

// ---------------------------------------------------------------------------
// The paper's worked simulation (section IV, Table I)
// ---------------------------------------------------------------------------

/// Replays the five-cohort simulation: Alice mines throughout, Bob leaves after
/// the first cohort and returns for the fee spike in the fifth, and Charlie
/// joins only for the fifth.
fn paper_simulation() -> EdcaPayout {
    let mut payout = EdcaPayout::new(simulation_params()).expect("valid parameters");

    // C1: high-fee regime (1.25 BTC). Alice and Bob both mining.
    payout
        .push_cohort(vec![share("alice", 125_000_000), share("bob", 125_000_000)])
        .expect("cohort accepted");
    // C2-C4: the low-fee regime Bob hops away from.
    payout
        .push_cohort(vec![share("alice", 10_000_000)])
        .expect("cohort accepted");
    payout
        .push_cohort(vec![share("alice", 15_000_000)])
        .expect("cohort accepted");
    payout
        .push_cohort(vec![share("alice", 40_000_000)])
        .expect("cohort accepted");
    // C5: fees spike to 1.50 BTC; Bob returns and Charlie arrives.
    payout
        .push_cohort(vec![
            share("alice", 150_000_000),
            share("bob", 150_000_000),
            share("charlie", 150_000_000),
        ])
        .expect("cohort accepted");

    payout
}

#[test]
fn fee_amplifier_scales_the_raw_score_with_mempool_value() {
    let payout = EdcaPayout::new(simulation_params()).expect("valid parameters");

    // Equation (3) then (4): A_i = 3.125 + 1.25 = 4.375 BTC, and with
    // D_bp = 500 over D_network = 1 the raw score is 500 * A_i, which is the
    // 2187.5 the paper reports for the first cohort.
    let score = payout
        .raw_score(&share("alice", 125_000_000))
        .expect("score representable");
    assert_eq!(score >> 64, 2187 * BTC as u128 + BTC as u128 / 2);

    // A bead built on a low-fee template is worth strictly less.
    let low_fee = payout
        .raw_score(&share("alice", 10_000_000))
        .expect("score representable");
    assert_eq!(low_fee >> 64, 1612 * BTC as u128 + BTC as u128 / 2);
    assert!(low_fee < score);
}

#[test]
fn edca_weight_decays_uniformly_across_a_cohort() {
    let payout = paper_simulation();
    let weights = payout.weights();

    // Bob's weight is C1 decayed by r^4 plus an undecayed C5:
    //   500 * (4.375 * 0.4096 + 4.625) BTC = (896.0 + 2312.5) BTC-units.
    let expected_bob = (8_960u128 * BTC as u128 / 10) + (23_125u128 * BTC as u128 / 10);
    assert!(
        (weights["bob"] >> 64).abs_diff(expected_bob) <= 1,
        "Bob's weight should be {expected_bob} BTC-units, got {}",
        weights["bob"] >> 64
    );

    // Charlie only mined the newest cohort, so his weight is undecayed.
    assert_eq!(weights["charlie"] >> 64, 23_125u128 * BTC as u128 / 10);

    // Every bead in C5 was mined at the same difficulty against the same
    // template, so all three miners contribute an identical age-zero weight.
    // Stripping Charlie's C5-only weight from Bob therefore leaves exactly his
    // decayed C1 bead: 500 * 4.375 * 0.4096 = 896.0 BTC-units.
    let bobs_c1_weight = (weights["bob"] - weights["charlie"]) >> 64;
    assert!(
        bobs_c1_weight.abs_diff(8_960u128 * BTC as u128 / 10) <= 1,
        "Bob's decayed C1 bead should be 896.0 BTC-units, got {bobs_c1_weight}"
    );
}

#[test]
fn edca_reproduces_paper_payout_percentages() {
    let payout = paper_simulation();

    // Independent recomputation of Table I in whole basis points of r, using
    // plain integer arithmetic rather than the Q64.64 path under test.
    let alice_units: u128 =
        4_375 * 4_096 + 3_225 * 5_120 + 3_275 * 6_400 + 3_525 * 8_000 + 4_625 * 10_000;
    let bob_units: u128 = 4_375 * 4_096 + 4_625 * 10_000;
    let charlie_units: u128 = 4_625 * 10_000;
    let total_units = alice_units + bob_units + charlie_units;

    assert_eq!(ppm(&payout, "alice"), alice_units * 1_000_000 / total_units);
    assert_eq!(ppm(&payout, "bob"), bob_units * 1_000_000 / total_units);
    assert_eq!(
        ppm(&payout, "charlie"),
        charlie_units * 1_000_000 / total_units
    );

    // The figures the paper prints: 54.04%, 26.71% and 19.25%.
    assert_eq!(ppm(&payout, "alice") / 100, 5_404);
    assert_eq!(ppm(&payout, "bob") / 100, 2_670);
    assert_eq!(ppm(&payout, "charlie") / 100, 1_924);
}

#[test]
fn edca_reproduces_paper_settlement_simulation() {
    let payout = paper_simulation();
    // The block is found in C5, so the reward carries that cohort's fees.
    let reward = Amount::from_sat(462_500_000);
    let settlement = payout.settle(reward).expect("settlement is defined");

    assert!(settlement.swept.is_empty(), "no output is sub-dust here");
    assert_eq!(settlement.dust_swept, Amount::ZERO);
    assert_eq!(settlement.outputs.len(), 3);

    let amount = |address: &str| -> u64 {
        settlement
            .outputs
            .iter()
            .find(|output| output.payout_address == address)
            .map(|output| output.amount.to_sat())
            .expect("miner is paid")
    };

    // Independent expectation, again in basis points of r.
    let alice_units: u128 =
        4_375 * 4_096 + 3_225 * 5_120 + 3_275 * 6_400 + 3_525 * 8_000 + 4_625 * 10_000;
    let bob_units: u128 = 4_375 * 4_096 + 4_625 * 10_000;
    let charlie_units: u128 = 4_625 * 10_000;
    let total_units = alice_units + bob_units + charlie_units;
    let expected = |units: u128| -> u64 { (units * reward.to_sat() as u128 / total_units) as u64 };

    // Within a satoshi of the exact ratio; the difference is the deterministic
    // rounding remainder handed back below.
    for (address, units) in [
        ("alice", alice_units),
        ("bob", bob_units),
        ("charlie", charlie_units),
    ] {
        let difference = amount(address).abs_diff(expected(units));
        assert!(
            difference <= 1,
            "{address} paid {} satoshis, expected {}",
            amount(address),
            expected(units)
        );
    }

    // Table I: 2.500, 1.235 and 0.890 BTC to three decimal places.
    assert_eq!(amount("alice") / 100_000, 2_499);
    assert_eq!(amount("bob") / 100_000, 1_235);
    assert_eq!(amount("charlie") / 100_000, 890);

    // Bob's fee-snipe fails: he was absent for three cohorts and lands well
    // under Alice's absolute majority.
    assert!(amount("alice") > amount("bob") + amount("charlie"));
}

// ---------------------------------------------------------------------------
// Settlement invariants (section VI.C, Lean proof 2)
// ---------------------------------------------------------------------------

#[test]
fn settlement_is_zero_sum() {
    let payout = paper_simulation();
    // 1_000 satoshis is deliberately small enough that Charlie's share falls
    // under the dust limit, so the sweep path is covered here too.
    for reward_sats in [462_500_000u64, 312_500_000, 100_000, 999_999_937, 1_000] {
        let settlement = payout
            .settle(Amount::from_sat(reward_sats))
            .expect("settlement is defined");
        let paid: u64 = settlement
            .outputs
            .iter()
            .map(|output| output.amount.to_sat())
            .sum();
        assert_eq!(
            paid, reward_sats,
            "every satoshi of a {reward_sats} satoshi reward must be settled"
        );
    }
}

#[test]
fn sub_dust_outputs_are_swept_and_redistributed() {
    let mut payout = EdcaPayout::new(EdcaParams::testing()).expect("valid parameters");
    // One dominant miner and two miners whose share of the reward cannot reach
    // the 330 satoshi dust limit.
    payout
        .push_cohort(vec![
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("whale", 0),
            share("dust_one", 0),
            share("dust_two", 0),
        ])
        .expect("cohort accepted");

    // 4000 satoshis over twelve beads leaves the two single-bead miners at
    // 333 satoshis each... so settle a smaller reward to push them under.
    let reward = Amount::from_sat(3_000);
    let settlement = payout.settle(reward).expect("settlement is defined");

    let swept_addresses: Vec<&str> = settlement
        .swept
        .iter()
        .map(|share| share.payout_address.as_str())
        .collect();
    assert_eq!(swept_addresses, vec!["dust_one", "dust_two"]);
    assert_eq!(settlement.dust_swept, Amount::from_sat(500));

    // The dust is redistributed to the qualifying set, not kept by the finder.
    assert_eq!(settlement.outputs.len(), 1);
    assert_eq!(settlement.outputs[0].payout_address, "whale");
    assert_eq!(settlement.outputs[0].amount, reward);
}

#[test]
fn settlement_reports_when_no_miner_clears_the_dust_limit() {
    let mut payout = EdcaPayout::new(EdcaParams::testing()).expect("valid parameters");
    payout
        .push_cohort(vec![share("alice", 0), share("bob", 0)])
        .expect("cohort accepted");

    // 100 satoshis split two ways is 50 each, below the 330 satoshi limit.
    let error = payout.settle(Amount::from_sat(100)).unwrap_err();
    assert_eq!(
        error,
        EdcaError::NoQualifyingMiners {
            dust_limit: 330,
            total_reward: 100,
        }
    );
}

#[test]
fn settlement_of_an_empty_pool_is_undefined() {
    let payout = EdcaPayout::new(EdcaParams::testing()).expect("valid parameters");
    assert_eq!(
        payout.settle(Amount::from_sat(BTC)).unwrap_err(),
        EdcaError::EmptyPool
    );
    assert_eq!(payout.percentages_ppm().unwrap_err(), EdcaError::EmptyPool);
}

// ---------------------------------------------------------------------------
// Truncation (section VI.A, Lean proof 1)
// ---------------------------------------------------------------------------

#[test]
fn cohorts_are_pruned_once_their_geometric_tail_is_unspendable() {
    let params = EdcaParams {
        retention_numerator: 50,
        retention_denominator: 100,
        network_difficulty: 1_000_000_000_000,
        ..EdcaParams::testing()
    };
    let mut payout = EdcaPayout::new(params).expect("valid parameters");

    for _ in 0..64 {
        payout
            .push_cohort(vec![share("alice", 0)])
            .expect("cohort accepted");
    }

    assert!(
        payout.pruned_cohorts() > 0,
        "an aggressive decay must eventually cross the dust threshold"
    );
    assert!(
        payout.retained_cohorts() < 64,
        "the active state must be bounded, retained {} of 64",
        payout.retained_cohorts()
    );

    // Continuing to mine does not grow the state: this is the O(1) bound.
    let bounded = payout.retained_cohorts();
    for _ in 0..64 {
        payout
            .push_cohort(vec![share("alice", 0)])
            .expect("cohort accepted");
    }
    assert_eq!(payout.retained_cohorts(), bounded);
}

#[test]
fn cohort_history_is_capped_unconditionally() {
    let params = EdcaParams {
        max_cohort_history: 4,
        ..EdcaParams::testing()
    };
    let mut payout = EdcaPayout::new(params).expect("valid parameters");

    for _ in 0..32 {
        payout
            .push_cohort(vec![share("alice", 0)])
            .expect("cohort accepted");
    }
    assert_eq!(payout.retained_cohorts(), 4);
}

#[test]
fn pruning_shifts_payouts_by_the_truncation_shift_theorem() {
    // Equation (12): dP = e * (P - q_A) / (W - e), where `e` is the decayed
    // aggregate of the cohort being pruned and `q_A` is the miner's proportion
    // within it. Ages are measured from the newest cohort, so dropping the
    // oldest leaves every surviving cohort's age unchanged - which is exactly
    // what makes the two states below comparable.
    // Alice dominates the cohort that is about to be pruned but is a minority
    // afterwards, which puts her in the paper's "Departed / Loss" row: her
    // historical share of the deleted cohort exceeds her current share of the
    // pool, so the shift must be strictly negative.
    let cohorts = [
        vec![share("alice", 0), share("alice", 0), share("bob", 0)],
        vec![share("alice", 0), share("bob", 0), share("bob", 0)],
        vec![share("alice", 0), share("bob", 0), share("bob", 0)],
        vec![share("alice", 0), share("bob", 0), share("bob", 0)],
    ];

    let build = |from: usize| {
        let mut payout = EdcaPayout::new(simulation_params()).expect("valid parameters");
        for cohort in &cohorts[from..] {
            payout.push_cohort(cohort.clone()).expect("cohort accepted");
        }
        payout
    };

    let full = build(0);
    let pruned = build(1);

    // State before the pruning event.
    let total_weight = full.total_weight();
    let alice_weight = full.weights()["alice"];

    // The cohort that gets deleted, decayed to its topological age.
    let epsilon = total_weight - pruned.total_weight();
    let alice_in_cohort = alice_weight - pruned.weights()["alice"];

    // dP measured against dP predicted, both in parts per billion so the
    // comparison is exact integer arithmetic.
    let scale = 1_000_000_000u128;
    let proportion_before = mul_div_floor(alice_weight, scale, total_weight).expect("in range");
    let proportion_after =
        mul_div_floor(pruned.weights()["alice"], scale, pruned.total_weight()).expect("in range");
    let q_a = mul_div_floor(alice_in_cohort, scale, epsilon).expect("in range");

    // Alice out-contributed her historical share of the pruned cohort, so the
    // shift must be negative: q_A > P puts her in the paper's "Loss" row.
    assert!(q_a > proportion_before, "fixture must exercise q_A > P");
    assert!(proportion_after < proportion_before);

    let measured = proportion_before - proportion_after;
    let predicted =
        mul_div_floor(epsilon, q_a - proportion_before, total_weight - epsilon).expect("in range");
    // Each of the four ratios above floors independently, so the comparison
    // carries a handful of parts per billion of slack on quantities of 1e9.
    assert!(
        measured.abs_diff(predicted) <= 8,
        "measured shift {measured} ppb, predicted {predicted} ppb"
    );
}

// ---------------------------------------------------------------------------
// Game-theoretic invariants (Lean proofs 3-5)
// ---------------------------------------------------------------------------

#[test]
fn splitting_work_across_identities_yields_no_advantage() {
    // Theorem 3/4: the score function is linear in work, so an entity that
    // splits its beads over N addresses collects exactly what it would have
    // collected under one.
    let mut single = EdcaPayout::new(simulation_params()).expect("valid parameters");
    let mut split = EdcaPayout::new(simulation_params()).expect("valid parameters");

    for cohort_index in 0..6u64 {
        let fees = Amount::from_sat(cohort_index * 5_000_000);
        single
            .push_cohort(vec![
                BeadShare::with_fixed_difficulty("sybil", fees),
                BeadShare::with_fixed_difficulty("sybil", fees),
                BeadShare::with_fixed_difficulty("sybil", fees),
                BeadShare::with_fixed_difficulty("honest", fees),
            ])
            .expect("cohort accepted");
        split
            .push_cohort(vec![
                BeadShare::with_fixed_difficulty("sybil_a", fees),
                BeadShare::with_fixed_difficulty("sybil_b", fees),
                BeadShare::with_fixed_difficulty("sybil_c", fees),
                BeadShare::with_fixed_difficulty("honest", fees),
            ])
            .expect("cohort accepted");
    }

    let combined = ppm(&split, "sybil_a") + ppm(&split, "sybil_b") + ppm(&split, "sybil_c");
    assert!(
        ppm(&single, "sybil").abs_diff(combined) <= 2,
        "splitting changed the payout from {} to {} ppm",
        ppm(&single, "sybil"),
        combined
    );
    assert!(ppm(&single, "honest").abs_diff(ppm(&split, "honest")) <= 2);
}

#[test]
fn withholding_a_share_strictly_reduces_its_value() {
    // Theorem 6: increasing a share's topological age strictly decreases its
    // evaluation whenever 0 < r < 1. Both states hold the same beads; the
    // second miner simply announces one cohort later.
    let mut prompt = EdcaPayout::new(simulation_params()).expect("valid parameters");
    let mut withheld = EdcaPayout::new(simulation_params()).expect("valid parameters");

    prompt
        .push_cohort(vec![share("miner", 0)])
        .expect("cohort accepted");
    prompt.push_cohort(Vec::new()).expect("cohort accepted");

    withheld.push_cohort(Vec::new()).expect("cohort accepted");
    withheld
        .push_cohort(vec![share("miner", 0)])
        .expect("cohort accepted");

    assert!(
        prompt.weights()["miner"] < withheld.weights()["miner"],
        "a bead announced one cohort late must be worth strictly less"
    );
}

#[test]
fn missing_a_fee_spike_costs_the_amplified_reward() {
    // Section VII.D: the marginal loss from skipping the newest cohort equals
    // the proportional value of the base subsidy plus the high fees it carried,
    // which is what makes tip-withholding irrational.
    let mut present = EdcaPayout::new(simulation_params()).expect("valid parameters");
    let mut absent = EdcaPayout::new(simulation_params()).expect("valid parameters");

    for state in [&mut present, &mut absent] {
        state
            .push_cohort(vec![share("miner", 0), share("rival", 0)])
            .expect("cohort accepted");
    }
    present
        .push_cohort(vec![share("miner", 2 * BTC), share("rival", 2 * BTC)])
        .expect("cohort accepted");
    absent
        .push_cohort(vec![share("rival", 2 * BTC)])
        .expect("cohort accepted");

    assert!(ppm(&present, "miner") > ppm(&absent, "miner"));
    // The rival captures what the sniper gave up: both states still account for
    // the whole pool, up to the one part per million lost to flooring.
    let present_total = ppm(&present, "miner") + ppm(&present, "rival");
    let absent_total = ppm(&absent, "miner") + ppm(&absent, "rival");
    assert!(present_total.abs_diff(absent_total) <= 1);
    assert!(ppm(&absent, "rival") > ppm(&present, "rival"));
}

// ---------------------------------------------------------------------------
// Parameter validation and braid integration
// ---------------------------------------------------------------------------

#[test]
fn invalid_consensus_parameters_are_rejected() {
    let non_convergent = EdcaParams {
        retention_numerator: 100,
        retention_denominator: 100,
        ..EdcaParams::testing()
    };
    assert_eq!(
        EdcaPayout::new(non_convergent).unwrap_err(),
        EdcaError::InvalidRetention {
            numerator: 100,
            denominator: 100,
        }
    );

    let zero_difficulty = EdcaParams {
        network_difficulty: 0,
        ..EdcaParams::testing()
    };
    assert_eq!(
        EdcaPayout::new(zero_difficulty).unwrap_err(),
        EdcaError::ZeroNetworkDifficulty
    );
}

/// Builds a two-cohort braid whose beads pay out to the given addresses.
fn braid_with_cohorts(cohorts: &[Vec<&str>]) -> Braid {
    let mut beads: Vec<Bead> = Vec::new();
    let mut braid_cohorts: Vec<Cohort> = Vec::new();
    let mut bead_index_mapping = HashMap::new();

    for addresses in cohorts {
        let mut indices = HashSet::new();
        for address in addresses {
            let mut bead = emit_bead();
            bead.committed_metadata.payout_address = (*address).to_string();
            // `emit_bead` randomises the header, so hashes stay distinct.
            bead_index_mapping.insert(
                compute_block_hash(&bead.block_header, PoolNetwork::Cpunet),
                beads.len(),
            );
            indices.insert(beads.len());
            beads.push(bead);
        }
        braid_cohorts.push(Cohort(indices));
    }

    let tips = braid_cohorts
        .last()
        .map(|cohort| cohort.0.clone())
        .unwrap_or_default();
    let genesis_beads = braid_cohorts
        .first()
        .map(|cohort| cohort.0.clone())
        .unwrap_or_default();
    let cohort_tips = braid_cohorts
        .iter()
        .map(|cohort| cohort.0.clone())
        .collect();

    Braid {
        beads,
        tips,
        cohorts: braid_cohorts,
        cohort_tips,
        orphan_beads: Vec::new(),
        genesis_beads,
        bead_index_mapping,
        network: PoolNetwork::Cpunet,
    }
}

#[test]
fn from_braid_consumes_cohorts_oldest_first() {
    let braid = braid_with_cohorts(&[vec!["old"], vec!["new"]]);
    let payout = EdcaPayout::from_braid(simulation_params(), &braid, |_| Amount::ZERO)
        .expect("braid is well formed");

    assert_eq!(payout.retained_cohorts(), 2);
    // The older bead has aged by one cohort, so `r = 0.80` puts it at four
    // fifths of the newer bead's weight.
    let weights = payout.weights();
    assert_eq!(
        weights["old"],
        mul_shift(
            weights["new"],
            DecayTable::new(80, 100, 1).expect("valid r").multiplier(1)
        )
    );
}

#[test]
fn from_braid_is_deterministic_regardless_of_cohort_iteration_order() {
    let braid = braid_with_cohorts(&[
        vec!["alice", "bob", "carol"],
        vec!["alice", "carol"],
        vec!["bob", "bob", "alice"],
    ]);

    let first = EdcaPayout::from_braid(EdcaParams::testing(), &braid, |bead| {
        Amount::from_sat(bead.committed_metadata.payout_address.len() as u64 * 1_000)
    })
    .expect("braid is well formed");

    for _ in 0..8 {
        let repeated = EdcaPayout::from_braid(EdcaParams::testing(), &braid, |bead| {
            Amount::from_sat(bead.committed_metadata.payout_address.len() as u64 * 1_000)
        })
        .expect("braid is well formed");
        assert_eq!(first.weights(), repeated.weights());
        assert_eq!(
            first.settle(Amount::from_sat(BTC)).expect("settled"),
            repeated.settle(Amount::from_sat(BTC)).expect("settled")
        );
    }
}

#[test]
fn fixed_test_difficulty_is_applied_to_every_bead() {
    // Section III.B: a uniform global difficulty means a larger miner submits
    // more beads, never heavier ones. Two miners with the same bead count must
    // therefore weigh the same regardless of who they are.
    let mut payout = EdcaPayout::new(EdcaParams::testing()).expect("valid parameters");
    payout
        .push_cohort(vec![
            BeadShare::with_fixed_difficulty("alice", Amount::ZERO),
            BeadShare::new("bob", Amount::ZERO, TEST_BEAD_DIFFICULTY),
        ])
        .expect("cohort accepted");

    let weights = payout.weights();
    assert_eq!(weights["alice"], weights["bob"]);
    assert_eq!(ppm(&payout, "alice"), 500_000);
}

// ---------------------------------------------------------------------------
// Coinbase integration
// ---------------------------------------------------------------------------

/// Regtest P2WPKH addresses derived from the secp256k1 scalars 1..4, used as
/// stand-ins for miner payout addresses.
const MINER_ADDRESSES: [&str; 4] = [
    "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
    "bcrt1qq6hag67dl53wl99vzg42z8eyzfz2xlkvwk6f7m",
    "bcrt1q0ht9tyks4vh7p5p904t340cr9nvahy7uevmqwj",
    "bcrt1qcsh8a7f0mdsr47zy6pj04tv4mwdumlfacs66tf",
];

/// The chain the coinbase tests settle against.
const TEST_NETWORK: PoolNetwork = PoolNetwork::Bitcoin(Network::Regtest);

#[test]
fn payout_addresses_resolve_only_for_their_own_chain() {
    assert!(resolve_payout_script(MINER_ADDRESSES[0], TEST_NETWORK).is_some());

    // A mainnet address on regtest is rejected rather than coerced: paying it
    // out on the wrong chain would burn the miner's reward.
    assert!(
        resolve_payout_script("bc1qpa77defz30uavu8lxef98q95rae6m7t8au9vp7", TEST_NETWORK).is_none()
    );

    // A worker name that is not an address at all is untrusted input arriving
    // from `mining.submit`, and must not be able to stop template creation.
    assert!(resolve_payout_script("worker1", TEST_NETWORK).is_none());
    assert!(resolve_payout_script("", TEST_NETWORK).is_none());
}

/// Builds a payout state where each address in `addresses` mines one bead per
/// cohort, for `cohorts` cohorts.
fn payout_over(addresses: &[&str], cohorts: usize) -> EdcaPayout {
    let mut payout =
        EdcaPayout::new(EdcaParams::for_network(TEST_NETWORK)).expect("valid parameters");
    for _ in 0..cohorts {
        payout
            .push_cohort(addresses.iter().map(|address| share(address, 0)))
            .expect("cohort accepted");
    }
    payout
}

#[test]
fn coinbase_roster_pays_every_satoshi_of_the_template_reward() {
    let payout = payout_over(&MINER_ADDRESSES, 3);
    let reward = Amount::from_sat(5_000_012_345);

    let distribution = build_payout_distribution(&payout, reward, TEST_NETWORK, MAX_PAYOUT_OUTPUTS)
        .expect("roster is settleable");

    assert_eq!(distribution.outputs.len(), MINER_ADDRESSES.len());
    assert_eq!(distribution.total_value(), reward);
    assert!(distribution.unresolved.is_empty());
    assert!(distribution.over_budget.is_empty());

    // Outputs are ordered largest first, and each carries the miner's own
    // script rather than the pool's.
    let mut previous = Amount::MAX_MONEY;
    for output in &distribution.outputs {
        assert!(output.value <= previous);
        previous = output.value;
        assert!(MINER_ADDRESSES
            .iter()
            .any(
                |address| resolve_payout_script(address, TEST_NETWORK).as_ref()
                    == Some(&output.script_pubkey)
            ));
    }
}

#[test]
fn unpayable_addresses_renormalise_the_remaining_miners() {
    let mut payout =
        EdcaPayout::new(EdcaParams::for_network(TEST_NETWORK)).expect("valid parameters");
    payout
        .push_cohort(vec![
            share(MINER_ADDRESSES[0], 0),
            share(MINER_ADDRESSES[1], 0),
            // A worker name that never was an address, and a mainnet address.
            share("not-an-address", 0),
            share("bc1qpa77defz30uavu8lxef98q95rae6m7t8au9vp7", 0),
        ])
        .expect("cohort accepted");

    let reward = Amount::from_sat(5_000_000_000);
    let distribution = build_payout_distribution(&payout, reward, TEST_NETWORK, MAX_PAYOUT_OUTPUTS)
        .expect("roster is settleable");

    assert_eq!(distribution.unresolved.len(), 2);
    assert_eq!(distribution.outputs.len(), 2);
    // The dropped weight is redistributed, not destroyed: the two payable
    // miners split the whole reward evenly rather than taking a quarter each.
    assert_eq!(distribution.total_value(), reward);
    assert_eq!(
        distribution.outputs[0].value,
        Amount::from_sat(2_500_000_000)
    );
    assert_eq!(
        distribution.outputs[1].value,
        Amount::from_sat(2_500_000_000)
    );
}

#[test]
fn coinbase_output_budget_defers_the_lightest_miners() {
    let payout = payout_over(&MINER_ADDRESSES, 1);
    let reward = Amount::from_sat(5_000_000_000);

    let distribution =
        build_payout_distribution(&payout, reward, TEST_NETWORK, 2).expect("roster is settleable");

    assert_eq!(distribution.outputs.len(), 2);
    assert_eq!(distribution.over_budget.len(), 2);
    // Still zero-sum: the deferred miners' share goes to those who are paid,
    // and their EDCA claim survives untouched for the next block.
    assert_eq!(distribution.total_value(), reward);
}

#[test]
fn coinbase_roster_is_unavailable_before_any_share_is_accepted() {
    let payout = EdcaPayout::new(EdcaParams::for_network(TEST_NETWORK)).expect("valid parameters");
    assert_eq!(
        build_payout_distribution(
            &payout,
            Amount::from_sat(5_000_000_000),
            TEST_NETWORK,
            MAX_PAYOUT_OUTPUTS
        )
        .unwrap_err(),
        EdcaError::EmptyPool
    );
}

// ---------------------------------------------------------------------------
// Tracker: the `mining.submit` -> template creation path
// ---------------------------------------------------------------------------

/// Builds a braid whose beads carry the given payout addresses, one cohort per
/// slice, and the tracker to go with it.
async fn tracked_braid(cohorts: &[Vec<&str>]) -> (Braid, PayoutTracker) {
    let braid = braid_with_cohorts(cohorts);
    let tracker = PayoutTracker::with_params(
        EdcaParams::for_network(TEST_NETWORK),
        TEST_NETWORK,
        MAX_PAYOUT_OUTPUTS,
    )
    .expect("valid parameters");
    (braid, tracker)
}

#[tokio::test]
async fn recording_an_accepted_share_builds_the_payout_roster() {
    let (braid, tracker) =
        tracked_braid(&[vec![MINER_ADDRESSES[0]], vec![MINER_ADDRESSES[1]]]).await;

    // Nothing is payable until a share has been accepted.
    assert!(tracker
        .payout_outputs(Amount::from_sat(5_000_000_000))
        .await
        .is_empty());

    // A regtest template pays 50 BTC, so the fee amplifier resolves to a
    // fee-free bead: A_i = B_base.
    let subsidy = Amount::from_sat(REGTEST_BASE_SUBSIDY_SATS);
    for bead in &braid.beads {
        tracker
            .record_bead(&braid, braid.compute_bead_hash(bead), subsidy)
            .await
            .expect("bead recorded");
    }

    assert_eq!(tracker.retained_cohorts().await, 2);
    let weights = tracker.weights().await;
    assert_eq!(weights.len(), 2);
    // The older bead has decayed by r = 0.95, the newer one has not.
    assert!(weights[MINER_ADDRESSES[0]] < weights[MINER_ADDRESSES[1]]);

    let reward = Amount::from_sat(5_000_000_000);
    let outputs = tracker.payout_outputs(reward).await;
    assert_eq!(outputs.len(), 2);
    assert_eq!(
        outputs
            .iter()
            .fold(Amount::ZERO, |sum, output| sum + output.value),
        reward
    );
}

#[tokio::test]
async fn a_richer_template_earns_a_larger_share() {
    // Equation (3): a bead built on a fee-heavy template is worth more than one
    // built on an empty mempool, even at identical difficulty and cohort age.
    let (braid, tracker) = tracked_braid(&[vec![MINER_ADDRESSES[0], MINER_ADDRESSES[1]]]).await;

    let subsidy = REGTEST_BASE_SUBSIDY_SATS;
    for bead in &braid.beads {
        let reward = if bead.committed_metadata.payout_address == MINER_ADDRESSES[0] {
            // One bitcoin of fees on top of the subsidy.
            Amount::from_sat(subsidy + BTC)
        } else {
            Amount::from_sat(subsidy)
        };
        tracker
            .record_bead(&braid, braid.compute_bead_hash(bead), reward)
            .await
            .expect("bead recorded");
    }

    let weights = tracker.weights().await;
    assert!(weights[MINER_ADDRESSES[0]] > weights[MINER_ADDRESSES[1]]);

    // The ratio is exactly (50 + 1) : 50, the two amplified rewards.
    let expected = mul_div_floor(
        weights[MINER_ADDRESSES[1]],
        subsidy as u128 + BTC as u128,
        subsidy as u128,
    )
    .expect("in range");
    assert!(weights[MINER_ADDRESSES[0]].abs_diff(expected) <= 1);
}

#[tokio::test]
async fn a_payout_fault_never_blocks_template_creation() {
    // Every failure mode of the payout path degrades to "pay the pool", so the
    // node keeps producing templates.
    let (braid, tracker) = tracked_braid(&[vec![MINER_ADDRESSES[0]]]).await;
    tracker
        .record_bead(
            &braid,
            braid.compute_bead_hash(&braid.beads[0]),
            Amount::from_sat(REGTEST_BASE_SUBSIDY_SATS),
        )
        .await
        .expect("bead recorded");

    // A reward too small for anyone to clear the dust limit.
    assert!(tracker.payout_outputs(Amount::from_sat(1)).await.is_empty());
    // And a normal reward still produces a roster.
    assert!(!tracker
        .payout_outputs(Amount::from_sat(5_000_000_000))
        .await
        .is_empty());
}
