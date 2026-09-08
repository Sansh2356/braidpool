//! Deterministic fixed-point arithmetic backing the EDCA payout algorithm.
//!
//! Section VI.B of the EDCA paper (`docs/EDCA.pdf`) forbids floating point in
//! consensus code: IEEE-754 rounding is not reproducible across architectures,
//! so two nodes could derive different payout percentages from an identical
//! DAG. Every quantity in [`crate::payout`] is therefore carried as an unsigned
//! **Q64.64** fixed-point integer — a `u128` whose low 64 bits are the
//! fractional part and whose high 64 bits are the integer part.
//!
//! Two primitives do all of the work:
//!
//! * [`mul_shift`] — the paper's "distributive split-shift" multiply. The two
//!   operands are decomposed into their high and low 64-bit segments, the four
//!   partial products are accumulated into a full 256-bit intermediate, and the
//!   result is shifted back down by 64. This keeps fidelity under "limitless
//!   fee spikes" instead of silently truncating a large miner's score.
//! * [`mul_div_floor`] — an exact `a * b / divisor` over the same 256-bit
//!   intermediate. Used wherever a ratio must be evaluated without first
//!   collapsing it to a lossy reciprocal.

/// Number of fractional bits in the Q64.64 representation used throughout EDCA.
pub const FRACTIONAL_BITS: u32 = 64;

/// The Q64.64 encoding of `1.0`, i.e. `1u128 << 64`.
///
/// This is the retention multiplier applied to a cohort of topological age
/// zero (`r^0 = 1`).
pub const ONE: u128 = 1u128 << FRACTIONAL_BITS;

/// Bit mask selecting the low 64-bit segment of a `u128`.
const LOW_SEGMENT: u128 = u64::MAX as u128;

/// Multiplies two `u128` values into a full 256-bit product.
///
/// This is the split-shift decomposition described in section VI.B: each
/// operand is cut into a high and a low 64-bit segment and the four partial
/// products are recombined, so no intermediate ever exceeds `u128`.
///
/// # Arguments
/// * `a` - Left operand.
/// * `b` - Right operand.
///
/// # Returns
/// The pair `(high, low)` such that the true product equals
/// `high * 2^128 + low`.
pub fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    let (a_high, a_low) = (a >> 64, a & LOW_SEGMENT);
    let (b_high, b_low) = (b >> 64, b & LOW_SEGMENT);

    let low_low = a_low * b_low;
    let low_high = a_low * b_high;
    let high_low = a_high * b_low;
    let high_high = a_high * b_high;

    // Carry the cross terms through the 64-bit boundary explicitly rather than
    // relying on a wider integer type.
    let middle = (low_low >> 64) + (low_high & LOW_SEGMENT) + (high_low & LOW_SEGMENT);
    let low = (low_low & LOW_SEGMENT) | (middle << 64);
    let high = high_high + (low_high >> 64) + (high_low >> 64) + (middle >> 64);

    (high, low)
}

/// Multiplies a Q64.64 value by a Q64.64 multiplier, returning a Q64.64 result.
///
/// Equivalent to `(a * b) >> 64` evaluated over a 256-bit intermediate, which
/// is how equation (5) of the paper (`W_i = S_i * r^{dc_i}`) is applied.
///
/// # Arguments
/// * `a` - Q64.64 multiplicand, typically a raw bead score.
/// * `b` - Q64.64 multiplier, typically a retention multiplier from
///   [`DecayTable`].
///
/// # Returns
/// The Q64.64 product, saturated at [`u128::MAX`] if it cannot be represented.
/// Saturation is deterministic and therefore consensus-safe, but it is only
/// reachable with scores far beyond any realistic block reward.
pub fn mul_shift(a: u128, b: u128) -> u128 {
    let (high, low) = mul_wide(a, b);
    if high >> 64 != 0 {
        return u128::MAX;
    }
    (high << 64) | (low >> 64)
}

/// Computes `floor(a * b / divisor)` exactly, over a 256-bit intermediate.
///
/// The quotient is produced by restoring binary long division over the wide
/// product, so the result is exact for every input for which it is
/// representable — no reciprocal is materialised and no precision is lost to an
/// intermediate rounding step.
///
/// # Arguments
/// * `a` - First factor of the numerator.
/// * `b` - Second factor of the numerator.
/// * `divisor` - Denominator.
///
/// # Returns
/// `Some(quotient)` when `divisor` is non-zero and the quotient fits in a
/// `u128`, otherwise `None`.
pub fn mul_div_floor(a: u128, b: u128, divisor: u128) -> Option<u128> {
    if divisor == 0 {
        return None;
    }
    let (high, low) = mul_wide(a, b);

    // Fast path: the product already fits in 128 bits.
    if high == 0 {
        return Some(low / divisor);
    }

    let mut remainder: u128 = 0;
    let mut quotient_high: u128 = 0;
    let mut quotient_low: u128 = 0;

    for bit_index in (0..256usize).rev() {
        let bit = if bit_index >= 128 {
            (high >> (bit_index - 128)) & 1
        } else {
            (low >> bit_index) & 1
        };

        // `remainder` is always strictly below `divisor` here, so the shift can
        // only overflow into a 129th bit, which is tracked separately.
        let carried_out = remainder >> 127 != 0;
        remainder = (remainder << 1) | bit;

        if carried_out || remainder >= divisor {
            remainder = remainder.wrapping_sub(divisor);
            if bit_index >= 128 {
                quotient_high |= 1u128 << (bit_index - 128);
            } else {
                quotient_low |= 1u128 << bit_index;
            }
        }
    }

    if quotient_high != 0 {
        None
    } else {
        Some(quotient_low)
    }
}

/// Lifts an integer (typically a satoshi amount) into Q64.64.
///
/// # Arguments
/// * `value` - Integer value to encode.
///
/// # Returns
/// The Q64.64 encoding of `value`.
pub fn to_fixed(value: u64) -> u128 {
    (value as u128) << FRACTIONAL_BITS
}

/// Truncates a Q64.64 value towards zero, yielding its integer part.
///
/// # Arguments
/// * `value` - Q64.64 value.
///
/// # Returns
/// The integer part of `value`.
pub fn to_integer(value: u128) -> u128 {
    value >> FRACTIONAL_BITS
}

/// Pre-computed table of EDCA retention multipliers `r^n` in Q64.64.
///
/// Section VI.B requires the decay curve to be "pre-computed into an `O(1)`
/// lookup table". The retention parameter `r` is held as an exact rational
/// `numerator / denominator` (e.g. `95 / 100` for `r = 0.95`) so that no
/// decimal literal — and therefore no float — ever enters the protocol. Each
/// entry is derived from its predecessor with a single exact
/// [`mul_div_floor`], which keeps the accumulated error below one unit in the
/// last place of Q64.64 per step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecayTable {
    /// `multipliers[n]` is the Q64.64 encoding of `r^n`.
    multipliers: Vec<u128>,
}

impl DecayTable {
    /// Builds the retention table for `r = numerator / denominator`.
    ///
    /// # Arguments
    /// * `numerator` - Numerator of the retention parameter `r`.
    /// * `denominator` - Denominator of the retention parameter `r`.
    /// * `max_age` - Largest topological age the table must answer for. The
    ///   table holds `max_age + 1` entries, bounding EDCA state to `O(1)`.
    ///
    /// # Returns
    /// `Some(table)` when `0 < numerator < denominator`, otherwise `None`. The
    /// bound is strict on both sides: `r = 0` collapses the pool to the newest
    /// cohort and `r >= 1` never decays, so neither yields a convergent
    /// geometric series.
    pub fn new(numerator: u64, denominator: u64, max_age: usize) -> Option<Self> {
        if numerator == 0 || denominator == 0 || numerator >= denominator {
            return None;
        }

        let mut multipliers = Vec::with_capacity(max_age + 1);
        multipliers.push(ONE);
        for age in 1..=max_age {
            let previous = multipliers[age - 1];
            let next = mul_div_floor(previous, numerator as u128, denominator as u128)?;
            multipliers.push(next);
        }

        Some(Self { multipliers })
    }

    /// Returns the Q64.64 retention multiplier `r^age`.
    ///
    /// # Arguments
    /// * `age` - Topological age in elapsed cohorts.
    ///
    /// # Returns
    /// `r^age` in Q64.64. Ages beyond the tabulated range clamp to the final
    /// entry; the truncation rule in [`crate::payout`] guarantees no retained
    /// cohort ever reaches that point.
    pub fn multiplier(&self, age: usize) -> u128 {
        match self.multipliers.get(age) {
            Some(multiplier) => *multiplier,
            None => self.multipliers.last().copied().unwrap_or(0),
        }
    }

    /// Returns the largest topological age this table was built for.
    pub fn max_age(&self) -> usize {
        self.multipliers.len().saturating_sub(1)
    }
}
