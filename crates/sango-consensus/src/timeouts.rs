//! Configuration des timeouts de consensus.
//!
//! Freeze section 17 :
//!
//! ```text
//! timeout_propose(r)   = 2s + r * 1s
//! timeout_prevote(r)   = 1s + r * 1s
//! timeout_precommit(r) = 1s + r * 1s
//! ```
//!
//! Le driver horloge ces valeurs ; le runner ne s'en sert pas directement.
//! Mais la **formule normative** vit ici, dans `sango-consensus`, pas dans
//! le driver.

use sango_primitives::Round;

/// Configuration des timeouts de consensus.
///
/// Toutes les valeurs sont en millisecondes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutConfig {
    /// Base du timeout `propose` (round 0).
    pub propose_base_ms: u64,
    /// Base du timeout `prevote` (round 0).
    pub prevote_base_ms: u64,
    /// Base du timeout `precommit` (round 0).
    pub precommit_base_ms: u64,
    /// Incrément par round, appliqué aux trois timeouts.
    pub increment_ms: u64,
}

impl TimeoutConfig {
    /// Configuration normative V1 (Freeze section 17).
    pub const V1: Self = Self {
        propose_base_ms: 2_000,
        prevote_base_ms: 1_000,
        precommit_base_ms: 1_000,
        increment_ms: 1_000,
    };

    /// Timeout `propose` pour le round `r` : `2s + r * 1s`.
    #[must_use]
    pub const fn propose_ms(&self, round: Round) -> u64 {
        self.propose_base_ms
            .saturating_add(self.increment_ms.saturating_mul(round.get()))
    }

    /// Timeout `prevote` pour le round `r` : `1s + r * 1s`.
    #[must_use]
    pub const fn prevote_ms(&self, round: Round) -> u64 {
        self.prevote_base_ms
            .saturating_add(self.increment_ms.saturating_mul(round.get()))
    }

    /// Timeout `precommit` pour le round `r` : `1s + r * 1s`.
    #[must_use]
    pub const fn precommit_ms(&self, round: Round) -> u64 {
        self.precommit_base_ms
            .saturating_add(self.increment_ms.saturating_mul(round.get()))
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self::V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_freeze() {
        let c = TimeoutConfig::V1;
        assert_eq!(c.propose_base_ms, 2_000);
        assert_eq!(c.prevote_base_ms, 1_000);
        assert_eq!(c.precommit_base_ms, 1_000);
        assert_eq!(c.increment_ms, 1_000);
    }

    #[test]
    fn round_0_values() {
        let c = TimeoutConfig::V1;
        assert_eq!(c.propose_ms(Round::new(0)), 2_000);
        assert_eq!(c.prevote_ms(Round::new(0)), 1_000);
        assert_eq!(c.precommit_ms(Round::new(0)), 1_000);
    }

    #[test]
    fn round_1_values() {
        let c = TimeoutConfig::V1;
        assert_eq!(c.propose_ms(Round::new(1)), 3_000);
        assert_eq!(c.prevote_ms(Round::new(1)), 2_000);
        assert_eq!(c.precommit_ms(Round::new(1)), 2_000);
    }

    #[test]
    fn round_3_values() {
        let c = TimeoutConfig::V1;
        assert_eq!(c.propose_ms(Round::new(3)), 5_000);
        assert_eq!(c.prevote_ms(Round::new(3)), 4_000);
        assert_eq!(c.precommit_ms(Round::new(3)), 4_000);
    }

    #[test]
    fn monotonic_in_round() {
        let c = TimeoutConfig::V1;
        for r in 0..100u64 {
            let curr = c.propose_ms(Round::new(r));
            let next = c.propose_ms(Round::new(r + 1));
            assert!(next > curr);
        }
    }

    #[test]
    fn no_overflow_on_huge_round() {
        let c = TimeoutConfig::V1;
        let _ = c.propose_ms(Round::new(u64::MAX));
        let _ = c.prevote_ms(Round::new(u64::MAX));
        let _ = c.precommit_ms(Round::new(u64::MAX));
    }
}
