//! The mutable half of an escrow: what the covenant carries in the payload.
//!
//! Fixed width and fixed field order, so the covenant script can pull any field
//! out with a constant-offset `OpTxPayloadSubstr` instead of parsing. Every
//! transition re-states the whole record; nothing is implicit.

use secp256k1::XOnlyPublicKey;
use thiserror::Error;

/// Payload layout, version 1:
///
/// ```text
/// offset  size  field
///      0     4  magic "kESC"
///      4     1  version
///      5     1  phase
///      6    32  terms id      — binds the state to the job it belongs to
///     38    32  maker         — zero while OPEN
///     70    32  tracking hash — zero unless SHIPPED
///    102     8  shipped_at    — DAA score at SHIPPED, for the auto-release clock
/// ```
pub const STATE_BYTES: usize = 110;

pub const MAGIC: [u8; 4] = *b"kESC";
pub const VERSION: u8 = 1;

pub const OFF_MAGIC: usize = 0;
pub const OFF_VERSION: usize = 4;
pub const OFF_PHASE: usize = 5;
pub const OFF_TERMS: usize = 6;
pub const OFF_MAKER: usize = 38;
pub const OFF_TRACKING: usize = 70;
pub const OFF_SHIPPED_AT: usize = 102;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("payload is {0} bytes, expected {STATE_BYTES}")]
    BadLength(usize),
    #[error("not an escrow payload (bad magic)")]
    BadMagic,
    #[error("unsupported escrow state version {0}")]
    BadVersion(u8),
    #[error("unknown phase byte {0}")]
    BadPhase(u8),
    #[error("{0}")]
    Malformed(&'static str),
    #[error("illegal transition {from:?} -> {to:?}")]
    IllegalTransition { from: Phase, to: Phase },
}

/// Only the phases that persist *inside* the covenant get a byte here. The
/// terminal outcomes (SETTLED, SLASH, REFUND) spend the escrow out of the
/// covenant, so there is no subsequent state to label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Open = 0,
    Claimed = 1,
    Shipped = 2,
    Disputed = 3,
}

impl Phase {
    pub fn from_byte(b: u8) -> Result<Self, StateError> {
        Ok(match b {
            0 => Phase::Open,
            1 => Phase::Claimed,
            2 => Phase::Shipped,
            3 => Phase::Disputed,
            other => return Err(StateError::BadPhase(other)),
        })
    }

    pub fn byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowState {
    pub phase: Phase,
    pub terms_id: [u8; 32],
    /// Set once the job is claimed; zero while OPEN.
    pub maker: Option<XOnlyPublicKey>,
    /// Carrier tracking number hash, set at SHIPPED.
    pub tracking: Option<[u8; 32]>,
    /// DAA score recorded at SHIPPED — the auto-release clock starts here.
    pub shipped_at: u64,
}

impl EscrowState {
    pub fn open(terms_id: [u8; 32]) -> Self {
        EscrowState { phase: Phase::Open, terms_id, maker: None, tracking: None, shipped_at: 0 }
    }

    pub fn encode(&self) -> [u8; STATE_BYTES] {
        let mut out = [0u8; STATE_BYTES];
        out[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        out[OFF_VERSION] = VERSION;
        out[OFF_PHASE] = self.phase.byte();
        out[OFF_TERMS..OFF_TERMS + 32].copy_from_slice(&self.terms_id);
        if let Some(m) = &self.maker {
            out[OFF_MAKER..OFF_MAKER + 32].copy_from_slice(&m.serialize());
        }
        if let Some(t) = &self.tracking {
            out[OFF_TRACKING..OFF_TRACKING + 32].copy_from_slice(t);
        }
        out[OFF_SHIPPED_AT..OFF_SHIPPED_AT + 8].copy_from_slice(&self.shipped_at.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() != STATE_BYTES {
            return Err(StateError::BadLength(bytes.len()));
        }
        if bytes[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
            return Err(StateError::BadMagic);
        }
        if bytes[OFF_VERSION] != VERSION {
            return Err(StateError::BadVersion(bytes[OFF_VERSION]));
        }
        let phase = Phase::from_byte(bytes[OFF_PHASE])?;

        let mut terms_id = [0u8; 32];
        terms_id.copy_from_slice(&bytes[OFF_TERMS..OFF_TERMS + 32]);

        let maker_bytes = &bytes[OFF_MAKER..OFF_MAKER + 32];
        let maker = if maker_bytes == [0u8; 32] {
            None
        } else {
            Some(XOnlyPublicKey::from_slice(maker_bytes).map_err(|_| StateError::Malformed("maker is not a valid x-only pubkey"))?)
        };

        let tracking_bytes = &bytes[OFF_TRACKING..OFF_TRACKING + 32];
        let tracking = if tracking_bytes == [0u8; 32] {
            None
        } else {
            let mut t = [0u8; 32];
            t.copy_from_slice(tracking_bytes);
            Some(t)
        };

        let mut sa = [0u8; 8];
        sa.copy_from_slice(&bytes[OFF_SHIPPED_AT..OFF_SHIPPED_AT + 8]);
        let state = EscrowState { phase, terms_id, maker, tracking, shipped_at: u64::from_le_bytes(sa) };
        state.check_invariants()?;
        Ok(state)
    }

    /// Fields that must agree with the phase. Enforced on decode so a
    /// well-formed-looking payload cannot describe a nonsensical escrow — e.g.
    /// a job that is SHIPPED by nobody, or OPEN yet already claimed.
    pub fn check_invariants(&self) -> Result<(), StateError> {
        match self.phase {
            Phase::Open => {
                if self.maker.is_some() {
                    return Err(StateError::Malformed("OPEN escrow cannot name a maker"));
                }
                if self.tracking.is_some() || self.shipped_at != 0 {
                    return Err(StateError::Malformed("OPEN escrow cannot be shipped"));
                }
            }
            Phase::Claimed => {
                if self.maker.is_none() {
                    return Err(StateError::Malformed("CLAIMED escrow must name a maker"));
                }
                if self.tracking.is_some() || self.shipped_at != 0 {
                    return Err(StateError::Malformed("CLAIMED escrow cannot be shipped"));
                }
            }
            Phase::Shipped | Phase::Disputed => {
                if self.maker.is_none() {
                    return Err(StateError::Malformed("shipped escrow must name a maker"));
                }
                if self.tracking.is_none() {
                    return Err(StateError::Malformed("shipped escrow must carry a tracking hash"));
                }
                if self.shipped_at == 0 {
                    return Err(StateError::Malformed("shipped escrow must record when it shipped"));
                }
            }
        }
        Ok(())
    }

    /// Which in-covenant phases may follow this one. Terminal outcomes leave
    /// the covenant and so are not listed here.
    pub fn may_transition_to(&self, next: Phase) -> Result<(), StateError> {
        let ok = matches!(
            (self.phase, next),
            (Phase::Open, Phase::Claimed) | (Phase::Claimed, Phase::Shipped) | (Phase::Shipped, Phase::Disputed)
        );
        if ok {
            Ok(())
        } else {
            Err(StateError::IllegalTransition { from: self.phase, to: next })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1};

    fn key(b: u8) -> XOnlyPublicKey {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap().x_only_public_key().0
    }

    fn shipped() -> EscrowState {
        EscrowState {
            phase: Phase::Shipped,
            terms_id: [3u8; 32],
            maker: Some(key(5)),
            tracking: Some([9u8; 32]),
            shipped_at: 12_345,
        }
    }

    #[test]
    fn round_trips_through_the_payload_encoding() {
        for state in [
            EscrowState::open([1u8; 32]),
            EscrowState { phase: Phase::Claimed, maker: Some(key(5)), ..EscrowState::open([2u8; 32]) },
            shipped(),
            EscrowState { phase: Phase::Disputed, ..shipped() },
        ] {
            let bytes = state.encode();
            assert_eq!(bytes.len(), STATE_BYTES);
            assert_eq!(EscrowState::decode(&bytes).unwrap(), state);
        }
    }

    #[test]
    fn field_offsets_are_stable() {
        // The covenant script reads these by constant offset, so a silent
        // reshuffle here would silently change what the script enforces.
        let s = shipped();
        let b = s.encode();
        assert_eq!(&b[OFF_MAGIC..OFF_MAGIC + 4], b"kESC");
        assert_eq!(b[OFF_VERSION], 1);
        assert_eq!(b[OFF_PHASE], Phase::Shipped.byte());
        assert_eq!(&b[OFF_TERMS..OFF_TERMS + 32], &[3u8; 32]);
        assert_eq!(&b[OFF_MAKER..OFF_MAKER + 32], &key(5).serialize());
        assert_eq!(&b[OFF_TRACKING..OFF_TRACKING + 32], &[9u8; 32]);
        assert_eq!(&b[OFF_SHIPPED_AT..OFF_SHIPPED_AT + 8], &12_345u64.to_le_bytes());
    }

    #[test]
    fn rejects_foreign_or_corrupt_payloads() {
        assert_eq!(EscrowState::decode(&[]).unwrap_err(), StateError::BadLength(0));
        assert_eq!(EscrowState::decode(&[0u8; 64]).unwrap_err(), StateError::BadLength(64));

        // A payload of the right length that belongs to something else — e.g. a
        // bare kRep anchor — must not parse as escrow state.
        let mut foreign = [0u8; STATE_BYTES];
        foreign[..32].copy_from_slice(&[0xab; 32]);
        assert_eq!(EscrowState::decode(&foreign).unwrap_err(), StateError::BadMagic);

        let mut bad_version = shipped().encode();
        bad_version[OFF_VERSION] = 2;
        assert_eq!(EscrowState::decode(&bad_version).unwrap_err(), StateError::BadVersion(2));

        let mut bad_phase = shipped().encode();
        bad_phase[OFF_PHASE] = 7;
        assert_eq!(EscrowState::decode(&bad_phase).unwrap_err(), StateError::BadPhase(7));
    }

    #[test]
    fn phase_invariants_are_enforced_on_decode() {
        // OPEN but with a maker recorded.
        let mut sneaky = EscrowState::open([1u8; 32]).encode();
        sneaky[OFF_MAKER..OFF_MAKER + 32].copy_from_slice(&key(5).serialize());
        assert!(matches!(EscrowState::decode(&sneaky), Err(StateError::Malformed(_))));

        // CLAIMED with no maker — would leave the bond unattributable.
        let mut no_maker = EscrowState { phase: Phase::Claimed, maker: Some(key(5)), ..EscrowState::open([1u8; 32]) }.encode();
        no_maker[OFF_MAKER..OFF_MAKER + 32].copy_from_slice(&[0u8; 32]);
        assert!(matches!(EscrowState::decode(&no_maker), Err(StateError::Malformed(_))));

        // SHIPPED with no tracking hash, or no shipped_at: the auto-release
        // clock would start from zero and the maker could release instantly.
        let mut no_tracking = shipped().encode();
        no_tracking[OFF_TRACKING..OFF_TRACKING + 32].copy_from_slice(&[0u8; 32]);
        assert!(matches!(EscrowState::decode(&no_tracking), Err(StateError::Malformed(_))));

        let mut no_time = shipped().encode();
        no_time[OFF_SHIPPED_AT..OFF_SHIPPED_AT + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(EscrowState::decode(&no_time), Err(StateError::Malformed(_))));
    }

    #[test]
    fn only_the_state_machine_edges_are_legal() {
        let open = EscrowState::open([1u8; 32]);
        let claimed = EscrowState { phase: Phase::Claimed, maker: Some(key(5)), ..EscrowState::open([1u8; 32]) };
        let ship = shipped();

        assert!(open.may_transition_to(Phase::Claimed).is_ok());
        assert!(claimed.may_transition_to(Phase::Shipped).is_ok());
        assert!(ship.may_transition_to(Phase::Disputed).is_ok());

        // No skipping, no going backwards, no self-loops. A self-loop would let
        // a maker re-ship forever and reset the auto-release clock each time.
        assert!(open.may_transition_to(Phase::Shipped).is_err());
        assert!(open.may_transition_to(Phase::Open).is_err());
        assert!(claimed.may_transition_to(Phase::Open).is_err());
        assert!(claimed.may_transition_to(Phase::Claimed).is_err());
        assert!(ship.may_transition_to(Phase::Shipped).is_err());
        assert!(ship.may_transition_to(Phase::Claimed).is_err());

        // DISPUTED only resolves out of the covenant (SETTLED or SLASH), never
        // back into another in-covenant phase.
        let disputed = EscrowState { phase: Phase::Disputed, ..shipped() };
        for p in [Phase::Open, Phase::Claimed, Phase::Shipped, Phase::Disputed] {
            assert!(disputed.may_transition_to(p).is_err(), "DISPUTED must be terminal in-covenant");
        }
    }
}
