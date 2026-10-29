//! 128-entry anti-replay window, mirroring `ReplayWindow` in handshake/kemtls.py.
//! Callers must `check`, then verify the tag, and only then `commit`.

pub const WINDOW: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Replayed,
    OutsideWindow,
}

#[derive(Debug, Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    pub fn check(&self, sequence: u64) -> Result<(), Reject> {
        match self.highest {
            Some(highest) if sequence <= highest => {
                let delta = highest - sequence;
                if delta >= WINDOW {
                    Err(Reject::OutsideWindow)
                } else if (self.bitmap >> delta) & 1 == 1 {
                    Err(Reject::Replayed)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    pub fn commit(&mut self, sequence: u64) {
        match self.highest {
            Some(highest) if sequence <= highest => {
                // `check` guarantees this; a misuse would otherwise mask the shift silently in release.
                debug_assert!(highest - sequence < WINDOW, "commit without check");
                self.bitmap |= 1 << (highest - sequence);
            }
            Some(highest) => {
                let shift = sequence - highest;
                self.bitmap = if shift >= WINDOW { 1 } else { (self.bitmap << shift) | 1 };
                self.highest = Some(sequence);
            }
            None => {
                self.bitmap = 1;
                self.highest = Some(sequence);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(w: &mut ReplayWindow, seq: u64) -> Result<(), Reject> {
        w.check(seq)?;
        w.commit(seq);
        Ok(())
    }

    #[test]
    fn edge_jump_and_top() {
        let mut w = ReplayWindow::default();
        assert_eq!(accept(&mut w, 200), Ok(()));
        assert_eq!(accept(&mut w, 200 - 127), Ok(()));
        assert_eq!(accept(&mut w, 200 - 128), Err(Reject::OutsideWindow));
        assert_eq!(accept(&mut w, 200 - 127), Err(Reject::Replayed));
        assert_eq!(accept(&mut w, 10_000), Ok(()));
        assert_eq!(accept(&mut w, 200), Err(Reject::OutsideWindow));
        assert_eq!(accept(&mut w, u64::MAX - 1), Ok(()));
        assert_eq!(accept(&mut w, u64::MAX), Ok(()));
        assert_eq!(accept(&mut w, u64::MAX), Err(Reject::Replayed));
    }

    #[test]
    fn check_without_commit_changes_nothing() {
        let mut w = ReplayWindow::default();
        accept(&mut w, 5).unwrap();
        w.check(1000).unwrap();
        assert_eq!(accept(&mut w, 4), Ok(()));
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    /// Clusters of nearby sequences (so replays and the window edge actually happen) around 0,
    /// an arbitrary base, or the top of the u64 space.
    fn sequences() -> impl Strategy<Value = Vec<u64>> {
        let base = prop_oneof![Just(0u64), any::<u64>(), Just(u64::MAX - 300)];
        (base, prop::collection::vec(0u64..400, 1..200))
            .prop_map(|(base, offsets)| offsets.into_iter().map(|o| base.saturating_add(o)).collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// (a) each sequence at most once, (b) anything WINDOW or more behind the highest is rejected,
        /// with OutsideWindow taking precedence over Replayed, as in Python's `ReplayWindow.check`.
        #[test]
        fn matches_a_set_model(sequences in sequences()) {
            let (mut window, mut seen, mut highest) = (ReplayWindow::default(), HashSet::new(), None::<u64>);
            for s in sequences {
                let expected = if highest.is_some_and(|h| s <= h && h - s >= WINDOW) {
                    Err(Reject::OutsideWindow)
                } else if seen.contains(&s) {
                    Err(Reject::Replayed)
                } else {
                    Ok(())
                };
                prop_assert_eq!(window.check(s), expected, "sequence {}", s);
                if expected.is_ok() {
                    window.commit(s);
                    seen.insert(s);
                    highest = highest.max(Some(s));
                }
            }
        }

        /// (c) `check` alone never moves the window: only `commit` (after the tag verifies) does.
        #[test]
        fn check_never_moves_the_window(sequences in sequences(), probes in prop::collection::vec(any::<u64>(), 1..20)) {
            let mut window = ReplayWindow::default();
            for s in sequences {
                if window.check(s).is_ok() {
                    window.commit(s);
                }
            }
            let before = format!("{window:?}");
            for p in probes {
                let _ = window.check(p);
                let _ = window.check(u64::MAX - (p % 300));
            }
            prop_assert_eq!(format!("{window:?}"), before);
        }
    }
}
