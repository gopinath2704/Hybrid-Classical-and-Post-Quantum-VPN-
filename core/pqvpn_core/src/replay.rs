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
