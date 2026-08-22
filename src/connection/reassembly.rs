//! Transaction reassembly.
//!
//! A server may answer one TRANS2/`SMB_COM_TRANSACTION` request with several
//! messages, each repeating the request's multiplex id, each declaring the
//! whole reply's `TotalParameterCount` and `TotalDataCount` and carrying its
//! own bytes at a displacement. What decides that the reply has arrived whole
//! is **coverage of each declared range, never a running sum of the bytes
//! received**: a sum is satisfied by fragments that overlap at one displacement
//! and leave a hole at another, which delivers a reply with zero-filled bytes
//! in the middle of it. An overlapping fragment is a protocol error in its own
//! right — a server contradicting itself about its own reply's bytes — and is
//! reported rather than unioned away.
//!
//! The buffer is sized from what the *request* asked for and never from what
//! the server declares, so a server cannot make the client allocate.

use crate::wire::transaction::TransactionResponse;

/// The most fragments accepted for one reply, after which the reassembly fails.
///
/// A liveness guard against a server that never signals completion, not a
/// quantity derived from the request size. Deliberately far above what any
/// observed server needs: nothing forbids a server splitting a reply more
/// finely than the ones observed, and a tighter cap would hard-fail it.
const FRAGMENT_CAP: usize = 64;

/// How many messages may contribute no bytes at all before the reassembly
/// fails. The second contribution-free message is what terminates a server that
/// keeps sending without progressing.
const EMPTY_TOLERANCE: usize = 1;

/// What a server can do to a reassembly that ends the request as a protocol
/// error.
///
/// Each of these fails the request and retires its multiplex id; none of them
/// fails the connection, because each corrupts one reply and says nothing about
/// where the next message begins.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReassemblyError {
    /// The totals were revised upward, measured against the pair the latest
    /// message declared and never against the largest ever declared.
    #[error("{block} total revised upward from {declared} to {revised} bytes")]
    RevisedUpward {
        /// Which of the two blocks.
        block: &'static str,
        /// What the previous message declared.
        declared: usize,
        /// What this one declares.
        revised: usize,
    },

    /// A fragment's bytes fall outside the range currently declared.
    #[error(
        "{block} fragment at displacement {displacement} of {length} bytes falls outside the declared {total}"
    )]
    OutsideDeclaredRange {
        /// Which of the two blocks.
        block: &'static str,
        /// Where the fragment claimed to belong.
        displacement: usize,
        /// How many bytes it carried.
        length: usize,
        /// The total currently declared.
        total: usize,
    },

    /// A fragment re-covers bytes the coverage map already holds.
    ///
    /// This is the condition a running-sum reassembler cannot see: it counts
    /// the bytes twice, reaches the declared total with a hole still open, and
    /// delivers the hole zero-filled.
    #[error(
        "{block} fragment at displacement {displacement} of {length} bytes re-covers bytes already held"
    )]
    Overlapping {
        /// Which of the two blocks.
        block: &'static str,
        /// Where the fragment claimed to belong.
        displacement: usize,
        /// How many bytes it carried.
        length: usize,
    },

    /// The reply declares more bytes than the request allowed it to return.
    #[error("reply declares {block} of {total} bytes, more than the {asked} the request allowed")]
    MoreThanAsked {
        /// Which of the two blocks.
        block: &'static str,
        /// What the reply declares.
        total: usize,
        /// What the request asked for.
        asked: usize,
    },

    /// The reply was split across more messages than the cap allows.
    #[error("reply split across more than {0} fragments")]
    TooManyFragments(usize),

    /// A second message contributed no bytes to the reassembly.
    #[error("a second message contributed no bytes to the reassembly")]
    NoProgress,
}

/// The bytes of one range that have been covered so far.
///
/// Ranges are half-open, kept sorted, disjoint and merged, so a range that is
/// completely covered is exactly one entry.
///
/// It is shared with the read fill loop, which tracks which ranges of the span
/// a caller asked for have arrived and by the same rule: replies land out of
/// order on a pipelining transport, so a running total cannot say which bytes
/// are in hand.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Coverage {
    ranges: Vec<(usize, usize)>,
}

impl Coverage {
    /// Records `start .. start + length` as covered.
    ///
    /// Returns `false` where any of those bytes was already covered, which is
    /// the overlap the caller reports as a protocol error.
    pub(crate) fn cover(&mut self, start: usize, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        let end = start + length;
        let at = self.ranges.partition_point(|&(from, _)| from < start);
        if at > 0 && self.ranges[at - 1].1 > start {
            return false;
        }
        if at < self.ranges.len() && self.ranges[at].0 < end {
            return false;
        }
        self.ranges.insert(at, (start, end));
        if at + 1 < self.ranges.len() && self.ranges[at].1 == self.ranges[at + 1].0 {
            self.ranges[at].1 = self.ranges[at + 1].1;
            self.ranges.remove(at + 1);
        }
        if at > 0 && self.ranges[at - 1].1 == self.ranges[at].0 {
            self.ranges[at - 1].1 = self.ranges[at].1;
            self.ranges.remove(at);
        }
        true
    }

    /// Drops coverage past `total`, which is what honouring a total revised
    /// downward does to the bytes already accepted beyond it.
    fn truncate(&mut self, total: usize) {
        self.ranges.retain(|&(from, _)| from < total);
        if let Some(last) = self.ranges.last_mut() {
            last.1 = last.1.min(total);
        }
    }

    /// The first range of `0 .. total` that has not been covered, if any.
    ///
    /// A hole in the middle and a short far end are the same outcome to a
    /// caller, and only the error's own text distinguishes them.
    pub(crate) fn gap(&self, total: usize) -> Option<(usize, usize)> {
        let mut at = 0;
        for &(from, to) in &self.ranges {
            if from > at {
                return Some((at, from.min(total)));
            }
            at = to;
            if at >= total {
                return None;
            }
        }
        (at < total).then_some((at, total))
    }

    /// The contiguous prefix from zero, which is the only part of a partial
    /// transfer that is safe to resume from.
    pub(crate) fn prefix(&self) -> usize {
        match self.ranges.first() {
            Some(&(0, end)) => end,
            _ => 0,
        }
    }

    /// Whether every byte of `0 .. total` has been covered.
    fn covers(&self, total: usize) -> bool {
        match self.ranges.as_slice() {
            [] => total == 0,
            [(0, end)] => *end == total,
            _ => false,
        }
    }
}

/// One of the two blocks a transaction reply carries.
#[derive(Debug)]
struct Track {
    block: &'static str,
    /// The total the latest message declared. It governs, and it may only
    /// shrink.
    total: usize,
    /// The most the request allowed the reply to return in this block.
    asked: usize,
    declared: bool,
    covered: Coverage,
    /// The reassembly buffer. A request that has lapsed holds none: it goes on
    /// tracking coverage so it can tell when its reply arrived whole, and drops
    /// the bytes.
    bytes: Option<Vec<u8>>,
}

impl Track {
    fn new(block: &'static str, asked: usize) -> Self {
        Self {
            block,
            total: 0,
            asked,
            declared: false,
            covered: Coverage::default(),
            bytes: Some(Vec::new()),
        }
    }

    /// Takes the total this message declares.
    fn declare(&mut self, total: usize) -> Result<(), ReassemblyError> {
        if self.declared && total > self.total {
            return Err(ReassemblyError::RevisedUpward {
                block: self.block,
                declared: self.total,
                revised: total,
            });
        }
        // The bound comes from the client side. Sizing the buffer from a
        // server-supplied number would hand the server the allocation decision.
        if total > self.asked {
            return Err(ReassemblyError::MoreThanAsked {
                block: self.block,
                total,
                asked: self.asked,
            });
        }
        if total < self.total {
            self.covered.truncate(total);
        }
        if let Some(bytes) = &mut self.bytes {
            bytes.resize(total, 0);
        }
        self.total = total;
        self.declared = true;
        Ok(())
    }

    /// Places one message's bytes at the displacement it declared.
    fn accept(&mut self, displacement: usize, payload: &[u8]) -> Result<(), ReassemblyError> {
        if payload.is_empty() {
            return Ok(());
        }
        if displacement + payload.len() > self.total {
            return Err(ReassemblyError::OutsideDeclaredRange {
                block: self.block,
                displacement,
                length: payload.len(),
                total: self.total,
            });
        }
        if !self.covered.cover(displacement, payload.len()) {
            return Err(ReassemblyError::Overlapping {
                block: self.block,
                displacement,
                length: payload.len(),
            });
        }
        if let Some(bytes) = &mut self.bytes {
            bytes[displacement..displacement + payload.len()].copy_from_slice(payload);
        }
        Ok(())
    }

    fn complete(&self) -> bool {
        self.declared && self.covered.covers(self.total)
    }

    fn release(&mut self) {
        self.bytes = None;
    }

    fn take(&mut self) -> Vec<u8> {
        self.bytes.take().unwrap_or_default()
    }
}

/// How far a message carried the reassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// More messages are still owed.
    Continuing,
    /// Every byte of both declared ranges is covered.
    Complete,
}

/// A transaction reply being reassembled.
#[derive(Debug)]
pub(crate) struct Assembly {
    parameters: Track,
    data: Track,
    setup: Vec<u16>,
    fragments: usize,
    empty: usize,
    /// Whether the reassembly still holds its buffer. The two termination
    /// guards go with the buffer: a request with nothing to reassemble into
    /// cannot fail a reassembly.
    buffered: bool,
}

impl Assembly {
    /// A reassembly bounded by what the request asked the reply to return.
    pub(crate) fn new(max_parameter_count: u16, max_data_count: u16) -> Self {
        Self {
            parameters: Track::new("parameter", usize::from(max_parameter_count)),
            data: Track::new("data", usize::from(max_data_count)),
            setup: Vec::new(),
            fragments: 0,
            empty: 0,
            buffered: true,
        }
    }

    /// Drops the reassembly buffer, which a request leaving Live or Orphaned
    /// does. Coverage tracking survives: it is what says the reply arrived
    /// whole, which is what keeps the multiplex id reserved for exactly as long
    /// as the server may still be sending.
    pub(crate) fn release(&mut self) {
        self.parameters.release();
        self.data.release();
        self.setup = Vec::new();
        self.buffered = false;
    }

    /// Takes one message of the reply.
    pub(crate) fn accept(
        &mut self,
        response: &TransactionResponse,
    ) -> Result<Progress, ReassemblyError> {
        if self.buffered {
            self.fragments += 1;
            if self.fragments > FRAGMENT_CAP {
                return Err(ReassemblyError::TooManyFragments(FRAGMENT_CAP));
            }
        }

        self.parameters
            .declare(usize::from(response.total_parameter_count))?;
        self.data.declare(usize::from(response.total_data_count))?;
        self.parameters.accept(
            usize::from(response.parameter_displacement),
            &response.parameters,
        )?;
        self.data
            .accept(usize::from(response.data_displacement), &response.data)?;
        if !response.setup.is_empty() {
            self.setup = response.setup.clone();
        }

        if self.buffered && response.parameters.is_empty() && response.data.is_empty() {
            self.empty += 1;
            if self.empty > EMPTY_TOLERANCE {
                return Err(ReassemblyError::NoProgress);
            }
        }

        Ok(if self.parameters.complete() && self.data.complete() {
            Progress::Complete
        } else {
            Progress::Continuing
        })
    }

    /// The reassembled reply.
    pub(crate) fn finish(mut self) -> (Vec<u16>, Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut self.setup),
            self.parameters.take(),
            self.data.take(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered(ranges: &[(usize, usize)]) -> Coverage {
        let mut coverage = Coverage::default();
        for &(from, length) in ranges {
            assert!(coverage.cover(from, length), "{from}+{length} overlapped");
        }
        coverage
    }

    #[test]
    fn a_sum_of_byte_counts_is_not_coverage() {
        // 100 bytes at 0, 100 at 200 and 100 at 150 sum to the declared 300
        // while 100..150 was never sent. Coverage sees the third fragment
        // re-cover 200..250 and refuses it; a running sum reaches 300 and
        // delivers the hole zero-filled.
        let mut coverage = covered(&[(0, 100), (200, 100)]);
        assert!(!coverage.covers(300));
        assert!(!coverage.cover(150, 100));
    }

    #[test]
    fn coverage_merges_and_completes_only_when_whole() {
        let mut coverage = covered(&[(0, 100), (200, 100)]);
        assert!(!coverage.covers(300));
        assert!(coverage.cover(100, 100));
        assert!(coverage.covers(300));
        assert!(!coverage.covers(301));
    }

    #[test]
    fn fragments_arriving_out_of_order_still_complete() {
        let coverage = covered(&[(200, 100), (0, 100), (100, 100)]);
        assert!(coverage.covers(300));
    }

    #[test]
    fn an_overlap_of_a_single_byte_is_refused() {
        let mut coverage = covered(&[(10, 10)]);
        assert!(!coverage.cover(19, 1));
        assert!(!coverage.cover(0, 11));
        assert!(coverage.cover(0, 10));
        assert!(coverage.cover(20, 5));
        assert!(coverage.covers(25));
    }

    #[test]
    fn a_total_revised_downward_truncates_what_it_puts_outside() {
        let mut track = Track::new("data", 4096);
        track.declare(1000).unwrap();
        track.accept(0, &[7; 900]).unwrap();
        track.declare(500).unwrap();
        assert!(track.complete());
        assert_eq!(track.take().len(), 500);
    }

    #[test]
    fn upward_is_measured_against_the_current_declaration() {
        // 1000, then 500, then 800: the 800 revises upward against the 500 that
        // governs, not against the 1000 the reassembly no longer holds.
        let mut track = Track::new("data", 4096);
        track.declare(1000).unwrap();
        track.declare(500).unwrap();
        assert!(matches!(
            track.declare(800),
            Err(ReassemblyError::RevisedUpward {
                declared: 500,
                revised: 800,
                ..
            })
        ));
    }

    #[test]
    fn a_reply_may_not_return_more_than_the_request_asked_for() {
        let mut track = Track::new("data", 1024);
        assert!(matches!(
            track.declare(1025),
            Err(ReassemblyError::MoreThanAsked {
                total: 1025,
                asked: 1024,
                ..
            })
        ));
    }
}
