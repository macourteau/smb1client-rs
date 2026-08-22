//! NDR32 — just enough of it for `srvsvc` at information level 1.
//!
//! NDR is a wire representation with two rules this module needs: every
//! primitive begins on a boundary its own width, measured from the start of the
//! stub, and a pointer travels as a *referent id* whose target is written later,
//! in the order the pointers were met. Nothing here interprets a referent id
//! beyond zero-or-not: the three servers in the fixture corpus number theirs
//! differently — `0x00020000` upward on Windows, `0x0002000c` upward on Samba —
//! so a decoder that looked one up would be reading a value the specification
//! only requires to be distinct.
//!
//! NDR64 is not implemented and the bind refuses to negotiate it (see
//! [`super::pdu`]).

use std::fmt;

/// The alignment every field this module reads and writes takes.
///
/// Level 1 share enumeration is `u32`s and strings of 16-bit characters, and
/// both align to four here — the string through the three counts that precede
/// it. Nothing in it is 64-bit, so this is the only boundary that arises.
const ALIGN: usize = 4;

/// What a stub can be that stops it decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NdrError {
    /// The stub ended inside a field.
    #[error("stub of {length} bytes ends before the {field} at offset {offset} needs {needed}")]
    Truncated {
        /// The field being read.
        field: &'static str,
        /// Where it began.
        offset: usize,
        /// How many bytes it needed from there.
        needed: usize,
        /// How many bytes the stub holds.
        length: usize,
    },

    /// A conformant varying string's three counts contradict each other.
    ///
    /// This is the check the fixture generator's own scrub rule exists to keep
    /// true: the counts and the characters are two statements about one string,
    /// and a server contradicting itself about it is refused rather than
    /// decoded to whichever half is believed.
    #[error(
        "string at offset {offset} declares maximum {maximum}, offset {first} and actual {actual}"
    )]
    InconsistentString {
        /// Where the string's counts began.
        offset: usize,
        /// The maximum element count.
        maximum: u32,
        /// The index of the first element present, which this crate requires to
        /// be zero.
        first: u32,
        /// The element count actually present.
        actual: u32,
    },

    /// A string that is not valid UTF-16.
    ///
    /// It is refused rather than decoded lossily, for the reason the wire layer
    /// refuses a lossy filename: a share whose name decoded lossily looks
    /// usable and fails when the caller connects to it.
    #[error("string at offset {offset} is not valid UTF-16")]
    InvalidUtf16 {
        /// Where the string's characters began.
        offset: usize,
    },
}

/// A cursor over a stub, aligning as NDR requires.
pub struct Reader<'a> {
    stub: &'a [u8],
    at: usize,
}

impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader")
            .field("at", &self.at)
            .field("length", &self.stub.len())
            .finish()
    }
}

impl<'a> Reader<'a> {
    /// A cursor at the start of a stub.
    pub fn new(stub: &'a [u8]) -> Self {
        Self { stub, at: 0 }
    }

    /// Advances to the next boundary. A stub that ends inside the padding is
    /// not an error here; the read that follows is what reports it.
    fn align(&mut self) {
        self.at = self.at.next_multiple_of(ALIGN);
    }

    fn take(&mut self, field: &'static str, length: usize) -> Result<&'a [u8], NdrError> {
        let end = self.at.checked_add(length).ok_or(NdrError::Truncated {
            field,
            offset: self.at,
            needed: length,
            length: self.stub.len(),
        })?;
        let slice = self.stub.get(self.at..end).ok_or(NdrError::Truncated {
            field,
            offset: self.at,
            needed: length,
            length: self.stub.len(),
        })?;
        self.at = end;
        Ok(slice)
    }

    /// Reads a 32-bit unsigned integer.
    pub fn u32(&mut self, field: &'static str) -> Result<u32, NdrError> {
        self.align();
        let raw = self.take(field, 4)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    /// Reads a referent id and reports only whether it is null.
    ///
    /// The value itself is deliberately not returned: it identifies a pointer
    /// within one stub and means nothing outside it, and the deferred targets
    /// are found by walking the stub in the order the pointers appeared rather
    /// than by looking an id up.
    pub fn is_null_pointer(&mut self, field: &'static str) -> Result<bool, NdrError> {
        Ok(self.u32(field)? == 0)
    }

    /// Reads a conformant varying string: a maximum count, the index of the
    /// first element present, an actual count, and that many UTF-16 code units
    /// ending in a null one.
    pub fn conformant_varying_string(&mut self, field: &'static str) -> Result<String, NdrError> {
        let counts_at = self.at.next_multiple_of(ALIGN);
        let maximum = self.u32(field)?;
        let first = self.u32(field)?;
        let actual = self.u32(field)?;
        // `first` is the index of the first element transmitted. Every string
        // in [MS-SRVS] is sent whole, so anything but zero is a shape this
        // crate does not decode rather than one it decodes wrongly.
        if first != 0 || actual > maximum {
            return Err(NdrError::InconsistentString {
                offset: counts_at,
                maximum,
                first,
                actual,
            });
        }
        let characters_at = self.at;
        // The count is a server-supplied number, so the bytes are taken from
        // the stub before anything is sized from it.
        // Saturating, not `* 2`: `actual` is a server-supplied `u32`, and on a
        // 32-bit target every value of it converts, so a count at or above
        // 0x8000_0000 overflows the multiply — a debug panic inside a parser an
        // unauthenticated peer reaches, or a wrapped small length in release.
        // `Reader::take` bounds the result but cannot see the multiply.
        let wide = usize::try_from(actual)
            .ok()
            .and_then(|count| count.checked_mul(2))
            .unwrap_or(usize::MAX);
        let bytes = self.take(field, wide)?;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        // The terminator is part of the count and not part of the string.
        let text = units.strip_suffix(&[0]).unwrap_or(&units);
        String::from_utf16(text).map_err(|_| NdrError::InvalidUtf16 {
            offset: characters_at,
        })
    }
}

/// Builds a stub, aligning as NDR requires.
#[derive(Debug, Default)]
pub struct Writer {
    stub: Vec<u8>,
}

impl Writer {
    /// An empty stub.
    pub fn new() -> Self {
        Self::default()
    }

    fn align(&mut self) {
        self.stub.resize(self.stub.len().next_multiple_of(ALIGN), 0);
    }

    /// Writes a 32-bit unsigned integer.
    pub fn u32(&mut self, value: u32) {
        self.align();
        self.stub.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a conformant varying string, its null terminator counted in all
    /// three counts and its characters padded out to the next boundary.
    pub fn conformant_varying_string(&mut self, text: &str) {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let count = units.len() as u32;
        self.u32(count);
        self.u32(0);
        self.u32(count);
        for unit in units {
            self.stub.extend_from_slice(&unit.to_le_bytes());
        }
        self.align();
    }

    /// The finished stub.
    pub fn finish(self) -> Vec<u8> {
        self.stub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_round_trips_through_its_own_counts() {
        let mut writer = Writer::new();
        writer.conformant_varying_string("SYNTH-VOL01");
        let stub = writer.finish();
        // Eleven characters and a terminator: three counts of 12, 24 bytes of
        // characters, and no padding because 12 and 24 are both multiples of 4.
        assert_eq!(stub.len(), 12 + 24);
        assert_eq!(&stub[..12], &[12, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0]);
        assert_eq!(
            Reader::new(&stub)
                .conformant_varying_string("test")
                .unwrap(),
            "SYNTH-VOL01"
        );
    }

    /// Seven characters with the terminator is fourteen bytes, so the string
    /// pads out by two. A reader that did not align would take the padding for
    /// the next field's first two bytes.
    #[test]
    fn a_string_pads_out_to_the_boundary_and_the_next_field_starts_after_it() {
        let mut writer = Writer::new();
        writer.conformant_varying_string("ADMIN$");
        writer.u32(0xDEAD_BEEF);
        let stub = writer.finish();
        assert_eq!(stub.len(), 12 + 14 + 2 + 4);

        let mut reader = Reader::new(&stub);
        assert_eq!(reader.conformant_varying_string("name").unwrap(), "ADMIN$");
        assert_eq!(reader.u32("next").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn counts_that_contradict_the_characters_are_refused() {
        // Actual count above maximum: the shape a length-changing edit of the
        // fixture generator would produce.
        let mut stub = Vec::new();
        stub.extend_from_slice(&4u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&9u32.to_le_bytes());
        stub.extend_from_slice(&[0; 18]);
        assert!(matches!(
            Reader::new(&stub).conformant_varying_string("name"),
            Err(NdrError::InconsistentString {
                maximum: 4,
                actual: 9,
                ..
            })
        ));
    }

    #[test]
    fn a_count_the_stub_cannot_hold_is_refused_rather_than_allocated() {
        let mut stub = Vec::new();
        stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(
            Reader::new(&stub).conformant_varying_string("name"),
            Err(NdrError::Truncated { .. })
        ));
    }

    #[test]
    fn an_unpaired_surrogate_is_refused_rather_than_decoded_lossily() {
        let mut stub = Vec::new();
        stub.extend_from_slice(&2u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&2u32.to_le_bytes());
        stub.extend_from_slice(&0xD800u16.to_le_bytes());
        stub.extend_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            Reader::new(&stub).conformant_varying_string("name"),
            Err(NdrError::InvalidUtf16 { .. })
        ));
    }
}
