//! DCE/RPC connection-oriented PDUs: the framing, the bind, and the assembly of
//! a reply that arrives in more than one of them.
//!
//! **This is a second layer of fragmentation sitting above the SMB one, and the
//! two are independent.** Underneath, the SMB layer delivers one complete
//! `SMB_COM_TRANSACTION` reply or a pipe read looped until the response is
//! whole; what those carry is a byte stream of PDUs, and this module assembles
//! it for itself. A reply is complete when a PDU carries `PFC_LAST_FRAG`:
//! payload accumulates from each PDU until then, and only the assembled payload
//! is parsed — never a single PDU. A stream that ends without `PFC_LAST_FRAG` is
//! an error and not a short result.
//!
//! Every committed fixture is a single PDU carrying `PFC_FIRST_FRAG` and
//! `PFC_LAST_FRAG` together, so a decoder that ignored the flag entirely would
//! pass against all of them. The assembly loop is written for the server the
//! corpus does not hold — one with enough shares to split a reply — and its
//! coverage is constructed rather than captured.

use std::fmt;

/// The header every PDU opens with.
pub const HEADER_LEN: usize = 16;

/// The prologue a request PDU carries ahead of its stub: an allocation hint, a
/// presentation context id and an operation number.
const REQUEST_PROLOGUE: usize = 8;

/// The prologue a response PDU carries ahead of its stub: an allocation hint, a
/// presentation context id, a cancel count and a reserved byte.
const RESPONSE_PROLOGUE: usize = 8;

/// The most PDUs accepted for one reply.
///
/// A liveness guard against a server that never sets `PFC_LAST_FRAG`, in the
/// same register as the connection layer's cap of 64 fragments on one
/// transaction reassembly and carried from it. It is also what bounds this
/// layer's allocation: `frag_length` is 16 bits, so 64 PDUs cannot assemble
/// more than four megabytes however large a share list a server claims to have.
const PDU_CAP: usize = 64;

/// `rpc_vers` and `rpc_vers_minor`: connection-oriented DCE/RPC 5.0.
const VERSION: (u8, u8) = (5, 0);

/// `packed_drep`: little-endian integers, ASCII characters, IEEE floats.
///
/// The whole four bytes are compared rather than the integer nibble alone. A
/// server answering in any other representation is answering in a format this
/// crate does not decode, and reading its little-endian fields anyway is how a
/// decoder produces confident nonsense.
const DATA_REPRESENTATION: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

/// The fragment size advertised in both directions.
///
/// Carried from the reference library without derivation, and pinned by every
/// bind in the corpus. It bounds nothing this crate enforces: what actually
/// bounds a reply is the SMB layer beneath — the transaction ceiling in the
/// transact mode and the pipe read that collects it in the other.
const MAX_FRAGMENT: u16 = 4280;

/// PDU types.
mod ptype {
    /// A call to an operation.
    pub const REQUEST: u8 = 0x00;
    /// A call's answer.
    pub const RESPONSE: u8 = 0x02;
    /// A call the server could not perform.
    pub const FAULT: u8 = 0x03;
    /// Establishes the interface and transfer syntax.
    pub const BIND: u8 = 0x0B;
    /// A bind accepted.
    pub const BIND_ACK: u8 = 0x0C;
    /// A bind refused outright.
    pub const BIND_NAK: u8 = 0x0D;
}

/// This PDU opens a reply.
const PFC_FIRST_FRAG: u8 = 0x01;
/// This PDU closes a reply. Nothing else says a reply is whole.
const PFC_LAST_FRAG: u8 = 0x02;

/// The transfer syntax this crate speaks: NDR32, version 2.
const NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR32_VERSION: u32 = 2;

/// Bind-time feature negotiation, offered as a second presentation context.
///
/// Windows uses it to report which optional features it supports and answers
/// the context with `negotiate_ack` rather than an acceptance. Offering it is
/// what the reference does and what every bind in the corpus carries; nothing
/// here depends on the answer, and the context that matters is the first.
const BIND_TIME_FEATURE_NEGOTIATION: [u8; 16] = [
    0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const BIND_TIME_FEATURE_NEGOTIATION_VERSION: u32 = 1;

/// The presentation context the interface is bound on, and the one every call
/// is issued against.
pub const INTERFACE_CONTEXT: u16 = 0;

/// A context negotiation that succeeded.
const RESULT_ACCEPTANCE: u16 = 0;

/// What a peer can send that this module refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PduError {
    /// A PDU header this crate does not recognise as one.
    #[error("PDU declares version {major}.{minor}, not 5.0")]
    Version {
        /// `rpc_vers`.
        major: u8,
        /// `rpc_vers_minor`.
        minor: u8,
    },

    /// The peer answered in a data representation this crate does not decode —
    /// big-endian integers, or a character set other than ASCII.
    #[error("PDU declares data representation {0:02x?}, not little-endian ASCII")]
    DataRepresentation([u8; 4]),

    /// A `frag_length` below the header it is measured from.
    #[error("PDU declares a fragment length of {0} bytes, below the 16-byte header")]
    FragmentLengthTooSmall(u16),

    /// A PDU type that has no place in this exchange.
    #[error("PDU type {actual:#04x} answers a call that expected {expected:#04x}")]
    UnexpectedType {
        /// What the reply should have been.
        expected: u8,
        /// What it was.
        actual: u8,
    },

    /// A reply on a call id other than the one asked.
    #[error("PDU carries call id {actual}, not the {expected} the request sent")]
    CallId {
        /// The call id the request carried.
        expected: u32,
        /// The call id the reply carried.
        actual: u32,
    },

    /// The first PDU of a reply did not open one.
    #[error("the first PDU of a reply does not carry PFC_FIRST_FRAG")]
    NotFirstFragment,

    /// The pipe stopped delivering before a PDU carried `PFC_LAST_FRAG`.
    ///
    /// This is the silent-truncation shape at this layer: a decoder that parsed
    /// what it had would hand back a share list missing whatever the server had
    /// still to send.
    #[error("the response ended after {pdus} PDUs without one carrying PFC_LAST_FRAG")]
    NoLastFragment {
        /// How many PDUs did arrive.
        pdus: usize,
    },

    /// More PDUs than one reply may be split into.
    #[error("the response exceeded {PDU_CAP} PDUs without completing")]
    TooManyFragments,

    /// A PDU ended inside its own body.
    #[error("{part} needs {needed} bytes and the PDU holds {length}")]
    Truncated {
        /// What was being read.
        part: &'static str,
        /// The bytes it needed.
        needed: usize,
        /// The bytes there were.
        length: usize,
    },

    /// The server refused the bind outright.
    #[error("the server refused the bind, reason {0:#06x}")]
    BindRejected(u16),

    /// The server accepted the bind but not on the interface context.
    #[error(
        "the server refused presentation context 0: result {result:#06x}, reason {reason:#06x}"
    )]
    ContextRejected {
        /// The result code.
        result: u16,
        /// The reason code.
        reason: u16,
    },

    /// The server accepted a transfer syntax this crate does not marshal.
    ///
    /// NDR64 is the one that arises: a server that negotiated it and a client
    /// that marshals NDR32 disagree about the width of every integer in the
    /// stub, and nothing later in the exchange reports it.
    #[error("the server accepted the bind on a transfer syntax other than NDR32")]
    NotNdr32,

    /// The server's answer to the call was a fault.
    #[error("the server faulted the call: {0:#010x}")]
    Fault(u32),
}

/// Splits a byte stream into whole PDUs.
///
/// The stream arrives in whatever chunks the SMB layer beneath delivers, and a
/// chunk boundary has nothing to do with a PDU boundary: one read can carry
/// several PDUs, part of one, or the tail of one and the head of the next.
#[derive(Default)]
pub struct PduStream {
    pending: Vec<u8>,
}

impl fmt::Debug for PduStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PduStream")
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl PduStream {
    /// Adds what the pipe delivered.
    pub fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// Takes the next whole PDU, or `None` where the stream has not delivered
    /// one yet.
    pub fn next(&mut self) -> Result<Option<Vec<u8>>, PduError> {
        if self.pending.len() < HEADER_LEN {
            return Ok(None);
        }
        let length = usize::from(u16::from_le_bytes([self.pending[8], self.pending[9]]));
        if length < HEADER_LEN {
            return Err(PduError::FragmentLengthTooSmall(length as u16));
        }
        if self.pending.len() < length {
            return Ok(None);
        }
        Ok(Some(self.pending.drain(..length).collect()))
    }
}

/// A PDU's header, read off its first sixteen bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    ptype: u8,
    flags: u8,
    call_id: u32,
}

impl Header {
    fn parse(pdu: &[u8]) -> Result<Self, PduError> {
        let head: &[u8; HEADER_LEN] = pdu
            .get(..HEADER_LEN)
            .and_then(|raw| raw.try_into().ok())
            .ok_or(PduError::Truncated {
                part: "PDU header",
                needed: HEADER_LEN,
                length: pdu.len(),
            })?;
        if (head[0], head[1]) != VERSION {
            return Err(PduError::Version {
                major: head[0],
                minor: head[1],
            });
        }
        let drep = [head[4], head[5], head[6], head[7]];
        if drep != DATA_REPRESENTATION {
            return Err(PduError::DataRepresentation(drep));
        }
        Ok(Self {
            ptype: head[2],
            flags: head[3],
            call_id: u32::from_le_bytes([head[12], head[13], head[14], head[15]]),
        })
    }
}

/// Writes a PDU header in front of a body.
fn pdu(ptype: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    let length = (HEADER_LEN + body.len()) as u16;
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&[VERSION.0, VERSION.1, ptype, PFC_FIRST_FRAG | PFC_LAST_FRAG]);
    out.extend_from_slice(&DATA_REPRESENTATION);
    out.extend_from_slice(&length.to_le_bytes());
    // `auth_length`: this crate binds without authentication verifiers.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&call_id.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// A bind offering one interface, on NDR32 and on bind-time feature
/// negotiation.
pub fn bind(interface: [u8; 16], version: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12 + 2 * 44);
    body.extend_from_slice(&MAX_FRAGMENT.to_le_bytes());
    body.extend_from_slice(&MAX_FRAGMENT.to_le_bytes());
    // `assoc_group_id` of zero asks the server to open a new association.
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[2, 0, 0, 0]);

    for (context, syntax, syntax_version) in [
        (INTERFACE_CONTEXT, NDR32, NDR32_VERSION),
        (
            INTERFACE_CONTEXT + 1,
            BIND_TIME_FEATURE_NEGOTIATION,
            BIND_TIME_FEATURE_NEGOTIATION_VERSION,
        ),
    ] {
        body.extend_from_slice(&context.to_le_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&interface);
        body.extend_from_slice(&version.to_le_bytes());
        body.extend_from_slice(&syntax);
        body.extend_from_slice(&syntax_version.to_le_bytes());
    }
    pdu(ptype::BIND, 0, &body)
}

/// A call on the bound interface.
pub fn request(call_id: u32, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(REQUEST_PROLOGUE + stub.len());
    // `alloc_hint`: how much stub follows, which is a hint and not a length.
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    body.extend_from_slice(&INTERFACE_CONTEXT.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(stub);
    pdu(ptype::REQUEST, call_id, &body)
}

/// Reads a `bind_ack` and holds the server to the syntax this crate marshals.
///
/// Two checks the reference library does not make. The transfer syntax the
/// server accepted is compared against NDR32, because a server that negotiated
/// NDR64 and a client that marshals NDR32 disagree about the width of every
/// integer in the stub and nothing later in the exchange says so. And a
/// `bind_nak` is reported as the refusal it is rather than as an unexpected
/// packet type.
///
/// The body's own alignment is measured from the start of the PDU, which the
/// 16-byte header makes the same as measuring from the start of the body.
pub fn bind_ack(answer: &Answer) -> Result<(), PduError> {
    if answer.ptype == ptype::BIND_NAK {
        let reason = answer
            .payload
            .get(..2)
            .map_or(0, |raw| u16::from_le_bytes([raw[0], raw[1]]));
        return Err(PduError::BindRejected(reason));
    }
    if answer.ptype != ptype::BIND_ACK {
        return Err(PduError::UnexpectedType {
            expected: ptype::BIND_ACK,
            actual: answer.ptype,
        });
    }
    let body = &answer.payload;
    let secondary_address_length = usize::from(read_u16(body, 8, "sec_addr_len")?);
    let results_at = (10 + secondary_address_length).next_multiple_of(4);
    let count = usize::from(*body.get(results_at).ok_or(PduError::Truncated {
        part: "bind_ack results",
        needed: results_at + 1,
        length: body.len(),
    })?);
    if count == 0 {
        return Err(PduError::ContextRejected {
            result: 0,
            reason: 0,
        });
    }
    // The interface rides on the first presentation context, and the second is
    // the feature negotiation whose answer nothing here depends on.
    let first = results_at + 4;
    let result = read_u16(body, first, "context result")?;
    let reason = read_u16(body, first + 2, "context reason")?;
    if result != RESULT_ACCEPTANCE {
        return Err(PduError::ContextRejected { result, reason });
    }
    let syntax = body.get(first + 4..first + 20).ok_or(PduError::Truncated {
        part: "context transfer syntax",
        needed: first + 20,
        length: body.len(),
    })?;
    if syntax != NDR32 {
        return Err(PduError::NotNdr32);
    }
    Ok(())
}

fn read_u16(body: &[u8], at: usize, part: &'static str) -> Result<u16, PduError> {
    body.get(at..at + 2)
        .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
        .ok_or(PduError::Truncated {
            part,
            needed: at + 2,
            length: body.len(),
        })
}

/// One reply, assembled from however many PDUs carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The PDU type the reply's first fragment declared.
    pub ptype: u8,
    /// Every fragment's payload, concatenated: the stub of a response, or the
    /// whole body of a `bind_ack`.
    pub payload: Vec<u8>,
}

/// Collects the PDUs of one reply out of the pipe's byte stream.
///
/// The collector is what decides that a reply is whole, and so it is what
/// decides that the pipe-read loop above may stop reading. Nothing else can:
/// a read that returns fewer bytes than asked for says nothing about whether
/// the server has finished answering.
#[derive(Debug)]
pub struct Collector {
    stream: PduStream,
    call_id: u32,
    ptype: Option<u8>,
    payload: Vec<u8>,
    pdus: usize,
    complete: bool,
}

impl Collector {
    /// A collector for the reply to one call.
    pub fn new(call_id: u32) -> Self {
        Self {
            stream: PduStream::default(),
            call_id,
            ptype: None,
            payload: Vec::new(),
            pdus: 0,
            complete: false,
        }
    }

    /// Takes what the pipe delivered and parses out whatever whole PDUs it
    /// completes.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), PduError> {
        self.stream.push(bytes);
        while let Some(fragment) = self.stream.next()? {
            self.accept(&fragment)?;
        }
        Ok(())
    }

    fn accept(&mut self, fragment: &[u8]) -> Result<(), PduError> {
        if self.complete {
            // Everything past `PFC_LAST_FRAG` belongs to no reply this crate
            // asked for. It is left in the stream rather than parsed, and the
            // pipe is closed after the exchange either way.
            return Ok(());
        }
        let header = Header::parse(fragment)?;
        if header.call_id != self.call_id {
            return Err(PduError::CallId {
                expected: self.call_id,
                actual: header.call_id,
            });
        }
        if header.ptype == ptype::FAULT {
            return Err(PduError::Fault(fault_status(fragment)));
        }
        match self.ptype {
            None => {
                if header.flags & PFC_FIRST_FRAG == 0 {
                    return Err(PduError::NotFirstFragment);
                }
                self.ptype = Some(header.ptype);
            }
            // A reply does not change type half way through. Reading the rest
            // of the stream as though it had would append one PDU's body to
            // another's stub.
            Some(opened) if opened != header.ptype => {
                return Err(PduError::UnexpectedType {
                    expected: opened,
                    actual: header.ptype,
                });
            }
            Some(_) => {}
        }
        self.pdus += 1;
        if self.pdus > PDU_CAP {
            return Err(PduError::TooManyFragments);
        }

        let prologue = match header.ptype {
            ptype::RESPONSE => RESPONSE_PROLOGUE,
            _ => 0,
        };
        let payload = fragment
            .get(HEADER_LEN + prologue..)
            .ok_or(PduError::Truncated {
                part: "PDU payload",
                needed: HEADER_LEN + prologue,
                length: fragment.len(),
            })?;
        self.payload.extend_from_slice(payload);
        self.complete = header.flags & PFC_LAST_FRAG != 0;
        Ok(())
    }

    /// Whether a PDU has carried `PFC_LAST_FRAG`, which is the only thing that
    /// says the reply is whole and the only thing that stops the read loop.
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// The assembled reply.
    ///
    /// A stream that ended without `PFC_LAST_FRAG` fails here rather than
    /// handing back what did arrive.
    pub fn finish(self) -> Result<Answer, PduError> {
        match self.ptype {
            Some(ptype) if self.complete => Ok(Answer {
                ptype,
                payload: self.payload,
            }),
            _ => Err(PduError::NoLastFragment { pdus: self.pdus }),
        }
    }

    /// Holds a reply to the type the call expects.
    pub fn response(answer: &Answer) -> Result<&[u8], PduError> {
        if answer.ptype != ptype::RESPONSE {
            return Err(PduError::UnexpectedType {
                expected: ptype::RESPONSE,
                actual: answer.ptype,
            });
        }
        Ok(&answer.payload)
    }
}

/// A fault PDU's status, which sits eight bytes into its body.
fn fault_status(fragment: &[u8]) -> u32 {
    fragment
        .get(HEADER_LEN + 8..HEADER_LEN + 12)
        .map_or(0, |raw| {
            u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::srvsvc;
    use crate::rpc::tests::{read_payload, transaction_payload};

    /// Builds a PDU the way a server does, independently of this module's own
    /// writer, so that a test's input is not the code it is testing.
    fn build(ptype: u8, flags: u8, call_id: u32, prologue: &[u8], payload: &[u8]) -> Vec<u8> {
        let length = (HEADER_LEN + prologue.len() + payload.len()) as u16;
        let mut out = vec![5, 0, ptype, flags, 0x10, 0, 0, 0];
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&call_id.to_le_bytes());
        out.extend_from_slice(prologue);
        out.extend_from_slice(payload);
        out
    }

    /// One fragment of a response: the eight-byte prologue every one of them
    /// carries, and its share of the stub.
    fn response_fragment(call_id: u32, flags: u8, stub: &[u8]) -> Vec<u8> {
        let mut prologue = (stub.len() as u32).to_le_bytes().to_vec();
        prologue.extend_from_slice(&[0, 0, 0, 0]);
        build(ptype::RESPONSE, flags, call_id, &prologue, stub)
    }

    fn collect(call_id: u32, chunks: &[&[u8]]) -> Result<Answer, PduError> {
        let mut collector = Collector::new(call_id);
        for chunk in chunks {
            collector.feed(chunk)?;
        }
        collector.finish()
    }

    /// The bind, byte for byte against every one in the corpus.
    ///
    /// Two presentation contexts, `assoc_group_id = 0`, and 4,280 advertised
    /// both ways: all of it the reference library's, and this is what says the
    /// bind is not a departure from it.
    #[test]
    fn the_bind_matches_every_captured_one() {
        let ours = bind(srvsvc::INTERFACE, srvsvc::INTERFACE_VERSION);
        assert_eq!(ours.len(), 116);
        for capture in [
            "capture-nmpipe/0011-c2s-cmd25.bin",
            "capture-win-nmpipe/0011-c2s-cmd25.bin",
            "capture-win-rap/0017-c2s-cmd25.bin",
            "capture-trans/0017-c2s-cmd25.bin",
        ] {
            assert_eq!(ours, transaction_payload(capture), "{capture}");
        }
        assert_eq!(
            ours,
            crate::wire::io::WriteAndxRequest::decode(&crate::rpc::tests::fixture(
                "srvsvc-synthesised/synth-0001-c2s-cmd2f.bin"
            ))
            .unwrap()
            .data
        );
    }

    /// The request PDU, byte for byte against the captured ones.
    #[test]
    fn the_request_pdu_matches_every_captured_one() {
        for (capture, server) in [
            ("capture-win-nmpipe/0013-c2s-cmd25.bin", "127.0.0.1"),
            ("capture-nmpipe/0013-c2s-cmd25.bin", "127.0.0.1:10458"),
        ] {
            assert_eq!(
                request(1, srvsvc::OPNUM, &srvsvc::request(server, 0)),
                transaction_payload(capture),
                "{capture}"
            );
        }
    }

    /// Every captured `bind_ack` is accepted, and every one is a single PDU
    /// carrying both fragment flags — which is exactly why the assembly loop
    /// below has no fixture.
    #[test]
    fn every_captured_bind_ack_is_accepted() {
        for payload in [
            transaction_payload("capture-nmpipe/0012-s2c-cmd25.bin"),
            transaction_payload("capture-win-nmpipe/0012-s2c-cmd25.bin"),
            read_payload("capture-trans/0022-s2c-cmd2e.bin"),
            read_payload("srvsvc-synthesised/synth-0004-s2c-cmd2e.bin"),
        ] {
            assert_eq!(payload[3], PFC_FIRST_FRAG | PFC_LAST_FRAG);
            let answer = collect(0, &[&payload]).unwrap();
            bind_ack(&answer).unwrap();
        }
    }

    /// A server that accepted the bind on NDR64 is refused here rather than
    /// left to produce a stub this crate would unmarshal as NDR32. The
    /// reference library reads the result code and not the syntax.
    #[test]
    fn a_bind_ack_on_another_transfer_syntax_is_refused() {
        let mut payload = transaction_payload("capture-win-nmpipe/0012-s2c-cmd25.bin");
        // The first context result's transfer syntax, found the way the decoder
        // finds it: past the secondary address and its padding.
        let secondary = usize::from(u16::from_le_bytes([payload[24], payload[25]]));
        let results = (HEADER_LEN + 10 + secondary).next_multiple_of(4);
        let syntax = results + 8;
        // NDR64: 71710533-beba-4937-8319-b5dbef9ccc36.
        payload[syntax..syntax + 16].copy_from_slice(&[
            0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c,
            0xcc, 0x36,
        ]);
        let answer = collect(0, &[&payload]).unwrap();
        assert_eq!(bind_ack(&answer), Err(PduError::NotNdr32));
    }

    #[test]
    fn a_refused_context_is_reported_with_its_reason() {
        let mut payload = transaction_payload("capture-win-nmpipe/0012-s2c-cmd25.bin");
        let secondary = usize::from(u16::from_le_bytes([payload[24], payload[25]]));
        let results = (HEADER_LEN + 10 + secondary).next_multiple_of(4);
        payload[results + 4..results + 8].copy_from_slice(&[2, 0, 1, 0]);
        let answer = collect(0, &[&payload]).unwrap();
        assert_eq!(
            bind_ack(&answer),
            Err(PduError::ContextRejected {
                result: 2,
                reason: 1
            })
        );
    }

    #[test]
    fn a_bind_nak_is_reported_as_the_refusal_it_is() {
        let nak = build(
            ptype::BIND_NAK,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            0,
            &[],
            &[0x02, 0x00],
        );
        let answer = collect(0, &[&nak]).unwrap();
        assert_eq!(bind_ack(&answer), Err(PduError::BindRejected(2)));
    }

    /// **The multi-PDU case, which has no fixture and can get none.** Every
    /// committed `srvsvc` response is a single PDU carrying
    /// `PFC_FIRST|PFC_LAST`, so a decoder that ignored the flag and parsed the
    /// first PDU it saw would pass against all of them.
    ///
    /// What this catches is exactly that decoder: the same three-share reply
    /// split across two PDUs, where the first alone does not decode at all —
    /// the split falls inside the second share's name — and the assembled pair
    /// decodes to all three. A first-PDU decoder returns an error here where a
    /// correct one returns three shares, and against a kinder split it would
    /// return one share and call the enumeration complete.
    #[test]
    fn only_the_assembled_stub_is_parsed_and_never_one_pdu() {
        let stub = srvsvc::tests::build(
            &[("alpha", 0, "one"), ("beta", 0, "two"), ("gamma", 3, "")],
            3,
            0,
            0,
        );
        let split = 64;
        let first = response_fragment(1, PFC_FIRST_FRAG, &stub[..split]);
        let second = response_fragment(1, PFC_LAST_FRAG, &stub[split..]);

        // What a decoder that parsed the first PDU would be holding.
        assert!(srvsvc::response(&stub[..split]).is_err());

        let answer = collect(1, &[&first, &second]).unwrap();
        let assembled = Collector::response(&answer).unwrap();
        assert_eq!(assembled, &stub[..]);
        let page = srvsvc::response(assembled).unwrap();
        assert_eq!(page.shares.len(), 3);
        assert_eq!(page.shares[2].name, "gamma");
    }

    /// A split that leaves a decodable prefix, which is the shape that makes a
    /// first-PDU decoder look like it works: it returns one share of three and
    /// reports the enumeration complete.
    #[test]
    fn a_first_pdu_that_decodes_on_its_own_is_still_not_the_answer() {
        let whole = srvsvc::tests::build(&[("alpha", 0, "one"), ("beta", 0, "two")], 2, 0, 0);
        let short = srvsvc::tests::build(&[("alpha", 0, "one")], 1, 0, 0);
        let first = response_fragment(7, PFC_FIRST_FRAG, &short);
        let second = response_fragment(7, PFC_LAST_FRAG, &whole[short.len()..]);

        // The trap: the first PDU parses, and says one share and no more to
        // come.
        let trap = srvsvc::response(&short).unwrap();
        assert_eq!(trap.shares.len(), 1);
        assert!(!trap.more);

        let mut collector = Collector::new(7);
        collector.feed(&first).unwrap();
        assert!(
            !collector.complete(),
            "a PDU without PFC_LAST_FRAG completed a reply"
        );
        collector.feed(&second).unwrap();
        assert!(collector.complete());
        assert_eq!(
            Collector::response(&collector.finish().unwrap())
                .unwrap()
                .len(),
            short.len() + whole.len() - short.len()
        );
    }

    /// A stream that stops before a PDU carries `PFC_LAST_FRAG` is an error and
    /// not a short result.
    #[test]
    fn a_stream_ending_without_the_last_fragment_is_an_error() {
        let stub = srvsvc::tests::build(&[("alpha", 0, "one")], 4, 0, 0);
        let only = response_fragment(1, PFC_FIRST_FRAG, &stub);
        assert_eq!(
            collect(1, &[&only]),
            Err(PduError::NoLastFragment { pdus: 1 })
        );
    }

    /// A PDU boundary has nothing to do with a read boundary: the same bytes
    /// delivered one at a time assemble to the same answer.
    #[test]
    fn a_pdu_split_across_reads_assembles_the_same_way() {
        let stub = srvsvc::tests::build(&[("alpha", 0, "one"), ("beta", 0, "two")], 2, 0, 0);
        let whole = response_fragment(3, PFC_FIRST_FRAG | PFC_LAST_FRAG, &stub);

        let mut collector = Collector::new(3);
        for byte in &whole {
            assert!(!collector.complete());
            collector.feed(&[*byte]).unwrap();
        }
        assert!(collector.complete());
        assert_eq!(
            Collector::response(&collector.finish().unwrap()).unwrap(),
            &stub[..]
        );
    }

    /// Two PDUs arriving in one read are both taken.
    #[test]
    fn several_pdus_in_one_read_are_all_taken() {
        let stub = srvsvc::tests::build(&[("alpha", 0, "one")], 1, 0, 0);
        let mut stream = response_fragment(1, PFC_FIRST_FRAG, &stub[..20]);
        stream.extend_from_slice(&response_fragment(1, PFC_LAST_FRAG, &stub[20..]));
        let answer = collect(1, &[&stream]).unwrap();
        assert_eq!(Collector::response(&answer).unwrap(), &stub[..]);
    }

    #[test]
    fn a_fault_is_reported_with_its_status() {
        let mut body = vec![0; 8];
        body.extend_from_slice(&0x1C01_0002u32.to_le_bytes());
        body.extend_from_slice(&[0; 4]);
        let fault = build(ptype::FAULT, PFC_FIRST_FRAG | PFC_LAST_FRAG, 1, &[], &body);
        assert_eq!(collect(1, &[&fault]), Err(PduError::Fault(0x1C01_0002)));
    }

    #[test]
    fn a_reply_on_another_call_id_is_refused() {
        let stub = srvsvc::tests::build(&[], 0, 0, 0);
        let reply = response_fragment(2, PFC_FIRST_FRAG | PFC_LAST_FRAG, &stub);
        assert_eq!(
            collect(1, &[&reply]),
            Err(PduError::CallId {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn a_reply_that_does_not_open_with_the_first_fragment_is_refused() {
        let stub = srvsvc::tests::build(&[], 0, 0, 0);
        let reply = response_fragment(1, PFC_LAST_FRAG, &stub);
        assert_eq!(collect(1, &[&reply]), Err(PduError::NotFirstFragment));
    }

    /// The liveness guard: a server that never sets `PFC_LAST_FRAG` is stopped
    /// rather than followed, and with it the memory this layer can be made to
    /// hold.
    #[test]
    fn more_pdus_than_the_cap_fail_rather_than_accumulating() {
        let mut collector = Collector::new(1);
        let flags = PFC_FIRST_FRAG;
        for round in 0..=PDU_CAP {
            let fragment = response_fragment(1, if round == 0 { flags } else { 0 }, &[0xAA; 16]);
            match collector.feed(&fragment) {
                Ok(()) => assert!(round < PDU_CAP, "the cap of {PDU_CAP} was not enforced"),
                Err(error) => {
                    assert_eq!(error, PduError::TooManyFragments);
                    return;
                }
            }
        }
        panic!("the cap of {PDU_CAP} was never reached");
    }

    /// A server answering in big-endian NDR is answering in a format this crate
    /// does not decode, and reading its little-endian fields anyway is how a
    /// decoder produces confident nonsense.
    #[test]
    fn another_data_representation_is_refused() {
        let mut reply = response_fragment(1, PFC_FIRST_FRAG | PFC_LAST_FRAG, &[0; 8]);
        reply[4] = 0x00;
        assert_eq!(
            collect(1, &[&reply]),
            Err(PduError::DataRepresentation([0, 0, 0, 0]))
        );
    }

    #[test]
    fn a_fragment_length_below_the_header_is_refused() {
        let mut reply = response_fragment(1, PFC_FIRST_FRAG | PFC_LAST_FRAG, &[0; 8]);
        reply[8..10].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(
            collect(1, &[&reply]),
            Err(PduError::FragmentLengthTooSmall(8))
        );
    }

    /// A reply that changes type half way through would otherwise have one
    /// PDU's body appended to another's stub.
    #[test]
    fn a_reply_does_not_change_type_half_way_through() {
        let first = response_fragment(1, PFC_FIRST_FRAG, &[0; 8]);
        let second = build(ptype::BIND_ACK, PFC_LAST_FRAG, 1, &[], &[0; 8]);
        assert_eq!(
            collect(1, &[&first, &second]),
            Err(PduError::UnexpectedType {
                expected: ptype::RESPONSE,
                actual: ptype::BIND_ACK
            })
        );
    }
}
