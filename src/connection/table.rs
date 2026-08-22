//! The request table: every request the connection issues is in exactly one
//! state, and the actor owns one table of them.
//!
//! Capacity and multiplex-id identity are facets of a request's state rather
//! than resources managed beside it, so there is one place that answers "how
//! many requests are outstanding" and "which ids are taken", and no way for the
//! two answers to disagree.
//!
//! The design names five states. Four of them are here, and the fifth —
//! **Queued** — is not, because it holds at most one request: the one the actor
//! has taken from a channel and is writing. The actor holds that one as the
//! write in progress, and it enters this table at the first byte on the socket.
//!
//! **Live and Orphaned are one state here**, [`State::OnWire`]. They charge
//! capacity alike and hold the same multiplex id, and they differ only in
//! whether a caller is still waiting — which the actor learns when it tries to
//! deliver and not the moment a receiver drops. That is the lazy detection the
//! design specifies: a request whose caller has gone is one whose delivery
//! fails, and there is nothing else to transition.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::status::NtStatus;
use crate::wire::Message;
use crate::wire::transaction::TransactionResponse;

use super::reassembly::{Assembly, Progress};
use super::{Error, Reply, RequestOutcome, Timeouts, TransactionBody};

/// The multiplex ids that may be issued: every 16-bit value but `0xFFFF`, which
/// \[MS-CIFS\] reserves for server-initiated oplock-break notifications.
const POOL: usize = 65_535;

/// The largest multiplex id this crate issues.
const LAST_MID: u16 = 0xFFFE;

/// How many multiplex ids may be retired before the connection fails — a
/// sixty-fourth of the id space.
///
/// The bound does two jobs, because a retired id is remembered rather than
/// forgotten: it caps what the pool loses, and it caps the memory the table
/// spends remembering retired ids so that a late frame on one can be recognised
/// and logged instead of killing the connection.
const RETIREMENT_BUDGET: usize = 1_024;

/// How many overall deadlines a lapsed request waits before it is given up on.
const GIVE_UP_DEADLINES: u32 = 8;

/// Where a request is.
#[derive(Debug)]
enum State {
    /// On the wire, charging capacity, holding its multiplex id — the design's
    /// Live and Orphaned both.
    OnWire {
        /// Where the reply goes. `None` is a request dispatched already
        /// orphaned: a close enqueued by `Drop`, which has nobody to return to.
        reply: Option<oneshot::Sender<Result<Reply, Error>>>,
        /// When silence lapses the request. Every message reaching it resets
        /// this.
        silence_at: Instant,
        /// The bound on the request's whole life, which caps those resets.
        overall_at: Instant,
    },
    /// The client no longer charges capacity, but the server may still answer,
    /// so the multiplex id stays held until the reply arrives whole.
    Lapsed {
        /// When the request is given up on. **Nothing resets this**: a message
        /// arriving at a lapsed request advances the coverage it is still
        /// tracking and buys no more time. Were it to reset, a server dribbling
        /// messages at a request nobody waits on would hold the id for as long
        /// as it cared to.
        give_up_at: Instant,
    },
    /// The identity is remembered so a frame arriving on it can be recognised
    /// and logged rather than killing the connection. The request itself
    /// reached Done when its id was retired.
    Retired,
}

/// One request's row.
#[derive(Debug)]
struct Entry {
    /// The command the request sent. A reply whose command does not match is
    /// unroutable on the same terms as one whose id matches nothing, which is a
    /// cheap backstop against the crosstalk the id alone cannot exclude.
    command: u8,
    /// The reassembly, for a transaction. It outlives a lapse with its buffer
    /// released, because coverage is what says the reply arrived whole.
    assembly: Option<Assembly>,
    /// What the caller arranged to outlive the request, applied exactly once
    /// when the request ends — whichever way it ends and whether or not anybody
    /// is still waiting. It is taken there, so a late reply to a request that
    /// has already lapsed applies nothing.
    outcome: Option<Arc<dyn RequestOutcome>>,
    state: State,
}

/// What one arrival did to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The request stays where it is.
    Continuing,
    /// The reply arrived whole. The multiplex id returns to the pool: a
    /// complete reply is proof the server is finished with that id, which is
    /// the only thing that makes it safe to reuse.
    Completed,
    /// The arrival ended the request without completing it, so the id is
    /// retired for the life of the connection. A server that sent a malformed
    /// reassembly has demonstrated nothing about whether it is still sending.
    Corrupted,
}

/// How a message divides once it has reached its request.
enum Arrival {
    /// `STATUS_PENDING` — an interim response. It contributes no bytes, leaves
    /// the reassembly exactly where it is, and is excluded from the
    /// contribution-free message count: counting it would fail a legitimate
    /// reassembly on the second interim, which is a slow server saying it is
    /// still working.
    Interim,
    /// One message of a transaction reply.
    Fragment(TransactionResponse),
    /// A complete response, arriving in place of the declared totals.
    Complete(Option<TransactionBody>),
}

/// Divides an arrival before anything is done with it.
fn classify(message: &Message, reassembles: bool) -> Result<Arrival, Error> {
    let status = message.header().status;
    if status == NtStatus::PENDING {
        return Ok(Arrival::Interim);
    }
    if !reassembles {
        return Ok(Arrival::Complete(None));
    }
    if status == NtStatus::SUCCESS {
        return Ok(Arrival::Fragment(TransactionResponse::decode(message)?));
    }
    // Any other status is a complete response rather than a fragment, and
    // whatever body it carries is the whole of the reply.
    // `STATUS_BUFFER_OVERFLOW` on a `TRANS_TRANSACT_NMPIPE` reply is the case
    // that makes this matter: a *completed* transaction whose pipe payload was
    // truncated, whose remedy is another pipe read one layer up. Holding it
    // against the declared totals as a continuation would wait for messages the
    // server will never send, and the request would lapse.
    Ok(match TransactionResponse::decode(message) {
        Ok(response) => Arrival::Complete(Some(TransactionBody {
            setup: response.setup,
            parameters: response.parameters,
            data: response.data,
        })),
        // The usual shape of a failed command: `WordCount = 0` and an empty byte
        // area, where the header's status is the whole of what it says.
        Err(_) => Arrival::Complete(None),
    })
}

impl Entry {
    /// When this request next needs the actor's attention.
    fn expires_at(&self) -> Option<Instant> {
        match &self.state {
            State::OnWire {
                silence_at,
                overall_at,
                ..
            } => Some((*silence_at).min(*overall_at)),
            State::Lapsed { give_up_at } => Some(*give_up_at),
            State::Retired => None,
        }
    }

    /// Whether this request charges capacity.
    fn charges(&self) -> bool {
        matches!(self.state, State::OnWire { .. })
    }

    /// The per-request clock measures silence and not elapsed work, so any
    /// message reaching a request still charging capacity resets it. In Lapsed
    /// nothing is reset.
    fn touch(&mut self, now: Instant, per_request: Duration) {
        if let State::OnWire { silence_at, .. } = &mut self.state {
            *silence_at = now + per_request;
        }
    }

    fn accept(&mut self, message: Message, now: Instant, per_request: Duration) -> Step {
        let mid = message.header().mid;
        self.touch(now, per_request);

        let arrival = match classify(&message, self.assembly.is_some()) {
            Ok(arrival) => arrival,
            Err(error) => return self.corrupt(mid, error),
        };

        match arrival {
            Arrival::Interim => {
                debug!(mid, "interim response; the request keeps waiting");
                Step::Continuing
            }
            Arrival::Complete(transaction) => {
                self.deliver(
                    mid,
                    Ok(Reply {
                        message,
                        transaction,
                    }),
                );
                Step::Completed
            }
            Arrival::Fragment(response) => {
                let assembly = self
                    .assembly
                    .as_mut()
                    .expect("only a request holding a reassembly classifies a fragment");
                match assembly.accept(&response) {
                    Err(error) => self.corrupt(mid, error.into()),
                    Ok(Progress::Continuing) => Step::Continuing,
                    Ok(Progress::Complete) => {
                        let (setup, parameters, data) = self
                            .assembly
                            .take()
                            .expect("the reassembly was there a line ago")
                            .finish();
                        self.deliver(
                            mid,
                            Ok(Reply {
                                message,
                                transaction: Some(TransactionBody {
                                    setup,
                                    parameters,
                                    data,
                                }),
                            }),
                        );
                        Step::Completed
                    }
                }
            }
        }
    }

    /// Ends the request on a protocol error in what arrived.
    fn corrupt(&mut self, mid: u16, error: Error) -> Step {
        warn!(mid, "reply corrupted: {error}");
        self.deliver(mid, Err(error));
        Step::Corrupted
    }

    /// Hands the outcome to whoever is waiting, and logs where nobody is.
    ///
    /// A reply reaching a request whose caller has gone is a reply reaching its
    /// request, not a discard — SMB1 offers no way to withdraw a request, so
    /// there was never anything to cancel.
    fn deliver(&mut self, mid: u16, outcome: Result<Reply, Error>) {
        let waiter = match &mut self.state {
            State::OnWire { reply, .. } => {
                if let Some(arranged) = self.outcome.take() {
                    arranged.ended(outcome.as_ref());
                }
                reply.take()
            }
            State::Lapsed { .. } => {
                debug!(
                    mid,
                    "a lapsed request's reply arrived; nothing was waiting on it"
                );
                return;
            }
            State::Retired => {
                debug!(mid, "a retired identity produced an outcome; discarded");
                return;
            }
        };
        match waiter {
            None => debug!(mid, "request had no caller to return to"),
            Some(reply) => {
                if reply.send(outcome).is_err() {
                    debug!(
                        mid,
                        "the caller had gone; the reply is logged rather than delivered"
                    );
                }
            }
        }
    }
}

/// The table of requests, and the multiplex-id pool that is a facet of it.
#[derive(Debug)]
pub(crate) struct RequestTable {
    /// Every id this connection holds: requests, and the identities it
    /// remembers as retired.
    entries: HashMap<u16, Entry>,
    /// The deadlines, keyed so the actor can find the earliest without walking
    /// the table.
    expiry: BTreeSet<(Instant, u16)>,
    charging: usize,
    retired: usize,
    /// Where the next allocation starts looking. The order ids are handed out
    /// in is not specified; that `0xFFFF` is never among them is.
    cursor: u16,
    limit: usize,
    timeouts: Timeouts,
}

impl RequestTable {
    pub(crate) fn new(limit: usize, timeouts: Timeouts) -> Self {
        Self {
            entries: HashMap::new(),
            expiry: BTreeSet::new(),
            charging: 0,
            retired: 0,
            cursor: 0,
            limit,
            timeouts,
        }
    }

    /// The connection's admission limit.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// How many requests charge capacity: the design's `|Live| + |Orphaned|`.
    pub(crate) fn charging(&self) -> usize {
        self.charging
    }

    /// When the actor next has timers to fire.
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.expiry.first().map(|&(at, _)| at)
    }

    /// Takes a free multiplex id, or `None` where every one of them is held at
    /// once.
    pub(crate) fn allocate(&mut self) -> Option<u16> {
        if self.entries.len() >= POOL {
            return None;
        }
        for _ in 0..POOL {
            let mid = self.cursor;
            self.cursor = if self.cursor == LAST_MID {
                0
            } else {
                self.cursor + 1
            };
            if !self.entries.contains_key(&mid) {
                return Some(mid);
            }
        }
        None
    }

    /// Puts a request on the wire, which is what the first byte written means.
    ///
    /// The per-request clock starts here and not at admission: time spent
    /// waiting for capacity does not consume it.
    pub(crate) fn dispatch(
        &mut self,
        mid: u16,
        command: u8,
        reply: Option<oneshot::Sender<Result<Reply, Error>>>,
        assembly: Option<Assembly>,
        outcome: Option<Arc<dyn RequestOutcome>>,
        now: Instant,
    ) {
        let silence_at = now + self.timeouts.per_request;
        let overall_at = now + self.timeouts.overall;
        self.expiry.insert((silence_at.min(overall_at), mid));
        self.entries.insert(
            mid,
            Entry {
                command,
                assembly,
                outcome,
                state: State::OnWire {
                    reply,
                    silence_at,
                    overall_at,
                },
            },
        );
        self.charging += 1;
    }

    /// Routes one message to its request.
    ///
    /// Fails only where the connection cannot carry on: an unroutable frame, or
    /// the retirement budget running out.
    pub(crate) fn accept(&mut self, message: Message, now: Instant) -> Result<(), Error> {
        let mid = message.header().mid;
        let command = message.header().command;

        let Some(entry) = self.entries.get_mut(&mid) else {
            return Err(Error::Unroutable { mid, command });
        };
        if matches!(entry.state, State::Retired) {
            // A frame on a retired id routes to something rather than to
            // nothing, which is what makes the rules written around a server
            // that goes on sending true as stated.
            debug!(
                mid,
                "frame for command {command:#04x} on a retired multiplex id; discarded"
            );
            return Ok(());
        }
        if entry.command != command {
            return Err(Error::Unroutable { mid, command });
        }

        let before = entry.expires_at();
        let charged = entry.charges();
        let step = entry.accept(message, now, self.timeouts.per_request);
        let after = match step {
            Step::Continuing => entry.expires_at(),
            Step::Completed | Step::Corrupted => None,
        };

        if before != after {
            if let Some(at) = before {
                self.expiry.remove(&(at, mid));
            }
            if let Some(at) = after {
                self.expiry.insert((at, mid));
            }
        }
        if charged && step != Step::Continuing {
            self.charging -= 1;
        }

        match step {
            Step::Continuing => Ok(()),
            // A complete reply of any status gives the id back.
            Step::Completed => {
                self.entries.remove(&mid);
                Ok(())
            }
            Step::Corrupted => self.retire(mid),
        }
    }

    /// Fires whatever the clock has reached.
    pub(crate) fn expire(&mut self, now: Instant) -> Result<(), Error> {
        while let Some(&(at, mid)) = self.expiry.first() {
            if at > now {
                break;
            }
            self.expiry.pop_first();
            let give_up_at = now + self.timeouts.overall * GIVE_UP_DEADLINES;

            let entry = self
                .entries
                .get_mut(&mid)
                .expect("the expiry index and the table agree");
            let lapsing = match &entry.state {
                State::OnWire {
                    silence_at,
                    overall_at,
                    ..
                } => {
                    // A timeout is not proof the server finished. It is a
                    // client-side decision to stop charging capacity, which is
                    // what lets a server that leaves particular requests
                    // unfinished degrade throughput rather than wedge the
                    // connection permanently.
                    let reason = if silence_at <= overall_at {
                        "per-request timeout"
                    } else {
                        "overall deadline"
                    };
                    warn!(
                        mid,
                        "request lapsed on the {reason}; it stops charging capacity and keeps its multiplex id"
                    );
                    true
                }
                State::Lapsed { .. } => {
                    warn!(
                        mid,
                        "lapsed request given up on; its multiplex id is retired for the life of the connection"
                    );
                    false
                }
                State::Retired => unreachable!("a retired identity carries no deadline"),
            };

            if lapsing {
                entry.deliver(mid, Err(Error::Timeout));
                // The reassembly buffer goes with the lapse; the coverage it
                // tracks does not, because that is what says the reply arrived
                // whole.
                if let Some(assembly) = &mut entry.assembly {
                    assembly.release();
                }
                entry.state = State::Lapsed { give_up_at };
                self.charging -= 1;
                self.expiry.insert((give_up_at, mid));
            } else {
                self.retire(mid)?;
            }
        }
        Ok(())
    }

    /// Withholds an id from the pool for the life of the connection, and keeps
    /// the identity so a frame arriving on it can be recognised.
    fn retire(&mut self, mid: u16) -> Result<(), Error> {
        let entry = self
            .entries
            .get_mut(&mid)
            .expect("only a request in the table is retired");
        entry.state = State::Retired;
        entry.assembly = None;
        self.retired += 1;
        if self.retired >= RETIREMENT_BUDGET {
            return Err(Error::RetirementBudget(self.retired));
        }
        Ok(())
    }

    /// Ends every request the connection was holding.
    pub(crate) fn fail_all(&mut self) {
        for (&mid, entry) in self.entries.iter_mut() {
            if entry.charges() {
                entry.deliver(mid, Err(Error::Lost));
            }
        }
        self.entries.clear();
        self.expiry.clear();
        self.charging = 0;
    }
}
