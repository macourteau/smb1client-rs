# Invariant coverage map

The design record names four properties the implementation holds and, for each,
the test or tests that prove it (`docs/design/2026-08-20-rust-port.md`,
"Invariants"). This file is that mapping made concrete: every invariant, the
test that proves it, and where the test lives.

**A test named here exists and passes.** An entry for work not yet done says so
in those words and names the build step that owes it, rather than naming a test
that is not there.

Three of the four invariants are timing properties and the fourth's
distinguishing content needs a fragment sequence no server in the corpus
produced, so all four reach the test seam — `smb1client::connection::transport`,
which is public and unfeatured so that these tests drive the same code path a
consumer gets. The timing tests run under tokio's virtual clock
(`#[tokio::test(start_paused = true)]`), the direct equivalent of Go's
`testing/synctest`.

---

## Invariant 1 — a caller never observes a partial transaction

A TRANS2/TRANSACTION reply is delivered only once every byte of the declared
parameter and data ranges has been **covered** by a fragment — coverage tracked
across each range, never a running sum of byte counts. An incomplete or
overlapping reassembly terminates as an error, failing the request and not the
connection.

| Test | File | What it proves |
|---|---|---|
| `invariant_1_coverage_refuses_what_a_running_sum_accepts` | `tests/connection.rs` | The rule's distinguishing content. Three hand-built fragments of a 300-byte reply at displacements 0, 200 and 150: their byte counts sum to exactly 300 while 100..150 was never sent. A running-sum reassembler declares the reply complete and delivers 300 bytes with a 50-byte zero-filled hole; a coverage map sees the third fragment re-cover 200..250 and fails the request with `ReassemblyError::Overlapping`. The `Ok` arm of the test prints the hole, so a sum-based implementation fails it with the corruption visible. |
| `invariant_1_a_gapped_reply_is_never_delivered` | `tests/connection.rs` | A hole no overlap papers over never completes: 200 of 300 declared bytes are never delivered as a whole reply, and the request lapses instead. |
| `invariant_1_a_fragmented_reply_is_delivered_whole` | `tests/connection.rs` | The reassembly path itself, over the committed fixture `capture-frag/0010` + `0011` replayed through the actor: 17,836 data bytes delivered as one reply, and nothing delivered after the first message alone. |
| `invariant_1_a_reply_larger_than_the_request_allowed_fails_it` | `tests/connection.rs` | Reassembly is memory-bounded by the request's own `MaxParameterCount`/`MaxDataCount`, never by the totals a server declares. |
| `a_sum_of_byte_counts_is_not_coverage`, `coverage_merges_and_completes_only_when_whole`, `fragments_arriving_out_of_order_still_complete`, `an_overlap_of_a_single_byte_is_refused`, `a_total_revised_downward_truncates_what_it_puts_outside`, `upward_is_measured_against_the_current_declaration`, `a_reply_may_not_return_more_than_the_request_asked_for` | `src/connection/reassembly.rs` | The coverage map and the declared-totals rules, unit level. |
| `a_fragmented_reply_declares_totals_and_displacements` | `src/wire/fixtures.rs` | The fixture's own totals and displacements decode as the reassembly needs them, and the entry chain cannot be walked over either message alone. |

The live small-`MaxBufferSize` test named in the design record is the other half
of the reassembly evidence and belongs to build step 4, where the listing paths
exist. It is not an invariant-1 proof on its own: it carries no overlapping or
gapped fragment either.

## Invariant 2 — no response is discarded silently

Every frame the connection task reads reaches its request, or reaches a
multiplex id the connection has retired and is logged against that identity, or
fails the connection. A NetBIOS keep-alive is the one exception.

| Test | File | What it proves |
|---|---|---|
| `invariant_2_every_frame_reaches_its_own_request` | `tests/connection.rs` | Four requests outstanding at once, answered out of order, with a keep-alive, an interim `STATUS_PENDING`, a two-message reply and a bodyless error status interleaved. Each caller gets its own bytes and no other. |
| `invariant_2_a_reply_to_an_abandoned_request_reaches_it` | `tests/connection.rs` | A reply to a request whose caller dropped is not a discard: it reaches the request in Orphaned and ends it. With an admission limit of one, whether the next request reaches the wire is exactly that question. |
| `invariant_2_a_frame_on_a_retired_id_is_discarded` | `tests/connection.rs` | A frame on a retired multiplex id routes to the retired identity and is discarded; the connection carries on and the id is withheld from the pool. |
| `invariant_2_an_unroutable_frame_fails_the_connection` | `tests/connection.rs` | A frame on an id no request holds and the table does not remember fails the connection. |
| `invariant_2_a_reply_under_the_wrong_command_is_unroutable` | `tests/connection.rs` | The reply's command must match the request's, which the reference library does not check. |
| `invariant_2_a_chained_response_fails_the_connection` | `tests/connection.rs` | A response whose `AndXCommand` is not `0xFF` fails the connection. |
| `invariant_2_an_unknown_netbios_type_fails_the_connection` | `tests/connection.rs` | A NetBIOS message type the port does not recognise fails the connection. |
| `a_deleted_session_fails_the_connection_after_the_reply_lands` | `tests/connection.rs` | `STATUS_USER_SESSION_DELETED` reaches its caller and then fails the connection. |

## Invariant 3 — admission never exceeds the negotiated limit

`|Live| + |Orphaned|` never exceeds `min(negotiated MaxMpxCount, 50)`, however
many tasks the consumer runs.

| Test | File | What it proves |
|---|---|---|
| `invariant_3_admission_never_exceeds_the_negotiated_limit` | `tests/connection.rs` | Twenty concurrent tasks against a server that negotiated four: exactly four frames reach the wire, and the fifth only once a reply has ended one of them. |
| `invariant_3_abandoned_requests_go_on_charging_capacity` | `tests/connection.rs` | Three dropped callers still fill a limit of three. Ceasing to charge at the drop would put requests the server is still working on over the negotiated ceiling with no bound at all. |
| `invariant_3_a_server_that_does_not_multiplex_is_serial` | `tests/connection.rs` | A reported `MaxMpxCount` of 0 or 1 gives an admission limit of 1. |
| `invariant_3_the_ceiling_caps_a_generous_server` | `tests/connection.rs` | A reported 200 is capped at 50. |

## Invariant 4 — a cancelled write never over-reports

A cancelled write never reports more than the contiguous prefix that reached the
server, on whichever path can report.

**No test exists yet, and this is not a gap in this build step.** Invariant 4 is
discharged at build step 4: its test needs the same fake transport, with
controllable per-chunk acknowledgement, but `write_all_at` and `WriteProgress`
do not exist until that step. The design record says so where it sets the build
order.

---

## The rules around the invariants

These are not the four invariants, but they are the conditions the invariants
are stated against, and each is proven here rather than assumed.

| Test | Rule |
|---|---|
| `the_per_request_clock_measures_silence` | The per-request timeout measures silence, not elapsed work. |
| `status_pending_resets_the_clock_and_counts_against_no_guard` | `STATUS_PENDING` is neither fragment nor error: it resets the clock and counts against neither reassembly guard. |
| `the_overall_deadline_caps_the_resets` | The overall deadline bounds a request making progress for ever. |
| `waiting_for_capacity_does_not_consume_the_timeout` | The per-request clock starts at dispatch, at the first byte on the socket. |
| `a_complete_late_reply_returns_a_lapsed_request_s_id` | A lapsed request keeps its multiplex id until its reply arrives whole; a complete late reply gives the id back. |
| `a_lapsed_request_is_given_up_on_and_its_id_retired` | Give-up at eight overall deadlines, and nothing resets that clock. |
| `the_connection_fails_after_one_deadline_of_silence` | The connection-silence rule. |
| `silence_on_an_idle_connection_fails_nothing` | An idle connection is not failed by it: the window measures silence a caller spends waiting. |
| `the_fragment_cap_ends_a_reply_that_never_finishes` | The 64-fragment cap. |
| `a_second_contribution_free_message_ends_the_reassembly` | The one-message contribution-free tolerance. |
| `a_blocked_write_stops_neither_replies_nor_timers` | A blocked socket write never stops the actor reading replies or firing timers, and dispatch commits at the first byte written. |
| `a_waiting_close_reaches_the_wire_ahead_of_a_waiting_request` | The close channel's priority in the `select`. |
| `eight_closes_in_a_row_do_not_starve_a_request` | The run of eight that stops closes starving requests. |
| `the_retirement_budget_fails_the_connection` | The connection fails once 1,024 multiplex ids have been retired. |

**Multiplex-id pool exhaustion has no test.** Reaching it needs all 65,535 ids
held at once, essentially all of them Lapsed, which the retirement budget fails
the connection long before. The check is enforced in `RequestTable::allocate`
and is unreachable from a test that does not first defeat the budget.
