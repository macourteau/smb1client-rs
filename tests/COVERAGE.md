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

---

## Share enumeration — what the corpus pins, and what it cannot

Not an invariant, but the same distinction is worth recording here, because
`rpc/` is the one module with no oracle: smb-rs's `smb-rpc` is NDR64-only, the
reference library's own decoder is wrong in four of the ways the design record
lists, and the fixtures are what stands behind everything the container's RAP
answer hides.

**Pinned by captured bytes**, in the unit tests beside the code:

| Behaviour | Test | Corpus |
|---|---|---|
| The DCE/RPC bind, byte for byte | `rpc::pdu::tests::the_bind_matches_every_captured_one` | `capture-nmpipe`, `capture-win-nmpipe`, `capture-win-rap`, `capture-trans`, `srvsvc-synthesised` |
| The `NetrShareEnum` request PDU and its stub, byte for byte | `rpc::pdu::tests::the_request_pdu_matches_every_captured_one`, `rpc::srvsvc::tests::the_request_stub_matches_every_captured_one` | the same, three corpora each |
| Four shares with their kinds and comments, from Windows | `rpc::srvsvc::tests::windows_four_shares_decode_with_their_kinds_and_comments` | `capture-win-rap/0020`, `capture-win-nmpipe/0014` |
| The same call answered over both transports by the container | `rpc::srvsvc::tests::the_container_answers_the_same_call_over_both_transports` | `capture-nmpipe/0014`, `capture-trans/0028` |
| A third server's shape of the write/read exchange | `rpc::srvsvc::tests::the_synthesised_fixture_decodes_to_its_three_shares` | `srvsvc-synthesised` |
| Every `bind_ack` accepted | `rpc::pdu::tests::every_captured_bind_ack_is_accepted` | four corpora |
| The RAP reply, converter arithmetic included | `rpc::rap::tests::the_answered_rap_reply_decodes_to_its_two_shares` | `capture-rap/0010` |
| The RAP request shape | `rpc::rap::tests::the_request_matches_the_captured_one_but_for_its_receive_buffer` | `capture-win-rap/0009` |
| `\PIPE\` on `TRANS_TRANSACT_NMPIPE` | `wire::transaction::tests::a_pipe_transact_names_the_pipe_and_declares_no_parameter_offset` | `capture-win-nmpipe/0011` |

**Constructed, because the corpus cannot hold it.** Every committed `srvsvc`
response is a *single* PDU carrying `PFC_FIRST|PFC_LAST`, and every one is a
*complete* enumeration — `TotalEntries` equal to `EntriesRead`, the resume
handle back at zero and the return value `WERR_OK`. So the multi-PDU assembly
loop and the `NetrShareEnum` paging loop have no fixture and can get none. They
are the parts a server with many shares reaches first, and where a port without
them truncates silently, so each is covered by a hand-built stream in
`tests/rpc.rs` and in `rpc::pdu`'s own tests.

Each of those tests was checked by mutation — the wrong implementation written
into the source, the suite run, the source restored:

| Mutation | Tests that fail |
|---|---|
| The assembler ignores `PFC_LAST_FRAG` (parses the first PDU) | six in `rpc::pdu::tests`, `only_the_assembled_stub_is_parsed_and_never_one_pdu` among them |
| The paging loop returns the first page | `netr_share_enum_pages_until_a_reply_comes_back_successful` and two others |
| The paging loop drops its no-progress guard | `a_page_that_adds_nothing_fails_rather_than_looping` |
| `STATUS_BUFFER_OVERFLOW` read as an error | `the_read_loop_collects_a_response_that_did_not_fit_one_reply`, `a_response_that_never_ends_fails_rather_than_truncating` |
| One pipe read and no loop, as the reference has it | eight of the eleven in `tests/rpc.rs` |
| The RAP fall-through narrowed to `STATUS_NOT_SUPPORTED`, as the reference has it | `rap_more_data_falls_through_rather_than_enumerating_nothing`, `a_rap_reply_short_of_its_own_available_count_falls_through` |
| The transact fall-through narrowed the same way | `both_paths_failing_says_why_each_did` |
| A `bind_ack` on NDR64 accepted | `a_bind_ack_on_another_transfer_syntax_is_refused` |
| A reply returning more shares than it says it holds accepted | `a_total_below_the_entries_returned_is_refused` |

**The live coverage is the reverse of what the corpus suggests.** The captures
were taken by a client the container refuses, so every one of them exercises the
write/read fallback. A correct client inverts it: the container answers RAP, so
share enumeration stops there and neither DCE/RPC transport runs at all.
Everything below `Ipc::list_shares`'s first attempt is unreached in CI, which is
what makes the fixtures above load-bearing rather than supplementary.
## The handshake's four refusals

Not invariants either, but they belong here for the same reason invariant 4's
absence does: the design record names each of the four and says where it is
proven, and **the acceptance container can produce none of them.** The capability
floor, the `NEGOTIATE_USER_SECURITY` refusal and the `MaxBufferSize` floor all
need a negotiate response no tested server sends, and the guest-logon refusal
needs an `Action` bit the container is configured never to set (`map to guest =
never`). No fixture can stand in, because session-setup frames are excluded from
the corpus by rule. So all four reach the same seam the invariants do, with the
handshake run over a scripted server on a `DuplexStream`.

| Test | File | What it proves, and what a wrong implementation does |
|---|---|---|
| `a_server_missing_any_required_capability_is_refused_by_name` | `tests/handshake.rs` | Each of the six required bits is dropped in turn and the refusal must name the missing one; the control run with all six present authenticates. A floor that checked one bit, or checked the word against a mask that happens to be non-zero, admits a server missing any of the other five — and `CAP_EXTENDED_SECURITY`'s absence would then surface inside the SPNEGO decoder instead. Each refusal is also asserted to arrive before any `SESSION_SETUP_ANDX` reaches the wire. |
| `a_share_level_security_server_is_refused` | `tests/handshake.rs` | `SecurityMode = 0x02` — encrypted passwords, share-level security — is refused. That is precisely the value an implementation reading the word for the encrypt-passwords bit alone is satisfied by, which is what the reference library does: it declares `NEGOTIATE_USER_SECURITY` and never tests it, and proceeding sends a password where a share key is expected. |
| `a_negotiated_buffer_below_the_smb1_minimum_is_refused` | `tests/handshake.rs` | 4,355 is refused naming the field and the floor, 512 — the value a subtraction of 1,024 would wrap on — is refused, and exactly 4,356, which Windows 11 24H2 advertises, passes and reaches the actor. **The check's location is what is being proven**: validating once on arrival is what makes every `MaxBufferSize − 1024` in the chunk-size rules safe by construction. An implementation that validated nowhere, or scattered saturating arithmetic through those subtractions instead, carries a nonsense buffer size forward with no place that said so. |
| `a_guest_logon_is_refused_on_both_paths` | `tests/handshake.rs` | The `Action` bit is refused on the two-leg exchange **and** on the one-leg one, allowed where the caller asked for guest access, and absent on a named logon. An implementation reading the bit on the second leg only misses it on exactly the exchange where it matters most: a server answering the first `SESSION_SETUP_ANDX` with `STATUS_SUCCESS` has issued no challenge and checked no password, which is the shape a guest downgrade takes. This one has live confirmation as well — the embedded device sets the bit for its `guest` account, and the refusal fired against it. |

Four more tests in the same file cover the conditions those four are stated
against.

| Test | Rule |
|---|---|
| `a_server_that_answers_the_first_leg_with_success_is_asked_nothing_further` | The exchange can end after the first leg: one `SESSION_SETUP_ANDX` where the server issued no challenge, two where it did. |
| `a_server_that_requires_signing_says_so` | A server admitting to `NEGOTIATE_SECURITY_SIGNATURES_REQUIRED` gets a named error rather than an access-denied further in. |
| `a_server_answering_outside_nt_status_is_refused` | A response clearing `SMB_FLAGS2_NT_STATUS` is reported as such rather than as a fabricated `NTSTATUS`. |
| `the_negotiated_parameters_reach_the_actor_as_values`, `the_large_io_capabilities_are_claimed_only_where_the_server_offered_them` | The negotiated parameters reach the actor as construction values, and the client's own `SESSION_SETUP_ANDX` carries the four fields it chooses rather than echoes: the advertised `MaxBufferSize` of 65,535, the multiplex count it then enforces, the echoed `SessionKey`, and its own capability word — `CAP_EXTENDED_SECURITY` included, without which Windows refuses the session setup outright. |

## `auth/` — vectors, not captures

Session-setup frames are excluded from the fixture corpus by rule, and they are
the only place NTLM and SPNEGO appear on the wire, so those two modules can have
no captured coverage of their own. Two committed vector files stand in, and they
are what CI asserts for `auth/`.

| Test | File | What it proves |
|---|---|---|
| `the_ms_nlmp_worked_example_is_reproduced` | `tests/auth.rs` | The whole NTLMv2 pipeline against [MS-NLMP] 4.2.4's published worked example: `NtChallengeResponse` and `EncryptedRandomSessionKey` byte for byte, the `LmChallengeResponse` of twenty-four zero bytes that says NTLMv2 only, and the whole message pinned. The example fixes the nonce and the timestamp, carries no real credential, and comes from the specification rather than from the reference library's source. |
| `the_negotiate_message_carries_the_nine_flags` | `tests/auth.rs` | The nine flags read off the bytes the NEGOTIATE message actually carries, with `ALWAYS_SIGN` and `VERSION` absent and `SIGN` present — the last being the one whose removal makes Windows refuse authentication outright. |
| `the_reference_library_agrees_on_every_value_the_two_share` | `tests/auth.rs` | The behavioural cross-check against the reference library at `b948f59`: both SPNEGO encoders byte for byte, the decoder on the token the reference received, the NTLMv2 blob and `NTProofStr` over the reference's own AV pair list, and the `mechListMIC` — which is the whole of `SIGNKEY`, `SEALKEY`, the HMAC and the RC4 that encrypts the checksum — on a session key the port did not choose. The run drove the reference against a scripted server answering with the specification's own challenge, so the committed vectors carry no captured frame and no real credential. |
| `credentials_never_reach_a_formatted_string` | `tests/auth.rs` | The redacted `Debug` on the password, the credentials, the client values and the AUTHENTICATE message. A redacted `Debug` is exactly what a later `#[derive(Debug)]` silently undoes, so its effect is asserted rather than assumed. |
| `the_session_setup_is_redacted_however_the_switch_is_set`, `a_session_setup_dump_keeps_the_header_and_nothing_else` | `src/wire/trace.rs` | The wire tracer's redaction, which is unconditional and not behind a feature flag. The case that matters is the one with the operator's dump switch **on**: with it off nothing is dumped anyway. |

**The live half is `tests/live_handshake.rs`, and it is `#[ignore]`d.** It reads
`SMB1_TEST_SERVER` and authenticates, and nothing in CI points it at anything but
the pinned container.
