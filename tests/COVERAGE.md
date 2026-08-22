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
server, on whichever path can report: the library's own per-request timeout
carries `written` in its error, and a caller that drops the future reads the
`WriteProgress` it passed, once that handle signals completion.

Every test below drives the same fake transport the three invariants above do,
with per-chunk acknowledgement under the test's control. The write that gets
three chunks onto the wire at once is 262,144 bytes — over the 256 KiB threshold
that decides whether a one-shot call pipelines at all — because an out-of-order
acknowledgement is not expressible on a serial write.

| Test | File | What it proves, and what a wrong implementation does |
|---|---|---|
| `invariant_4_a_timeout_reports_the_prefix_and_not_the_sum` | `tests/write_progress.rs` | The library's own timeout path. The first chunk and the **third** are acknowledged and the second lapses, so a running total says 132,096 bytes reached the server and the contiguous prefix says 130,048. A sum-based implementation reports 132,096 and a caller resuming there never writes the second chunk's bytes; one counting what each chunk *asked* to write reports 262,144 and claims the whole write landed; one returning at the first error rather than draining what is outstanding reports a race rather than a number. |
| `invariant_4_a_dropped_write_records_through_the_handle` | `tests/write_progress.rs` | **Orphaned's first exit, an arrival that completes the reply**, on the caller-drop path. Ranges are recorded after the future is gone, by the actor applying what the caller arranged to outlive the request. An implementation recording ranges in the awaiting future reports 0; one without a completion signal leaves the caller reading a handle that is still growing. |
| `invariant_4_an_arrival_that_corrupts_the_reply_still_leaves_the_group` | `tests/write_progress.rs` | **The other half of that exit: an arrival that ends the request without completing the reply.** The middle chunk is answered with the bodyless shape SMB1 answers a failed command with, which acknowledges nothing this crate can read. One recording the chunk's requested length whenever the request ends reports 262,144 bytes for a write of which 130,048 landed. **What it does not discriminate**, checked by mutation rather than assumed: leaving the group only on a readable reply still passes, because `Drop for Chunk` empties the group as a safety net. The test proves the outcome, not that mechanism; the safety net is what makes the mechanism untestable from here. |
| `invariant_4_a_lapse_leaves_the_chunk_group` | `tests/write_progress.rs` | **Orphaned's second exit: the request lapsing.** The chunk leaves the group at the lapse while the request stays in the table holding its multiplex id, so an implementation keying the signal on the request table never fires — on exactly the case the handle exists for. |
| `invariant_4_the_connection_dying_leaves_the_chunk_group` | `tests/write_progress.rs` | **Orphaned's third exit: the connection dying.** Every request the connection held ends, so every chunk leaves the group. An implementation firing the signal only from a reply hangs for ever here, on the case a caller is likeliest to meet in production. |
| `invariant_4_a_short_acknowledgement_records_what_the_reply_said` | `tests/write_progress.rs` | **A range is recorded from the reply, not from the request.** A chunk asking to write 130,048 bytes is acknowledged 1,000, and the remainder is re-issued from the first unacknowledged byte. An implementation recording what was asked reports 130,048 bytes as having reached the server, and a caller resuming there skips 129,048 bytes it never wrote. |
| `invariant_4_an_over_acknowledgement_cannot_inflate_the_prefix` | `tests/write_progress.rs` | **The acknowledgement is clamped to what the chunk offered.** A reply is free to claim more than the request carried, and the invariant says the handle never reports more than the prefix that *reached* the server. An implementation recording the reply's count unclamped reports 130,048 bytes for a 1,000-byte write — which is what this did until the test existed, the fill loop clamping on its own path while the progress ticket did not. |
| `invariant_4_one_handle_serves_one_write` | `tests/write_progress.rs` | One handle serves one write for its whole lifetime; a second registration is an `Err` and not a panic, and the refused write puts nothing on the wire. |
| `invariant_4_a_final_prefix_does_not_grow` | `tests/write_progress.rs` | A prefix already declared final may not grow afterwards — a caller may have resumed from it — and a reply arriving after the lapse records nothing, reaching a request that has already lapsed. |

A caller drop is the **entry** to Orphaned and not an exit from it, which is why
it appears in every test above rather than as one of the three.

---

## The read fill loop, the listing, and the verbs

Not invariants, but the same distinction applies: each is a rule the design
states, proven against a server answering *badly* — which no capture can, every
one of them being a well-behaved exchange.

| Test | File | What it proves, and what a wrong implementation does |
|---|---|---|
| `a_short_chunk_is_re_issued_rather_than_read_as_end_of_file` | `tests/resource.rs` | A chunk answered short is re-issued for the bytes it did not return. **This is not defensive**: Windows 11 24H2 serves every `READ_ANDX` `min(asked, 65536)` while accepting a 130,048-byte write, so against that server the path runs on every large read. An implementation reading a short answer as end of file returns 65,536 of 130,048 bytes and loses the rest of the file silently — which is what the reference library does. |
| `a_chunk_answered_with_zero_bytes_is_never_re_issued` | `tests/resource.rs` | The loop's no-progress guard, read off the covered ranges rather than off the cached size. Re-issuing a zero-byte answer asks the same question for ever; gating the read on the cached length returns `Ok` with a zeroed buffer, which is smb-rs's own defect. |
| `a_hole_in_the_middle_fails_the_call` | `tests/resource.rs` | Coverage rather than a running total: a middle chunk answering nothing with a later chunk full leaves a hole, and the call fails. A byte-counting loop returns `Ok` with a zero-filled hole in the caller's buffer. |
| `status_end_of_file_ends_a_whole_file_read_rather_than_failing_it` | `tests/resource.rs` | `STATUS_END_OF_FILE` is a zero-byte answer under a status rather than a count, and `Tree::read` is the one place the fill-or-error rule does not apply. |
| `a_refused_chunk_downgrades_the_connection_once_and_retries_it` | `tests/resource.rs` | The one-shot downgrade: one of the three statuses that mean a refusal retries that operation once at `MaxBufferSize − 1024` and records the connection small-buffer for its whole life, so nothing is attempted a third time. **The span read is deliberately larger than the downgraded chunk.** An earlier version read exactly `MaxBufferSize − 1024` bytes, so its first request was already small and it could not tell a retry that re-clamps from one that re-sends the size the server just refused — which is what the code did. Mutation-checked: re-queuing without re-clamping now fails it with `left: 130048, right: 64511`. |
| `a_server_without_the_capability_asks_for_the_smaller_bound` | `tests/resource.rs` | The chunk size's second case, `min(65,520, MaxBufferSize − 1024)`, which comes from the field that asks for the bytes rather than from the negotiated buffer. |
| `the_reader_adapter_reports_end_of_file_off_the_wire` | `tests/resource.rs` | The adapter observes the terminal condition itself rather than reading it off a count, and never gates a read on the length the open reported. |
| `a_listing_ends_on_end_of_search`, `a_listing_ends_on_status_no_more_files` | `tests/resource.rs` | Both directory-chain terminators, and `.` and `..` filtered above the parser. |
| `an_empty_directory_lists_no_entries_and_no_error` | `tests/resource.rs` | **The no-progress guard counts the entries the server returned, before `.` and `..` are removed.** Counting after the filter turns listing an empty directory — the ordinary case, and one the container produces — into an error. |
| `a_page_that_returns_nothing_and_does_not_end_fails` | `tests/resource.rs` | Without the guard a server answering `SearchCount = 0` with `EndOfSearch = 0` pages for ever. |
| `every_find_next2_asks_the_server_to_close_at_end_of_stream` | `tests/resource.rs` | `SMB_FIND_CLOSE_AT_EOS` on the FIND_FIRST2 **and** on every FIND_NEXT2, beside the continuation flag, with the search id and pattern repeated. The reference sets it on the FIND_FIRST2 alone, so every listing longer than one page ends on a request that never asked the server to close — the leak behind its recursive delete's retry loop. |
| `a_listing_dropped_before_the_end_closes_its_search` | `tests/resource.rs` | The other closing path: `SMB_COM_FIND_CLOSE2` for a listing dropped before end-of-stream, naming the search the FIND_FIRST2 returned. |
| `deleting_is_an_open_under_delete_on_close_and_then_a_close` | `tests/resource.rs` | Deleting is an open with `DELETE` under `FILE_DELETE_ON_CLOSE` and then a close, with the create option saying which kind of object the open expects — and no stat before it. |
| `remove_dir_all_drains_a_level_before_it_deletes_from_it` | `tests/resource.rs` | Each level is collected fully and its search closed before anything on it is deleted; a level drained to the end needs no `SMB_COM_FIND_CLOSE2`. |
| `a_stat_issues_the_two_levels_it_needs` | `tests/resource.rs` | Two queries rather than one, neither level carrying both halves, and `is_dir()` off the attributes. |
| `clearing_every_attribute_sends_the_value_that_clears_them` | `tests/resource.rs` | `set_attributes(0)` sends `FILE_ATTRIBUTE_NORMAL`: the zero would return success having changed nothing. |
| `the_volume_query_falls_back_and_says_which_level_answered` | `tests/resource.rs` | The fallback triggers on any error from the modern level, and `FsStatistics::level` says which answered — the only way to tell a real number from a wrapped one on a large volume. |
| `a_transaction_that_does_not_fit_one_message_fails_before_the_wire` | `tests/resource.rs` | Both transaction limits are enforced where the request is built. A long path is the realistic way the one-message rule breaks, and it fails locally naming the limit rather than being truncated or split. |
| `a_path_that_escapes_the_share_is_refused_before_the_wire` | `tests/resource.rs` | The three path refusals, none of which reaches the wire. |
| `a_dropped_file_enqueues_its_close` | `tests/resource.rs` | `Drop` hands the close to the actor without awaiting or spawning. |
| `the_query_path_parameters_are_the_captured_ones`, `a_stat_reads_its_two_halves_off_the_two_captured_replies` | `src/wire/info.rs` | The TRANS2 information parameter blocks against the committed capture, byte for byte, and the two reply levels decoded off the frames the container sent. |

**Two wire paths still have no offline oracle**, as the design record says:
`SMB_COM_FIND_CLOSE2` and `SMB_COM_ECHO`. The first is exercised against all
four live servers by `a_dropped_listing_closes_its_search_on_a_live_server` in
`tests/live_filesystem.rs`, which is the only evidence there is that a real
server accepts what this crate builds from the specification.

## The live half — `tests/live_filesystem.rs`

`#[ignore]`d and driven from the environment, like the rest of the acceptance
suite. It carries the container acceptance checks the design record names, and
it is what proves the four client-side wire changes no server in the corpus has
been observed to accept: the permissive `ShareAccess` of `0x7`, a
`DesiredAccess` without `SYNCHRONIZE`, `SMB_FIND_CLOSE_AT_EOS` on a FIND_NEXT2,
and `SMB_COM_FIND_CLOSE2` itself.

| Test | What it covers |
|---|---|
| `a_live_share_lists_and_stats` | Listing, stat, `exists`, and the volume query. Read-only, so it is the one test safe to point at a device holding somebody's data. |
| `a_dropped_listing_closes_its_search_on_a_live_server` | Both closing paths against a real server. |
| `a_live_server_takes_the_whole_write_path` | Create, write, read back, `read_exact_at` across chunk boundaries, both adapters through `tokio::io::copy`, stat, rename, listing, an empty directory, and `remove_dir_all`. It writes only under its own scratch directory and removes what it creates; `SMB1_TEST_READ_ONLY` skips it. |
| `the_seeded_directory_lists_every_entry` | The container's own acceptance check: the seeded 600-entry directory returns **600**, which needs paging and reassembly both, and the empty directory beside it returns no entries and no error. |
| `a_small_advertised_buffer_reaches_the_reassembly_path` | **The live coverage for reassembly**: the client advertises a `MaxBufferSize` of 4,356 while the transaction still asks for a `MaxDataCount` of 65,472, so a page that would otherwise arrive whole arrives in fragments — at the port's own advertisement, against a real server. |

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

## `client.rs` — the connection and tree caches

The caching layer's rules are keying, single-flight dialling, three routes to a
dead connection, the idle probe, the eviction sweep and the teardown. Three of
those are timing properties — the probe at one overall deadline, eviction at
twenty, and the goodbye being awaited rather than raced — so they reach the same
virtual clock the invariants do. The seam is a dialer of the test's own, which
replaces the stream and nothing else: every connection below runs the real
handshake, the real actor and the real teardown.

| Test | File | What it proves, and what a wrong implementation does |
|---|---|---|
| `two_ports_on_one_host_are_two_servers` | `tests/client.rs` | The key is host *and* port. A cache keyed on the host alone hands the second path the first path's connection — the exact shape of this campaign's acceptance container, a second SMB1 server on `127.0.0.1:10445` beside whatever answers on 445. |
| `one_server_is_one_connection_however_it_is_spelled` | `tests/client.rs` | The key is `Server::cache_key`, whose host half is lowercased, and the share is no part of it. Keying on the `Server` value dials twice for one server written in two cases; keying on the path dials again for a second share. |
| `one_share_asked_for_twice_is_one_tree_connect` | `tests/client.rs` | Trees are cached under the connection. Connecting afresh per call spends a round trip and a server-side handle each time. |
| `the_host_goes_on_the_wire_as_the_caller_wrote_it` | `tests/client.rs` | The lowercasing belongs to the key alone. An implementation normalising at the front door sends a host the caller did not write — and on the `IPC$` path, a name the server may not recognise. |
| `several_tasks_meeting_a_cold_cache_produce_one_dial` | `tests/client.rs` | Single-flight. Releasing the cache lock before the dial completes — the shape smb-rs carries a `// TODO: This is a bit racy` against — has every task that met the cold cache dial and authenticate one of its own. |
| `a_dial_in_flight_runs_to_completion_when_its_last_waiter_drops` | `tests/client.rs` | The dial runs on a task of its own, so the last waiter dropping does not cancel it: the handshake finishes, the connection is cached, and the next call finds it. Running the dial inside the waiter's future throws the expensive half of the work away exactly when a caller has shown it is wanted. |
| `a_dial_that_fails_is_not_cached`, `every_task_waiting_on_a_failed_dial_is_told` | `tests/client.rs` | A failure caches nothing, and one dial's failure reaches every task waiting on it with that failure's own classification. Caching it makes a briefly unreachable server unreachable for ever; leaving the in-flight marker strands every later caller. |
| `a_connection_that_died_is_evicted_and_the_next_call_re_dials` | `tests/client.rs` | The actor having terminated evicts the entry, the in-flight call fails as `ConnectionLost` rather than being retried, and the next call re-dials. Without it a long-running consumer is permanently broken after its first idle disconnect — fifteen minutes on a stock Windows server. |
| `a_connection_idle_past_one_deadline_is_probed_before_it_is_reused` | `tests/client.rs` | The probe, and every value the design fixes about it: `TID = 0xFFFF`, `UID = 0`, `WordCount = 1`, `EchoCount = 1`, `ByteCount = 0`. At any count above one, every reply after the first routes to no request and fails the connection the probe exists to vouch for. |
| `a_connection_idle_under_one_deadline_is_not_probed` | `tests/client.rs` | The threshold is real. Probing on every reuse puts a round trip in front of every call. |
| `a_probe_that_fails_evicts_and_the_call_re_dials` | `tests/client.rs` | A failed probe evicts and the call re-dials rather than returning the probe's failure to the caller, which would turn the one thing the probe was for into the caller paying for it anyway. |
| `concurrent_reuse_of_an_idle_connection_probes_it_once` | `tests/client.rs` | Idleness is read and reset in one act. Reading it without marking the entry used has every task arriving in the same instant send its own echo. |
| `a_discarded_tree_is_re_opened_and_the_connection_is_left_alone` | `tests/client.rs` | `STATUS_NETWORK_NAME_DELETED` is tree-scoped: it evicts that tree, returns `Error::TreeDisconnected`, and leaves the connection, the other trees on it and their handles alone. Treating it as a lost connection tears down work that is still good; leaving the tree cached has every later call refused by a server that already said it was gone. |
| `a_deleted_session_fails_the_connection_and_the_next_call_re_dials` | `tests/client.rs` | `STATUS_USER_SESSION_DELETED` is the other scope: session and connection are the same object, so the connection fails and the next call re-dials. |
| `a_connection_nobody_comes_back_to_is_evicted_and_says_goodbye` | `tests/client.rs` | The sweeper. Nothing in the test touches the cache after the first call, so a lazy sweep at lookup — which visits exactly the entries eviction does not care about — evicts nothing at all. It also pins the order: `TREE_DISCONNECT` before `LOGOFF_ANDX`. |
| `an_entry_used_inside_the_window_is_never_evicted` | `tests/client.rs` | Idleness is measured from the last use and not from the dial, over ten eviction windows of elapsed time. |
| `close_awaits_the_goodbye_rather_than_racing_it` | `tests/client.rs` | `close()` waits for the logoff it sent to be answered. A fire-and-forget close reports success while the server still holds the session, and reporting that release is the whole reason the method is fallible. |
| `close_reports_a_failed_goodbye_and_closes_anyway` | `tests/client.rs` | The failure reaches the caller, the socket closes regardless, and nothing is retried. |
| `close_does_not_invalidate_a_tree_the_caller_still_holds`, `dropping_the_client_does_not_log_off_a_connection_a_handle_still_holds` | `tests/client.rs` | Both teardown paths check whether anything else holds the connection before the session's goodbye. Sending it anyway invalidates the file, listing and tree handles a caller still owns — the one thing shutdown must not do. |
| `dropping_the_client_releases_everything_the_cache_held` | `tests/client.rs` | A client dropped rather than closed still says goodbye, best-effort on the actor's close queue, and the socket closes. A sweeper holding a strong reference of its own would keep every cached connection alive for the process's lifetime. |
| `the_configured_read_ahead_reaches_the_adapters`, `the_configured_buffer_advertisement_reaches_the_session_setup` | `tests/client.rs` | The two `ClientConfig` values that are invisible unless they reach the wire. The second is the threshold at which a reply arrives in several messages at all, and lowering it is the one deliberate way to reach the reassembly path against a live server. |
| `the_probe_asks_for_one_reply_and_echoes_nothing` | `src/wire/echo.rs` | The probe's body, byte for byte. Nothing else pins it: the reference sends no echo and no fixture carries one, so this is the whole of the encoder's offline evidence. |

**The live half is `tests/live_client.rs`, and it is `#[ignore]`d.** It carries
the probe's conformance check — a hand-built `SMB_COM_ECHO` under `UID = 0` and
`TID = 0xFFFF`, and a real operation after it — because that frame has no
offline oracle at all. Run against the pinned container, a Samba VM, an embedded
device and Windows 11 24H2, all four answer it `STATUS_SUCCESS` and the session
is unharmed. The other half of that conformance item — whether a server answers
an echo on a connection whose session it has discarded — needs a server that can
be made to discard one, and stays on the conformance script.
