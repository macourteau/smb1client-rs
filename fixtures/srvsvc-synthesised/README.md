# A synthesised DCE/RPC `srvsvc` exchange — not a capture

**Read this first: the `.bin` files in this directory were not captured off a
wire. They were built by `make-fixture.py` in this directory.** Every byte in
them is a literal in that script. They are shaped like the frames an embedded
SMB1 server answered with, and the share names and comments they carry are
invented — they name nothing that exists.

That matters for what the fixture can be used to prove. It exercises **this
port's own decoder** against a DCE/RPC share enumeration carried over
`WRITE_ANDX` / `READ_ANDX`. It is **not evidence of what any server sent**. A
question of the form "does a real server do X?" cannot be answered from these
bytes, and a test that fails against them has found a bug in the decoder, not a
discrepancy with a device.

## Why it is synthesised rather than captured

The exchange exists in exactly one capture, taken against the operator's own
embedded device. That capture is git-excluded and stays that way: it names that
device's real shares, and the corpus rule (see the design doc, *Fixture
obligations*, and the reasons written into the repository's `.gitignore`) is
that nothing carrying real share names, filenames or file bytes off someone's
device is committed, whatever else it would prove. Re-capturing the same
exchange against the project's Samba container is not open either: the container
answers RAP and so never reaches this fallback at all, and stock Samba has no
setting that refuses `SMB_COM_TRANSACTION` while still serving the share. So the
path is: rebuild the frames, with the device's content replaced.

## The scrub is length-preserving, and it has to stay that way

NDR conformant-varying strings carry a maximum count, an offset and an actual
count ahead of the characters. A replacement name of a different length leaves
those counts disagreeing with the string bytes, and the frame stops parsing —
along with everything after it in the same stub, because the entries that follow
are found by walking past the ones before. So every invented name matches the
one it replaced **character for character in length**:

| field | length (characters, terminator excluded) | replacement |
| --- | --- | --- |
| share 1 netname | 11 | `SYNTH-VOL01` |
| share 1 comment | 35 | `Synthesised fixture share number 01` |
| share 2 netname | 12 | `SYNTH-DISK01` |
| share 2 comment | 35 | `Synthesised fixture share number 02` |
| share 3 netname | 4 | `IPC$` — the protocol's own name, not device content, so kept |
| share 3 comment | 37 | `Synthesised fixture IPC$ share remark` |

**Editing a name in `make-fixture.py` without keeping its length breaks the
fixture.** `decode-fixture.py` re-checks the counts against the bytes and fails
if they part company.

Everything else is the device's shape and is kept: the tree and user ids, the
pipe file id, the message ids, the pipe byte offsets that advance across the
four operations, the advertised fragment sizes, the bind's two presentation
contexts and the bind_ack's `Acceptance` + `Negotiate ACK` pair. The
`ServerName` string is the capture relay's own loopback address and ephemeral
port, carried literally as the rest of the corpus carries it.

## What is here

Four request/response pairs, in order — the path that **works** on a server that
refuses `SMB_COM_TRANSACTION`:

| file | SMB command | bytes | pipe payload |
| --- | --- | --- | --- |
| `synth-0001-c2s-cmd2f.bin` | `WRITE_ANDX` `0x2f` | 183 | `bind`, frag_length 116, `PFC_FIRST_FRAG`+`PFC_LAST_FRAG` |
| `synth-0002-s2c-cmd2f.bin` | `WRITE_ANDX` `0x2f` | 51 | — (Count 116) |
| `synth-0003-c2s-cmd2e.bin` | `READ_ANDX` `0x2e` | 63 | — (reads at pipe offset 116) |
| `synth-0004-s2c-cmd2e.bin` | `READ_ANDX` `0x2e` | 156 | `bind_ack`, frag_length 92, `PFC_FIRST_FRAG`+`PFC_LAST_FRAG` |
| `synth-0005-c2s-cmd2f.bin` | `WRITE_ANDX` `0x2f` | 175 | `request`, opnum 15 (`NetrShareEnum`), frag_length 108, `PFC_FIRST_FRAG`+`PFC_LAST_FRAG` |
| `synth-0006-s2c-cmd2f.bin` | `WRITE_ANDX` `0x2f` | 51 | — (Count 108) |
| `synth-0007-c2s-cmd2e.bin` | `READ_ANDX` `0x2e` | 63 | — (reads at pipe offset 316) |
| `synth-0008-s2c-cmd2e.bin` | `READ_ANDX` `0x2e` | 520 | `response`, frag_length 456, `PFC_FIRST_FRAG`+`PFC_LAST_FRAG` |

## What is deliberately not here

- **The two refused `SMB_COM_TRANSACTION` attempts.** In the original exchange
  they sit either side of this — the bind attempt before frame 1, the request
  attempt before frame 5, both answered `STATUS_NOT_SUPPORTED`. They establish
  the fallback trigger and say nothing about the path that works. Their message
  ids are the gap in the sequence (`0x0b` between `0x0a` and `0x0c`).
- **Session-setup frames (`0x73`).** Never committed, from any server: SMB1
  authenticates with NTLMv2, so a session setup is an offline-crackable
  handshake.
- **The negotiate, tree connect and pipe open** that precede the exchange. The
  fixture starts at the first write to an already-open `\PIPE\srvsvc`.

## What this fixture cannot cover

Two loops the port is required to have are **not** exercised by these bytes, and
knowing that is part of using them:

- **PDU assembly.** The response is a *single* PDU: `PFC_LAST_FRAG` is set on
  the first and only fragment. A decoder that ignores the flag entirely and
  parses the first PDU it sees passes against this fixture. The multi-PDU case —
  where a stub has to accumulate until `PFC_LAST_FRAG`, and where a stream that
  ends without it is an error — has no fixture, and a server with many shares is
  where it first matters.
- **`NetrShareEnum` paging.** This reply is a complete enumeration:
  `TotalEntries` equals `EntriesRead` equals 3, the resume handle comes back 0,
  and the return value is `WERR_OK`. The `ERROR_MORE_DATA`-plus-resume-handle
  loop, and its no-progress guard, are likewise uncovered.

Neither gap can be closed from the device this was modelled on — three shares is
what it has.

## Regenerating and checking

```
python3 make-fixture.py     # rewrites the eight .bin files
python3 decode-fixture.py   # parses them back and prints what is in them
```

`decode-fixture.py` shares no code with `make-fixture.py` on purpose: it decodes
the committed bytes rather than restating what built them, and it fails if a
frame stops parsing or an NDR string's counts stop agreeing with its characters.

The frames were also put through `tshark` as an independent dissector, which
reports the SMB layer as the four `Write AndX` / `Read AndX` pairs on FID
`0xe7ea`, and the pipe payloads as `Bind` / `Bind_ack` / `NetShareEnumAll
request` / `NetShareEnumAll response` with all three shares decoded.
