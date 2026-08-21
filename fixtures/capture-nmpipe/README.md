# DCE/RPC srvsvc over `TRANS_TRANSACT_NMPIPE`, answered

Captured by the **corrected harness** in `spikes/rapname/`, not by the
reference Go library as it stands. It is evidence about *the server* and says
nothing about what the Go client sends — `spikes/capture-trans/` is the fixture
for that, and still shows both of its `TRANS_TRANSACT_NMPIPE` attempts refused.

The reference library sends **no `Name` field at all** on this subcommand: in
`capture-trans/0017-c2s-cmd25.bin` and `/0023` the byte area begins `05 00 0b
03`, the DCE/RPC bind PDU, with `ParameterOffset = 0` and `DataOffset = 67`.
[MS-CIFS] 2.2.4.33.1 puts a `Name` there on every `SMB_COM_TRANSACTION`, this
subcommand included, even though the FID in the setup words is what identifies
the pipe. Samba requires it, matches it against `\PIPE\`, strips the prefix and
dispatches on what is left; an absent name matches nothing and is refused.

Supply it and the same container answers. The whole srvsvc exchange rides on
`SMB_COM_TRANSACTION` here — bind, `bind_ack`, `NetrShareEnum` request,
response — and there is no `WRITE_ANDX` or `READ_ANDX` anywhere, because the
write/read fallback is never reached. `tshark` dissects the four frames as
`Bind` / `Bind_ack` / `NetShareEnumAll request` / `NetShareEnumAll response`.

`0011-c2s-cmd25.bin` and `0013-c2s-cmd25.bin` carry `Flags2=0xC803`, the name as
UTF-16LE `\PIPE\`, `SetupCount=2` with subcommand `0x0026` and the FID that
`0010-s2c-cmda2.bin` returned, `ParameterCount=0`, `ParameterOffset=0`,
`DataOffset=82`, and `ByteCount` 131 and 123. `0012` and `0014` are
`STATUS_SUCCESS` with `WordCount=10`, carrying an unfragmented PDU of 92 bytes
(`bind_ack`, ptype `0x0C`) and 228 bytes (response, ptype `0x02`).

This is the corpus's only **captured** DCE/RPC exchange in the transact mode:
`srvsvc-synthesised/` is hand-built, and `capture-trans/` holds the write/read
transport instead.

`spikes/rapname/README.md` has the full account; `check-fixtures.py`
(`--only rap`) asserts every value above.
