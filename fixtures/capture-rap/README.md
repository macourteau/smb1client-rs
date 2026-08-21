# RAP NetShareEnum, answered — UTF-16LE `Name`

Captured by the **corrected harness** in `spikes/rapname/`, not by the
reference Go library as it stands. The library at `b948f59` cannot produce this
exchange: it spells the `SMB_COM_TRANSACTION` `Name` as 8-bit ASCII while
setting `SMB_FLAGS2_UNICODE`, and is refused. This corpus is therefore evidence
about *the server* — that Samba 4.23.8 does serve RAP here — and says nothing
about what the Go client sends. `spikes/capture-trans/` is the fixture for
that, and still shows the refusal.

`0009-c2s-cmd25.bin` carries `Flags2=0xC803` with the name as UTF-16LE,
`ParameterOffset=94`, `DataOffset=114`, `ByteCount=47`. `0010-s2c-cmd25.bin` is
`STATUS_SUCCESS` with `WordCount=10`, RAP status `NERR_Success`, 2 of 2
entries: `testshare` (type `0x0000`) and `IPC$` (type `0x0003`). No
`NT_CREATE_ANDX`, `WRITE_ANDX` or `READ_ANDX` frame appears, because the
DCE/RPC `srvsvc` fallback never ran.

`spikes/rapname/README.md` has the full account; `check-fixtures.py`
(`--only rap`) asserts every value above.
