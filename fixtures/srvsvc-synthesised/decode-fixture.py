#!/usr/bin/env python3
"""Decode the fixture in this directory and print what is actually in it.

Spike harness, not product code. This shares no code with make-fixture.py on
purpose: it parses the bytes back out, so the facts in README.md are decoded
rather than asserted, and so a fixture edited by hand is caught rather than
trusted. It also re-checks the invariant the scrub has to hold -- every NDR
conformant-varying string's maximum count, offset and actual count agreeing
with the string bytes that follow -- and fails if any frame stops parsing.

Usage:  python3 decode-fixture.py [dir]
"""

import glob
import os
import struct
import sys

PTYPE = {0x00: "request", 0x02: "response", 0x0B: "bind", 0x0C: "bind_ack"}
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02


def pipe_payload(frame: bytes):
    """Return (command, the pipe bytes this frame carries) or (command, None)."""
    assert frame[:4] == b"\x00" + struct.pack(">I", len(frame) - 4)[1:], "bad NBT header"
    smb = frame[4:]
    assert smb[:4] == b"\xffSMB", "bad SMB signature"
    command = smb[4]
    is_reply = bool(smb[9] & 0x80)
    word_count = smb[32]
    if command == 0x2F and not is_reply:  # WRITE_ANDX request
        length = struct.unpack_from("<H", smb, 33 + 20)[0]
        offset = struct.unpack_from("<H", smb, 33 + 22)[0]
        return command, smb[offset: offset + length]
    if command == 0x2E and is_reply:  # READ_ANDX response
        length = struct.unpack_from("<H", smb, 33 + 10)[0]
        offset = struct.unpack_from("<H", smb, 33 + 12)[0]
        return command, smb[offset: offset + length]
    assert word_count in (6, 12), f"unexpected WordCount {word_count}"
    return command, None


def decode_strings(stub: bytes, pos: int, count: int):
    out = []
    for _ in range(count):
        maximum, offset, actual = struct.unpack_from("<III", stub, pos)
        assert offset == 0, f"unexpected NDR string offset {offset}"
        assert maximum == actual, f"NDR counts disagree: maximum {maximum}, actual {actual}"
        raw = stub[pos + 12: pos + 12 + 2 * actual]
        assert len(raw) == 2 * actual, "NDR string runs past the stub"
        text = raw.decode("utf-16-le")
        assert text.endswith("\x00"), "NDR string is not NUL-terminated"
        out.append(text[:-1])
        pos += 12 + 2 * actual
        pos += -pos % 4
    return out, pos


def main() -> int:
    where = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    paths = sorted(glob.glob(os.path.join(where, "synth-*.bin")))
    assert paths, f"no fixture frames in {where}"

    for path in paths:
        with open(path, "rb") as fh:
            frame = fh.read()
        command, payload = pipe_payload(frame)
        line = f"{os.path.basename(path):28s} cmd=0x{command:02x} {len(frame):4d} bytes"
        if payload is None:
            print(line + "  (carries no pipe payload)")
            continue
        ptype, flags = payload[2], payload[3]
        frag = struct.unpack_from("<H", payload, 8)[0]
        assert frag == len(payload), f"frag_length {frag} != payload {len(payload)}"
        last = "PFC_LAST_FRAG" if flags & PFC_LAST_FRAG else "no PFC_LAST_FRAG"
        first = "PFC_FIRST_FRAG" if flags & PFC_FIRST_FRAG else "no PFC_FIRST_FRAG"
        print(f"{line}  {PTYPE.get(ptype, hex(ptype)):9s} frag_length={frag} flags=0x{flags:02x} {first}|{last}")

        if ptype == 0x02:  # the share list
            stub = payload[24:]
            level, tag = struct.unpack_from("<II", stub, 0)
            entries = struct.unpack_from("<I", stub, 12)[0]
            maximum = struct.unpack_from("<I", stub, 20)[0]
            assert level == 1 and tag == 1, "not an information level 1 container"
            assert maximum == entries, f"array maximum {maximum} != EntriesRead {entries}"
            types = [struct.unpack_from("<I", stub, 24 + 12 * i + 4)[0] for i in range(entries)]
            strings, pos = decode_strings(stub, 24 + 12 * entries, 2 * entries)
            total, _, resume, status = struct.unpack_from("<IIII", stub, pos)
            assert total == entries, f"TotalEntries {total} != EntriesRead {entries}"
            assert pos + 16 == len(stub), "stub has trailing bytes"
            for i in range(entries):
                print(f"    share type=0x{types[i]:08x} netname={strings[2*i]!r} remark={strings[2*i+1]!r}")
            print(f"    TotalEntries={total} ResumeHandle={resume} return=0x{status:08x}")
        elif ptype == 0x00:  # the NetrShareEnum request
            stub = payload[24:]
            opnum = struct.unpack_from("<H", payload, 22)[0]
            (server,), pos = decode_strings(stub, 4, 1)
            level, tag, _, read, buf, prefer = struct.unpack_from("<IIIIII", stub, pos)
            print(f"    opnum={opnum} ServerName={server!r} Level={level}")
            print(f"    EntriesRead={read} Buffer={'NULL' if buf == 0 else buf} PreferedMaximumLength=0x{prefer:08x}")

    print("\nAll frames parsed end to end; every NDR string's counts agree with its bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
