#!/usr/bin/env python3
"""Build the synthesised DCE/RPC srvsvc write/read fixture in this directory.

Spike harness, not product code. See README.md: the frames this writes are
SYNTHESISED, not captured. Every field is a literal in this file, so the
fixture is reproducible without the excluded capture it was modelled on, and
so a reader can check what is in it without decoding the bytes by hand.

The exchange is the one an embedded SMB1 server forces when it refuses
SMB_COM_TRANSACTION: bind and NetrShareEnum carried over WRITE_ANDX /
READ_ANDX on \\PIPE\\srvsvc instead. Field values -- transaction and user ids,
pipe file id, message ids, the pipe byte offsets, the advertised fragment
sizes, the bind's two presentation contexts and the bind_ack's split result --
reproduce the shape that device answers; the share names and comments do not,
and are the synthetic strings in SHARES below.

Usage:  python3 make-fixture.py [outdir]
"""

import os
import struct
import sys

# --- the synthetic content -------------------------------------------------
#
# (netname, shi1_type, remark). These are invented. The lengths are not: the
# device's own names and comments had exactly these character counts, and NDR
# conformant-varying strings carry a maximum count, an offset and an actual
# count, so a replacement of a different length would leave the counts
# disagreeing with the string bytes and the frame unparseable. Anything edited
# here has to keep its length, or the frame stops decoding.
SHARES = [
    ("SYNTH-VOL01", 0x00000000, "Synthesised fixture share number 01"),
    ("SYNTH-DISK01", 0x00000000, "Synthesised fixture share number 02"),
    ("IPC$", 0x80000003, "Synthesised fixture IPC$ share remark"),
]

# The relay's own loopback address and ephemeral port, as the rest of the
# corpus carries them: the committed frames are not templated for host and
# port (see the design doc, Fixture obligations).
SERVER_NAME = "\\\\127.0.0.1:10447"

# --- interface identifiers -------------------------------------------------
SRVSVC_UUID = bytes.fromhex("c84f324b7016d30112785a47bf6ee188")  # 4b324fc8-1670-01d3-1278-5a47bf6ee188
NDR32_UUID = bytes.fromhex("045d888aeb1cc9119fe808002b104860")  # 8a885d04-1ceb-11c9-9fe8-08002b104860
BTFN_UUID = bytes.fromhex("2c1cb76c12984045" "0300000000000000")  # bind-time feature negotiation

# --- SMB1 session identifiers ----------------------------------------------
TID = 0xE4CF  # tree connect to IPC$
PID = 0x0001
UID = 0x4CB9
FID = 0xE7EA  # the open \PIPE\srvsvc
FLAGS = 0x18  # CASE_INSENSITIVE | CANONICALIZED_PATHS
FLAGS_REPLY = 0x88  # ... | REPLY
FLAGS2 = 0xC803  # UNICODE | NT_STATUS | EXTENDED_SECURITY | EAS | LONG_NAMES
MAX_READ = 0x3D04  # MaxCountOfBytesToReturn the client asked for
MAX_FRAG = 0x10B8  # max_xmit_frag / max_recv_frag both directions
ASSOC_GROUP = 0x000066AA

SMB_COM_WRITE_ANDX = 0x2F
SMB_COM_READ_ANDX = 0x2E
OPNUM_NETR_SHARE_ENUM = 15

# --- SMB1 framing ----------------------------------------------------------


def nbt(smb: bytes) -> bytes:
    """NetBIOS session service header: type 0x00, 24-bit length."""
    assert len(smb) < 1 << 24
    return struct.pack(">I", len(smb)) + smb


def smb_header(command: int, flags: int, mid: int) -> bytes:
    return struct.pack(
        "<4sBIBHH8sHHHHH",
        b"\xffSMB",
        command,
        0,  # NT status: STATUS_SUCCESS
        flags,
        FLAGS2,
        0,  # PIDHigh
        b"\x00" * 8,  # SecuritySignature
        0,  # Reserved
        TID,
        PID,
        UID,
        mid,
    )


def write_andx_request(mid: int, offset: int, data: bytes) -> bytes:
    data_offset = 32 + 1 + 28 + 2  # header, WordCount, 14 words, ByteCount
    params = struct.pack(
        "<BBHHIIHHHHHI",
        0xFF,  # AndXCommand: none
        0,  # AndXReserved
        0,  # AndXOffset
        FID,
        offset,
        0,  # Timeout
        0,  # WriteMode
        0,  # Remaining
        0,  # DataLengthHigh
        len(data),
        data_offset,
        0,  # OffsetHigh
    )
    body = bytes([14]) + params + struct.pack("<H", len(data)) + data
    return nbt(smb_header(SMB_COM_WRITE_ANDX, FLAGS, mid) + body)


def write_andx_response(mid: int, count: int) -> bytes:
    params = struct.pack(
        "<BBHHHI",
        0xFF,
        0,
        0,  # AndXOffset
        count,
        0,  # Remaining
        0,  # Reserved (CountHigh + Reserved)
    )
    body = bytes([6]) + params + struct.pack("<H", 0)
    return nbt(smb_header(SMB_COM_WRITE_ANDX, FLAGS_REPLY, mid) + body)


def read_andx_request(mid: int, offset: int) -> bytes:
    params = struct.pack(
        "<BBHHIHHIHI",
        0xFF,
        0,
        0,  # AndXOffset
        FID,
        offset,
        MAX_READ,
        0,  # MinCount
        0,  # Timeout / MaxCountHigh
        0,  # Remaining
        0,  # OffsetHigh
    )
    body = bytes([12]) + params + struct.pack("<H", 0)
    return nbt(smb_header(SMB_COM_READ_ANDX, FLAGS, mid) + body)


def read_andx_response(mid: int, data: bytes) -> bytes:
    # One pad byte between ByteCount and the data, which is what puts
    # DataOffset at 60 rather than 59.
    data_offset = 32 + 1 + 24 + 2 + 1
    params = struct.pack(
        "<BBHHHHHHH8s",
        0xFF,
        0,
        0,  # AndXOffset
        0,  # Available
        0,  # DataCompactionMode
        0,  # Reserved
        len(data),
        data_offset,
        0,  # DataLengthHigh
        b"\x00" * 8,  # Reserved
    )
    body = bytes([12]) + params + struct.pack("<H", len(data) + 1) + b"\x00" + data
    return nbt(smb_header(SMB_COM_READ_ANDX, FLAGS_REPLY, mid) + body)


# --- DCE/RPC ---------------------------------------------------------------

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02


def pdu(ptype: int, flags: int, call_id: int, body: bytes) -> bytes:
    header = struct.pack(
        "<BBBB4sHHI",
        5,  # rpc_vers
        0,  # rpc_vers_minor
        ptype,
        flags,
        b"\x10\x00\x00\x00",  # packed_drep: little-endian, ASCII, IEEE
        16 + len(body),  # frag_length
        0,  # auth_length
        call_id,
    )
    return header + body


def context(cont_id: int, abstract: bytes, abstract_ver: int, transfer: bytes, transfer_ver: int) -> bytes:
    return (
        struct.pack("<HBB", cont_id, 1, 0)
        + abstract
        + struct.pack("<I", abstract_ver)
        + transfer
        + struct.pack("<I", transfer_ver)
    )


def bind() -> bytes:
    contexts = context(0, SRVSVC_UUID, 3, NDR32_UUID, 2) + context(1, SRVSVC_UUID, 3, BTFN_UUID, 1)
    body = struct.pack("<HHIBBH", MAX_FRAG, MAX_FRAG, 0, 2, 0, 0) + contexts
    return pdu(0x0B, PFC_FIRST_FRAG | PFC_LAST_FRAG, 0, body)


def bind_ack() -> bytes:
    sec_addr = b"\\pipe\\srvsvc\x00"
    body = struct.pack("<HHIH", MAX_FRAG, MAX_FRAG, ASSOC_GROUP, len(sec_addr)) + sec_addr
    body += b"\x00" * (-len(body) % 4)
    body += struct.pack("<BBH", 2, 0, 0)
    # Context 0: acceptance, NDR32. Context 1: negotiate_ack (3), where the
    # reason field carries the negotiated bind-time features (0x0003) rather
    # than a rejection reason, and the transfer syntax comes back zeroed.
    body += struct.pack("<HH", 0, 0) + NDR32_UUID + struct.pack("<I", 2)
    body += struct.pack("<HH", 3, 3) + b"\x00" * 16 + struct.pack("<I", 0)
    return pdu(0x0C, PFC_FIRST_FRAG | PFC_LAST_FRAG, 0, body)


def rpc_request(call_id: int, opnum: int, stub: bytes) -> bytes:
    return pdu(0x00, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id, struct.pack("<IHH", len(stub), 0, opnum) + stub)


def rpc_response(call_id: int, stub: bytes) -> bytes:
    return pdu(0x02, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id, struct.pack("<IHBB", len(stub), 0, 0, 0) + stub)


# --- NDR -------------------------------------------------------------------


def ndr_string(s: str) -> bytes:
    """A conformant-varying, NUL-terminated UTF-16LE string, padded to 4.

    Maximum count, offset and actual count all describe the same character
    count, terminator included. This is the encoding a length-changing scrub
    would break.
    """
    chars = len(s) + 1
    out = struct.pack("<III", chars, 0, chars) + s.encode("utf-16-le") + b"\x00\x00"
    return out + b"\x00" * (-len(out) % 4)


def netr_share_enum_request_stub(server_name: str) -> bytes:
    stub = struct.pack("<I", 0x00020000) + ndr_string(server_name)
    stub += struct.pack("<I", 1)  # Level
    stub += struct.pack("<I", 1)  # ShareInfo union: SHARE_INFO_1_CONTAINER
    stub += struct.pack("<I", 0x00020004)  # -> container
    stub += struct.pack("<I", 0)  # EntriesRead
    stub += struct.pack("<I", 0)  # Buffer: NULL
    stub += struct.pack("<I", 0xFFFFFFFF)  # PreferedMaximumLength: no cap
    stub += struct.pack("<I", 0x00020008)  # -> ResumeHandle
    stub += struct.pack("<I", 0)  # ResumeHandle
    return stub


def netr_share_enum_response_stub(shares) -> bytes:
    referent = 0x00020014  # the container and its array took 0c and 10
    stub = struct.pack("<I", 1)  # Level
    stub += struct.pack("<I", 1)  # ShareInfo union: SHARE_INFO_1_CONTAINER
    stub += struct.pack("<I", 0x0002000C)  # -> container
    stub += struct.pack("<I", len(shares))  # EntriesRead
    stub += struct.pack("<I", 0x00020010)  # -> Buffer
    stub += struct.pack("<I", len(shares))  # conformant array maximum count
    for _, share_type, _ in shares:
        stub += struct.pack("<III", referent, share_type, referent + 4)
        referent += 8
    for netname, _, remark in shares:
        stub += ndr_string(netname) + ndr_string(remark)
    stub += struct.pack("<I", len(shares))  # TotalEntries
    stub += struct.pack("<I", referent)  # -> ResumeHandle
    stub += struct.pack("<I", 0)  # ResumeHandle: the enumeration is complete
    stub += struct.pack("<I", 0)  # return value: WERR_OK
    return stub


# --- the exchange ----------------------------------------------------------


def frames(shares, server_name: str):
    """The four request/response pairs, in order, as (name, bytes).

    The two SMB_COM_TRANSACTION attempts the device refuses sit either side of
    this in the original exchange. They are deliberately absent: they establish
    the fallback trigger and prove nothing about the path that works.
    """
    bind_pdu = bind()
    ack_pdu = bind_ack()
    request_pdu = rpc_request(1, OPNUM_NETR_SHARE_ENUM, netr_share_enum_request_stub(server_name))
    response_pdu = rpc_response(1, netr_share_enum_response_stub(shares))

    # The pipe's file offset advances over everything written and read before.
    after_bind = len(bind_pdu)
    after_ack = after_bind + len(ack_pdu)
    after_request = after_ack + len(request_pdu)

    return [
        ("synth-0001-c2s-cmd2f.bin", write_andx_request(0x0009, 0, bind_pdu)),
        ("synth-0002-s2c-cmd2f.bin", write_andx_response(0x0009, len(bind_pdu))),
        ("synth-0003-c2s-cmd2e.bin", read_andx_request(0x000A, after_bind)),
        ("synth-0004-s2c-cmd2e.bin", read_andx_response(0x000A, ack_pdu)),
        ("synth-0005-c2s-cmd2f.bin", write_andx_request(0x000C, after_ack, request_pdu)),
        ("synth-0006-s2c-cmd2f.bin", write_andx_response(0x000C, len(request_pdu))),
        ("synth-0007-c2s-cmd2e.bin", read_andx_request(0x000D, after_request)),
        ("synth-0008-s2c-cmd2e.bin", read_andx_response(0x000D, response_pdu)),
    ]


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    for name, data in frames(SHARES, SERVER_NAME):
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"{name}  {len(data)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
