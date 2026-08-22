#![allow(dead_code)]

//! A scripted server for the filesystem layer, over the connection's test seam.
//!
//! The wire layer is not public surface, so every frame here is hand-built —
//! which is what lets a test send an answer no server in the corpus sends: a
//! chunk served short, a chunk served nothing, a reply whose body cannot be
//! read.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

use smb1client::NtStatus;
use smb1client::connection::{Negotiated, Timeouts, transport};
use smb1client::tree::Tree;

pub const HEADER_LEN: usize = 32;
pub const MID_AT: usize = 30;

pub const CLOSE: u8 = 0x04;
pub const RENAME: u8 = 0x07;
pub const TRANSACTION2: u8 = 0x32;
pub const READ_ANDX: u8 = 0x2E;
pub const WRITE_ANDX: u8 = 0x2F;
pub const FIND_CLOSE2: u8 = 0x34;
pub const TREE_DISCONNECT: u8 = 0x71;
pub const NT_CREATE_ANDX: u8 = 0xA2;

/// How long a test waits before concluding nothing more is coming. Under a
/// paused clock this settles the moment the actor has nothing left to do.
pub const SETTLE: Duration = Duration::from_millis(1);

/// Wraps an SMB message in its NetBIOS session-message header.
fn framed(message: &[u8]) -> Vec<u8> {
    let length = message.len();
    let mut out = vec![
        0x00,
        ((length >> 16) & 0x01) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ];
    out.extend_from_slice(message);
    out
}

/// A response header.
pub fn response_header(command: u8, status: NtStatus, mid: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(b"\xffSMB");
    header.push(command);
    header.extend_from_slice(&status.code().to_le_bytes());
    header.push(0x98);
    header.extend_from_slice(&0xC803u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&mid.to_le_bytes());
    assert_eq!(header.len(), HEADER_LEN);
    header
}

/// A message from its header, its words and its byte area.
pub fn message(command: u8, status: NtStatus, mid: u16, words: &[u8], area: &[u8]) -> Vec<u8> {
    assert!(words.len().is_multiple_of(2));
    let mut out = response_header(command, status, mid);
    out.push((words.len() / 2) as u8);
    out.extend_from_slice(words);
    out.extend_from_slice(&(area.len() as u16).to_le_bytes());
    out.extend_from_slice(area);
    out
}

/// The shape SMB1 usually answers a failed command with: `WordCount = 0` and an
/// empty byte area, where the header's status is the whole of what it says.
pub fn bodyless(command: u8, status: NtStatus, mid: u16) -> Vec<u8> {
    message(command, status, mid, &[], &[])
}

fn words(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// An `NT_CREATE_ANDX` response, which is what an open answers with.
pub fn create_response(mid: u16, fid: u16, end_of_file: u64, directory: bool) -> Vec<u8> {
    let mut block = Vec::new();
    // AndX: no further command, and the reserved byte and offset beside it.
    block.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    block.push(0); // OplockLevel
    block.extend_from_slice(&fid.to_le_bytes());
    block.extend_from_slice(&1u32.to_le_bytes()); // CreateAction
    for _ in 0..4 {
        block.extend_from_slice(&0i64.to_le_bytes());
    }
    block.extend_from_slice(&0x80u32.to_le_bytes()); // ExtFileAttributes
    block.extend_from_slice(&end_of_file.to_le_bytes()); // AllocationSize
    block.extend_from_slice(&end_of_file.to_le_bytes()); // EndOfFile
    block.extend_from_slice(&0u16.to_le_bytes()); // ResourceType
    block.extend_from_slice(&0u16.to_le_bytes()); // NMPipeStatus
    block.push(u8::from(directory));
    assert_eq!(block.len(), 34 * 2);
    message(NT_CREATE_ANDX, NtStatus::SUCCESS, mid, &block, &[])
}

/// A `READ_ANDX` response carrying `data`.
pub fn read_response(mid: u16, data: &[u8]) -> Vec<u8> {
    let word_count = 12usize;
    let data_offset = HEADER_LEN + 1 + word_count * 2 + 2;
    let mut block = Vec::new();
    block.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    block.extend_from_slice(&words(&[
        0xFFFF,                    // Available
        0,                         // DataCompactionMode
        0,                         // Reserved
        data.len() as u16,         // DataLength
        data_offset as u16,        // DataOffset
        (data.len() >> 16) as u16, // DataLengthHigh
        0,
        0,
        0,
        0,
    ]));
    assert_eq!(block.len(), word_count * 2);
    message(READ_ANDX, NtStatus::SUCCESS, mid, &block, data)
}

/// A `WRITE_ANDX` response acknowledging `count` bytes.
pub fn write_response(mid: u16, count: u32) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    block.extend_from_slice(&words(&[count as u16, 0, (count >> 16) as u16, 0]));
    assert_eq!(block.len(), 6 * 2);
    message(WRITE_ANDX, NtStatus::SUCCESS, mid, &block, &[])
}

/// A transaction response carrying one whole reply.
pub fn transaction_response(mid: u16, status: NtStatus, parameters: &[u8], data: &[u8]) -> Vec<u8> {
    let word_count = 10usize;
    let mut area = Vec::new();
    let mut at = HEADER_LEN + 1 + word_count * 2 + 2;

    let parameter_offset = if parameters.is_empty() {
        0
    } else {
        while !at.is_multiple_of(2) {
            area.push(0);
            at += 1;
        }
        let offset = at;
        area.extend_from_slice(parameters);
        at += parameters.len();
        offset
    };
    while !at.is_multiple_of(2) {
        area.push(0);
        at += 1;
    }
    let data_offset = at;
    area.extend_from_slice(data);

    let block = words(&[
        parameters.len() as u16,
        data.len() as u16,
        0,
        parameters.len() as u16,
        parameter_offset as u16,
        0,
        data.len() as u16,
        data_offset as u16,
        0,
        0,
    ]);
    assert_eq!(block.len(), word_count * 2);
    message(TRANSACTION2, status, mid, &block, &area)
}

/// One `SMB_FIND_FILE_BOTH_DIRECTORY_INFO` entry.
pub fn entry(next: u32, name: &str, directory: bool) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = vec![0u8; 94];
    out[0..4].copy_from_slice(&next.to_le_bytes());
    out[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
    let attributes: u32 = if directory { 0x10 } else { 0x80 };
    out[56..60].copy_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&name);
    out
}

/// A chain of entries, each pointing at the next and the last terminating.
pub fn chain(names: &[(&str, bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, (name, directory)) in names.iter().enumerate() {
        let body = entry(0, name, *directory);
        let next = if index + 1 == names.len() {
            0
        } else {
            body.len() as u32
        };
        let mut body = entry(next, name, *directory);
        if index + 1 == names.len() {
            body[0..4].copy_from_slice(&0u32.to_le_bytes());
        }
        out.extend_from_slice(&body);
    }
    out
}

/// The parameter block of a `TRANS2_FIND_FIRST2` reply.
pub fn find_first_parameters(sid: u16, count: u16, end_of_search: bool) -> Vec<u8> {
    words(&[sid, count, u16::from(end_of_search), 0, 0])
}

/// The parameter block of a `TRANS2_FIND_NEXT2` reply.
pub fn find_next_parameters(count: u16, end_of_search: bool) -> Vec<u8> {
    words(&[count, u16::from(end_of_search), 0, 0])
}

/// The multiplex id a frame carries.
pub fn mid_of(message: &[u8]) -> u16 {
    u16::from_le_bytes([message[MID_AT], message[MID_AT + 1]])
}

/// The command a frame carries.
pub fn command_of(message: &[u8]) -> u8 {
    message[4]
}

/// The word block of a request frame.
pub fn words_of(message: &[u8]) -> &[u8] {
    let count = usize::from(message[HEADER_LEN]);
    &message[HEADER_LEN + 1..HEADER_LEN + 1 + count * 2]
}

/// A `u16` out of a request's word block.
pub fn word_at(message: &[u8], index: usize) -> u16 {
    let words = words_of(message);
    u16::from_le_bytes([words[index * 2], words[index * 2 + 1]])
}

/// The byte area of a request frame.
pub fn area_of(message: &[u8]) -> &[u8] {
    let count = usize::from(message[HEADER_LEN]);
    &message[HEADER_LEN + 1 + count * 2 + 2..]
}

/// What a `READ_ANDX` request asked for: the offset and the count.
pub fn read_request(frame: &[u8]) -> (u64, u32) {
    let offset = u64::from(u32::from_le_bytes([
        words_of(frame)[6],
        words_of(frame)[7],
        words_of(frame)[8],
        words_of(frame)[9],
    ]));
    let max_count = u32::from(word_at(frame, 5));
    let high = u32::from_le_bytes([
        words_of(frame)[14],
        words_of(frame)[15],
        words_of(frame)[16],
        words_of(frame)[17],
    ]);
    let offset_high = u64::from(u32::from_le_bytes([
        words_of(frame)[20],
        words_of(frame)[21],
        words_of(frame)[22],
        words_of(frame)[23],
    ]));
    (offset | (offset_high << 32), max_count | (high << 16))
}

/// What a `WRITE_ANDX` request offered: the offset and the length.
pub fn write_request(frame: &[u8]) -> (u64, u32) {
    let words = words_of(frame);
    let offset = u64::from(u32::from_le_bytes([words[6], words[7], words[8], words[9]]));
    let length = u32::from(word_at(frame, 10)) | (u32::from(word_at(frame, 9)) << 16);
    let offset_high = u64::from(u32::from_le_bytes([
        words[24], words[25], words[26], words[27],
    ]));
    (offset | (offset_high << 32), length)
}

/// The far side of the connection: whatever a test wants a server to be.
pub struct Peer {
    stream: DuplexStream,
}

impl Peer {
    async fn try_frame(&mut self) -> Option<Vec<u8>> {
        let mut header = [0u8; 4];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(error) => panic!("reading a NetBIOS header: {error}"),
        }
        let length = (usize::from(header[1] & 0x01) << 16)
            | usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut message = vec![0; length];
        self.stream
            .read_exact(&mut message)
            .await
            .expect("a whole frame");
        Some(message)
    }

    /// The next frame the client sends.
    pub async fn frame(&mut self) -> Vec<u8> {
        self.try_frame()
            .await
            .expect("a frame, not the end of the stream")
    }

    /// The next frame, or `None` where nothing more is coming.
    pub async fn next_frame(&mut self) -> Option<Vec<u8>> {
        timeout(SETTLE, self.try_frame()).await.ok().flatten()
    }

    /// Every frame the client has sent and not been answered for.
    pub async fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame().await {
            frames.push(frame);
        }
        frames
    }

    pub async fn send(&mut self, message: &[u8]) {
        self.stream
            .write_all(&framed(message))
            .await
            .expect("the client is reading");
    }

    /// Answers the next frame, whatever it is, with what `answer` builds from
    /// its multiplex id.
    pub async fn answer(&mut self, answer: impl FnOnce(&[u8], u16) -> Vec<u8>) -> Vec<u8> {
        let frame = self.frame().await;
        let mid = mid_of(&frame);
        let reply = answer(&frame, mid);
        self.send(&reply).await;
        frame
    }

    /// Answers an open with a handle, and returns the request.
    pub async fn answer_open(&mut self, fid: u16, len: u64) -> Vec<u8> {
        self.answer(|frame, mid| {
            assert_eq!(command_of(frame), NT_CREATE_ANDX);
            create_response(mid, fid, len, false)
        })
        .await
    }

    /// Answers a close, and returns the request.
    pub async fn answer_close(&mut self) -> Vec<u8> {
        self.answer(|frame, mid| {
            assert_eq!(command_of(frame), CLOSE);
            bodyless(CLOSE, NtStatus::SUCCESS, mid)
        })
        .await
    }

    /// Drops the far side, which is what a connection dying looks like.
    pub fn hang_up(self) {
        drop(self);
    }
}

/// A tree over a duplex pair, with the negotiated parameters injected.
pub fn tree(negotiated: Negotiated, timeouts: Timeouts) -> (Tree, Peer) {
    let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
    let connection = transport::spawn(client, negotiated, timeouts);
    (Tree::attach(connection, 7, 3), Peer { stream: server })
}

/// A server with both large-I/O capabilities and a 64 KiB message buffer, which
/// is what the container advertises.
pub fn large_io() -> Negotiated {
    Negotiated {
        max_mpx_count: 50,
        max_buffer_size: 65_535,
        capabilities: 0x0000_4000 | 0x0000_8000,
    }
}

/// A server advertising neither large-I/O capability.
pub fn small_io(max_buffer_size: u32) -> Negotiated {
    Negotiated {
        max_mpx_count: 50,
        max_buffer_size,
        capabilities: 0,
    }
}

/// The TRANS2 subcommand a request carries, which is its first setup word.
pub fn trans2_subcommand(frame: &[u8]) -> u16 {
    word_at(frame, 14)
}

/// The parameter block of a TRANS2 request, read off the offset it declares.
pub fn trans2_parameters(frame: &[u8]) -> &[u8] {
    let count = usize::from(word_at(frame, 9));
    let offset = usize::from(word_at(frame, 10));
    &frame[offset..offset + count]
}

/// The data block of a TRANS2 request.
pub fn trans2_data(frame: &[u8]) -> &[u8] {
    let count = usize::from(word_at(frame, 11));
    let offset = usize::from(word_at(frame, 12));
    &frame[offset..offset + count]
}

/// What an `NT_CREATE_ANDX` request asked for: the access, the disposition and
/// the create options.
pub fn create_request(frame: &[u8]) -> (u32, u32, u32) {
    let words = words_of(frame);
    let at = |index: usize| {
        u32::from_le_bytes([
            words[index],
            words[index + 1],
            words[index + 2],
            words[index + 3],
        ])
    };
    (at(15), at(35), at(39))
}

/// The name an `NT_CREATE_ANDX` request carries.
pub fn create_name(frame: &[u8]) -> String {
    let area = area_of(frame);
    let name = &area[1..];
    let units: Vec<u16> = name
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16(&units).expect("a name this crate encoded")
}
