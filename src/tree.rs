//! The tree connection and the filesystem verbs.
//!
//! A caller reaches a file through `Client` → [`Tree`] → [`File`], and the verbs
//! here are named for `std::fs`: [`Tree::open`], [`Tree::create`],
//! [`Tree::remove_file`], [`Tree::rename`], [`Tree::read_dir`] and the rest take
//! paths and mean what their names mean locally. Three do not carry a
//! `std::fs` name — [`Tree::set_times`], [`Tree::set_attributes`] and
//! [`Tree::statistics`] — because `std::fs` has no verb for what they do.
//!
//! **Deleting is an open and a close, not a delete command.** `SMB_COM_DELETE`
//! cannot delete a directory at all, so [`Tree::remove_file`],
//! [`Tree::remove_dir`] and every level of [`Tree::remove_dir_all`] open the
//! path with `DELETE` access under `FILE_DELETE_ON_CLOSE` and close the handle,
//! and the server unlinks the entry on that close. The create option is what
//! says which kind of object the open expects, so a `remove_file` aimed at a
//! directory is refused by the server rather than by a client-side check that
//! spends a round trip to reach the same refusal.
//!
//! **Every transaction this crate builds is built here**, in one private
//! function, which is where both transaction limits are enforced. A size rule applied per
//! call site is a rule the next call site added will not apply, and both
//! failures are silent until a server complains about them.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use time::OffsetDateTime;
use tracing::debug;

use crate::connection::{Connection, Reply, Request};
use crate::error::{Error, Result};
use crate::path;
use crate::resource::{DEFAULT_READ_AHEAD, File, ReadDir};
use crate::session::Session;
use crate::status::NtStatus;
use crate::unc::SharePath;
use crate::wire::header::command;
use crate::wire::info;
use crate::wire::transaction::TransactionRequest;
use crate::wire::{file as wire_file, tree as wire_tree};

/// `DELETE`, the right the delete path opens with.
pub(crate) const DELETE: u32 = 0x0001_0000;
/// `FILE_READ_DATA`.
pub(crate) const FILE_READ_DATA: u32 = 0x0000_0001;
/// `FILE_WRITE_DATA`.
pub(crate) const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// `FILE_APPEND_DATA`.
pub(crate) const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// `FILE_READ_ATTRIBUTES`.
pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// `FILE_WRITE_ATTRIBUTES`.
pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

/// `FILE_OPEN`.
const FILE_OPEN: u32 = 1;
/// `FILE_CREATE`.
const FILE_CREATE: u32 = 2;
/// `FILE_OPEN_IF`.
const FILE_OPEN_IF: u32 = 3;
/// `FILE_OVERWRITE`.
const FILE_OVERWRITE: u32 = 4;
/// `FILE_OVERWRITE_IF`.
const FILE_OVERWRITE_IF: u32 = 5;

/// `FILE_DIRECTORY_FILE`.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// `FILE_NON_DIRECTORY_FILE`.
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// `FILE_DELETE_ON_CLOSE`.
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// `SEC_IMPERSONATE`.
const SEC_IMPERSONATE: u32 = 2;

/// What other openers are admitted unless the caller narrows it:
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
///
/// Delete sharing is part of the default and not an omission from it. It is what
/// decides whether [`Tree::remove_file`] succeeds on a file another opener still
/// holds rather than returning a sharing violation, and Windows' own exclusive
/// default is what surprises a caller porting from local filesystem code.
pub const SHARE_ALL: u32 = 0x0000_0007;

/// The `LastWriteTime` an `SMB_COM_CLOSE` carries: zero, which tells the server
/// to leave the time it already has alone. Times are set through
/// [`Tree::set_times`] and nowhere else.
pub(crate) const CLOSE_LEAVES_THE_TIME_ALONE: u32 = 0;

/// The FILETIME epoch — 1601-01-01 — as an offset from the Unix one, in
/// 100-nanosecond ticks.
const FILETIME_EPOCH_TICKS: i128 = 116_444_736_000_000_000;

/// A tree connection, and everything opened on it.
///
/// It holds its session and connection alive: a [`File`] or a [`ReadDir`] holds
/// its `Tree` alive in turn, so nothing releases a tree connect while a handle
/// opened on it is still live.
#[derive(Debug, Clone)]
pub struct Tree {
    pub(crate) inner: Arc<TreeInner>,
}

/// What a tree owns, shared by every handle opened on it.
#[derive(Debug)]
pub(crate) struct TreeInner {
    connection: Connection,
    uid: u16,
    tid: u16,
    /// How many chunks an adapter keeps outstanding.
    read_ahead: AtomicUsize,
    /// Whether the tree connection has already been released, so that an
    /// awaited `close()` and the `Drop` behind it do not both send one.
    released: AtomicBool,
}

impl TreeInner {
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn tid(&self) -> u16 {
        self.tid
    }

    pub(crate) fn uid(&self) -> u16 {
        self.uid
    }

    pub(crate) fn read_ahead(&self) -> usize {
        self.read_ahead.load(Ordering::Relaxed)
    }

    /// Issues one request on this tree.
    pub(crate) async fn request(&self, request: Request) -> Result<Reply> {
        Ok(self.connection().request(request).await?)
    }

    /// Issues one request and refuses a status that is not success.
    pub(crate) async fn checked(&self, request: Request) -> Result<Reply> {
        let reply = self.request(request).await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        Ok(reply)
    }
}

impl Drop for TreeInner {
    fn drop(&mut self) {
        if self.released.load(Ordering::Relaxed) {
            return;
        }
        // `Drop` can neither await the round trip nor report its failure, so the
        // disconnect is handed to the connection actor best-effort. A connection
        // that has gone releases every handle on it anyway.
        self.connection.enqueue_close(Request::new(
            command::TREE_DISCONNECT,
            self.tid,
            self.uid,
            wire_tree::TreeDisconnect.encode_body().unwrap_or_default(),
        ));
    }
}

impl Tree {
    /// Connects to a share.
    ///
    /// `share_path` is the UNC path of the share, built from the host alone and
    /// never from the dial address: a port in it is what Windows refuses with
    /// `STATUS_DUPLICATE_NAME`.
    pub async fn connect(session: Session, share_path: &str, service: &str) -> Result<Self> {
        let request = wire_tree::TreeConnectAndxRequest::new(share_path, service);
        let reply = session
            .connection()
            .request(Request::new(
                command::TREE_CONNECT_ANDX,
                0xFFFF,
                session.uid(),
                request.encode_body()?,
            ))
            .await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        let response = wire_tree::TreeConnectAndxResponse::decode(reply.parsed())?;
        debug!(
            tid = reply.tid(),
            service = response.service,
            "tree connected"
        );
        Ok(Self::attach(
            session.connection().clone(),
            session.uid(),
            reply.tid(),
        ))
    }

    /// Puts a tree on a connection the caller has already tree-connected.
    ///
    /// **This is the test seam's other half, and it is public and unfeatured for
    /// the same reason [`transport::spawn`](crate::connection::transport::spawn)
    /// is.** Nothing above the connection layer could be driven offline without
    /// it: the filesystem verbs need a tree id and a user id, and reaching them
    /// through a real handshake would make every test here a live one. What a
    /// test replaces is the stream, not the sequence.
    pub fn attach(connection: Connection, uid: u16, tid: u16) -> Self {
        Self {
            inner: Arc::new(TreeInner {
                connection,
                uid,
                tid,
                read_ahead: AtomicUsize::new(DEFAULT_READ_AHEAD),
                released: AtomicBool::new(false),
            }),
        }
    }

    /// Sets how many chunks the adapters opened on this tree keep outstanding.
    ///
    /// It is a memory-versus-throughput trade, and a consumer holding many
    /// adapters at once is the one with a reason to make it differently. Four is
    /// the default. It takes `&self` rather than consuming the tree, so that
    /// setting it cannot release a tree connection other handles are using.
    pub fn set_read_ahead(&self, chunks: usize) {
        self.inner
            .read_ahead
            .store(chunks.max(1), Ordering::Relaxed);
    }

    /// The tree id the server assigned.
    pub fn tid(&self) -> u16 {
        self.inner.tid
    }

    /// The connection this tree runs on.
    pub fn connection(&self) -> &Connection {
        &self.inner.connection
    }

    /// Releases the tree connection, reporting whether the round trip
    /// succeeded.
    ///
    /// **A tree somebody else still holds returns `Ok` having sent nothing**,
    /// because disconnecting a tree other callers hold would invalidate handles
    /// they still own. The `TREE_DISCONNECT` goes out when the last owner is
    /// gone — which, once the connection cache exists, is when its own entry is
    /// evicted or the client is closed.
    pub async fn close(self) -> Result<()> {
        let Some(inner) = Arc::into_inner(self.inner) else {
            debug!("tree still held elsewhere; close sends nothing");
            return Ok(());
        };
        inner.released.store(true, Ordering::Relaxed);
        let reply = inner
            .request(Request::new(
                command::TREE_DISCONNECT,
                inner.tid,
                inner.uid,
                wire_tree::TreeDisconnect.encode_body()?,
            ))
            .await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        Ok(())
    }

    /// Opens an existing file for reading.
    pub async fn open(&self, path: &str) -> Result<File> {
        self.open_with(path, &OpenOptions::new().read(true)).await
    }

    /// Creates a file, or truncates what is already there.
    pub async fn create(&self, path: &str) -> Result<File> {
        self.open_with(
            path,
            &OpenOptions::new().write(true).create(true).truncate(true),
        )
        .await
    }

    /// Opens a file, on whatever terms the options ask for.
    pub async fn open_with(&self, path: &str, options: &OpenOptions) -> Result<File> {
        let path = SharePath::new(path)?.into_string();
        let opened = self.create_andx(&options.request(&path)).await?;
        Ok(File::new(
            self.inner.clone(),
            opened.fid,
            opened.end_of_file,
            options.append,
        ))
    }

    /// Creates a directory.
    ///
    /// It is the same `NT_CREATE_ANDX` every other path uses —
    /// `FILE_CREATE` with `FILE_DIRECTORY_FILE`, then a close — and not
    /// `SMB_COM_CREATE_DIRECTORY`.
    pub async fn create_dir(&self, path: &str) -> Result<()> {
        let path = SharePath::new(path)?.into_string();
        let opened = self
            .create_andx(&wire_file::NtCreateAndxRequest {
                flags: 0,
                root_directory_fid: 0,
                desired_access: FILE_WRITE_ATTRIBUTES,
                allocation_size: 0,
                ext_file_attributes: info::ATTRIBUTE_NORMAL,
                share_access: SHARE_ALL,
                create_disposition: FILE_CREATE,
                create_options: FILE_DIRECTORY_FILE,
                impersonation_level: SEC_IMPERSONATE,
                security_flags: 0,
                name: path,
            })
            .await?;
        self.close_handle(opened.fid).await
    }

    /// Deletes a file.
    pub async fn remove_file(&self, path: &str) -> Result<()> {
        self.delete(path, FILE_NON_DIRECTORY_FILE).await
    }

    /// Deletes an empty directory.
    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        self.delete(path, FILE_DIRECTORY_FILE).await
    }

    /// Deletes a directory and everything under it.
    ///
    /// It collects each level fully, and **awaits that level's search close**,
    /// before deleting from it, rather than deleting as it walks: routing closes
    /// through the actor settles send order and nothing more, and mutating a
    /// directory while an enumeration over it is still open may skip or repeat
    /// entries, with no two SMB1 servers obliged to agree on which.
    ///
    /// **It cannot tell a directory symlink from a directory.** At the info
    /// level the listing uses the two are indistinguishable, so a caller who
    /// cannot vouch for what a tree contains should walk it itself: descending
    /// one leaves the tree it was given and deletes whatever is on the other
    /// side.
    pub async fn remove_dir_all(&self, path: &str) -> Result<()> {
        let path = SharePath::new(path)?.into_string();
        self.remove_level(&path).await
    }

    /// One level of the recursive delete, drained and closed before anything on
    /// it is deleted.
    async fn remove_level(&self, path: &str) -> Result<()> {
        let mut listing = self.read_dir(path).await?;
        let mut entries = Vec::new();
        while let Some(entry) = listing.next_entry().await? {
            entries.push(entry);
        }
        // A listing drained to end-of-stream has already been closed by the
        // server, so this costs a round trip nobody makes; a listing that ended
        // any other way is closed here, before the level is touched.
        listing.close().await?;

        for entry in entries {
            let child = path::join(path, entry.name());
            if entry.is_dir() {
                Box::pin(self.remove_level(&child)).await?;
            } else {
                self.remove_file(&child).await?;
            }
        }
        self.remove_dir(path).await
    }

    /// Renames a path.
    ///
    /// It does **not** overwrite an existing destination: the server answers
    /// `STATUS_OBJECT_NAME_COLLISION`, which surfaces as
    /// [`std::io::ErrorKind::AlreadyExists`]. This differs from
    /// `std::fs::rename`, and the name invites the wrong assumption.
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        // The one command whose paths on the wire are not the normalized
        // share-relative form: each name goes out with a leading backslash,
        // matching the reference. Both are refused by the same three checks
        // first.
        let from = with_leading_backslash(&SharePath::new(from)?.into_string());
        let to = with_leading_backslash(&SharePath::new(to)?.into_string());
        let request = wire_file::RenameRequest {
            search_attributes: crate::wire::find::SEARCH_ATTRIBUTES,
            old_name: from,
            new_name: to,
        };
        self.inner
            .checked(Request::new(
                command::RENAME,
                self.inner.tid,
                self.inner.uid(),
                request.encode_body()?,
            ))
            .await?;
        Ok(())
    }

    /// Starts a listing and returns the iterator, which owns the server-side
    /// search from there on.
    pub async fn read_dir(&self, path: &str) -> Result<ReadDir> {
        let path = SharePath::new(path)?.into_string();
        ReadDir::start(self.inner.clone(), &path::search_pattern(&path)).await
    }

    /// Stats a path, needing no open handle.
    ///
    /// **It issues two queries rather than one**: the basic level for the
    /// timestamps and the attributes, then the standard level for the size and
    /// the allocation size, neither carrying both.
    pub async fn metadata(&self, path: &str) -> Result<Metadata> {
        let path = SharePath::new(path)?.into_string();
        let basic = self
            .query_path(&path, info::query_level::BASIC_INFO)
            .await?;
        let basic = info::BasicInfo::decode(&basic)?;
        let standard = self
            .query_path(&path, info::query_level::STANDARD_INFO)
            .await?;
        let standard = info::StandardInfo::decode(&standard)?;
        Ok(Metadata {
            creation_time: basic.creation_time.unwrap_or_default(),
            last_access_time: basic.last_access_time.unwrap_or_default(),
            last_write_time: basic.last_write_time.unwrap_or_default(),
            change_time: basic.change_time.unwrap_or_default(),
            len: standard.end_of_file,
            allocation_size: standard.allocation_size,
            attributes: basic.attributes.unwrap_or_default(),
        })
    }

    /// Whether a path is there.
    ///
    /// A server answering "not found" is not an error here; anything else is.
    pub async fn exists(&self, path: &str) -> Result<bool> {
        match self.metadata(path).await {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Reads a whole file.
    ///
    /// It sizes its buffer from the length the open reported, which is the one
    /// allocation in this crate a server-supplied number decides: asking for a
    /// whole file in memory is asking for an allocation the size of that file,
    /// and the library has no better number than the one the server reports. A
    /// caller who cannot vouch for the size reads through
    /// [`File::read_exact_at`], which allocates what it is handed and nothing
    /// more, or through the reader adapter.
    ///
    /// **This is the one place the fill-or-error rule does not apply.** A file
    /// another writer truncates in between answers short at the far end, and
    /// that is end of file here rather than the error `read_exact_at` would
    /// raise. What comes back is what was there.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let file = self.open(path).await?;
        let bytes = file.read_to_end().await;
        let closed = file.close().await;
        let bytes = bytes?;
        closed?;
        Ok(bytes)
    }

    /// Writes a whole file, creating it or truncating what is already there,
    /// exactly as `std::fs::write` does.
    pub async fn write(&self, path: &str, contents: &[u8]) -> Result<()> {
        let file = self.create(path).await?;
        let written = file.write_all_at(contents, 0, None).await;
        let closed = file.close().await;
        written?;
        closed?;
        Ok(())
    }

    /// Sets a path's timestamps, leaving each one the caller did not name as it
    /// was.
    ///
    /// A `None` encodes as the zero that tells the server to leave that field
    /// alone. Without it a caller could not set a modification time without also
    /// asserting a creation time it does not know.
    pub async fn set_times(
        &self,
        path: &str,
        creation: Option<OffsetDateTime>,
        last_access: Option<OffsetDateTime>,
        last_write: Option<OffsetDateTime>,
        change: Option<OffsetDateTime>,
    ) -> Result<()> {
        let block = info::BasicInfo {
            creation_time: creation.map(to_filetime),
            last_access_time: last_access.map(to_filetime),
            last_write_time: last_write.map(to_filetime),
            change_time: change.map(to_filetime),
            attributes: None,
        };
        self.set_path(path, block).await
    }

    /// Sets a path's attributes, leaving its timestamps as they were.
    ///
    /// **Asking to clear every attribute sends `FILE_ATTRIBUTE_NORMAL`
    /// instead.** A zero attribute word means "do not change", so sending it
    /// would return success and change nothing — the silent no-op class this
    /// crate exists to catch, and one the reference leaves to its caller to know
    /// about.
    pub async fn set_attributes(&self, path: &str, attributes: u32) -> Result<()> {
        let attributes = if attributes == 0 {
            info::ATTRIBUTE_NORMAL
        } else {
            attributes
        };
        self.set_path(
            path,
            info::BasicInfo {
                attributes: Some(attributes),
                ..info::BasicInfo::default()
            },
        )
        .await
    }

    /// The share's size, from whichever level answered.
    ///
    /// The modern level's unit counts are 64-bit; the legacy level's are 32-bit
    /// and wrap on a large volume, which is why [`FsStatistics::level`] says
    /// which one answered. The fallback triggers on **any** error from the
    /// modern level, the reference accepting five distinct statuses there — a
    /// narrower trigger would rest on guessing which of them a given server
    /// picks.
    pub async fn statistics(&self) -> Result<FsStatistics> {
        let modern = self.query_fs(info::fs_level::SIZE_INFO).await;
        let (size, level) = match modern {
            Ok(data) => (info::FsSize::decode_size_info(&data)?, FsInfoLevel::Size),
            Err(first) => {
                debug!("the modern volume level failed ({first}); falling back to the legacy one");
                let data = match self.query_fs(info::fs_level::ALLOCATION).await {
                    Ok(data) => data,
                    Err(second) => {
                        return Err(Error::BothAttemptsFailed {
                            operation: "volume statistics",
                            first: Box::new(first),
                            second: Box::new(second),
                        });
                    }
                };
                (
                    info::FsSize::decode_allocation(&data)?,
                    FsInfoLevel::Allocation,
                )
            }
        };
        Ok(FsStatistics {
            total_bytes: size.bytes(size.total_units),
            available_bytes: size.bytes(size.free_units),
            level,
        })
    }

    // -- the shapes the verbs above are built from --------------------------

    /// Opens a path, and returns what the server said about what it opened.
    async fn create_andx(
        &self,
        request: &wire_file::NtCreateAndxRequest,
    ) -> Result<wire_file::NtCreateAndxResponse> {
        let reply = self
            .inner
            .checked(Request::new(
                command::NT_CREATE_ANDX,
                self.inner.tid,
                self.inner.uid(),
                request.encode_body()?,
            ))
            .await?;
        Ok(wire_file::NtCreateAndxResponse::decode(reply.parsed())?)
    }

    /// Releases a handle and reports the failure of the round trip.
    async fn close_handle(&self, fid: u16) -> Result<()> {
        let request = wire_file::CloseRequest {
            fid,
            last_time_modified: CLOSE_LEAVES_THE_TIME_ALONE,
        };
        self.inner
            .checked(Request::new(
                command::CLOSE,
                self.inner.tid,
                self.inner.uid(),
                request.encode_body()?,
            ))
            .await?;
        Ok(())
    }

    /// The delete path: open with `DELETE` under `FILE_DELETE_ON_CLOSE`, then
    /// close.
    async fn delete(&self, path: &str, kind: u32) -> Result<()> {
        let path = SharePath::new(path)?.into_string();
        let opened = self
            .create_andx(&wire_file::NtCreateAndxRequest {
                flags: 0,
                root_directory_fid: 0,
                desired_access: DELETE,
                allocation_size: 0,
                ext_file_attributes: 0,
                share_access: SHARE_ALL,
                create_disposition: FILE_OPEN,
                create_options: kind | FILE_DELETE_ON_CLOSE,
                impersonation_level: SEC_IMPERSONATE,
                security_flags: 0,
                name: path,
            })
            .await?;
        self.close_handle(opened.fid).await
    }

    async fn query_path(&self, path: &str, level: u16) -> Result<Vec<u8>> {
        let request = TransactionRequest::trans2(
            info::SUBCOMMAND_QUERY_PATH_INFORMATION,
            info::query_path_parameters(level, path),
            Vec::new(),
        );
        let reply = transaction(&self.inner, request, "TRANS2_QUERY_PATH_INFORMATION").await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        Ok(transaction_data(&reply))
    }

    async fn set_path(&self, path: &str, block: info::BasicInfo) -> Result<()> {
        let path = SharePath::new(path)?.into_string();
        let request = TransactionRequest::trans2(
            info::SUBCOMMAND_SET_PATH_INFORMATION,
            info::set_path_parameters(info::set_level::BASIC_INFO, &path),
            block.encode()?,
        );
        let reply = transaction(&self.inner, request, "TRANS2_SET_PATH_INFORMATION").await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        Ok(())
    }

    async fn query_fs(&self, level: u16) -> Result<Vec<u8>> {
        let request = TransactionRequest::trans2(
            info::SUBCOMMAND_QUERY_FS_INFORMATION,
            info::query_fs_parameters(level),
            Vec::new(),
        );
        let reply = transaction(&self.inner, request, "TRANS2_QUERY_FS_INFORMATION").await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        Ok(transaction_data(&reply))
    }
}

/// The one place a transaction request reaches the wire, and where both
/// transaction limits are enforced.
///
/// The ceiling bounds what the request asks the server to *return*; the request
/// having to fit one message within the negotiated `MaxBufferSize` is a separate
/// rule, and a long path or a long search pattern is the realistic way it
/// breaks. Neither is truncated and neither is silently split.
///
/// It is here and not inside the encoder because the encoder also re-encodes
/// captured frames, forty-three of which ask for 66,559 bytes and would stop
/// re-encoding if the ceiling were applied there.
pub(crate) async fn transaction(
    tree: &TreeInner,
    request: TransactionRequest,
    what: &'static str,
) -> Result<Reply> {
    request
        .check_limits(tree.connection().negotiated().max_buffer_size)
        .map_err(|error| too_large(error, what))?;
    tree.request(Request::transaction(
        request.command,
        tree.tid(),
        tree.uid(),
        request.encode_body()?,
        request.max_parameter_count,
        request.max_data_count,
    ))
    .await
}

/// A transaction this crate built that will not fit one message.
pub(crate) fn too_large(error: crate::wire::WireError, request: &'static str) -> Error {
    match error {
        crate::wire::WireError::FieldTooLong {
            field: "transaction request",
            length,
            limit,
        } => Error::TransactionTooLarge {
            request,
            size: length,
            limit,
        },
        other => Error::Protocol(Box::new(other)),
    }
}

/// The data block of a reassembled transaction reply, or nothing where the
/// reply carried none.
pub(crate) fn transaction_data(reply: &Reply) -> Vec<u8> {
    reply
        .transaction()
        .map(|body| body.data().to_vec())
        .unwrap_or_default()
}

/// Prepends the backslash `SMB_COM_RENAME` puts in front of each of its names.
fn with_leading_backslash(path: &str) -> String {
    if path.starts_with('\\') {
        path.to_owned()
    } else {
        format!("\\{path}")
    }
}

/// A `time::OffsetDateTime` as the FILETIME the wire carries.
fn to_filetime(at: OffsetDateTime) -> i64 {
    let ticks = at.unix_timestamp_nanos() / 100 + FILETIME_EPOCH_TICKS;
    ticks.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// A FILETIME as a `time::OffsetDateTime`.
///
/// The type represents the whole FILETIME range rather than clamping it, which
/// is why it is this crate's timestamp: a server is free to return a time a
/// narrower type would have to fabricate a value for rather than report.
pub(crate) fn from_filetime(ticks: i64) -> Option<OffsetDateTime> {
    if ticks == 0 {
        return None;
    }
    let nanos = (i128::from(ticks) - FILETIME_EPOCH_TICKS) * 100;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
}

/// How to open a file: the `std::fs::OpenOptions` set, plus one field that has
/// no local analogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    share: u32,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenOptions {
    /// Options that ask for nothing yet.
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            share: SHARE_ALL,
        }
    }

    /// Opens for reading.
    pub fn read(mut self, yes: bool) -> Self {
        self.read = yes;
        self
    }

    /// Opens for writing.
    pub fn write(mut self, yes: bool) -> Self {
        self.write = yes;
        self
    }

    /// Positions the **writer adapter's** writes at the file's length as
    /// observed when the handle was opened, and advances them from there.
    ///
    /// **It is not atomic, and it reaches the adapter alone.** SMB1 offers no
    /// append-at-end-of-file a server resolves per write, so two writers
    /// appending to one file through this crate can overwrite each other; and
    /// [`File::write_all_at`] is untouched by it, an absolute-offset write
    /// having no cursor to append to. Both halves need saying, because the name
    /// invites the other reading.
    pub fn append(mut self, yes: bool) -> Self {
        self.append = yes;
        self
    }

    /// Truncates what is already there.
    pub fn truncate(mut self, yes: bool) -> Self {
        self.truncate = yes;
        self
    }

    /// Creates the file if it is not there.
    pub fn create(mut self, yes: bool) -> Self {
        self.create = yes;
        self
    }

    /// Creates the file and fails if it is already there.
    pub fn create_new(mut self, yes: bool) -> Self {
        self.create_new = yes;
        self
    }

    /// Narrows what other openers are allowed while this handle is open.
    ///
    /// The default admits readers, writers and deleters alike. Narrowing it is
    /// the deliberate act.
    pub fn share(mut self, access: u32) -> Self {
        self.share = access;
        self
    }

    /// The rights these options ask for, and never `SYNCHRONIZE`.
    ///
    /// The reference asks for the `GENERIC_*` groups, which claim a good deal
    /// more than the operations behind them exercise. `SYNCHRONIZE` is the right
    /// to wait on the handle itself, and nothing in this crate waits on one:
    /// reads and writes carry absolute offsets and the actor waits on replies.
    fn desired_access(&self) -> u32 {
        let mut access = 0;
        if self.read {
            access |= FILE_READ_DATA | FILE_READ_ATTRIBUTES;
        }
        if self.write || self.append {
            access |= FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
        }
        if self.append {
            // `FILE_WRITE_DATA` stays alongside it, where the reference clears
            // it: without that an append-opened handle could not serve the
            // absolute-offset `write_all_at` this API keeps working on one.
            access |= FILE_APPEND_DATA;
        }
        if access == 0 {
            access = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
        }
        access
    }

    fn create_disposition(&self) -> u32 {
        match (self.create_new, self.create, self.truncate) {
            (true, _, _) => FILE_CREATE,
            (_, true, true) => FILE_OVERWRITE_IF,
            (_, true, false) => FILE_OPEN_IF,
            (_, false, true) => FILE_OVERWRITE,
            (_, false, false) => FILE_OPEN,
        }
    }

    fn request(&self, path: &str) -> wire_file::NtCreateAndxRequest {
        wire_file::NtCreateAndxRequest {
            // Not reachable through the options and fixed at zero: no oplock is
            // requested, which is what makes a server-initiated request a thing
            // the actor never has to route.
            flags: 0,
            // Every path this crate sends is relative to the tree, so there is
            // no directory handle to resolve it against.
            root_directory_fid: 0,
            desired_access: self.desired_access(),
            // A hint about a file being created; a caller wanting space reserved
            // sets the length afterwards.
            allocation_size: 0,
            ext_file_attributes: info::ATTRIBUTE_NORMAL,
            share_access: self.share,
            create_disposition: self.create_disposition(),
            create_options: FILE_NON_DIRECTORY_FILE,
            impersonation_level: SEC_IMPERSONATE,
            security_flags: 0,
            name: path.to_owned(),
        }
    }
}

/// What a stat carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    len: u64,
    allocation_size: u64,
    attributes: u32,
}

impl Metadata {
    /// The file's length.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Space allocated to the file, which may exceed its length.
    pub fn allocation_size(&self) -> u64 {
        self.allocation_size
    }

    /// The attribute word.
    pub fn attributes(&self) -> u32 {
        self.attributes
    }

    /// Whether this is a directory, derived from the attributes rather than
    /// from a query of its own.
    pub fn is_dir(&self) -> bool {
        self.attributes & info::ATTRIBUTE_DIRECTORY != 0
    }

    /// When the file was created, where the server reported it.
    pub fn created(&self) -> Option<OffsetDateTime> {
        from_filetime(self.creation_time)
    }

    /// When it was last read.
    pub fn accessed(&self) -> Option<OffsetDateTime> {
        from_filetime(self.last_access_time)
    }

    /// When it was last written.
    pub fn modified(&self) -> Option<OffsetDateTime> {
        from_filetime(self.last_write_time)
    }

    /// When its metadata last changed.
    pub fn changed(&self) -> Option<OffsetDateTime> {
        from_filetime(self.change_time)
    }

    pub(crate) fn from_parts(
        basic: info::BasicInfo,
        len: u64,
        allocation_size: u64,
        attributes: u32,
    ) -> Self {
        Self {
            creation_time: basic.creation_time.unwrap_or_default(),
            last_access_time: basic.last_access_time.unwrap_or_default(),
            last_write_time: basic.last_write_time.unwrap_or_default(),
            change_time: basic.change_time.unwrap_or_default(),
            len,
            allocation_size,
            attributes,
        }
    }
}

/// Which level answered [`Tree::statistics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsInfoLevel {
    /// `SMB_QUERY_FS_SIZE_INFO`, whose unit counts are 64-bit.
    Size,
    /// `SMB_INFO_ALLOCATION`, whose counts are 32-bit and wrap on a large
    /// volume.
    Allocation,
}

/// A share's size.
///
/// Both levels report allocation units rather than bytes, and the verb
/// multiplies them out once so that every caller does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStatistics {
    /// The volume's size.
    pub total_bytes: u64,
    /// What is still free on it.
    pub available_bytes: u64,
    /// Which level answered. It is not decoration: the fallback is otherwise
    /// silent, and on a volume large enough to overflow the legacy level's
    /// 32-bit counts a caller has no other way to tell a real number from a
    /// wrapped one.
    pub level: FsInfoLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping from options to `NT_CREATE_ANDX` fields, which is fixed here
    /// rather than at each call site.
    #[test]
    fn the_options_reach_the_wire_as_the_fields_the_table_names() {
        let read = OpenOptions::new().read(true).request("a.txt");
        assert_eq!(read.desired_access, FILE_READ_DATA | FILE_READ_ATTRIBUTES);
        assert_eq!(read.create_disposition, FILE_OPEN);
        assert_eq!(read.share_access, SHARE_ALL);
        assert_eq!(read.create_options, FILE_NON_DIRECTORY_FILE);
        assert_eq!(read.impersonation_level, SEC_IMPERSONATE);
        assert_eq!(read.flags, 0);
        assert_eq!(read.allocation_size, 0);
        assert_eq!(read.root_directory_fid, 0);
        assert_eq!(read.security_flags, 0);

        let create = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .request("a.txt");
        assert_eq!(create.create_disposition, FILE_OVERWRITE_IF);
        assert_eq!(
            create.desired_access,
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
        );

        assert_eq!(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .request("a")
                .create_disposition,
            FILE_CREATE
        );
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .request("a")
                .create_disposition,
            FILE_OVERWRITE
        );
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .create(true)
                .request("a")
                .create_disposition,
            FILE_OPEN_IF
        );
    }

    /// `SYNCHRONIZE` is asked for nowhere, and `append` keeps `FILE_WRITE_DATA`
    /// where the reference clears it.
    #[test]
    fn append_keeps_write_data_and_nothing_asks_for_synchronize() {
        const SYNCHRONIZE: u32 = 0x0010_0000;
        let append = OpenOptions::new().append(true).request("a.txt");
        assert_eq!(
            append.desired_access,
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_APPEND_DATA
        );
        for options in [
            OpenOptions::new().read(true),
            OpenOptions::new().write(true),
            OpenOptions::new().read(true).write(true).append(true),
        ] {
            assert_eq!(options.request("a").desired_access & SYNCHRONIZE, 0);
        }
    }

    /// Rename's two names go on the wire with a leading backslash, and nothing
    /// else about them changes.
    #[test]
    fn rename_prefixes_both_names_and_changes_nothing_else() {
        assert_eq!(with_leading_backslash("a\\b.txt"), "\\a\\b.txt");
        assert_eq!(with_leading_backslash("\\a"), "\\a");
    }

    /// The FILETIME epoch, round-tripped, and the zero that means "no time".
    #[test]
    fn filetimes_round_trip_and_zero_is_absent() {
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(from_filetime(to_filetime(at)), Some(at));
        assert_eq!(from_filetime(0), None);
        // 1601-01-01T00:00:00Z is the FILETIME epoch itself.
        assert_eq!(
            to_filetime(OffsetDateTime::from_unix_timestamp(0).unwrap()),
            FILETIME_EPOCH_TICKS as i64
        );
    }
}
