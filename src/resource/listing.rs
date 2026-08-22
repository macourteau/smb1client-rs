//! The lazily-paged listing iterator `Tree::read_dir` returns.
//!
//! It exposes an inherent `next_entry().await` rather than `impl Stream`:
//! `Stream` is not in `std`, so returning one would put a pre-1.0 crate in this
//! crate's public signature and force every consumer to add a dependency to
//! perform the most common SMB operation. A `Stream` implementation can be added
//! later without breaking anything.
//!
//! **Two things end a listing.** `EndOfSearch` in a reply is one; a FIND
//! answered `STATUS_NO_MORE_FILES` is the other — warning severity rather than
//! the error class, carrying no entries, and saying the search is exhausted. The
//! listing ends normally on either, and [`ReadDir::next_entry`] returns
//! `Ok(None)` rather than an error.
//!
//! **The port closes the search on both paths.** `SMB_FIND_CLOSE_AT_EOS` goes on
//! the FIND_FIRST2 *and* on every FIND_NEXT2, so whichever request reaches
//! end-of-stream is the one that asks the server to close it; and
//! `SMB_COM_FIND_CLOSE2` covers the other ending, a listing dropped before EOS,
//! which lazy listing makes ordinary. The reference does neither reliably — it
//! sets the flag on the FIND_FIRST2 alone, so every listing longer than one page
//! ends on a request that never asked the server to close — and that leak is why
//! its recursive delete needs a retry loop.
//!
//! **The no-progress guard counts the entries the server returned, before `.`
//! and `..` are removed**, and the ordering is the rule rather than an
//! implementation detail: an empty directory's first page is `.` and `..` and
//! nothing else, so on a server that does not set `EndOfSearch` on it the
//! post-filter reading turns listing an empty directory — the ordinary case —
//! into an error.

use std::collections::VecDeque;
use std::sync::Arc;

use time::OffsetDateTime;
use tracing::debug;

use crate::connection::Request;
use crate::error::{Error, Result};
use crate::status::NtStatus;
use crate::tree::{self, Metadata, TreeInner};
use crate::wire::find::{self, FindClose2Request, FindFirst2Params, FindNext2Params, FindReply};
use crate::wire::header::command;
use crate::wire::info;
use crate::wire::transaction::TransactionRequest;

/// What each round asks for.
///
/// `SearchCount` is advisory — a server returns whatever fits, and what bounds a
/// page is `MaxDataCount` rather than the count asked for — but the number is
/// load-bearing in one place: it is what makes a Samba reply large enough to
/// fragment, which is the reassembly path's live coverage.
const BATCH: u16 = 100;

/// What both FIND requests ask the server to close at end of stream, and the
/// FIND_NEXT2's own continuation flag.
const FIRST_FLAGS: u16 = find::FLAG_CLOSE_AT_EOS;
const NEXT_FLAGS: u16 = find::FLAG_CLOSE_AT_EOS | find::FLAG_CONTINUE_FROM_LAST;

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    name: String,
    metadata: Metadata,
}

impl DirEntry {
    /// The entry's name, as the server spelled it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Everything a stat would carry, which this level already returned.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// The file's length.
    pub fn len(&self) -> u64 {
        self.metadata.len()
    }

    /// Whether the entry is empty.
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }

    /// Whether the entry is a directory, derived from the attributes.
    pub fn is_dir(&self) -> bool {
        self.metadata.is_dir()
    }

    /// When the entry was last written.
    pub fn modified(&self) -> Option<OffsetDateTime> {
        self.metadata.modified()
    }
}

/// A directory listing, which owns the server-side search.
#[derive(Debug)]
pub struct ReadDir {
    tree: Arc<TreeInner>,
    /// Re-sent on every FIND_NEXT2: the request is not self-contained.
    pattern: String,
    sid: Option<u16>,
    /// Whether the search has reached its end by either terminator, which is
    /// also what says the server has already closed it.
    finished: bool,
    closed: bool,
    page: VecDeque<DirEntry>,
}

impl ReadDir {
    /// Issues the `TRANS2_FIND_FIRST2` and returns the iterator over its first
    /// page.
    pub(crate) async fn start(tree: Arc<TreeInner>, pattern: &str) -> Result<Self> {
        let mut listing = Self {
            tree,
            pattern: pattern.to_owned(),
            sid: None,
            finished: false,
            closed: false,
            page: VecDeque::new(),
        };
        let params = FindFirst2Params {
            search_attributes: find::SEARCH_ATTRIBUTES,
            search_count: BATCH,
            flags: FIRST_FLAGS,
            information_level: find::INFO_LEVEL_BOTH_DIRECTORY_INFO,
            pattern: pattern.to_owned(),
        };
        let request =
            TransactionRequest::trans2(find::SUBCOMMAND_FIND_FIRST2, params.encode()?, Vec::new());
        listing.page_in(request, "TRANS2_FIND_FIRST2", true).await?;
        Ok(listing)
    }

    /// The next entry, or `None` where the listing has ended.
    ///
    /// Most calls are answered out of the page already in hand and send nothing;
    /// the call that exhausts a page issues the FIND_NEXT2 from the search id and
    /// pattern the iterator has held since the FIND_FIRST2.
    pub async fn next_entry(&mut self) -> Result<Option<DirEntry>> {
        loop {
            if let Some(entry) = self.page.pop_front() {
                return Ok(Some(entry));
            }
            if self.finished || self.closed {
                return Ok(None);
            }
            let Some(sid) = self.sid else {
                return Ok(None);
            };
            let params = FindNext2Params {
                sid,
                search_count: BATCH,
                information_level: find::INFO_LEVEL_BOTH_DIRECTORY_INFO,
                // Continuation is server-side and the client keeps no resume
                // point of its own.
                resume_key: 0,
                flags: NEXT_FLAGS,
                pattern: self.pattern.clone(),
            };
            let request = TransactionRequest::trans2(
                find::SUBCOMMAND_FIND_NEXT2,
                params.encode()?,
                Vec::new(),
            );
            self.page_in(request, "TRANS2_FIND_NEXT2", false).await?;
        }
    }

    /// Releases the search, reporting whether the round trip succeeded.
    ///
    /// **A listing drained to end-of-stream has already been closed by the
    /// server**: the request that ended it carried `SMB_FIND_CLOSE_AT_EOS`, and
    /// the server released the search when it processed it. So on a drained
    /// listing this sends no `SMB_COM_FIND_CLOSE2` and returns success rather
    /// than a round trip's error.
    pub async fn close(mut self) -> Result<()> {
        self.closed = true;
        let Some(sid) = self.sid else { return Ok(()) };
        if self.finished {
            return Ok(());
        }
        let request = FindClose2Request { sid };
        self.tree
            .checked(Request::new(
                command::FIND_CLOSE2,
                self.tree.tid(),
                self.tree.uid(),
                request.encode_body()?,
            ))
            .await?;
        Ok(())
    }

    /// Issues one FIND round and takes its entries.
    async fn page_in(
        &mut self,
        request: TransactionRequest,
        what: &'static str,
        first: bool,
    ) -> Result<()> {
        let reply = tree::transaction(&self.tree, request, what).await?;
        let status = reply.status();
        if status == NtStatus::NO_MORE_FILES {
            // The second terminator: warning severity, no entries, and the
            // search is exhausted. The request carried `SMB_FIND_CLOSE_AT_EOS`,
            // so the server has released it.
            self.finished = true;
            return Ok(());
        }
        if status != NtStatus::SUCCESS {
            return Err(Error::refused(status));
        }
        let body = reply.transaction().ok_or_else(|| {
            Error::Protocol(Box::new(crate::wire::WireError::NoResponseBody {
                command: command::TRANSACTION2,
                status,
            }))
        })?;

        let found = if first {
            let found = FindReply::decode_first(body.parameters())?;
            self.sid = found.sid;
            found
        } else {
            FindReply::decode_next(body.parameters())?
        };

        let entries = find::walk_entries(body.data(), found.search_count)?;
        let returned = entries.len();
        let end_of_search = found.end_of_search != 0;

        for entry in entries {
            // `.` and `..` are filtered by the listing API and not by the
            // parser, so a chain that is short because the server truncated it
            // stays distinguishable from one that is short because two entries
            // were dropped. The filter sits above the guard below for the same
            // reason.
            if entry.file_name == "." || entry.file_name == ".." {
                continue;
            }
            self.page.push_back(DirEntry {
                name: entry.file_name,
                metadata: Metadata::from_parts(
                    info::BasicInfo {
                        creation_time: Some(entry.creation_time),
                        last_access_time: Some(entry.last_access_time),
                        last_write_time: Some(entry.last_write_time),
                        change_time: Some(entry.change_time),
                        attributes: Some(entry.ext_file_attributes),
                    },
                    entry.end_of_file,
                    entry.allocation_size,
                    entry.ext_file_attributes,
                ),
            });
        }

        if end_of_search {
            self.finished = true;
            return Ok(());
        }
        // The no-progress guard, counting what the server returned rather than
        // what survived the filter: a page that yields no entries and does not
        // end the search is an error, not another round. Without it a server
        // answering `SearchCount = 0` with `EndOfSearch = 0` pages for ever. A
        // terminating reply is entitled to carry no entries, which is why the
        // guard sits after both terminators.
        if returned == 0 {
            return Err(Error::Protocol(Box::new(ListingError::NoProgress {
                pattern: self.pattern.clone(),
            })));
        }
        Ok(())
    }
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        if self.closed || self.finished {
            return;
        }
        let Some(sid) = self.sid else { return };
        match (FindClose2Request { sid }).encode_body() {
            Ok(body) => self.tree.connection().enqueue_close(Request::new(
                command::FIND_CLOSE2,
                self.tree.tid(),
                self.tree.uid(),
                body,
            )),
            Err(error) => debug!("a dropped listing's close could not be encoded: {error}"),
        }
    }
}

/// What a listing can fail with that no status names.
#[derive(Debug, thiserror::Error)]
enum ListingError {
    /// A page that returned no entries and did not end the search.
    #[error("the search for {pattern} returned no entries and did not end")]
    NoProgress {
        /// The pattern the search was made with.
        pattern: String,
    },
}
