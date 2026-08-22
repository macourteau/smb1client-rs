//! [`Client`], [`ClientConfig`], and the connection and tree caches.
//!
//! A caller reaches a file through `Client` → [`Tree`] → [`File`](crate::File),
//! and everything below that chain is this module's business: dialling,
//! authenticating, keeping the connection, noticing when it has died and
//! dialling again.
//!
//! # What the caches are keyed on
//!
//! **Connections are keyed by the dial address alone** — host *and* port, which
//! is what a UNC path's server component carries. Two paths naming different
//! ports on one host are two different servers. The key is
//! [`Server::cache_key`], the literal string the caller wrote with the host
//! lowercased, never the address it resolves to: resolving first would make the
//! cache's identity depend on DNS state at the moment of the lookup, and would
//! collapse two genuinely different servers behind one rotating name onto a
//! single connection.
//!
//! Credentials are no part of that key, because **one `Client` is one
//! identity**: they live on [`ClientConfig`], so every connection a `Client`
//! dials authenticates with the same material, and a caller needing two
//! identities builds two `Client`s. That is also what makes a connection carry
//! exactly one session, so **trees are keyed by the connection and the share**,
//! with no third component for a distinction that cannot arise.
//!
//! # How a dead connection is noticed
//!
//! Three routes reach a connection that no longer works, and they are not the
//! same:
//!
//! - **the actor has terminated** — the socket failed, or a rule the connection
//!   layer enforces ended it. The entry is evicted and the next call re-dials.
//! - **a silent drop with no FIN**, which leaves the actor alive reading a
//!   socket that will never speak again. The connection layer's silence rule
//!   catches that while a caller is waiting; a connection nobody is waiting on
//!   is caught by the idle probe below instead.
//! - **the server discarding session or tree while keeping TCP alive.**
//!   `STATUS_USER_SESSION_DELETED` fails the connection — session and
//!   connection are the same object here — while `STATUS_NETWORK_NAME_DELETED`
//!   evicts one tree and returns [`Error::TreeDisconnected`], leaving the
//!   connection, its other trees, their handles and every in-flight request
//!   alone.
//!
//! [`Error::ConnectionLost`] means "this connection had already died; the
//! *next* call will re-dial". Transparent re-dial cannot cover the mid-flight
//! case, because writes are not idempotent. **A re-dial carries no handles
//! across**: every file id, search id, tree id and user id means nothing
//! outside the connection it was opened on.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::auth::Credentials;
use crate::connection::{DEFAULT_OVERALL_DEADLINE, DEFAULT_PER_REQUEST_TIMEOUT, Request, Timeouts};
use crate::error::{Error, Result};
use crate::resource::DEFAULT_READ_AHEAD;
use crate::rpc::{Ipc, Share};
use crate::session::{ADVERTISED_MAX_BUFFER_SIZE, Session, SessionOptions};
use crate::status::NtStatus;
use crate::tree::Tree;
use crate::unc::{IPC_SHARE, Server, UncPath};
use crate::wire::echo::EchoRequest;
use crate::wire::header::command;
use crate::wire::session::LogoffAndx;
use crate::wire::tree::{SERVICE_ANY, SERVICE_IPC};

/// The connect timeout a [`ClientConfig`] carries unless the caller sets
/// another.
///
/// `tokio::net::TcpStream::connect` imposes none of its own, so a dead host
/// otherwise hangs for the operating system's SYN timeout — around two minutes
/// on Linux. Ten seconds is comfortably inside that and longer than any dial
/// and handshake a server that is there at all needs.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many overall deadlines of idleness make a cached connection worth
/// probing before it is handed out again.
const PROBE_AFTER_DEADLINES: u32 = 1;

/// How many overall deadlines of idleness evict a cached connection instead.
///
/// A fixed multiple of the deadline rather than a knob of its own, so that the
/// two thresholds cannot be configured into contradiction.
const EVICT_AFTER_DEADLINES: u32 = 20;

/// How often the sweeper wakes, as a fraction of the eviction window.
const SWEEPS_PER_EVICTION_WINDOW: u32 = 4;

/// The `TID` the probe's header carries: SMB1's "no tree".
const NO_TREE: u16 = 0xFFFF;

/// The `UID` the probe's header carries: no session.
const NO_SESSION: u16 = 0;

/// The `TID` a logoff carries. It is session-scoped and names no tree.
const LOGOFF_TREE: u16 = 0;

/// A stream to an SMB1 server: what a dial produces and the handshake runs on.
///
/// Implemented for every stream that qualifies; there is nothing to write.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for S {}

/// What a dial hands back.
pub type Dialed = Pin<Box<dyn Future<Output = Result<Box<dyn Stream>>> + Send>>;

/// How a [`Client`] reaches a server.
///
/// [`Client::new`] dials TCP, which is what a consumer wants. A dialer of the
/// caller's own replaces **the stream and nothing else** — the handshake, the
/// timing bounds, the caches and the teardown are the same code either way —
/// which is what makes it both the test seam for this module and the way to
/// reach a server through a tunnel of the consumer's own.
pub type Dialer = Arc<dyn Fn(Server) -> Dialed + Send + Sync>;

/// What a [`Client`] is configured with.
///
/// The credentials are the one identity every connection this client dials
/// authenticates with. The three timing bounds are the crate's whole timing
/// surface, and the last of them does five jobs — see [`ClientConfig::
/// overall_deadline`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Who to authenticate as, on every connection this client dials.
    pub credentials: Credentials,
    /// The bound on the dial and the handshake together.
    pub connect_timeout: Duration,
    /// How long one request on the wire may go without any message reaching it.
    ///
    /// It bounds one request and not one public call: a `Tree::read` of a large
    /// file is many requests, and a caller who wants one figure for the whole
    /// call wraps it in `tokio::time::timeout`.
    pub per_request_timeout: Duration,
    /// The bound on one request's whole life — and four other things.
    ///
    /// It is the span of silence that fails a connection; the idle time after
    /// which a cached connection is probed before it is reused; at twenty times
    /// its value, the idle time after which a cached connection is evicted
    /// instead; and at eight times its value, how long a lapsed request waits
    /// before it is given up on. Raising it for a slow server lengthens all
    /// five.
    pub overall_deadline: Duration,
    /// Whether a guest logon is acceptable.
    ///
    /// `false` by default, so a server that quietly downgrades a wrong password
    /// to guest access fails the handshake rather than handing back a session
    /// with whatever rights guests have.
    pub allow_guest: bool,
    /// The `MaxBufferSize` this client advertises in its own session setup.
    ///
    /// It is the threshold at which a reply arrives in several messages at all,
    /// and lowering it is how the reassembly path is reached deliberately
    /// against a live server.
    pub advertised_max_buffer_size: u16,
    /// How many chunks the read and write adapters keep outstanding.
    pub read_ahead: usize,
    /// Whether the tracer writes frame bytes for this run.
    ///
    /// Off by default: a dump of a listing or a read reply carries filenames
    /// and file contents. Turning it on does **not** reach
    /// `SESSION_SETUP_ANDX`, whose byte section the tracer redacts whatever
    /// this says.
    pub dump_wire_bytes: bool,
}

impl ClientConfig {
    /// A configuration with the defaults, for the given credentials.
    ///
    /// There is no `Default`: the credentials have none, and an empty pair
    /// would be a guest logon written as an oversight.
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            per_request_timeout: DEFAULT_PER_REQUEST_TIMEOUT,
            overall_deadline: DEFAULT_OVERALL_DEADLINE,
            allow_guest: false,
            advertised_max_buffer_size: ADVERTISED_MAX_BUFFER_SIZE,
            read_ahead: DEFAULT_READ_AHEAD,
            dump_wire_bytes: false,
        }
    }

    /// The two bounds the connection actor works to.
    fn timeouts(&self) -> Timeouts {
        Timeouts {
            per_request: self.per_request_timeout,
            overall: self.overall_deadline,
        }
    }

    /// What the handshake is run with.
    fn session_options(&self) -> SessionOptions {
        SessionOptions {
            connect_timeout: self.connect_timeout,
            timeouts: self.timeouts(),
            allow_guest: self.allow_guest,
            advertised_max_buffer_size: self.advertised_max_buffer_size,
            dump_wire_bytes: self.dump_wire_bytes,
        }
    }
}

/// An SMB1 client: one identity, and the connections and trees it caches.
///
/// Every method takes `&self`, the cache being behind interior mutability, so a
/// consumer shares one client across as many tasks as it likes behind an `Arc`
/// and never wraps it in a lock of its own.
///
/// ```no_run
/// use smb1client::{Client, ClientConfig, Credentials, UncPath};
///
/// # async fn example() -> smb1client::Result<()> {
/// let client = Client::new(ClientConfig::new(Credentials::new("smbtest", "smbtest")));
/// let path: UncPath = r"\\server\share".parse()?;
/// let tree = client.tree(&path).await?;
/// let listing = tree.read_dir("").await?;
/// client.close().await
/// # }
/// ```
pub struct Client {
    inner: Arc<ClientInner>,
}

/// What the client owns, behind the `Arc` the sweeper holds weakly.
struct ClientInner {
    config: ClientConfig,
    dialer: Dialer,
    state: Mutex<State>,
}

/// The cache itself, and the sweeper that empties it.
struct State {
    connections: HashMap<String, Slot>,
    /// The eviction sweeper, spawned with the first entry the cache holds.
    ///
    /// It is spawned lazily rather than in [`Client::new`] because there is
    /// nothing to sweep before the first connection — which is also what lets a
    /// client be built outside a runtime.
    sweeper: Option<JoinHandle<()>>,
    /// Whether [`Client::close`] has run, which a dial still in flight reads
    /// rather than caching into a client that has gone.
    closed: bool,
}

/// What the cache holds against one dial address.
enum Slot {
    /// A dial in flight. Every task meeting this waits on it rather than
    /// dialling its own.
    Dialing(Arc<Dial>),
    /// A connection, its session, and the trees connected on it.
    Ready(Arc<Cached>),
}

/// One connection's cache entry.
struct Cached {
    session: Session,
    /// The trees on this connection, keyed by share name. Keyed by the
    /// connection by construction: they live inside its entry.
    trees: Mutex<HashMap<String, Tree>>,
    /// When the cache last handed this entry out, which is what the probe and
    /// the sweeper measure idleness from.
    last_used: Mutex<Instant>,
    /// Whether the goodbye has already been said, so that an awaited teardown
    /// and the `Drop` behind it do not both send one.
    released: AtomicBool,
}

impl Cached {
    fn new(session: Session) -> Self {
        Self {
            session,
            trees: Mutex::new(HashMap::new()),
            last_used: Mutex::new(Instant::now()),
            released: AtomicBool::new(false),
        }
    }

    /// How long this entry has been idle, and marks it used.
    ///
    /// The two are one operation deliberately: marking it used *before* the
    /// probe is what stops two tasks reaching for one idle connection from
    /// probing it twice.
    fn take_idle(&self) -> Duration {
        let now = Instant::now();
        let mut last_used = lock(&self.last_used);
        let idle = now.saturating_duration_since(*last_used);
        *last_used = now;
        idle
    }

    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*lock(&self.last_used))
    }

    /// The cached tree for `share`, where there is a healthy one.
    ///
    /// A tree the server has discarded is dropped here rather than handed out:
    /// `STATUS_NETWORK_NAME_DELETED` says that one tree is gone and says
    /// nothing about the connection or about the other trees on it.
    fn tree(&self, share: &str) -> Option<Tree> {
        let mut trees = lock(&self.trees);
        let tree = trees.get(share)?;
        if tree.is_disconnected() {
            debug!(
                share,
                "the server discarded this tree; connecting a fresh one"
            );
            trees.remove(share);
            return None;
        }
        Some(tree.clone())
    }

    /// Puts a freshly connected tree in the cache, or takes the one that
    /// arrived while this one was being connected.
    ///
    /// Two tasks connecting one share at once is not the stampede single-flight
    /// exists to prevent — a tree connect is one round trip, not a dial and a
    /// handshake — so the loser simply drops its own, which disconnects it.
    fn remember(&self, share: &str, tree: Tree) -> Tree {
        let mut trees = lock(&self.trees);
        if let Some(existing) = trees.get(share)
            && !existing.is_disconnected()
        {
            return existing.clone();
        }
        trees.insert(share.to_owned(), tree.clone());
        tree
    }
}

impl Drop for Cached {
    /// The goodbye for a client dropped rather than closed.
    ///
    /// `Drop` can neither await the round trips nor report their failure, so
    /// they are handed to the connection actor best-effort — the same route a
    /// dropped `File` or `Tree` takes, and for the same reason. The trees go
    /// first, so that each `TREE_DISCONNECT` is queued ahead of the logoff.
    fn drop(&mut self) {
        if self.released.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(trees) = self.trees.get_mut() {
            trees.drain();
        }
        let connection = self.session.connection();
        if connection.handles() > 1 {
            // Something still holds this connection, and a logoff would
            // invalidate the handles it holds.
            return;
        }
        connection.enqueue_close(Request::new(
            command::LOGOFF_ANDX,
            LOGOFF_TREE,
            self.session.uid(),
            LogoffAndx::request().encode_body().unwrap_or_default(),
        ));
    }
}

/// A dial in flight, and the outcome every task waiting on it reads.
struct Dial {
    /// `false` until the dial has finished, whichever way it went.
    done: watch::Sender<bool>,
    outcome: Mutex<Option<std::result::Result<Arc<Cached>, Error>>>,
}

impl Dial {
    fn new() -> Arc<Self> {
        let (done, _) = watch::channel(false);
        Arc::new(Self {
            done,
            outcome: Mutex::new(None),
        })
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.done.subscribe()
    }

    fn finish(&self, outcome: std::result::Result<Arc<Cached>, Error>) {
        *lock(&self.outcome) = Some(outcome);
        // Every waiter subscribed before the dial task could reach here, and a
        // `watch` receiver reads the current value rather than waiting for the
        // next change, so there is no wake-up to miss.
        let _ = self.done.send(true);
    }

    /// Waits for the dial and hands back what it produced.
    async fn wait(&self, done: &mut watch::Receiver<bool>) -> Result<Arc<Cached>> {
        while !*done.borrow_and_update() {
            if done.changed().await.is_err() {
                // The dial task cannot end without publishing, so this is only
                // reachable if it was aborted with the runtime under it.
                return Err(Error::ConnectionLost { status: None });
            }
        }
        match &*lock(&self.outcome) {
            Some(Ok(cached)) => Ok(Arc::clone(cached)),
            Some(Err(error)) => Err(duplicate(error)),
            None => Err(Error::ConnectionLost { status: None }),
        }
    }
}

impl Client {
    /// A client that dials TCP.
    ///
    /// Nothing is dialled here: the first connection is made by the first call
    /// that needs one.
    pub fn new(config: ClientConfig) -> Self {
        Self::with_dialer(config, tcp_dialer())
    }

    /// A client that reaches servers through a dialer of the caller's own.
    ///
    /// What a dialer replaces is the stream, not the sequence: the handshake
    /// still runs on what it hands back, and every timing bound, cache and
    /// teardown rule is the same code [`Client::new`] gets.
    pub fn with_dialer(config: ClientConfig, dialer: Dialer) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                config,
                dialer,
                state: Mutex::new(State {
                    connections: HashMap::new(),
                    sweeper: None,
                    closed: false,
                }),
            }),
        }
    }

    /// What this client is configured with.
    pub fn config(&self) -> &ClientConfig {
        &self.inner.config
    }

    /// Connects to a share, dialling the server or reusing the connection
    /// already open to it.
    ///
    /// The path is the only address this API carries: `\\server:port\share`
    /// says where to connect, and the tree connect it produces says
    /// `\\server\share`.
    ///
    /// The `Tree` this hands back is shared with the cache and with every other
    /// caller that asked for the same share, which is why
    /// [`Tree::close`] on it returns `Ok` having sent nothing. The
    /// `TREE_DISCONNECT` goes out when the cache's own entry is evicted or the
    /// client is closed.
    pub async fn tree(&self, path: &UncPath) -> Result<Tree> {
        let cached = self.inner.acquire(path.server()).await?;
        self.inner
            .tree_on(&cached, path.share(), &path.share_path(), SERVICE_ANY)
            .await
    }

    /// Enumerates a server's shares.
    ///
    /// It names no share and needs no [`Tree`]: enumerating is what a caller
    /// does before it has a share to connect to. RAP is tried first and
    /// DCE/RPC `srvsvc` answers where it cannot.
    pub async fn list_shares(&self, server: &Server) -> Result<Vec<Share>> {
        let cached = self.inner.acquire(server).await?;
        let ipc = self
            .inner
            .tree_on(&cached, IPC_SHARE, &server.ipc_path(), SERVICE_IPC)
            .await?;
        let enumeration = Ipc::new(ipc.connection().clone(), ipc.tid(), ipc.inner.uid())
            .list_shares(server)
            .await;
        if matches!(enumeration, Err(Error::TreeDisconnected)) {
            // The `IPC$` tree is gone and the connection is not. Dropping the
            // cache's entry is what the next call re-connects from; the pipe
            // paths reach the wire through `Ipc` rather than through the tree,
            // so this is where that status is read.
            lock(&cached.trees).remove(IPC_SHARE);
        }
        enumeration
    }

    /// Releases everything the cache holds, reporting whether the servers were
    /// told.
    ///
    /// It drops every reference the cache holds — connections, sessions and
    /// trees alike. A connection whose last handle goes with it closes there
    /// and then; one a live handle still holds closes when that handle drops,
    /// which is what makes shutdown deterministic without invalidating handles
    /// a caller still owns.
    ///
    /// **The goodbye is awaited rather than raced against the socket close** —
    /// a `TREE_DISCONNECT` per tree and a `LOGOFF_ANDX` for the session —
    /// because reporting that release is the whole reason this is fallible. On
    /// failure the socket closes regardless and the first error is returned.
    pub async fn close(self) -> Result<()> {
        let (entries, sweeper) = {
            let mut state = lock(&self.inner.state);
            state.closed = true;
            let entries: Vec<Arc<Cached>> = state
                .connections
                .drain()
                .filter_map(|(_, slot)| match slot {
                    Slot::Ready(cached) => Some(cached),
                    // A dial still in flight runs to completion and finds the
                    // client closed; there is nothing here to say goodbye to.
                    Slot::Dialing(_) => None,
                })
                .collect();
            (entries, state.sweeper.take())
        };
        if let Some(sweeper) = sweeper {
            sweeper.abort();
        }

        let mut failure = None;
        for cached in entries {
            if let Err(error) = goodbye(&cached).await {
                warn!("releasing a connection failed: {error}");
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        f.debug_struct("Client")
            .field("config", &self.inner.config)
            .field("connections", &state.connections.len())
            .finish()
    }
}

impl ClientInner {
    /// The connection for one server: cached, probed, or dialled.
    async fn acquire(self: &Arc<Self>, server: &Server) -> Result<Arc<Cached>> {
        let key = server.cache_key();
        loop {
            match self.slot(&key, server) {
                Held::Ready(cached, idle) => {
                    // Two routes to a connection that is dead where it stands.
                    // The actor having terminated is visible without asking;
                    // a socket dropped with no FIN is not, and one overall
                    // deadline of idleness is what makes it worth a round trip
                    // to find out.
                    if cached.session.connection().is_closed() {
                        debug!(key, "the cached connection had ended; re-dialling");
                        self.forget(&key, &cached);
                        continue;
                    }
                    if idle >= self.probe_after()
                        && let Err(error) = probe(&cached).await
                    {
                        debug!(key, "the idle probe failed, re-dialling: {error}");
                        self.forget(&key, &cached);
                        continue;
                    }
                    return Ok(cached);
                }
                Held::Waiting(dial, mut done) => return dial.wait(&mut done).await,
            };
        }
    }

    /// Reads the cache for one key, starting a dial where it is cold.
    ///
    /// It is its own function so that nothing awaits while the cache is locked.
    fn slot(self: &Arc<Self>, key: &str, server: &Server) -> Held {
        let mut state = lock(&self.state);
        match state.connections.get(key) {
            Some(Slot::Ready(cached)) => {
                let cached = Arc::clone(cached);
                let idle = cached.take_idle();
                Held::Ready(cached, idle)
            }
            // The whole of single-flight: a dial in flight is a cache entry, so
            // the tasks that meet it wait on that dial instead of starting one.
            Some(Slot::Dialing(dial)) => Held::Waiting(Arc::clone(dial), dial.subscribe()),
            None => {
                let dial = Dial::new();
                state
                    .connections
                    .insert(key.to_owned(), Slot::Dialing(Arc::clone(&dial)));
                self.ensure_sweeper(&mut state);
                // Subscribed before the dial is started, so that a dial always
                // has its waiter from the first instant of its life.
                let done = dial.subscribe();
                self.spawn_dial(key.to_owned(), server.clone(), Arc::clone(&dial));
                Held::Waiting(dial, done)
            }
        }
    }

    /// Runs one dial to completion on a task of its own.
    ///
    /// **A task rather than the caller's own future, deliberately.** A dial in
    /// flight runs to completion when its last waiter drops rather than being
    /// cancelled with them: the dial is expensive, another caller is likely,
    /// and a connection dialled with nobody left to want it is exactly what the
    /// cache exists to hold — it is cached like any other and evicted like any
    /// other if nobody does come back.
    fn spawn_dial(self: &Arc<Self>, key: String, server: Server, dial: Arc<Dial>) {
        let inner = Arc::clone(self);
        tokio::spawn(async move {
            let outcome = match inner.dial(&server).await {
                Ok(session) => {
                    let cached = Arc::new(Cached::new(session));
                    let mut state = lock(&inner.state);
                    if state.closed {
                        debug!(key, "the client closed while this dial was in flight");
                    } else {
                        state
                            .connections
                            .insert(key, Slot::Ready(Arc::clone(&cached)));
                    }
                    Ok(cached)
                }
                Err(error) => {
                    // A dial that fails is not cached, so the next call meets a
                    // cold cache and dials afresh.
                    let mut state = lock(&inner.state);
                    if let Some(Slot::Dialing(current)) = state.connections.get(&key)
                        && Arc::ptr_eq(current, &dial)
                    {
                        state.connections.remove(&key);
                    }
                    Err(error)
                }
            };
            dial.finish(outcome);
        });
    }

    /// One dial and the handshake on it, under the connect timeout.
    async fn dial(&self, server: &Server) -> Result<Session> {
        let options = self.config.session_options();
        let dialing = (self.dialer)(server.clone());
        let handshake = async {
            let stream = dialing.await?;
            Session::establish(stream, &self.config.credentials, &options).await
        };
        let session = tokio::time::timeout(self.config.connect_timeout, handshake)
            .await
            .map_err(|_| Error::ConnectTimeout)??;
        debug!(server = %server, "dialled and authenticated");
        Ok(session)
    }

    /// The tree for one share on a connection: cached, or connected and cached.
    async fn tree_on(
        &self,
        cached: &Arc<Cached>,
        share: &str,
        share_path: &str,
        service: &str,
    ) -> Result<Tree> {
        if let Some(tree) = cached.tree(share) {
            return Ok(tree);
        }
        let tree = Tree::connect(cached.session.clone(), share_path, service).await?;
        tree.set_read_ahead(self.config.read_ahead);
        Ok(cached.remember(share, tree))
    }

    /// Drops the cache's reference to one entry, where it is still that entry.
    ///
    /// A connection torn down because it failed says no goodbye: there is
    /// nothing left to send it over, and TCP teardown releases everything the
    /// server holds anyway.
    fn forget(&self, key: &str, cached: &Arc<Cached>) {
        let mut state = lock(&self.state);
        if let Some(Slot::Ready(current)) = state.connections.get(key)
            && Arc::ptr_eq(current, cached)
        {
            state.connections.remove(key);
        }
    }

    /// Starts the eviction sweeper if it is not already running.
    ///
    /// **Eviction needs a component of its own.** A connection nobody comes
    /// back to is by construction never reached by a check performed on access,
    /// so a lazy sweep at cache lookup would leave exactly the entries eviction
    /// exists for untouched.
    fn ensure_sweeper(self: &Arc<Self>, state: &mut MutexGuard<'_, State>) {
        if state.sweeper.is_some() || state.closed {
            return;
        }
        let inner = Arc::downgrade(self);
        let every = self.evict_after() / SWEEPS_PER_EVICTION_WINDOW;
        let after = self.evict_after();
        state.sweeper = Some(tokio::spawn(sweep(inner, every, after)));
    }

    fn probe_after(&self) -> Duration {
        self.config.overall_deadline * PROBE_AFTER_DEADLINES
    }

    fn evict_after(&self) -> Duration {
        self.config.overall_deadline * EVICT_AFTER_DEADLINES
    }
}

impl Drop for ClientInner {
    /// Ends the sweeper with the client, for a client dropped rather than
    /// closed.
    ///
    /// Aborting a task neither spawns one nor needs a runtime to be running, so
    /// the guarantee that dropping a handle does neither is untouched.
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut()
            && let Some(sweeper) = state.sweeper.take()
        {
            sweeper.abort();
        }
    }
}

/// What the cache had for one key.
enum Held {
    /// A connection, and how long it had been idle.
    Ready(Arc<Cached>, Duration),
    /// A dial to wait on, whether this task started it or found it, and the
    /// subscription it waits on.
    Waiting(Arc<Dial>, watch::Receiver<bool>),
}

/// The eviction sweeper: one task per client, ending with it.
///
/// It wakes every quarter of the eviction window — five overall deadlines,
/// twenty-five minutes at the defaults — and drops the cache's reference to
/// every entry idle past twenty deadlines. Evicting is what releases that
/// reference; a handle still holding the connection keeps it alive regardless,
/// and the connection closes when that handle drops.
async fn sweep(client: Weak<ClientInner>, every: Duration, after: Duration) {
    loop {
        tokio::time::sleep(every).await;
        // Upgrading after the sleep rather than holding a reference across it
        // is what ends this task with a client that was dropped rather than
        // closed.
        let Some(client) = client.upgrade() else {
            return;
        };
        let evicted = {
            let mut state = lock(&client.state);
            if state.closed {
                return;
            }
            let now = Instant::now();
            let stale: Vec<String> = state
                .connections
                .iter()
                .filter_map(|(key, slot)| match slot {
                    Slot::Ready(cached) if cached.idle_for(now) >= after => Some(key.clone()),
                    _ => None,
                })
                .collect();
            stale
                .into_iter()
                .filter_map(|key| match state.connections.remove(&key) {
                    Some(Slot::Ready(cached)) => Some(cached),
                    other => {
                        // Nothing else can be here: the key was Ready a moment
                        // ago under this same lock.
                        debug_assert!(other.is_none());
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        for cached in evicted {
            debug!("evicting a connection idle past the eviction window");
            if let Err(error) = goodbye(&cached).await {
                debug!("an evicted connection was not released cleanly: {error}");
            }
        }
    }
}

/// What a deliberate teardown says before the socket closes.
///
/// A `TREE_DISCONNECT` for each tree the cache holds, then `LOGOFF_ANDX` for
/// the session — and the second only where nothing else holds the connection.
/// A logoff sent while a caller still owns a handle would invalidate it, which
/// is exactly what the teardown rule forbids: a tree another owner holds
/// disconnects when that owner drops it, and the session goes with it.
async fn goodbye(cached: &Arc<Cached>) -> Result<()> {
    cached.released.store(true, Ordering::Relaxed);
    let trees: Vec<Tree> = lock(&cached.trees).drain().map(|(_, tree)| tree).collect();
    let mut failure = None;
    for tree in trees {
        if let Err(error) = tree.close().await {
            failure.get_or_insert(error);
        }
    }

    let connection = cached.session.connection();
    if connection.handles() > 1 {
        debug!("a handle still holds this connection; it closes when that handle drops");
        return match failure {
            Some(error) => Err(error),
            None => Ok(()),
        };
    }

    let logoff = async {
        let reply = connection
            .request(Request::new(
                command::LOGOFF_ANDX,
                LOGOFF_TREE,
                cached.session.uid(),
                LogoffAndx::request().encode_body()?,
            ))
            .await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        Ok(())
    };
    if let Err(error) = logoff.await {
        failure.get_or_insert(error);
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// One `SMB_COM_ECHO`, and whether the server answered it.
///
/// **What the probe closes is the silent TCP drop, and only that.**
/// `SMB_COM_ECHO` is neither session- nor tree-scoped on most implementations,
/// so it answers perfectly well on a connection whose session the server has
/// discarded; that route is caught by `STATUS_USER_SESSION_DELETED` on the next
/// real request, where it always was.
async fn probe(cached: &Cached) -> Result<()> {
    let reply = cached
        .session
        .connection()
        .request(Request::new(
            command::ECHO,
            NO_TREE,
            NO_SESSION,
            EchoRequest::probe().encode_body()?,
        ))
        .await?;
    if reply.status() != NtStatus::SUCCESS {
        return Err(Error::refused(reply.status()));
    }
    Ok(())
}

/// The dialer [`Client::new`] uses: TCP, and nothing else.
fn tcp_dialer() -> Dialer {
    Arc::new(|server: Server| {
        Box::pin(async move {
            let (host, port) = server.dial_address();
            let stream = TcpStream::connect((host, port)).await?;
            Ok(Box::new(stream) as Box<dyn Stream>)
        })
    })
}

/// The error a task that *waited* on somebody else's dial is given.
///
/// [`Error`] is not `Clone` — an `io::Error` and a boxed decoder failure are
/// not — and one dial has one failure to report to however many tasks were
/// waiting on it. Every variant a dial can produce is rebuilt exactly; anything
/// else keeps its classification and its message, which is what
/// [`Error::kind`] and the formatted output are read for.
fn duplicate(error: &Error) -> Error {
    match error {
        Error::ConnectTimeout => Error::ConnectTimeout,
        Error::GuestLogon => Error::GuestLogon,
        Error::SigningRequired => Error::SigningRequired,
        Error::UnsupportedServer(message) => Error::UnsupportedServer(message.clone()),
        Error::InvalidPath(message) => Error::InvalidPath(message.clone()),
        Error::Status(status) => Error::Status(*status),
        Error::ConnectionLost { status } => Error::ConnectionLost { status: *status },
        Error::TreeDisconnected => Error::TreeDisconnected,
        Error::RequestTimeout => Error::RequestTimeout,
        other => Error::Io(io::Error::new(other.kind(), other.to_string())),
    }
}

/// A lock on cache state, which nothing awaits under.
///
/// A poisoned mutex here would mean a panic inside one of those short critical
/// sections, none of which can fail: taking the guard back is better than
/// propagating a panic into every later call.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
