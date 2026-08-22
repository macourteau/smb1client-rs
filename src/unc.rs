//! UNC paths, and the policy every share-relative path is held to.
//!
//! Three types carry it. [`Server`] is a host and the port to dial it on;
//! [`UncPath`] is that server and a share; and [`SharePath`] is a path inside a
//! share, normalized and checked. Each is validated on construction *and* on
//! parsing, by the same code — a parser that accepts what its constructor
//! refuses is the defect this module exists to avoid.
//!
//! **A path carries a port for dialling and never carries one on the wire.**
//! `\\127.0.0.1:10445\testshare` says where to connect; the tree connect it
//! produces says `\\127.0.0.1\testshare`. Every UNC string that reaches the
//! wire is built from the host alone by [`Server::unc_name`], so the share
//! path, the `IPC$` path and the `ServerName` an srvsvc call carries cannot
//! drift apart: building one of them with the port produces `\\host:445\IPC$`,
//! which Windows refuses with `STATUS_DUPLICATE_NAME`.
//!
//! The host reaches the wire in the case the caller wrote it. Lowercasing
//! belongs to [`Server::cache_key`] and to nothing else; no request carries
//! that key.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// The port an SMB1 server is dialled on unless a path names another.
pub const DEFAULT_PORT: u16 = 445;

/// The share share enumeration connects to.
const IPC_SHARE: &str = "IPC$";

/// The server half of a UNC path: a host, and the port to dial it on.
///
/// This is what `Client::list_shares` takes, enumerating being what a caller
/// does before it has a share to connect to. It is deliberately not [`Hash`]:
/// two spellings of one host are one server to the connection cache and two
/// distinct values here, so a cache keyed on this type directly would key on
/// the case the caller happened to write. [`Server::cache_key`] is what a cache
/// keys on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    host: String,
    port: u16,
}

impl Server {
    /// A server from a host and the port to dial it on.
    ///
    /// The host is a hostname or an IPv4 literal. An IPv6 literal is refused:
    /// SMB1's UNC syntax has no form for one, so reaching such a server means
    /// naming it by a hostname that resolves to it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] if the host is empty, carries a null byte, a path
    /// separator or whitespace, or is an IPv6 literal, or if the port is zero.
    pub fn new(host: &str, port: u16) -> Result<Self> {
        validate_host(host)?;
        if port == 0 {
            return Err(Error::InvalidPath("port 0 cannot be dialled".to_owned()));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The host, exactly as the caller wrote it.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port to dial, which is [`DEFAULT_PORT`] unless the caller named
    /// another.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Where to dial, in the form `tokio::net::TcpStream::connect` takes.
    pub fn dial_address(&self) -> (&str, u16) {
        (&self.host, self.port)
    }

    /// What a connection cache keys on: the dial address, with the host
    /// lowercased.
    ///
    /// Host *and* port, because two paths naming different ports on one host
    /// are two servers. The host half is the literal string the caller wrote
    /// rather than the address it resolves to, so two spellings of one server
    /// are two entries — resolving first would make the cache's identity depend
    /// on DNS state at the moment of the lookup. Lowercasing is the one
    /// normalisation, hostnames being case-insensitive, and it belongs to the
    /// key alone.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.host.to_lowercase(), self.port)
    }

    /// The server-name component as it goes on the wire: `\\host`, built from
    /// the host alone.
    ///
    /// Never the dial address. This is the one place a server's wire name is
    /// built, which is what keeps the share path, the `IPC$` path and the
    /// `ServerName` an srvsvc call carries from disagreeing about the port.
    pub fn unc_name(&self) -> String {
        format!(r"\\{}", self.host)
    }

    /// The UNC path of this server's `IPC$` share, which share enumeration
    /// connects to.
    pub fn ipc_path(&self) -> String {
        self.unc_to(IPC_SHARE)
    }

    /// The UNC path of one share on this server.
    fn unc_to(&self, share: &str) -> String {
        format!(r"{}\{}", self.unc_name(), share)
    }
}

impl FromStr for Server {
    type Err = Error;

    /// Parses `host` or `host:port`.
    ///
    /// The bracketed form an IPv6 literal requires is recognised here precisely
    /// so that such a literal is handed to [`Server::new`] whole and refused as
    /// what it is, rather than split on its last colon into a mangled host and
    /// port.
    fn from_str(server: &str) -> Result<Self> {
        if server.starts_with('[') || server.contains(']') {
            return Server::new(server, DEFAULT_PORT);
        }
        match server.rsplit_once(':') {
            // A colon left in the host half means the whole string is an
            // address, not a host and a port.
            Some((host, _)) if host.contains(':') => Server::new(server, DEFAULT_PORT),
            Some((host, port)) => {
                let port = port.parse().map_err(|_| {
                    Error::InvalidPath(format!("{port:?} is not a port to dial on"))
                })?;
                Server::new(host, port)
            }
            None => Server::new(server, DEFAULT_PORT),
        }
    }
}

impl fmt::Display for Server {
    /// The form [`Server::from_str`] parses back to the same value. The port
    /// appears only where it is not the default, that being the only case a
    /// caller has to write.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == DEFAULT_PORT {
            f.write_str(&self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// A UNC path naming a server and a share: `\\server\share`.
///
/// This is what `Client::tree` takes, and the only address anything in this
/// API carries — which is why the server component may name a port, for a
/// server not listening on [`DEFAULT_PORT`].
///
/// ```
/// use smb1client::UncPath;
///
/// let path: UncPath = r"\\127.0.0.1:10445\testshare".parse()?;
/// assert_eq!(path.server().dial_address(), ("127.0.0.1", 10445));
/// assert_eq!(path.share_path(), r"\\127.0.0.1\testshare");
/// # Ok::<(), smb1client::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncPath {
    server: Server,
    share: String,
}

impl UncPath {
    /// A UNC path from a server and a share name.
    ///
    /// The share name is carried verbatim: spaces are valid in one and no
    /// escaping or quoting is applied, because none belongs on the wire.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] if the share name is empty, carries a null byte,
    /// or carries a path separator — a share name is one component, and a path
    /// inside the share is a [`SharePath`] the verbs take separately.
    pub fn new(server: Server, share: &str) -> Result<Self> {
        validate_share(share)?;
        Ok(Self {
            server,
            share: share.to_owned(),
        })
    }

    /// The server this path names.
    pub fn server(&self) -> &Server {
        &self.server
    }

    /// The share this path names, verbatim.
    pub fn share(&self) -> &str {
        &self.share
    }

    /// The path the tree connect carries: `\\host\share`, with no port.
    pub fn share_path(&self) -> String {
        self.server.unc_to(&self.share)
    }
}

impl FromStr for UncPath {
    type Err = Error;

    /// Parses `\\server\share`, where `server` is `host` or `host:port`.
    ///
    /// One trailing separator after the share is accepted, that being the form
    /// Windows displays; anything after it names something *inside* the share
    /// and is refused, rather than silently dropped.
    fn from_str(path: &str) -> Result<Self> {
        let rest = path.strip_prefix(r"\\").ok_or_else(|| {
            Error::InvalidPath(format!(
                r"{path:?} does not begin with \\, as a UNC path does"
            ))
        })?;
        let (server, share) = rest.split_once('\\').ok_or_else(|| {
            Error::InvalidPath(format!(
                r"{path:?} names no share; the form is \\server\share"
            ))
        })?;
        let share = share.strip_suffix('\\').unwrap_or(share);
        UncPath::new(server.parse()?, share)
    }
}

impl fmt::Display for UncPath {
    /// The form [`UncPath::from_str`] parses back to the same value, port and
    /// all.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r"\\{}\{}", self.server, self.share)
    }
}

/// A path inside a share, normalized and checked.
///
/// Every path a `Tree` verb takes becomes one of these before it reaches the
/// wire, and what [`SharePath::as_str`] hands back is the form the request
/// carries — with one exception, `SMB_COM_RENAME`, which puts a leading
/// backslash in front of each of its two names on the wire and so writes
/// `format!(r"\{}", path.as_str())`. That is the rename encoder's business, and
/// nothing normalizes a path a second time to reach it.
///
/// **Normalization does two things and nothing else**: it rewrites `/` to `\`,
/// so that a caller writing `dir/file.txt` is not made to know what the wire
/// wants, and it trims Unicode whitespace — not just ASCII spaces — from both
/// ends. Both are unconditional, because a path policy a caller can turn off is
/// one no caller can rely on.
///
/// ```
/// use smb1client::SharePath;
///
/// assert_eq!(SharePath::new("dir/file.txt")?.as_str(), r"dir\file.txt");
/// // `.` and `..` are resolved to decide whether the path escapes the share,
/// // and are left alone otherwise.
/// assert_eq!(SharePath::new(r"a\..\b.txt")?.as_str(), r"a\..\b.txt");
/// assert!(SharePath::new(r"..\..\etc\passwd").is_err());
/// # Ok::<(), smb1client::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePath(String);

impl SharePath {
    /// Normalizes a caller's path and holds it to the policy.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPath`] on the three refusals. An **absolute** path,
    /// since a path is relative to the share root and there is nothing for a
    /// leading separator to mean. A path carrying a **null byte**, which can
    /// only be a truncation waiting to happen in whatever reads it at the other
    /// end. And a path that **escapes the share root**, so that a caller
    /// joining a user-supplied name onto a prefix cannot reach outside the
    /// share it connected to.
    pub fn new(path: &str) -> Result<Self> {
        // The two rewrites are independent — `/` is not whitespace and no
        // whitespace character is `/` — so neither can create or destroy work
        // for the other and the order they apply in is immaterial.
        let normalized = path.trim().replace('/', r"\");
        if normalized.contains('\0') {
            return Err(Error::InvalidPath(format!(
                "{normalized:?} carries a null byte"
            )));
        }
        if normalized.starts_with('\\') {
            return Err(Error::InvalidPath(format!(
                "{normalized:?} is absolute; a path is relative to the share root"
            )));
        }
        if escapes_share_root(&normalized) {
            return Err(Error::InvalidPath(format!(
                "{normalized:?} escapes the share root"
            )));
        }
        Ok(Self(normalized))
    }

    /// The normalized path, which is the form the request carries.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the path and yields the normalized string that goes on the
    /// wire. Offered beside [`SharePath::as_str`] so a caller building a
    /// request does not clone what it is about to own.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Whether this is the share root, which is the empty path.
    ///
    /// A listing distinguishes the two: the pattern for a path inside the share
    /// is the path, a separator and an asterisk, and for the root it is `\*`
    /// with the leading backslash.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for SharePath {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self> {
        SharePath::new(path)
    }
}

impl AsRef<str> for SharePath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SharePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether resolving `.` and `..` reaches above the share root at any point.
///
/// The verdict is reached by walking the components and tracking depth, so an
/// escape cannot be evaded by spelling it differently. Resolving them is *all*
/// this does with them: the path that goes on the wire is the normalized one
/// the caller gave, components and all.
///
/// A path that leaves the share and returns escapes: the check answers on the
/// depth at every step rather than at the end, because `a\..\..\b` ends one
/// level inside a share it has already left.
fn escapes_share_root(path: &str) -> bool {
    let mut depth = 0usize;
    for component in path.split('\\') {
        match component {
            // An empty component comes from a doubled or trailing separator and
            // names nothing, so it adds no depth for a later `..` to spend.
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(shallower) => depth = shallower,
                None => return true,
            },
            _ => depth += 1,
        }
    }
    false
}

/// The refusal an IPv6 literal earns, in the one place it is worded.
///
/// Microsoft's workaround for SMB1's UNC syntax having no IPv6 form is a
/// separate `ipv6-literal.net` name transform, which this crate does not
/// implement, so the honest answer is that the address cannot be named here.
fn no_ipv6_literal(host: &str) -> Error {
    Error::InvalidPath(format!(
        "{host:?} is an IPv6 address, and SMB1's UNC syntax has no form for an IPv6 \
         literal; reach that server by a hostname that resolves to it"
    ))
}

/// Holds a host to what may go on the wire as one.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::InvalidPath("names no server".to_owned()));
    }
    // Brackets belong to the IPv6 literal form and to nothing else, and a colon
    // survives here only because the parser recognised one rather than reading
    // it as a port.
    if host.contains('[') || host.contains(']') || host.contains(':') {
        return Err(no_ipv6_literal(host));
    }
    if let Some(bad) = host
        .chars()
        .find(|ch| *ch == '\\' || *ch == '/' || ch.is_whitespace() || ch.is_control())
    {
        return Err(Error::InvalidPath(format!(
            "{host:?} is not a host: {bad:?} cannot appear in one"
        )));
    }
    Ok(())
}

/// Holds a share name to what may go on the wire as one.
fn validate_share(share: &str) -> Result<()> {
    if share.is_empty() {
        return Err(Error::InvalidPath("names no share".to_owned()));
    }
    if share.contains('\0') {
        return Err(Error::InvalidPath(format!("{share:?} carries a null byte")));
    }
    if share.contains('\\') || share.contains('/') {
        return Err(Error::InvalidPath(format!(
            "{share:?} is not a share name: a share name is one component, and a path inside the share is given separately"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way of spelling one server that the module accepts.
    fn server(spelling: &str) -> Server {
        spelling.parse().expect("a valid server")
    }

    fn path(spelling: &str) -> UncPath {
        spelling.parse().expect("a valid UNC path")
    }

    fn share_path(spelling: &str) -> SharePath {
        SharePath::new(spelling).expect("a valid share-relative path")
    }

    /// The port says where to dial and appears in no UNC string built from it.
    #[test]
    fn a_path_naming_a_port_dials_it_and_never_carries_it_on_the_wire() {
        let path = path(r"\\127.0.0.1:10445\testshare");
        assert_eq!(path.server().dial_address(), ("127.0.0.1", 10445));
        assert_eq!(path.server().port(), 10445);
        assert_eq!(path.share_path(), r"\\127.0.0.1\testshare");
        assert_eq!(path.server().unc_name(), r"\\127.0.0.1");
    }

    /// The reference builds share paths without the port and the `IPC$` path
    /// with it, producing `\\host:445\IPC$` — which Windows refuses with
    /// `STATUS_DUPLICATE_NAME`, so share enumeration fails against it for that
    /// reason alone. Every UNC string here comes from the host.
    #[test]
    fn the_ipc_path_carries_no_port_however_the_server_was_reached() {
        for spelling in ["host", "host:445", "host:10445"] {
            assert_eq!(server(spelling).ipc_path(), r"\\host\IPC$");
            assert_eq!(server(spelling).unc_name(), r"\\host");
        }
        assert_eq!(
            path(r"\\host:10445\share").share_path(),
            path(r"\\host\share").share_path()
        );
    }

    /// Lowercasing normalises the cache key and nothing else; no request
    /// carries that key.
    #[test]
    fn the_host_reaches_the_wire_in_the_case_the_caller_wrote() {
        let path = path(r"\\MixedCase.Example\ShareName");
        assert_eq!(path.share_path(), r"\\MixedCase.Example\ShareName");
        assert_eq!(path.server().unc_name(), r"\\MixedCase.Example");
        assert_eq!(path.server().ipc_path(), r"\\MixedCase.Example\IPC$");
        assert_eq!(path.server().host(), "MixedCase.Example");
    }

    /// Two spellings of one host are one connection; two ports on one host are
    /// two servers, which is the shape of the acceptance container.
    #[test]
    fn the_cache_key_folds_case_and_the_default_port_but_not_two_ports() {
        assert_eq!(server("HOST").cache_key(), server("host").cache_key());
        assert_eq!(server("host:445").cache_key(), server("host").cache_key());
        assert_ne!(server("host:10445").cache_key(), server("host").cache_key());
        assert_ne!(server("host").cache_key(), server("other").cache_key());
    }

    /// smb-rs's defect is that its `FromStr` bypasses even the checks its own
    /// constructor performs, so `\\\\` parses as an empty server and an empty
    /// share. Here one refuses exactly what the other does, because parsing
    /// ends in the constructor.
    #[test]
    fn the_constructor_and_the_parser_refuse_the_same_things() {
        for (host, share) in [
            ("", "share"),
            ("host", ""),
            ("", ""),
            ("2001:db8::1", "share"),
            ("[2001:db8::1]", "share"),
            ("host", "sha\0re"),
            ("host", r"share\dir"),
            ("host", "share/dir"),
            (r"host\evil", "share"),
            ("host/evil", "share"),
            ("ho st", "share"),
            ("host\0", "share"),
        ] {
            let constructed = Server::new(host, DEFAULT_PORT)
                .and_then(|server| UncPath::new(server, share))
                .err();
            let parsed = format!(r"\\{host}\{share}").parse::<UncPath>().err();
            assert!(
                constructed.is_some(),
                "the constructor accepted {host:?} and {share:?}"
            );
            assert!(
                parsed.is_some(),
                "the parser accepted {host:?} and {share:?}"
            );
        }
    }

    /// The empty server and the empty share smb-rs accepts, in every spelling
    /// that reaches them.
    #[test]
    fn an_empty_server_or_share_is_refused_however_it_is_spelled() {
        for spelling in [
            r"\\\\",
            r"\\\share",
            r"\\host\",
            r"\\host",
            r"\\",
            r"\",
            "",
            "host",
        ] {
            assert!(
                spelling.parse::<UncPath>().is_err(),
                "{spelling:?} was accepted"
            );
        }
    }

    /// The bracketed form is parsed in order to be *recognised*: split on the
    /// last colon it would become a host of `[2001:db8::1]` and a port of 445,
    /// and reach the wire mangled.
    #[test]
    fn an_ipv6_literal_is_refused_as_one_rather_than_split_into_a_host_and_a_port() {
        for spelling in [
            "[2001:db8::1]:445",
            "[2001:db8::1]",
            "2001:db8::1",
            "::1",
            "[::1]:10445",
            "fe80::1%eth0",
        ] {
            let Err(error) = spelling.parse::<Server>() else {
                panic!("{spelling:?} was accepted");
            };
            let message = error.to_string();
            assert!(
                message.contains("IPv6"),
                "{spelling:?} was refused for the wrong reason: {message}"
            );
            assert!(
                format!(r"\\{spelling}\share")
                    .parse::<UncPath>()
                    .is_err_and(|error| error.to_string().contains("IPv6")),
                "{spelling:?} was accepted or misdiagnosed inside a UNC path"
            );
        }
    }

    /// A host with a port is still a host with a port; the IPv6 recognition
    /// does not swallow the ordinary case.
    #[test]
    fn a_single_colon_is_a_port_and_not_an_address() {
        assert_eq!(server("host:10445").port(), 10445);
        assert_eq!(server("host:10445").host(), "host");
        assert_eq!(server("host").port(), DEFAULT_PORT);
        assert_eq!(server("127.0.0.1").host(), "127.0.0.1");
    }

    /// A port that cannot be dialled is refused rather than defaulted.
    #[test]
    fn a_port_that_cannot_be_dialled_is_refused() {
        for spelling in [
            "host:0",
            "host:70000",
            "host:abc",
            "host:",
            "host:-1",
            ":445",
        ] {
            assert!(
                spelling.parse::<Server>().is_err(),
                "{spelling:?} was accepted"
            );
        }
        assert!(Server::new("host", 0).is_err());
    }

    /// Share names containing spaces are valid and are carried verbatim; no
    /// escaping or quoting is applied, because none belongs on the wire.
    #[test]
    fn a_share_name_with_spaces_is_carried_verbatim() {
        let path = path(r"\\host\My Share ");
        assert_eq!(path.share(), "My Share ");
        assert_eq!(path.share_path(), r"\\host\My Share ");
    }

    /// One trailing separator is the form Windows displays; a path after it
    /// names something inside the share and is refused rather than dropped.
    #[test]
    fn a_trailing_separator_is_the_share_and_anything_after_it_is_not() {
        assert_eq!(path(r"\\host\share\"), path(r"\\host\share"));
        assert!(r"\\host\share\dir".parse::<UncPath>().is_err());
        assert!(r"\\host\share\\".parse::<UncPath>().is_err());
    }

    /// Display is the form the parser reads back, which is what makes a path
    /// safe to log and re-parse.
    #[test]
    fn a_path_round_trips_through_its_display_form() {
        for spelling in [
            r"\\host\share",
            r"\\host:10445\share",
            r"\\127.0.0.1:10445\testshare",
            r"\\MixedCase\My Share",
        ] {
            let path = path(spelling);
            assert_eq!(path.to_string().parse::<UncPath>().unwrap(), path);
        }
        // The default port is what a caller need not write, so it is not
        // written back out.
        assert_eq!(path(r"\\host:445\share").to_string(), r"\\host\share");
    }

    /// The separator rewrite is unconditional: the reference puts it behind a
    /// flag, and a path policy a caller can turn off is one no caller can rely
    /// on.
    #[test]
    fn a_forward_slash_becomes_a_backslash() {
        assert_eq!(share_path("dir/file.txt").as_str(), r"dir\file.txt");
        assert_eq!(share_path("a/b/c/d.txt").as_str(), r"a\b\c\d.txt");
        assert_eq!(share_path(r"a\b/c").as_str(), r"a\b\c");
    }

    /// Unicode whitespace, not just ASCII spaces: a legacy server can hold a
    /// name with a non-breaking space in it.
    #[test]
    fn unicode_whitespace_is_trimmed_from_both_ends() {
        assert_eq!(
            share_path("\u{a0} dir/file.txt \u{2003}\t\n").as_str(),
            r"dir\file.txt"
        );
        assert_eq!(
            share_path("\u{3000}a.txt\u{feff}\u{a0}").as_str(),
            "a.txt\u{feff}"
        );
    }

    /// Trimming both ends must not reach inside: a name that legitimately
    /// carries a non-breaking space keeps it.
    #[test]
    fn an_interior_non_breaking_space_survives_the_trim() {
        assert_eq!(share_path("a\u{a0}b.txt").as_str(), "a\u{a0}b.txt");
        assert_eq!(share_path("  a\u{a0}b.txt  ").as_str(), "a\u{a0}b.txt");
        assert_eq!(
            share_path("dir/a\u{a0}b\u{a0}c.txt").as_str(),
            "dir\\a\u{a0}b\u{a0}c.txt"
        );
    }

    /// A path is relative to the share root, and there is nothing for a leading
    /// separator to mean. The check runs on the normalized form, so a leading
    /// forward slash and a leading separator behind whitespace are refused too.
    #[test]
    fn an_absolute_path_is_refused() {
        for spelling in [
            r"\a",
            "/a",
            r"\",
            "/",
            r"  \a  ",
            r"\\host\share\file.txt",
            "\u{a0}/a",
        ] {
            assert!(
                SharePath::new(spelling).is_err(),
                "{spelling:?} was accepted"
            );
        }
    }

    /// A null byte can only be a truncation waiting to happen in whatever reads
    /// the path at the other end.
    #[test]
    fn a_null_byte_anywhere_is_refused() {
        for spelling in ["a\0b", "\0", "a.txt\0", "dir/\0/b", " a\0 "] {
            assert!(
                SharePath::new(spelling).is_err(),
                "{spelling:?} was accepted"
            );
        }
    }

    /// `..\..\etc\passwd` is refused here rather than sent for the server to
    /// have an opinion about, and it cannot be evaded by spelling it
    /// differently.
    #[test]
    fn a_path_that_escapes_the_share_root_is_refused() {
        for spelling in [
            r"..\..\etc\passwd",
            "..",
            r"..\",
            r".\..",
            r"a\..\..",
            "../../etc/passwd",
            r"a\b\..\..\..",
            r"..\a",
            r".\.\..\a",
        ] {
            assert!(
                SharePath::new(spelling).is_err(),
                "{spelling:?} was accepted"
            );
        }
    }

    /// The depth is answered at every step and not at the end: this path ends
    /// one level *inside* a share it has already left, so an implementation
    /// checking only the final depth accepts it.
    #[test]
    fn a_path_that_escapes_and_returns_is_refused() {
        for spelling in [r"a\..\..\b", r"a\b\..\..\..\c\d", r"..\a\b"] {
            assert!(
                SharePath::new(spelling).is_err(),
                "{spelling:?} was accepted: the check answers on the final depth"
            );
        }
    }

    /// An empty component names nothing, so it adds no depth for a later `..`
    /// to spend — counting one would make a doubled separator a way to buy a
    /// level and escape.
    #[test]
    fn an_empty_component_buys_no_depth() {
        assert!(SharePath::new(r"a\\..\..\b").is_err());
        assert!(SharePath::new(r"a\\\..\..").is_err());
        assert!(SharePath::new(r"a\\\..\..\..\b").is_err());
    }

    /// The check resolves `.` and `..` to reach its verdict, and resolving them
    /// is all it does with them: the port does not rewrite a path it has
    /// decided is safe.
    #[test]
    fn a_dotdot_that_stays_inside_the_share_is_sent_as_written() {
        assert_eq!(share_path(r"a\..\b.txt").as_str(), r"a\..\b.txt");
        assert_eq!(share_path("a/../b.txt").as_str(), r"a\..\b.txt");
        assert_eq!(share_path(r".\a.txt").as_str(), r".\a.txt");
        assert_eq!(share_path(r"a\b\..\c").as_str(), r"a\b\..\c");
        assert_eq!(share_path("a/./b/../../c").as_str(), r"a\.\b\..\..\c");
    }

    /// Separators the caller left in are the caller's, including a trailing one
    /// and a doubled one, since the path that goes on the wire is the
    /// normalized one and not a rebuilt one.
    #[test]
    fn separators_are_carried_as_written() {
        assert_eq!(share_path(r"a\b\").as_str(), r"a\b\");
        assert_eq!(share_path("a/b/").as_str(), r"a\b\");
        assert_eq!(share_path(r"a\\b").as_str(), r"a\\b");
        assert_eq!(share_path("a//b").as_str(), r"a\\b");
    }

    /// The share root is the empty path: a listing of it uses `\*` where a
    /// listing inside the share appends to the path, so it has to be
    /// expressible.
    #[test]
    fn the_share_root_is_the_empty_path() {
        for spelling in ["", "   ", "\u{a0}\t"] {
            let root = share_path(spelling);
            assert!(root.is_root(), "{spelling:?} is not the root");
            assert_eq!(root.as_str(), "");
        }
        assert!(!share_path("a.txt").is_root());
    }

    /// The same disagreement smb-rs has between its constructor and its parser,
    /// checked on the other type this module validates.
    #[test]
    fn a_share_relative_path_parses_exactly_as_it_constructs() {
        for spelling in [
            "dir/file.txt",
            "",
            r"a\..\b",
            r"\a",
            "a\0b",
            r"..\b",
            r"a\..\..\b",
        ] {
            assert_eq!(
                spelling.parse::<SharePath>().ok(),
                SharePath::new(spelling).ok(),
                "{spelling:?} parses differently from how it constructs"
            );
        }
    }

    /// `SMB_COM_RENAME` puts a leading backslash in front of each of its two
    /// names. That belongs to the rename encoder, and this is what makes it
    /// expressible without normalizing a second time.
    #[test]
    fn the_rename_form_is_a_prefix_on_the_normalized_path() {
        let path = share_path("dir/old.txt");
        assert_eq!(format!(r"\{}", path.as_str()), r"\dir\old.txt");
        assert_eq!(format!(r"\{path}"), r"\dir\old.txt");
    }
}
