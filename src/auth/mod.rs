//! NTLMv2 and SPNEGO.
//!
//! These two modules are written from their specifications — [MS-NLMP] and
//! RFC 4178 — and from nothing else. That is a licensing decision made before
//! the code was written rather than an audit afterwards, and the design record
//! sets out what it buys: the reference library's NTLM and SPNEGO packages are
//! documented as adapted from a third-party library whose attribution is
//! unresolved, so reading them for their shape would propagate the derivation
//! into Rust and defeat the reason for writing from specification at all.
//! Where the reference was consulted it was consulted *behaviourally* — the
//! same inputs run through both, and the bytes on the wire compared — and the
//! comparisons are committed as expected-value vectors.
//!
//! **NTLMv2 only.** No LM, no NTLMv1, and `des` is deliberately not a
//! dependency: it is needed for neither.
//!
//! # What is here
//!
//! - [`ntlm`] builds the NEGOTIATE message, parses the server's CHALLENGE, and
//!   builds the AUTHENTICATE message that answers it.
//! - [`spnego`] wraps those in the GSS-API tokens `SESSION_SETUP_ANDX` carries.
//!   It encodes DER and decodes lenient BER, because real servers emit
//!   indefinite-length encodings.
//!
//! # Credentials
//!
//! [`Password`] and the NT hash derived from it have redacted [`Debug`]
//! implementations, and the wire tracer redacts the `SESSION_SETUP_ANDX` byte
//! section unconditionally. The same material travels in those request bytes,
//! and a hex dump added while debugging a wire problem is otherwise a
//! complete, offline-crackable handshake written to a log file.

use std::fmt;

pub mod ntlm;
pub mod spnego;

/// A password, which never reaches a log.
///
/// The redacted [`Debug`] is the point of the type. A `String` field on a
/// `#[derive(Debug)]` struct is one derive away from a credential in a trace
/// line, and the test suite asserts the secret does not appear in this type's
/// formatted output — a redacted `Debug` being exactly what a later derive
/// silently undoes.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    /// Takes a password.
    pub fn new(password: impl Into<String>) -> Self {
        Self(password.into())
    }

    /// The password itself, for the one caller that needs it: the NT hash.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

impl From<&str> for Password {
    fn from(password: &str) -> Self {
        Self::new(password)
    }
}

impl From<String> for Password {
    fn from(password: String) -> Self {
        Self::new(password)
    }
}

/// Who the client authenticates as.
///
/// The domain is credential material rather than a name this crate chooses:
/// NTLMv2 mixes it into the response, so two callers who leave it unset must
/// compute the same response. It is therefore **sent as the empty string when
/// unset rather than omitted** — an unset domain is a value, not an absence.
///
/// The workstation name is not here, and is not the caller's to give. This
/// crate sends it empty: shipping the operator's hostname to a legacy SMB1
/// server on an untrusted network is exposure no server needs.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    user: String,
    password: Password,
    domain: String,
}

impl Credentials {
    /// Credentials with no domain, which is sent as the empty string.
    pub fn new(user: impl Into<String>, password: impl Into<Password>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
            domain: String::new(),
        }
    }

    /// Sets the NTLM domain.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// The user name, which travels in the clear in the AUTHENTICATE message.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The NTLM domain, empty where the caller set none.
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// The whole of what [`Debug`] says about a credential: who, never what.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("domain", &self.domain)
            .field("password", &self.password)
            .finish()
    }
}
