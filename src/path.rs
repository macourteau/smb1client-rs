//! The share-relative path policy: one place every `Tree` verb's path goes
//! through before it reaches the wire.
//!
//! **Normalization does two things and nothing else.** It rewrites `/` to `\`,
//! so a caller writing `dir/file.txt` is not made to know that the wire wants
//! backslashes, and it trims Unicode whitespace from both ends — not just ASCII
//! spaces, since a legacy server can hold a name with a non-breaking space in
//! it. Both are unconditional, because a path policy a caller can turn off is
//! one no caller can rely on.
//!
//! **Three refusals.** An absolute path, because a path is relative to the share
//! root and there is nothing for a leading separator to mean; a path carrying a
//! null byte, which can only be a truncation waiting to happen in whatever reads
//! it at the other end; and a path that escapes the share root, which is refused
//! here rather than sent for the server to have an opinion about.
//!
//! **The escape check resolves `.` and `..` to reach its verdict, and resolving
//! them is all it does with them.** `a\..\b.txt` passes and is sent as
//! `a\..\b.txt`, not as `b.txt`: the port does not rewrite a path it has decided
//! is safe.

use crate::error::{Error, Result};

/// Normalizes a share-relative path and refuses what the policy forbids.
///
/// What comes back is the form the request carries, with one exception:
/// `SMB_COM_RENAME` puts a leading backslash in front of each of its two names,
/// which is applied after this and changes nothing about what a caller may hand
/// in.
pub(crate) fn share_relative(path: &str) -> Result<String> {
    let normalized: String = path
        .trim_matches(char::is_whitespace)
        .chars()
        .map(|character| if character == '/' { '\\' } else { character })
        .collect();

    if normalized.contains('\0') {
        return Err(Error::InvalidPath(format!(
            "{path:?} carries a null byte, which truncates whatever reads it"
        )));
    }
    if normalized.starts_with('\\') {
        return Err(Error::InvalidPath(format!(
            "{path:?} is absolute; a path is relative to the share root"
        )));
    }
    if escapes(&normalized) {
        return Err(Error::InvalidPath(format!(
            "{path:?} resolves outside the share root"
        )));
    }
    Ok(normalized)
}

/// Whether walking the components ever takes the path above the share root.
///
/// Depth is tracked rather than the components rewritten, so an escape cannot
/// be evaded by spelling it differently and the path that goes on the wire is
/// still the one the caller gave.
fn escapes(path: &str) -> bool {
    let mut depth = 0i32;
    for component in path.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// The pattern a listing searches on: the normalized path, a trailing backslash
/// where it has not got one, and an asterisk — and for the share root, where
/// there is no path, `\*` with the leading backslash.
///
/// The asymmetry is the reference's and is inherited deliberately: every listing
/// this campaign observed was made with these patterns, and no evidence says
/// what a server that refused the root form's leading backslash would do
/// instead.
pub(crate) fn search_pattern(normalized: &str) -> String {
    if normalized.is_empty() {
        return "\\*".to_owned();
    }
    if normalized.ends_with('\\') {
        format!("{normalized}*")
    } else {
        format!("{normalized}\\*")
    }
}

/// Joins a directory to an entry's name, for the recursive walk.
pub(crate) fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else if directory.ends_with('\\') {
        format!("{directory}{name}")
    } else {
        format!("{directory}\\{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_are_rewritten_and_whitespace_trimmed() {
        assert_eq!(share_relative("dir/file.txt").unwrap(), "dir\\file.txt");
        // Unicode whitespace, not merely ASCII: a legacy server can hold a name
        // with a non-breaking space in it.
        assert_eq!(share_relative("\u{2003} a.txt \u{a0}").unwrap(), "a.txt");
    }

    #[test]
    fn the_three_refusals_each_name_themselves() {
        for path in ["\\etc\\passwd", "/etc/passwd"] {
            assert!(
                share_relative(path)
                    .unwrap_err()
                    .to_string()
                    .contains("absolute"),
                "{path}"
            );
        }
        assert!(
            share_relative("a\0b")
                .unwrap_err()
                .to_string()
                .contains("null byte")
        );
        for path in ["..\\..\\etc\\passwd", "a\\..\\..\\b", ".."] {
            assert!(
                share_relative(path)
                    .unwrap_err()
                    .to_string()
                    .contains("outside the share root"),
                "{path}"
            );
        }
    }

    /// Resolving `.` and `..` is what reaches the verdict and is all that is
    /// done with them: a path that passes goes on the wire as the caller wrote
    /// it, components and all.
    #[test]
    fn a_path_that_passes_is_not_rewritten() {
        assert_eq!(share_relative("a\\..\\b.txt").unwrap(), "a\\..\\b.txt");
        assert_eq!(share_relative(".\\a\\.\\b").unwrap(), ".\\a\\.\\b");
    }

    #[test]
    fn the_root_pattern_carries_a_leading_backslash_and_a_path_does_not() {
        assert_eq!(search_pattern(""), "\\*");
        assert_eq!(search_pattern("dir\\sub"), "dir\\sub\\*");
        assert_eq!(search_pattern("dir\\"), "dir\\*");
    }
}
