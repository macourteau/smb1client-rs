//! Path shapes the tree verbs build on top of the share-relative policy.
//!
//! The policy itself — the two normalizations and the three refusals — lives
//! with [`crate::unc::SharePath`], which is the one construction path every
//! caller-supplied path goes through. What is left here is the two shapes
//! built *from* a path already held to it: the search pattern a listing
//! searches on, and joining a directory to an entry name.

/// Normalizes a share-relative path and refuses what the policy forbids.
///
/// What comes back is the form the request carries, with one exception:
/// `SMB_COM_RENAME` puts a leading backslash in front of each of its two names,
/// which is applied after this and changes nothing about what a caller may hand
/// in.
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
    fn the_root_pattern_carries_a_leading_backslash_and_a_path_does_not() {
        assert_eq!(search_pattern(""), "\\*");
        assert_eq!(search_pattern("dir\\sub"), "dir\\sub\\*");
        assert_eq!(search_pattern("dir\\"), "dir\\*");
    }
}
