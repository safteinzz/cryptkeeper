//! `/` filtering: which rows survive what has been typed. It narrows and
//! never reorders, so the list keeps the order it is read in.

/// Whether any of `haystacks` matches `query`, ignoring case: as a substring,
/// or failing that as its letters in order, so `phs` finds `photos`.
pub(super) fn matches(query: &str, haystacks: &[&str]) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    haystacks.iter().any(|h| {
        let h = h.to_lowercase();
        h.contains(&q) || in_order(&q, &h)
    })
}

/// Every char of `needle`, in order, somewhere in `haystack`.
fn in_order(needle: &str, haystack: &str) -> bool {
    let mut chars = haystack.chars();
    needle.chars().all(|c| chars.any(|h| h == c))
}
