//! Utilities for the superprofiler

pub fn offset(a: u64, b: u64) -> i64 {
    if b > a {
        return (b - a) as i64;
    } else {
        return -1 * (a - b) as i64;
    }
}
