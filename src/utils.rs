//! Utilities for the superprofiler

use std::fmt::Write;

pub fn offset(a: u64, b: u64) -> i64 {
    if b > a {
        return (b - a) as i64;
    } else {
        return -1 * (a - b) as i64;
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    // From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}