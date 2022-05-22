//! Utilities for the superprofiler

use std::{fmt::Write, mem::size_of};

pub fn offset(a: u64, b: u64) -> i64 {
    if b > a {
        return (b - a) as i64;
    } else {
        return -1 * (a - b) as i64;
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    // From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    write!(&mut s, "0x").unwrap();
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

// From https://reberhardt.com/cs110l/spring-2020/assignments/project-1/
pub fn align_addr_to_word(addr: u64) -> u64 {
    addr & (-(size_of::<u64>() as isize) as u64)
}

#[cfg(test)]
mod tests {
    use crate::utils::align_addr_to_word;

    #[test]
    fn test_align_addr_to_word() {
        assert_eq!(align_addr_to_word(123457), 123456);
        assert_eq!(align_addr_to_word(123458), 123456);
        assert_eq!(align_addr_to_word(123459), 123456);
        assert_eq!(align_addr_to_word(123460), 123456);
        assert_eq!(align_addr_to_word(123461), 123456);
        assert_eq!(align_addr_to_word(123462), 123456);
        assert_eq!(align_addr_to_word(123463), 123456);
        assert_eq!(align_addr_to_word(123464), 123464);
    }
}
