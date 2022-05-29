use crate::utils;
#[cfg(target_arch = "x86_64")]
use iced_x86::Formatter;
use std::fmt;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Instruction {
    pub data: Vec<u8>,
    pub disassembly: Option<String>,
    pub length: usize,
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
fn disassemble_instruction(bytes: &[u8], addr: u64) -> (usize, String) {
    let instruction = ((bytes[0] as u32) << 0)
        | ((bytes[1] as u32) << 8)
        | ((bytes[2] as u32) << 16)
        | ((bytes[3] as u32) << 24);

    let decoded = bad64::decode(instruction, addr).unwrap();

    return (4, decoded.to_string()); // For ARM, always 4
}

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
fn disassemble_instruction(bytes: &[u8], addr: u64) -> (usize, String) {
    let BITNESS: u32 = 64;
    let mut decoder = iced_x86::Decoder::new(BITNESS, bytes, iced_x86::DecoderOptions::NONE);
    let instruction = decoder.decode();
    let mut output: String = String::new();
    let mut formatter = iced_x86::IntelFormatter::new();
    formatter.format(&instruction, &mut output);
    (instruction.len(), output)
}

impl Instruction {
    pub fn from_data(data: &[u8], addr: u64) -> Self {
        let (length, disassembly) = disassemble_instruction(data, addr);
        Self {
            data: data[..length].into(),
            disassembly: Some(disassembly),
            length: length,
        }
    }

    pub fn is_breakpoint(&self) -> bool {
        self.data.as_slice() == 0xCC_u8.to_le_bytes()
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&utils::encode_hex(&self.data))?;
        if let Some(disassembly) = &self.disassembly {
            fmt.write_str(" (")?;
            fmt.write_str(&disassembly)?;
            fmt.write_str(")")?;
        }
        Ok(())
    }
}
