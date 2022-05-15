static BITNESS: u32 = 64;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Instruction(pub Vec<u8>);

impl Instruction {
    #[cfg(target_arch = "arm")]
    #[allow(dead_code)]
    pub fn instruction_size(&self) -> usize {
        return 4; // For arm, always 4
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(dead_code)]
    pub fn instruction_size(&self) -> usize {
        let bytes: &[u8] = &self.0;
        let mut decoder = iced_x86::Decoder::new(BITNESS, bytes, iced_x86::DecoderOptions::NONE);
        
        let instruction = decoder.decode();

        instruction.len()
    }
}
