#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Instruction(pub u64);

impl Instruction {
    #[cfg(target_arch = "arm")]
    #[allow(dead_code)]
    pub fn instruction_size(&self) -> u8 {
        return 4; // For arm, always 4
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(dead_code)]
    pub fn instruction_size(&self) -> u8 {
        return 0;
    }
}
