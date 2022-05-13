#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Instruction(u64);

impl Instruction {
    pub fn instruction_size(&self) -> u8 {
        return 4; // For arm, always 4
    }
}