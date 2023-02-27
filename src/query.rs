use capstone::prelude::*;
use std::{iter, fmt};

#[derive (Debug)]
pub struct Query {
    pub rr: Option<capstone::RegId>,
    pub wr: Option<capstone::RegId>,
    pub op: Option<capstone::InsnId>,
}

impl Query {

    pub fn create() -> Self {
        return Query {rr: None, wr: None, op: None};
    }

    pub fn add_rr_constraint(&mut self, reg: RegId) {
        self.rr = Some(reg);
    }

    pub fn add_rw_constraint(&mut self, reg: RegId) {
        self.wr = Some(reg);
    }

    pub fn add_op_constraint(&mut self, ins: InsnId) {
        self.op = Some(ins);
    }

}

impl fmt::Display for Query {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cs = Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
            .build()
            .expect("Failed to create Capstone object");

        writeln!(f, "instruction:    {}", cs.insn_name(self.op.unwrap_or(InsnId(0))).unwrap_or(String::from("-")))?;
        writeln!(f, "read register:  {}", cs.reg_name(self.rr.unwrap_or(RegId(0))).unwrap_or(String::from("-")))?;
        writeln!(f, "write register  {}", cs.reg_name(self.wr.unwrap_or(RegId(0))).unwrap_or(String::from("-")))?;
        Ok(())
    }
}
