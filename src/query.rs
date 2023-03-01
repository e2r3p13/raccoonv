use capstone::prelude::*;
use capstone::Insn;
use capstone::arch::riscv::{RiscVInsnDetail, RiscVOperand};
use std::{iter, fmt};

#[derive (Debug)]
pub struct Query {
    pub rr: Option<capstone::RegId>,
    pub wr: Option<capstone::RegId>,
    pub op: Option<capstone::InsnId>,
}

impl Query {

    #[allow(dead_code)]
    pub fn create() -> Self {
        return Query {rr: None, wr: None, op: None};
    }

    pub fn create_from(rr: Option<RegId>, wr: Option<RegId>, op: Option<InsnId>) -> Self {
        return Query {rr, wr, op};
    }

    pub fn is_satisfied(&self, ins: &Insn, d: &InsnDetail, ad: &RiscVInsnDetail) -> bool {
        println!("{:?} {:?}", d.regs_read(), d.regs_write());
        if let Some(op) = self.op {
            if op != ins.id() {
                return false;
            }
        }

        if let Some(wr) = self.wr {
            if !ad.operands().any(|e| {
                if let RiscVOperand::Reg(id) = e {
                    id == wr
                } else {
                    false
                }
            }) {
                return false;
            }
        }

        if let Some(rr) = self.rr {
            if !ad.operands().any(|e| {
                if let RiscVOperand::Reg(id) = e {
                    id == rr
                } else {
                    false
                }
            }) {
                return false;
            }
        }

        return true;
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
