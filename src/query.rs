use std::{iter, fmt};

use capstone::prelude::*;
use capstone::arch::riscv::RiscVOperand;

use crate::gadget::{Gadget, GadgetInsn};

#[derive (Debug)]
pub struct Query {
    pub rr: Option<capstone::RegId>,
    pub wr: Option<capstone::RegId>,
    pub op: Option<capstone::InsnId>,
    empty: bool,
}

impl Query {

    pub fn create_from(rr: Option<RegId>, wr: Option<RegId>, op: Option<InsnId>) -> Self {
        let empty: bool = rr == None && wr == None && op == None;
        return Query {rr, wr, op, empty};
    }

    pub fn is_satisfied_by_ins(&self, ins: &GadgetInsn) -> bool {
        if self.empty {
            return false;
        }
        if let Some(op) = self.op {
            if op != ins.id() {
                return false;
            }
        }

        if let Some(wr) = self.wr {
            if !ins.operands().contains(&RiscVOperand::Reg(wr)) {
                return false;
            }
        }
        if let Some(rr) = self.rr {
            if !ins.operands().contains(&RiscVOperand::Reg(rr)) {
                return false;
            }
        }

        return true;
    }

    pub fn is_satisfied_by_gadget(&self, gadget: &Gadget) -> bool {
        if self.empty {
            return true;
        }
        for ins in gadget.insns() {
            if self.is_satisfied_by_ins(&ins) {
                return true;
            }
        }
        return false;
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
