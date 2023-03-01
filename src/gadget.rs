use std::fmt;

use capstone::{
    Instructions,
    Insn,
    InsnId,
    OwnedInsn,
    Capstone,
    arch::riscv::RiscVOperand,
    arch::DetailsArchInsn,
};
use colored::*;

use crate::err::RVError;
use crate::query::Query;
use crate::core::is_branching;

#[derive (Clone, Copy)]
pub enum OutputMode {
    Inline,
    Block,
}

pub struct GadgetInsn<'a> {
    ins: OwnedInsn<'a>,
    ops: Vec<RiscVOperand>
}

impl fmt::Display for GadgetInsn<'_> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mnemonic().unwrap(), self.op_str().unwrap())
    }

}

impl<'a> GadgetInsn<'a> {

    fn create(cs: &'a Capstone, ins: &Insn) -> Result<Self, RVError> {
        if let Ok(details) = cs.insn_detail(ins) {
            if let Some(arch) = details.arch_detail().riscv() {
                let g = GadgetInsn {
                    ins: OwnedInsn::from(ins),
                    ops: arch.operands().collect(),
                };
                return Ok(g);
            }
        }
        let e = RVError { msg: String::from("Failed to get instruction details")};
        Err(e)
    
    }

    pub fn bytes(&self) -> &[u8] {
        return self.ins.bytes();
    }

    pub fn id(&self) -> InsnId {
        return self.ins.id();
    }

    pub fn mnemonic(&self) -> Option<&str> {
        return self.ins.mnemonic();
    }

    pub fn op_str(&self) -> Option<&str> {
        return self.ins.op_str();
    }

    pub fn address(&self) -> u64 {
        return self.ins.address();
    }

    pub fn operands(&self) -> &Vec<RiscVOperand> {
        return &self.ops;
    }

    pub fn satisfies(&self, q: &Query) -> bool {
        return q.is_satisfied_by_ins(self);
    }

}

pub struct Gadget<'a> {
    insns: Vec<GadgetInsn<'a>>,
    hash: u32
}

impl PartialEq for Gadget<'_> {
    fn eq(&self, other: &Self) -> bool {
        return self.hash == other.hash;
    }
}

impl<'a> Gadget<'a> {

    pub fn create(cs: &'a Capstone, insns: Instructions<'a>) -> Result<Self, RVError> {
        let mut g = Gadget {
            insns: Vec::new(),
            hash: 5381,
        };

        for ins in insns.as_ref() {
            for b in ins.bytes() {
                g.hash = g.hash.wrapping_mul(33).wrapping_add(*b as u32);
            }
            g.insns.push(GadgetInsn::create(cs, &ins)?);
        }

        return Ok(g);
    }

    pub fn insns(&self) -> &Vec<GadgetInsn> {
        return &self.insns;
    }

    pub fn satisfies(&self, q: &Query) -> bool {
        return q.is_satisfied_by_gadget(self);
    }

    pub fn print(&self, q: &Query, mode: OutputMode) {
        match mode {
            OutputMode::Block => self.print_block(q),
            OutputMode::Inline => self.print_inline(q),
        };
    }

    fn print_block(&self, q: &Query) {
        for ins in self.insns.iter() {
            let addr = format!("{:#010x}", ins.address());
            let bytes = ins.bytes().iter().fold(String::new(), |mut acc, b| {
                acc.push_str(&format!("{:02x} ", b));
                acc
            });
            let bytes = format!("{:>015}", bytes);
            let insstr = format!("{}", ins);             

            println!("{} {} {}",
                addr.yellow(),
                bytes,
                if ins.satisfies(q) {
                    insstr.blue()
                } else if is_branching(ins.id()) {
                    insstr.black().red()
                } else {
                    insstr.white()
                }
            );
        }
    }

    fn print_inline(&self, q: &Query) {
        let addr = if let Some(a) = self.insns.first() {
            format!("{:#010x}", a.address())
        } else {
            return;
        };
        let mut acc = String::new();
        for ins in self.insns.iter() {
            let insstr = format!("{}", ins);             
            acc.push_str(&format!("{} ; ",
                if ins.satisfies(q) {
                    insstr.blue()
                } else if is_branching(ins.id()) {
                    insstr.black().red()
                } else {
                    insstr.white()
                }
            ));
        }
        println!("{}   {}", addr.yellow(), acc);
    }

}
