use std::fmt;
use crate::core::{is_arithmetic, is_load};
use std::ops::Deref;
use std::hash::{Hash, Hasher};
use std::collections::HashMap;

use capstone::{
    Insn,
    InsnId,
    RegId,
    OwnedInsn,
    Capstone,
    arch::riscv::RiscVOperand,
    arch::riscv::RiscVOperand::*,
    arch::DetailsArchInsn,
};
use colored::*;

use crate::err::RVError;
use crate::query::Query;

#[derive (Clone, Copy)]
pub enum OutputMode {
    Inline,
    Block,
}

pub struct GadgetInsn<'a> {
    ins: OwnedInsn<'a>,
    ops: Vec<RiscVOperand>
}

impl<'a> Clone for GadgetInsn<'a> {

    fn clone(&self) -> Self {
        return GadgetInsn {
            ins: OwnedInsn::from(self.ins.deref()),
            ops: self.ops.clone()
        }
    }

}

impl fmt::Display for GadgetInsn<'_> {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut mnemonic = self.mnemonic().unwrap();
        if mnemonic.starts_with("c.") {
            mnemonic = &mnemonic[2..];
        }
        write!(f, "{} {}", mnemonic, self.op_str().unwrap())
    }

}

impl<'a> GadgetInsn<'a> {

    pub fn create(cs: &'a Capstone, ins: &Insn) -> Result<Self, RVError> {
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

    pub fn regs(&self) -> impl Iterator<Item=RegId>+'_ {
        self.operands().iter().filter_map(|op| match op {
            &Reg(id) => Some(id),
            _ => None,
        })
    }

    pub fn satisfies(&self, q: &Query) -> bool {
        return q.is_satisfied_by_ins(self);
    }

    pub fn print(&self, q: &Query, last: bool) {
        let addr = format!("{:#010x}", self.address());
        let bytes = self.bytes().iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{:02x} ", b));
            acc
        });
        let bytes = format!("{:>015}", bytes);
        let insstr = format!("{}", self);             
        
        println!("{} {} {}",
            addr.yellow(),
            bytes,
            if last {
                insstr.red()
            } else if self.satisfies(q) {
                insstr.blue()
            } else {
                insstr.color("useless").clear()
                }
            );

    }

}

#[derive(Clone)]
pub struct GadgetRoot<'a> {
    pub root: GadgetInsn<'a>,
    pub off: u64,
}

impl<'a> GadgetRoot<'a> {

    pub fn from(root: GadgetInsn<'a>, at: u64) -> Self {
        return GadgetRoot {
            root,
            off: at
        }
    }

}

pub struct Gadget<'a> {
    root: GadgetRoot<'a>,
    insns: Vec<GadgetInsn<'a>>,
}

impl<'a> Hash for Gadget<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for ins in &self.insns {
            ins.bytes().hash(state);
        }
        self.root.root.bytes().hash(state);
    }
}

impl<'a> PartialEq for Gadget<'a> {
    fn eq(&self, other: &Gadget) -> bool {
        if self.insns.len() != other.insns.len() {
            return false;
        }
        for (si, oi) in self.insns.iter().zip(other.insns.iter()) {
            if si.bytes() != oi.bytes() {
                return false
            }
        }
        return self.root.root.bytes() == other.root.root.bytes();
    }
}

impl<'a> Eq for Gadget<'a> {

}

impl<'a> Gadget<'a> {

    pub fn create(root: GadgetRoot<'a>, insns: Vec<GadgetInsn<'a>>) -> Result<Self, RVError> {
        let g = Gadget {
            root,
            insns,
        };

        return Ok(g);
    }

    pub fn is_dispatcher(&self) -> bool {
        #[derive(Clone, Copy, Default)]
        struct State { load: bool, add: bool }

        let mut states: HashMap<RegId, State> = HashMap::new();
        let jrid = self.root.root.regs().last().unwrap();

        for ins in &self.insns {
            if is_load(ins.id()) {
                let src = ins.regs().last().unwrap();
                let dst = ins.regs().next().unwrap();
                if dst == jrid {
                    states.entry(src).or_default().load = true;
                }
            } else if is_arithmetic(ins.id()) {
                if let Some(dst) = ins.regs().next() {
                    states.entry(dst).or_default().add = true;
                }
            }
        }
        return states.values().any(|s| s.add && s.load);
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
            ins.print(q, false);
        }
        self.root.root.print(q, true);
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
                } else {
                    insstr.color("useless").clear()
                }
            ));
        }
        let insstr = format!("{}", self.root.root);             
        acc.push_str(&format!("{}", insstr.red()));
        println!("{}   {}", addr.yellow(), acc);
    }

}
