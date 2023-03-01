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

#[derive (Clone, Copy)]
pub enum OutputMode {
    Inline,
    Block,
}

pub struct GadgetInsn<'a> {
    ins: OwnedInsn<'a>,
    ops: Vec<RiscVOperand>
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

    pub fn print(&self, mode: OutputMode) {
        match mode {
            OutputMode::Block => self.print_block(),
            OutputMode::Inline => self.print_inline(),
        };
    }

    fn print_block(&self) {
        for (i, ins) in self.insns.iter().enumerate() {
            let branch: bool = i == self.insns.len() - 1;

            let mut insstr = format!("{} {}", {
                let mn = ins.mnemonic().unwrap();
                if mn.starts_with("c.") {
                    &mn[2..]
                } else {
                    mn
                }
            },
                ins.op_str().unwrap(),
            );
            if branch {
                insstr = insstr.red().to_string();
            }
            let bytes = ins.bytes().iter().fold(String::new(), |mut acc, b| {
                acc.push_str(&format!("{:02x} ", b));
                acc
            });
            println!("{:#010x}    {:>015}   {}",
                ins.address(),
                bytes,
                insstr,
            );
        }
    }

    fn print_inline(&self) {
        let mut acc = String::from(format!("{:#010x}     ", self.insns.first().unwrap().address()));
        for (i, ins) in self.insns.iter().enumerate() {
            let branch: bool = i == self.insns.len() - 1;

            let mut insstr = format!("{} {}",
                {
                    let mn = ins.mnemonic().unwrap();
                    if mn.starts_with("c.") {
                        &mn[2..]
                    } else {
                        mn
                    }
                },
                ins.op_str().unwrap(),
            );
            if branch {
                insstr = insstr.red().to_string();
            }
            acc.push_str(&insstr);
            if !branch {
                acc.push_str(if ins.op_str().unwrap().len() == 0 {"; "} else {" ; "});
            }
        }
        println!("{}", acc);
    }

}
