use capstone::{Instructions, OwnedInsn, Capstone};
use colored::*;
use crate::err::RVError;

#[derive (Clone, Copy)]
pub enum OutputMode {
    Inline,
    Block,
}

pub struct Gadget<'a> {
    insns: Vec<OwnedInsn<'a>>,
    hash: u32
}

impl<'a> Gadget<'a> {

    pub fn create(cs: &'a Capstone, insns: Instructions<'a>) -> Result<Self, RVError> {
        let mut g = Gadget {
            insns: insns.iter().map(|x| OwnedInsn::from(x)).collect(),
            hash: 5381,
        };

        for ins in g.insns.iter() {
            for b in ins.bytes() {
                g.hash = g.hash.wrapping_mul(33).wrapping_add(*b as u32);
            }
            if let Err(_) = cs.insn_detail(ins) {
                let err = RVError { msg: String::from("Failed to get instruction details") };
                return Err(err);
            }
        }
        return Ok(g);
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

            let mut insstr = format!("{} {}",
                ins.mnemonic().unwrap(),
                ins.op_str().unwrap(),
            );
            if branch {
                insstr = insstr.red().to_string();
            }
            println!("{:#08x}     {}",
                ins.address(),
                insstr,
            );
        }
    }

    fn print_inline(&self) {
        let mut acc = String::from(format!("{:#08x}     ", self.insns.first().unwrap().address()));
        for (i, ins) in self.insns.iter().enumerate() {
            let branch: bool = i == self.insns.len() - 1;

            let mut insstr = format!("{} {}",
                ins.mnemonic().unwrap(),
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

impl PartialEq for Gadget<'_> {
    fn eq(&self, other: &Self) -> bool {
        return self.hash == other.hash;
    }
}
