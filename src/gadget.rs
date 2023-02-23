use std::{error, fmt};

use capstone::{Instructions, OwnedInsn, Capstone};

#[derive(Debug)]
pub struct GadgetError {
    msg: String
}

pub struct Gadget<'a> {
    insns: Vec<OwnedInsn<'a>>,
    hash: u32
}

impl<'a> Gadget<'a> {

    pub fn create(cs: &'a Capstone, insns: Instructions<'a>) -> Result<Self, GadgetError> {
        let mut g = Gadget {
            insns: insns.iter().map(|x| OwnedInsn::from(x)).collect(),
            hash: 5381,
        };

        for ins in g.insns.iter() {
            for b in ins.bytes() {
                g.hash = g.hash.wrapping_mul(33).wrapping_add(*b as u32);
            }
            if let Err(_) = cs.insn_detail(ins) {
                let err = GadgetError { msg: String::from("Failed to get instruction details") };
                return Err(err);
            }
        }
        return Ok(g);
    }

}

impl PartialEq for Gadget<'_> {

    fn eq(&self, other: &Self) -> bool {
        return self.hash == other.hash;
    }

}

impl error::Error for GadgetError {}

impl fmt::Display for GadgetError {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: {}", &self.msg)
    }

}
