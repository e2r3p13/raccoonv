mod gadget;
mod err;

use std::{iter, error::Error};

use capstone::{prelude::*, arch::riscv::RiscVInsn};
use elf::{ElfBytes ,endian};
use colored::Colorize;

use gadget::{Gadget, OutputMode};

const ALIGNMENT: usize = 2;
const MAX_INSNS: usize = 5;
const MAX_INSSZ: usize = 4;
const MIN_INSSZ: usize = 2;

const BRANCH_INSNS: &[RiscVInsn] = &[
    RiscVInsn::RISCV_INS_JAL,
    RiscVInsn::RISCV_INS_JALR,
    RiscVInsn::RISCV_INS_C_JAL,
    RiscVInsn::RISCV_INS_C_JALR,
    RiscVInsn::RISCV_INS_MRET,
    RiscVInsn::RISCV_INS_SRET,
    RiscVInsn::RISCV_INS_URET,
    RiscVInsn::RISCV_INS_C_J,
    RiscVInsn::RISCV_INS_C_JR,
];

pub fn get_text<'a>(elf: &'a ElfBytes<endian::AnyEndian>) -> Result<(&'a [u8], u64), Box<dyn Error>> {
    if let Ok(Some(shdr)) = elf.section_header_by_name(".text") {
        let data = elf.section_data(&shdr)?.0;
        return Ok((data, shdr.sh_addr));
    }
    return Err(Box::new(err::RVError {msg: String::from("There is no .text section. The binary may be stripped")}));
}

pub fn get_code<'a>(elf: &'a ElfBytes<endian::AnyEndian>) -> Result<(usize, usize, u64), Box<dyn Error>> {
    if let Some(segs) = elf.segments() {
        for phdr in segs {
            if phdr.p_flags == elf::abi::PF_R | elf::abi::PF_X {
                return Ok((phdr.p_offset as usize, phdr.p_filesz as usize, phdr.p_vaddr));
            }
        }
    }
    return Err(Box::new(err::RVError {msg: String::from("There is no .text section. The binary may be stripped")}));
}

fn find_gadget_roots(cs: &capstone::Capstone, code: &[u8]) -> Vec<usize> {
    let mut roots = Vec::new();

    for off in (0..code.len() + ALIGNMENT).step_by(ALIGNMENT) {
        if let Ok(insns) = cs.disasm_count(&code[off..], off as u64, 1) {
            if let Some(ins) = insns.first() {
                if BRANCH_INSNS.contains(&RiscVInsn::from(ins.id().0)) {
                    roots.push(off + ins.len());
                }
            }
        }
    }
    return roots;
}

fn find_gadgets_at_root<'a>(cs: &'a capstone::Capstone, root: usize, addr: u64, code: &'a [u8]) -> Vec<Gadget<'a>> {
    let mut gadgets: Vec<Gadget> = Vec::new();

    for size in ((MIN_INSSZ * 2)..(MAX_INSNS * MAX_INSSZ)).step_by(ALIGNMENT) {
        if size > root { break; }

        let base = root - size;
        let slice = &code[base..root];
        if let Ok(insns) = cs.disasm_all(slice, addr + base as u64) {
            if insns.len() > 1 && insns.len() <= MAX_INSNS {
                if let Ok(gadget) = Gadget::create(&cs, insns) {
                    gadgets.push(gadget);
                }
            }
        }
    }
    return gadgets;
}

fn main() {
    let path = "./tests/ch91";
    let outmode = OutputMode::Block;

    let data = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) => {
            println!("{} Failed to read '{}'. {}", "ERROR:".red(), path, e);
            return;
        }
    };
    let elf = match ElfBytes::<endian::AnyEndian>::minimal_parse(&data) {
        Ok(elf) => elf,
        Err(_) => {
            println!("{} Failed to parse '{}'. Make sure to provide a valid ELF file", "ERROR:".red(), path);
            return;
        }
    };
    if elf.ehdr.e_machine != elf::abi::EM_RISCV || elf.ehdr.class != elf::file::Class::ELF64 {
        println!("{} racoonv only supports Risc-V binaries (ISA RV64IC)", "ERROR:".red());
        return;
    }
    let (off, size, addr) = match get_code(&elf) {
        Ok(text) => text,
        Err(e) => {
            println!("{} Failed to find code in '{}'. {}", "ERROR:".red(), path, e);
            return;
        }
    };

    let mut cs = Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV64)
        .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
        .build()
        .expect("Failed to create Capstone object");

    let mut unique_gadgets: Vec<Gadget> = Vec::new();

    cs.set_detail(false).expect("Failed to update Capstone object");
    let code = &data[off..(off + size)];
    let gadget_roots = find_gadget_roots(&cs, &code);

    cs.set_detail(true).expect("Failed to update Capstone object");
    for root in gadget_roots {
        let gadgets = find_gadgets_at_root(&cs, root, addr, &code);
        for gadget in gadgets {
            if !unique_gadgets.contains(&gadget) {
                gadget.print(outmode);
                println!();
                unique_gadgets.push(gadget);
            }
        }
    }
    println!("----------");
    println!("Found {} unique gadgets.", unique_gadgets.len());
}
