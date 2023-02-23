mod gadget;

use capstone::prelude::*;
use capstone::arch::riscv::RiscVInsn;
use std::iter;

use gadget::Gadget;
use gadget::OutputMode;

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
];

fn find_gadget_roots(cs: &capstone::Capstone, code: &[u8]) -> Vec<usize> {
    let mut roots = Vec::new();

    for off in (0..code.len() + ALIGNMENT).step_by(ALIGNMENT) {
        if let Ok(insns) = cs.disasm_count(&code[off..], (0x1010c + off) as u64, 1) {
            if let Some(ins) = insns.first() {
                if BRANCH_INSNS.contains(&RiscVInsn::from(ins.id().0)) {
                    roots.push(off + ins.len());
                }
            }
        }
    }
    return roots;
}

fn find_gadgets_at_root<'a>(cs: &'a capstone::Capstone, root: usize, code: &'a [u8]) -> Vec<Gadget<'a>> {
    let mut gadgets: Vec<Gadget> = Vec::new();

    for size in ((MIN_INSSZ * 2)..(MAX_INSNS * MAX_INSSZ)).step_by(ALIGNMENT) {
        if size > root {
            break;
        }

        let window = &code[(root - size)..root];
        if let Ok(insns) = cs.disasm_all(window, 0x0) {
            if insns.len() <= MAX_INSNS {
                if let Ok(gadget) = Gadget::create(&cs, insns) {
                    gadgets.push(gadget);
                }
            }
        }
    }
    return gadgets;
}

fn main() {
    // RISC-V code with some branching instructions (C extension)
    let code: &[u8] = b"\x05\x45\x93\x08\xd0\x05\x73\x00\x00\x00\x82\x90\x02\x94\x82\x93\x02\x95\x67\x80\x00\x00";

    let mut cs = Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV64)
        .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
        .build()
        .expect("Failed to create Capstone object");

    let mut unique_gadgets: Vec<Gadget> = Vec::new();

    cs.set_detail(false).expect("Failed to update Capstone object");
    let gadget_roots = find_gadget_roots(&cs, &code);

    cs.set_detail(true).expect("Failed to update Capstone object");
    for root in gadget_roots {
        let gadgets = find_gadgets_at_root(&cs, root, &code);
        for gadget in gadgets {
            if !unique_gadgets.contains(&gadget) {
                gadget.print(OutputMode::Inline);
                println!();
                gadget.print(OutputMode::Block);
                println!();
                unique_gadgets.push(gadget);
            }
        }
    }
}
