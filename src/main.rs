use capstone::prelude::*;
use capstone::arch::riscv::RiscVInsn;
use std::iter;

const ALIGNMENT: usize = 2;

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

fn main() {
    // RISC-V code with some branching instructions (C extension)
    let code: &[u8] = b"\x05\x45\x93\x08\xd0\x05\x73\x00\x00\x00\x82\x90\x02\x94\x82\x93\x02\x95\x67\x80\x00\x00";

    let mut cs = Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV64)
        .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
        .build()
        .expect("Failed to create Capstone object");

    cs.set_detail(false).expect("Failed to update Capstone object");
    let gadget_roots = find_gadget_roots(&cs, &code);

    cs.set_detail(true).expect("Failed to update Capstone object");
    for root in gadget_roots {
        // TODO: Disassemble backward and print gadgets
    }

}
