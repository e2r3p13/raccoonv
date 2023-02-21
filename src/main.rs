use capstone::prelude::*;
use std::iter;

fn main() {
    // RISC-V code with some branching instructions (C extension)
    let code: &[u8] = b"\x05\x45\x93\x08\xd0\x05\x73\x00\x00\x00\x82\x90\x02\x94\x82\x93\x02\x95\x67\x80\x00\x00";

    let cs = Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV64)
        .detail(true)
        .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs.disasm_all(code, 0x1000)
        .expect("Failed to disassemble code");

    println!("Successfully disassembled {} instruction(s)", insns.len());
    for ins in insns.as_ref() {
        println!("i: {ins}");
    }
}
