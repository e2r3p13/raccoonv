use std::error::Error;

use capstone::Capstone;
use capstone::arch::riscv::RiscVOperand;
use capstone::arch::riscv::{RiscVInsn, RiscVInsn::*, RiscVReg::*};
use capstone::prelude::{RegId, InsnId};
use elf::{ElfBytes ,endian};

use crate::gadget::{Gadget, GadgetInsn, GadgetRoot};
use crate::err::RVError;

const ALIGNMENT: usize = 2;
const MAX_INSSZ: usize = 4;
const MIN_INSSZ: usize = 2;

const BRANCH_INSNS: &[RiscVInsn] = &[
    RISCV_INS_JAL,
    RISCV_INS_JALR,
    RISCV_INS_C_JAL,
    RISCV_INS_C_JALR,
    RISCV_INS_MRET,
    RISCV_INS_SRET,
    RISCV_INS_URET,
    RISCV_INS_C_J,
    RISCV_INS_C_JR,
];

pub fn is_branching_ins(id: InsnId) -> bool {
    return BRANCH_INSNS.contains(&RiscVInsn::from(id.0));
}

pub fn ins_from_str(ins: &str) -> Result<InsnId, RVError> {
    let val = match ins {
        "add" => RISCV_INS_ADD,
        "addi" => RISCV_INS_ADDI,
        "addiw" => RISCV_INS_ADDIW,
        "addw" => RISCV_INS_ADDW,
        "and" => RISCV_INS_AND,
        "andi" => RISCV_INS_ANDI,
        "auipc" => RISCV_INS_AUIPC,
        "beq" => RISCV_INS_BEQ,
        "bge" => RISCV_INS_BGE,
        "bgeu" => RISCV_INS_BGEU,
        "blt" => RISCV_INS_BLT,
        "bltu" => RISCV_INS_BLTU,
        "bne" => RISCV_INS_BNE,
        "c.add" => RISCV_INS_C_ADD,
        "c.addi" => RISCV_INS_C_ADDI,
        "c.addi16sp" => RISCV_INS_C_ADDI16SP,
        "c.addi4spn" => RISCV_INS_C_ADDI4SPN,
        "c.addiw" => RISCV_INS_C_ADDIW,
        "c.addw" => RISCV_INS_C_ADDW,
        "c.and" => RISCV_INS_C_AND,
        "c.andi" => RISCV_INS_C_ANDI,
        "c.beqz" => RISCV_INS_C_BEQZ,
        "c.bnez" => RISCV_INS_C_BNEZ,
        "c.ebreak" => RISCV_INS_C_EBREAK,
        "c.fld" => RISCV_INS_C_FLD,
        "c.fldsp" => RISCV_INS_C_FLDSP,
        "c.flw" => RISCV_INS_C_FLW,
        "c.flwsp" => RISCV_INS_C_FLWSP,
        "c.fsd" => RISCV_INS_C_FSD,
        "c.fsdsp" => RISCV_INS_C_FSDSP,
        "c.fsw" => RISCV_INS_C_FSW,
        "c.fswsp" => RISCV_INS_C_FSWSP,
        "c.j" => RISCV_INS_C_J,
        "c.jal" => RISCV_INS_C_JAL,
        "c.jalr" => RISCV_INS_C_JALR,
        "c.jr" => RISCV_INS_C_JR,
        "c.ld" => RISCV_INS_C_LD,
        "c.ldsp" => RISCV_INS_C_LDSP,
        "c.li" => RISCV_INS_C_LI,
        "c.lui" => RISCV_INS_C_LUI,
        "c.lw" => RISCV_INS_C_LW,
        "c.lwsp" => RISCV_INS_C_LWSP,
        "c.mv" => RISCV_INS_C_MV,
        "c.nop" => RISCV_INS_C_NOP,
        "c.or" => RISCV_INS_C_OR,
        "c.sd" => RISCV_INS_C_SD,
        "c.sdsp" => RISCV_INS_C_SDSP,
        "c.slli" => RISCV_INS_C_SLLI,
        "c.srai" => RISCV_INS_C_SRAI,
        "c.srli" => RISCV_INS_C_SRLI,
        "c.sub" => RISCV_INS_C_SUB,
        "c.subw" => RISCV_INS_C_SUBW,
        "c.sw" => RISCV_INS_C_SW,
        "c.swsp" => RISCV_INS_C_SWSP,
        "c.unimp" => RISCV_INS_C_UNIMP,
        "c.xor" => RISCV_INS_C_XOR,
        "div" => RISCV_INS_DIV,
        "divu" => RISCV_INS_DIVU,
        "divuw" => RISCV_INS_DIVUW,
        "divw" => RISCV_INS_DIVW,
        "ebreak" => RISCV_INS_EBREAK,
        "ecall" => RISCV_INS_ECALL,
        "fence" => RISCV_INS_FENCE,
        "fld" => RISCV_INS_FLD,
        "flw" => RISCV_INS_FLW,
        "fsd" => RISCV_INS_FSD,
        "fsw" => RISCV_INS_FSW,
        "jal" => RISCV_INS_JAL,
        "jalr" => RISCV_INS_JALR,
        "lb" => RISCV_INS_LB,
        "lbu" => RISCV_INS_LBU,
        "ld" => RISCV_INS_LD,
        "lh" => RISCV_INS_LH,
        "lhu" => RISCV_INS_LHU,
        "lui" => RISCV_INS_LUI,
        "lw" => RISCV_INS_LW,
        "lwu" => RISCV_INS_LWU,
        "mret" => RISCV_INS_MRET,
        "mul" => RISCV_INS_MUL,
        "mulh" => RISCV_INS_MULH,
        "mulhsu" => RISCV_INS_MULHSU,
        "mulhu" => RISCV_INS_MULHU,
        "mulw" => RISCV_INS_MULW,
        "or" => RISCV_INS_OR,
        "ori" => RISCV_INS_ORI,
        "rem" => RISCV_INS_REM,
        "remu" => RISCV_INS_REMU,
        "remuw" => RISCV_INS_REMUW,
        "remw" => RISCV_INS_REMW,
        "sb" => RISCV_INS_SB,
        "sd" => RISCV_INS_SD,
        "sh" => RISCV_INS_SH,
        "sll" => RISCV_INS_SLL,
        "slli" => RISCV_INS_SLLI,
        "slliw" => RISCV_INS_SLLIW,
        "sllw" => RISCV_INS_SLLW,
        "slt" => RISCV_INS_SLT,
        "slti" => RISCV_INS_SLTI,
        "sltiu" => RISCV_INS_SLTIU,
        "sltu" => RISCV_INS_SLTU,
        "sra" => RISCV_INS_SRA,
        "srai" => RISCV_INS_SRAI,
        "sraiw" => RISCV_INS_SRAIW,
        "sraw" => RISCV_INS_SRAW,
        "sret" => RISCV_INS_SRET,
        "srl" => RISCV_INS_SRL,
        "srli" => RISCV_INS_SRLI,
        "srliw" => RISCV_INS_SRLIW,
        "srlw" => RISCV_INS_SRLW,
        "sub" => RISCV_INS_SUB,
        "subw" => RISCV_INS_SUBW,
        "sw" => RISCV_INS_SW,
        "unimp" => RISCV_INS_UNIMP,
        "uret" => RISCV_INS_URET,
        "wfi" => RISCV_INS_WFI,
        "xor" => RISCV_INS_XOR,
        "xori" => RISCV_INS_XORI,
        _ => RISCV_INS_INVALID,
    };
    if !ins.starts_with("c.") {
        return ins_from_str(&format!("c.{}", ins));
    }
    match val {
        RISCV_INS_INVALID => Err(RVError {msg: String::from("not an instruction")}),
        _ => Ok(InsnId(val as u32))
    }
}

pub fn reg_from_str(reg: &str) -> Result<RegId, RVError> {
    let val = match reg {
        "a0" => RISCV_REG_A0,
        "a1" => RISCV_REG_A1,
        "a2" => RISCV_REG_A2,
        "a3" => RISCV_REG_A3,
        "a4" => RISCV_REG_A4,
        "a5" => RISCV_REG_A5,
        "a6" => RISCV_REG_A6,
        "a7" => RISCV_REG_A7,
        "fp" => RISCV_REG_FP,
        "gp" => RISCV_REG_GP,
        "ra" => RISCV_REG_RA,
        "s0" => RISCV_REG_S0,
        "s1" => RISCV_REG_S1,
        "s2" => RISCV_REG_S2,
        "s3" => RISCV_REG_S3,
        "s4" => RISCV_REG_S4,
        "s5" => RISCV_REG_S5,
        "s6" => RISCV_REG_S6,
        "s7" => RISCV_REG_S7,
        "s8" => RISCV_REG_S8,
        "s9" => RISCV_REG_S9,
        "s10" => RISCV_REG_S10,
        "s11" => RISCV_REG_S11,
        "sp" => RISCV_REG_SP,
        "t0" => RISCV_REG_T0,
        "t1" => RISCV_REG_T1,
        "t2" => RISCV_REG_T2,
        "t3" => RISCV_REG_T3,
        "t4" => RISCV_REG_T4,
        "t5" => RISCV_REG_T5,
        "t6" => RISCV_REG_T6,
        "tp" => RISCV_REG_TP,
        "x0" => RISCV_REG_X0,
        "x1" => RISCV_REG_X1,
        "x2" => RISCV_REG_X2,
        "x3" => RISCV_REG_X3,
        "x4" => RISCV_REG_X4,
        "x5" => RISCV_REG_X5,
        "x6" => RISCV_REG_X6,
        "x7" => RISCV_REG_X7,
        "x8" => RISCV_REG_X8,
        "x9" => RISCV_REG_X9,
        "x10" => RISCV_REG_X10,
        "x11" => RISCV_REG_X11,
        "x12" => RISCV_REG_X12,
        "x13" => RISCV_REG_X13,
        "x14" => RISCV_REG_X14,
        "x15" => RISCV_REG_X15,
        "x16" => RISCV_REG_X16,
        "x17" => RISCV_REG_X17,
        "x18" => RISCV_REG_X18,
        "x19" => RISCV_REG_X19,
        "x20" => RISCV_REG_X20,
        "x21" => RISCV_REG_X21,
        "x22" => RISCV_REG_X22,
        "x23" => RISCV_REG_X23,
        "x24" => RISCV_REG_X24,
        "x25" => RISCV_REG_X25,
        "x26" => RISCV_REG_X26,
        "x27" => RISCV_REG_X27,
        "x28" => RISCV_REG_X28,
        "x29" => RISCV_REG_X29,
        "x30" => RISCV_REG_X30,
        "x31" => RISCV_REG_X31,
        "" => RISCV_REG_ZERO,
        _ => RISCV_REG_INVALID,
    };
    match val {
        RISCV_REG_INVALID => Err(RVError {msg: String::from("not a register")}),
        _ => Ok(RegId(val as u16))
    }
}

pub fn get_code<'a>(elf: &'a ElfBytes<endian::AnyEndian>) -> Result<(usize, usize, u64), Box<dyn Error>> {
    if let Some(segs) = elf.segments() {
        for phdr in segs {
            if phdr.p_flags == elf::abi::PF_R | elf::abi::PF_X {
                return Ok((phdr.p_offset as usize, phdr.p_filesz as usize, phdr.p_vaddr));
            }
        }
    }
    return Err(Box::new(RVError {msg: String::from("There is no .text section. The binary may be stripped")}));
}

pub fn find_gadget_roots<'a>(cs: &'a capstone::Capstone, code: &[u8], jr: Option<RegId>) -> Vec<GadgetRoot<'a>> {
    let mut roots = Vec::new();

    for off in (0..code.len()).step_by(ALIGNMENT) {
        if let Ok(insns) = cs.disasm_count(&code[off..], off as u64, 1) {
            if let Some(ins) = insns.first() {
                if let Ok(ins) = GadgetInsn::create(cs, ins) {
                    if is_branching_ins(ins.id()) {
                        for op in ins.operands() {
                            if let RiscVOperand::Reg(reg) = op {
                                if reg == &RegId(0) {
                                    continue
                                }
                                if let Some(target) = jr {
                                    if reg != &target {
                                        break
                                    }
                                }
                                roots.push(GadgetRoot::from(ins, off as u64));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    return roots;
}

pub fn find_gadgets_at_root<'a>(
    cs: &'a Capstone,
    root: GadgetRoot<'a>,
    addr: u64,
    code: &'a [u8],
    max: usize,
) -> Vec<Gadget<'a>> {
    let mut gadgets: Vec<Gadget> = Vec::new();

    let off = root.off;

    #[derive(Clone, Copy)]
    enum StackState {
        // off
        Unvisited(u64),
        // off, pushed
        Compressed(u64, bool),
        // pushed
        Visited(bool),
    }
    use StackState::*;

    let mut stack_insns: Vec<GadgetInsn<'a>> = vec![];
    let mut stack: Vec<StackState> = vec![Unvisited(off)];

    while let Some(state) = stack.pop() {
        match state {
            Unvisited(off) => {
                if 4 <= off && stack_insns.len() < max {
                    if let Ok(ins) =
                        cs.disasm_all(&code[(off - 4) as usize..off as usize], addr + off - 4)
                    {
                        if let Some(ins) = ins.first() {
                            if ins.len() == 4 as usize && !is_branching_ins(ins.id()) {
                                if let Ok(insn) = GadgetInsn::create(cs, ins) {
                                    stack.push(Compressed(off, true));
                                    stack.push(Unvisited(off - 4));
                                    stack_insns.push(insn);
                                    continue;
                                }
                            }
                        }
                    }
                }
                stack.push(Compressed(off, false))
            }
            Compressed(off, pushed) => {
                if 2 <= off && stack_insns.len() < max {
                    if let Ok(ins) =
                        cs.disasm_count(&code[(off - 2) as usize..off as usize], addr + off - 2, 1)
                    {
                        if let Some(ins) = ins.first() {
                            if ins.len() == 2 as usize && !is_branching_ins(ins.id()) {
                                if let Ok(insn) = GadgetInsn::create(cs, ins) {
                                    stack.append(&mut vec![Visited(true), Unvisited(off - 2)]);
                                    stack_insns.push(insn);
                                    continue;
                                }
                            }
                        }
                    }
                }
                stack.push(Visited(pushed))
            }
            Visited(pushed) => {
                if !pushed && !stack_insns.is_empty(){
                    if let Ok(g) = Gadget::create(root.clone(), stack_insns.clone()) {
                        gadgets.push(g);
                    }
                }
                stack_insns.pop();
            }
        }
    }
    return gadgets;
}
