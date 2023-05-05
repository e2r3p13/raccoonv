mod gadget;
mod err;
mod query;
mod core;

use std::iter;
use std::collections::HashSet;

use capstone::prelude::*;
use elf::{ElfBytes ,endian};
use colored::Colorize;
use clap::Parser;

use gadget::OutputMode;
use query::Query;

/// Command line tool to find JOP gadgets in a Risc-V application
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path of the target binary
    #[arg()]
    path: String,

    /// Find dispatcher gadgets
    #[arg(short, long)]
    dispatcher: bool,

    /// Display gadgets in a single line
    #[arg(long)]
    inline: bool,

    /// Only search gadgets with at maximum <max> instructions
    #[arg(short, long, default_value="5")]
    max: usize,

    /// Only find gadgets ending with a jump to <reg> register
    #[arg(short, long, value_name="reg", value_parser=core::reg_from_str)]
    jr: Option<RegId>,

    /// Only find gadgets where the <reg> register is written to
    #[arg(short, long, value_name="reg", value_parser=core::reg_from_str)]
    wr: Option<RegId>,

    /// Only find gadgets where the <imm> immediate is used
    #[arg(short, long, value_name="imm")]
    imm: Option<i64>,

    /// Only find gadgets where the <reg> register is read from
    #[arg(short, long, value_name="reg", value_parser=core::reg_from_str)]
    rr: Option<RegId>,

    /// Only find gadgets containing the <ins> instruction
    #[arg(short, long, value_name="ins", value_parser=core::ins_from_str)]
    op: Option<InsnId>,

    /// Process raw code instead of elf file
    #[arg(long)]
    raw: bool,
}

fn main() {

    /* Arguments parsing */

    let args = Args::parse();
    let outmode = match args.inline {
        true => OutputMode::Inline,
        false => OutputMode::Block,
    };
    let query = Query::create_from(args.rr, args.wr, args.imm, args.op, args.dispatcher);

    /* ELF parsing */

    let data = match std::fs::read(&args.path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("{} Failed to read '{}'. {}", "ERROR:".red(), &args.path, e);
            return;
        }
    };

    let (off, size, addr) = if args.raw {
        (0, data.len(), 0)
    } else {
        let elf = match ElfBytes::<endian::AnyEndian>::minimal_parse(&data) {
            Ok(elf) => elf,
            Err(_) => {
                eprintln!("{} Failed to parse '{}'. Make sure to provide a valid ELF file", "ERROR:".red(), &args.path);
                return;
            }
        };
        if elf.ehdr.e_machine != elf::abi::EM_RISCV || elf.ehdr.class != elf::file::Class::ELF32 {
            eprintln!("{} racoonv only supports Risc-V binaries (ISA RV32IC)", "ERROR:".red());
            return;
        }
        match core::get_code(&elf) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("{} Failed to find code in '{}'. {}", "ERROR:".red(), &args.path, e);
                return;
            }
        }
    };

    /* Gadgets finding & displaying */

    let cs = Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV32)
        .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let code = &data[off..(off + size)];
    let gadget_roots = core::find_gadget_roots(&cs, &code, args.jr);

    let mut gadgets_hs = HashSet::new();

    for root in gadget_roots {
        let gadgets = core::find_gadgets_at_root(&cs, root, addr, &code, args.max);
        for gadget in gadgets {
            if gadget.satisfies(&query) {
                gadgets_hs.insert(gadget);
            }
        }
    }

    for gadget in &gadgets_hs {
        gadget.print(&query, outmode);
        if let OutputMode::Block = outmode {
            println!();
        }
    }

    println!("----------");
    println!("Found {} unique gadgets.", gadgets_hs.len());
}
