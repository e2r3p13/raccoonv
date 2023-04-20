mod gadget;
mod err;
mod query;
mod core;

use std::iter;

use capstone::prelude::*;
use elf::{ElfBytes ,endian};
use colored::Colorize;
use clap::Parser;

use gadget::{Gadget, OutputMode};
use query::Query;

/// Command line tool to find JOP gadgets in a Risc-V application
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path of the target binary
    #[arg()]
    path: String,

    /// Display gadgets in a single line
    #[arg(short, long)]
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
    let query = Query::create_from(args.rr, args.wr, args.op);

    /* ELF parsing */

    let data = match std::fs::read(&args.path) {
        Ok(raw) => raw,
        Err(e) => {
            println!("{} Failed to read '{}'. {}", "ERROR:".red(), &args.path, e);
            return;
        }
    };

    let (off, size, addr) = if args.raw {
        (0, data.len(), 0)
    } else {
        let elf = match ElfBytes::<endian::AnyEndian>::minimal_parse(&data) {
            Ok(elf) => elf,
            Err(_) => {
                println!("{} Failed to parse '{}'. Make sure to provide a valid ELF file", "ERROR:".red(), &args.path);
                return;
            }
        };
        if elf.ehdr.e_machine != elf::abi::EM_RISCV || elf.ehdr.class != elf::file::Class::ELF32 {
            println!("{} racoonv only supports Risc-V binaries (ISA RV32IC)", "ERROR:".red());
            return;
        }
        match core::get_code(&elf) {
            Ok(text) => text,
            Err(e) => {
                println!("{} Failed to find code in '{}'. {}", "ERROR:".red(), &args.path, e);
                return;
            }
        }
    };

    /* Gadgets finding & displaying */

    let mut cs = Capstone::new()
        .riscv()
        .mode(arch::riscv::ArchMode::RiscV32)
        .extra_mode(iter::once(arch::riscv::ArchExtraMode::RiscVC))
        .build()
        .expect("Failed to create Capstone object");

    let mut unique_gadgets: Vec<Gadget> = Vec::new();

    cs.set_detail(true).expect("Failed to update Capstone object");
    let code = &data[off..(off + size)];
    let gadget_roots = core::find_gadget_roots(&cs, &code, args.jr);

    cs.set_detail(true).expect("Failed to update Capstone object");
    for root in gadget_roots {
        let gadgets = core::find_gadgets_at_root(&cs, root, addr, &code, args.max);
        for gadget in gadgets {
            if !unique_gadgets.contains(&gadget) && gadget.satisfies(&query) {
                gadget.print(&query, outmode);
                if let OutputMode::Block = outmode {
                    println!();
                }
                unique_gadgets.push(gadget);
            }
        }
    }
    println!("----------");
    println!("Found {} unique gadgets.", unique_gadgets.len());
}
