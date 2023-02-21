# RacoonV - A RiscV ROP gadget finder

RacoonV is a linux command line tool. It has many advantages compared to a real racoon: Insead of digging holes in your garden to find food, it will investigate binaries to find ROP gadgets.

Another advantage is that it is made out of Rust instead of legs, snouts and stuff like this. This makes it more robust than a real racoon, indeed.

⚠️ It only works on **Linux** for **elf** binaries with **Risc-V** architecture (ISA RV64IC).

## Quick start

First, you need to install the [Rust toolchain](https://www.rust-lang.org/tools/install) and the [Capstone library](https://www.capstone-engine.org). Done? Congratz, you can move on.

Here are quick instructions to build/install the project. Please refer to the [cargo documentation](https://doc.rust-lang.org/cargo/commands/cargo-doc.html) for more details.

```bash
git clone git@github.com:lfalkau/racoonv.git
cd racoonv
cargo build --release

# If you want to install it in your home directory
cargo install --path .
```

## Usage

RacoonV is currently in early phases of development, and I have to admit than command line arguments are not yet accepted. Even the code in which it searches for gadget is hardcoded for now.

However, here is the expected synopsis of RacoonV:

```
rv [options] <binary>
```

I plan to add options to display gadgets inline or blockwise, to query specific instruction opcodes & registers etc...

---
Feedbacks & suggestions are welcome, especially concerning the project name.
