# RaccoonV - A Risc-V JOP gadget finder

RaccoonV is a linux command line tool. It has many advantages compared to a real raccoon: Insead of digging holes in your garden to find food, it will investigate binaries to find JOP gadgets.

Another advantage is that it is made out of Rust instead of legs, snouts and stuff like this. This makes it more robust than a real raccoon, indeed.

⚠️ It only works on **Linux** for **elf** binaries with **Risc-V** architecture (ISA RV32IC).

## Quick start

First, you need to install the [Rust toolchain](https://www.rust-lang.org/tools/install).

Here are quick instructions to build/install the project. Please refer to the [cargo documentation](https://doc.rust-lang.org/cargo/commands/cargo-doc.html) for more details.

**Build:**
```bash
cargo build --release
```

**Install:**
```bash
# In your home directory
cargo install --path .
# Or systemwise
sudo cargo install --path . --root /bin
```

## Usage

```
Usage: rv [OPTIONS] <PATH>

Arguments:
  <PATH>  Path of the target binary

Options:
  -d, --dispatcher  Find dispatcher gadgets
      --inline      Display gadgets in a single line
  -m, --max <MAX>   Only search gadgets with at maximum <max> instructions [default: 5]
  -j, --jr <reg>    Only find gadgets ending with a jump to <reg> register
  -w, --wr <reg>    Only find gadgets where the <reg> register is written to
  -i, --imm <imm>   Only find gadgets where the <imm> immediate is used
  -r, --rr <reg>    Only find gadgets where the <reg> register is read from
  -o, --op <ins>    Only find gadgets containing the <ins> instruction
      --raw         Process raw code instead of elf file
  -h, --help        Print help
  -V, --version     Print version
```

---
Feedbacks & suggestions are welcome, especially concerning the project name.
