# Superprofiler

The superprofiler uses a combination of random sampling and dynamic code analysis to achieve high precision profiling with comparatively lower overhead (aspirationally, at least). Like all good modern CLI tools, it is written in Rust.

## Building from source
Install [Rust](https://rustup.rs/) and the following (if you are on Ubuntu):
```
sudo apt-get install build-essential # if you don't have C toolchain
sudo apt-get install pkg-config
sudo apt-get install libunwind-dev
sudo apt-get install -y clang # if you are running AArch64 (ARM64)
```
In order to build the superprofiler, clone this repository and run `cargo build`. Note that installing `libunwind` might be a bottleneck on other operating systems.

## Supported architectures
Currently, the superprofiler supports AArch64 (ARM64) [TODO] and x86.

## TODO

- Narrow instrumentation to a specific function
- Find some way to show which basic blocks are running most
- Show as flamegraph
- Output parquet
- Log syscalls

## Design Goals

- Architecture independent...
- Can attach to a running program...
- Catches (almost) all functions/instruction blocks (at least in long-running programs)...

## Components

- **Dynamic code analyzer** — given access to a program's memory (i.e., it's code) and an instruction pointer, both (1) automatically figure out which instruction encodings are branches of any sort, and (2) figure out the end of the block (once part (1) is complete).
- **Coordinator** — works with the dynamic code analyzer to insert breakpoints, collects sampling data
- **CLI** — reads profiling data from the coordinator

## Architecture Overview

...

### Dynamic Code Analyzer

The first goal of the dynamic code analyzer is to figure out which instruction encodings are branches. In order to accomplish this it:

1. Single steps through the process it is attached to, monitors changes in pc that reflects a branch and stores the encoding of the instruction that resulted in the change.
2. Predicts what opcodes/instruction encodings might map into a branch. Our goal is to exit single stepping as soon as possible, and only interrupt the program when we suspect that we have reached the end of a basic block.

    > Certain instructions ("pop {pc}", "movs pc, lr") result in a change only when the destination register is the program counter. In this case, we cannot rely only on the opcode information. On the other hand, recognizing patterns among opcodes of branch instructions help us predict what instructions result in a branch, and we can exit single stepping mode as soon as possible + handle instruction encodings that we have not encountered before.

3. Exits single stepping, adding breakpoints to a predicted branch. We need to come up with some metric that decides that we have sufficiently collected information about branch instructions.
4. To make things faster, (perhaps) keeps a lookup table of possible branch points of an instruction located at a particular address + keep a list of branch opcodes for widely-used instruction sets. 



...

### Coordinator 

...


