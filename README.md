# Superprofiler

The superprofiler uses a combination of random sampling and dynamic code analysis to achieve high precision profiling with comparatively lower overhead (aspirationally, at least). Like all good modern CLI tools, it is written in Rust.

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
    2. Using this stored encoding, it predicts what opcodes/instruction encodings might map into a branch. Our goal is to exit single stepping as soon as possible, and only interrupt the program when we suspect that a branch/function call has occurred.

    Certain instructions ("pop {pc}", "movs pc, lr") result in a change only when the destination register is the program counter. In this case, we cannot rely only on the opcode information. On the other hand, recognizing patterns among opcodes of branch instructions help us predict what instructions result in a branch, and we can exit single stepping mode as soon as possible + handle instruction encodings that we have not encountered before.
    
    3. After sufficiently collecting information about branch instructions using some metric (TBD), we exit single stepping, adding breakpoints to a predicted branch.
    4. To make things faster, we can keep a lookup table of possible branch points of an instruction located at a particular address + keep a list of branch opcodes for widely-used instruction sets. 



...

### Coordinator 

...


