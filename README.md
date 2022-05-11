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

...

### Coordinator 

...

