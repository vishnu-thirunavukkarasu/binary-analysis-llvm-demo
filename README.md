# BinaryLens

A Python toolkit for exploring binary analysis and automated vulnerability detection.
Built as part of self-directed learning in binary program modernization research.

## The Problem This Explores

Millions of legacy programs exist as compiled binaries with no available source code.
They contain security vulnerabilities and run only on outdated processor architectures.
Modernizing them manually is expensive and error-prone.

This project explores the first steps of automating that process:

- Parse the structure of a compiled binary
- Extract what external functions it calls
- Represent equivalent logic as LLVM IR
- Scan that IR for dangerous vulnerability patterns
- Output a structured vulnerability report

## Pipeline
Old binary (.exe / ELF)

↓

Step 1: Parse binary header — identify sections and format

↓

Step 2: Extract imports — what external APIs does it call?

↓

Step 3: Lift to LLVM IR — represent logic in structured form

↓

Step 4: Scan IR — detect dangerous patterns

↓

Step 5: Report — JSON output of all findings

## Files

| File | What it does |
|------|--------------|
| `llvm_demo.py` | Generates LLVM IR from scratch using llvmlite |
| `llvm_scanner.py` | Scans LLVM IR for vulnerability patterns and outputs JSON report |
| `parse_binary.py` | Reads a PE binary and extracts imports and dangerous API calls |

## How to Run

Install the dependency:
pip install llvmlite

Generate and view LLVM IR:
python llvm_demo.py

Run the vulnerability scanner:
python llvm_scanner.py

Parse a real Windows binary:
python parse_binary.py C:\Windows\System32\notepad.exe

## What the Scanner Detects

- Known dangerous function names such as unsafe_strcpy, unsafe_memcpy, unsafe_gets
- Functions with two pointer arguments and no size parameter — classic unchecked copy pattern
- Functions with a single pointer argument and no length limit — unsafe input read pattern
- Each finding includes risk level HIGH or MEDIUM, recommended fix, and CWE reference

## Tools Used

- [llvmlite](https://llvmlite.readthedocs.io/) — Python binding for LLVM
- [Ghidra](https://ghidra-sre.org/) — NSA reverse engineering tool, used hands-on to analyse Windows PE binaries

## Literature Referenced

- Lattner and Adve, LLVM: A Compilation Framework for Lifelong Program Analysis and Transformation, CGO 2004
- Dinesh et al., RetroWrite: Statically Instrumenting COTS Binaries, IEEE S&P 2020

## What I Learned Building This

- PE binary format structure — headers and sections including .text .rdata .data and .reloc
- LLVM IR as a structured intermediate representation sitting between machine code and source
- How type information is permanently lost during compilation and why recovery is hard
- Why automated vulnerability detection at IR level is non-trivial
- The difference between what Ghidra recovers from a binary and what the original source contained

## Research Context

This project is motivated by the open research problem of binary program modernization —
automating security vulnerability remediation, architecture porting, and equivalence testing
for programs where source code is no longer available.

The hardest unsolved problem in this space is binary lifting — recovering enough structural
and type information from raw machine code to safely analyse and transform it.
Existing tools recover reliable type information for roughly 68 percent of memory accesses
on average across C benchmarks (Lattner and Adve, 2004).
Improving that number is an active and open research problem.
