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
