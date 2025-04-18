# Lint Workflow Documentation

## Overview

This project uses Github Action to automatically run linting processes. The goal is to ensure code format consistency and code quality across the repository.

The automated workflow includes two main tasks: `lint` (for formatting and static analysis) and `cargo-deny` (for dependency checks).


This document explains how to run these checks manually on your local machine. This helps you fund and fix issues before committing your code.



## Lint Job (Formatting & Clipy Checks)

This job checks if the code follows the project's formatting rules and uses Clippy for static analysis to find potential errors and improvements.

#### Run Locally:

1. Install required toolchain and components:

This script install the specific Rust nightly toolchain.

```bash
./cargo_fmt.sh --install
```

2. Check code format:

Run the script to check if the project's code format is correct.

```bash
# Check format without making changes
./cargo_fmt.sh -- --check
# Automatically fix formatting issues
./cargo_fmt.sh

```

3. Run Clippy

Use `cargo clippy` to perform static analysis on all code.

```bash
cargo clippy --release --all -- -A warnings
```

## Cargo Deny Job(Dependency Checks)

This job uses the `cargo-deny` tool to check project dependencies. It ensures they meet predefined rules for things like license compatibility. security vulnerabilities, and avoiding specific or duplicate dependencies.

### Run Locally:

1. Install cargo deny:

```bash
# A specific version is needed due to project Rust version constraints.
cargo install --locked cargo-deny --version 0.15.1
```

2. Run a full check:

This command runs al checks defined in the `deny.toml` configuration file located in the project root.

```bash
cargo deny check
```

#### Running specific check individually:

You can also run individual cargo-deny checks:

1. Licenses:

Check if the licenses of all dependencies are acceptable according to `deny.toml` rules.

```bash
cargo deny check licenses
```

2. Advisories:

Checks dependencies against known security vulnerability databases

```bash
cargo deny check advisories
```

3. Bans:

Check for denied crates or multiple version of the same crate, as defined in `deny.toml`.

```bash
cargo deny check bans
```

4. Sources:
Ensures dependencies only come from trusted sources.

```bash
cargo deny check sources
```
