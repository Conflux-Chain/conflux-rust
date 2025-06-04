# Tools

This directory contains several tools primarily used for testing, including benchmarking and EVM spec tests. Currently, it includes the following tools:

- [consensus_bench](./consensus_bench): A tool for testing consensus performance.
- [evm-spec-tester](./evm-spec-tester): A tool for executing EVM specification tests.

Currently, these tools are standalone and not included in the main Rust workspace.
This means you need to navigate to the corresponding directory and use the cargo command to compile and run them.

In addition, we provide a helper script [`dev-support/cargo_all.sh`](../dev-support/cargo_all.sh) to streamline development.
This script enables executing cargo commands across the entire workspace, including all subdirectories under tools.

```bash
# Example: To run cargo check across the entire workspace, including all tools, use the following command:
./dev-support/cargo_all.sh check
```