# Conflux-Rust Security Scanning Configuration

This directory contains the configuration and setup files for running autonomous security vulnerability scans on conflux-rust using the defending-code-reference-harness framework.

## Files

- **threat-model.md**: Comprehensive threat model identifying attack surfaces, threat categories, and key modules to review in Conflux-rust
- **scan-extras.txt**: Rust and blockchain-specific vulnerability categories for the scanner to focus on
- **fp-rules.txt**: False positive filtering rules to reduce noise in scan results
- **pipeline-config.yaml**: Configuration for the defending-code-reference-harness pipeline
- **Dockerfile**: Container image definition for building and scanning conflux-rust
- **entry.rs**: Fuzzing harness entry point for testing transaction/block parsing

## Quick Start

### Step 1: Static Analysis (Local, No Sandbox Required)

If you have the defending-code-reference-harness repository cloned:

```bash
cd defending-code-reference-harness
claude

# Build threat model
/threat-model bootstrap /path/to/conflux-rust

# Run static scan with blockchain-specific guidelines
/vuln-scan /path/to/conflux-rust --extra /path/to/conflux-rust/SECURITY_SCAN_CONFIG/scan-extras.txt

# Triage findings with false positive rules
/triage ./VULN-FINDINGS.json --fp-rules /path/to/conflux-rust/SECURITY_SCAN_CONFIG/fp-rules.txt

# Generate candidate patches
/patch ./TRIAGE.json --repo /path/to/conflux-rust
```

### Step 2: Autonomous Pipeline (Requires gVisor Sandbox)

```bash
# One-time setup
python3 -m venv .venv
.venv/bin/pip install -e .
./scripts/setup_sandbox.sh
export ANTHROPIC_API_KEY=sk-ant-...

# Copy this config to the targets directory
cp -r /path/to/conflux-rust/SECURITY_SCAN_CONFIG/pipeline-config.yaml targets/conflux-rust/config.yaml
cp /path/to/conflux-rust/SECURITY_SCAN_CONFIG/Dockerfile targets/conflux-rust/Dockerfile
cp /path/to/conflux-rust/SECURITY_SCAN_CONFIG/entry.rs targets/conflux-rust/entry.rs

# Run the full autonomous pipeline
bin/vp-sandboxed run conflux-rust --auto-focus --runs 3 --parallel --stream

# Generate patches for verified findings
bin/vp-sandboxed patch results/conflux-rust/$(ls -t results/conflux-rust | head -1)/
```

## Threat Model Summary

Key threat categories for Conflux-rust:

1. **Panic Attacks**: Code crashes on malformed network input (DoS)
2. **Integer Overflow/Underflow**: In balance, nonce, gas calculations
3. **Cryptographic Flaws**: Signature verification bypass, replay attacks
4. **Consensus Logic**: Double spending, invalid state transitions, weight calculation errors
5. **Smart Contract Execution**: EVM opcode misinterpretation, memory bounds violations

## Scanning Focus Areas

The scanner will prioritize:

- Transaction validation (cfxcore/src/transaction/)
- Block processing and consensus (cfxcore/src/consensus/)
- Network message parsing (network/src/)
- Cryptographic operations (primitives/src/)
- State management (cfxcore/src/state/)
- EVM execution (cfxcore/src/vm/)
- RPC endpoint handling (rpc/src/)
- Cross-space interactions (cfxcore/src/vm/crossspace/)

## Expected Output

Scanning produces:

- `VULN-FINDINGS.json`: Candidate vulnerabilities from static analysis
- `TRIAGE.json`: Deduplicated and ranked findings
- `results/conflux-rust/<timestamp>/`: Pipeline execution results with:
  - `run_NNN/result.json`: Individual run outcomes
  - `reports/bug_NN/report.json`: Exploitability analysis per bug
  - `reports/bug_NN/patch.diff`: Candidate patches (if enabled)

## Next Steps

1. Review the threat model and focus areas
2. Run the static analysis first (Step 1) for quick feedback
3. Use `/customize` to adapt the harness if needed for your environment
4. Run the full pipeline when ready (Step 2) for execution-verified findings
5. Triage and prioritize findings by severity
6. Generate and validate patches for critical issues

For more details, see: https://github.com/anthropics/defending-code-reference-harness
