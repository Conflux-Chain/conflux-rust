# Static Security Scan for Conflux-rust - Step 1 (Day 1)

This guide walks you through running the first static scan on conflux-rust using the defending-code-reference-harness framework.

**Estimated Time:** 30-60 minutes  
**Requirements:** Claude Code, Python 3.11+, GitHub access  
**Output:** THREAT_MODEL.md, VULN-FINDINGS.json, TRIAGE.json, candidate patches

---

## Prerequisites

1. **Clone the defending-code-reference-harness repository**
```bash
git clone https://github.com/anthropics/defending-code-reference-harness.git
cd defending-code-reference-harness
```

2. **Clone conflux-rust repository (or checkout the security-scan-baseline branch we created)**
```bash
git clone https://github.com/Conflux-Chain/conflux-rust.git
cd conflux-rust
git checkout security-scan-baseline  # Get our scanning configs
```

3. **Set environment variables**
```bash
export ANTHROPIC_API_KEY=sk-ant-...  # Your Anthropic API key
export CLAUDE_CODE_SUBAGENT_MODEL=claude-opus-4-1  # Recommended for best results
```

---

## Phase 1: Initialize Claude Code

From the defending-code-reference-harness repository:

```bash
claude
```

This opens Claude Code with the skills `/quickstart`, `/threat-model`, `/vuln-scan`, `/triage`, `/patch`, and `/customize` available.

---

## Phase 2: Build or Review the Threat Model

### Option A: Auto-generate threat model

```bash
> /threat-model bootstrap /path/to/conflux-rust
```

This will:
- Analyze the codebase structure
- Identify entry points (network, RPC, transactions, blocks)
- Propose key threat categories
- Generate `THREAT_MODEL.md`

**Output:** `THREAT_MODEL.md` with attack surfaces and threat categories

### Option B: Use our pre-built threat model

We've already created one in `SECURITY_SCAN_CONFIG/threat-model.md`:

```bash
> /threat-model review SECURITY_SCAN_CONFIG/threat-model.md
```

Review it and suggest refinements:
```bash
> /threat-model refine SECURITY_SCAN_CONFIG/threat-model.md \
  --add "Integer overflow in state root calculation" \
  --add "Race condition in transaction ordering"
```

**✅ Expected output:** 
- Clear threat model focused on blockchain-critical areas
- Attack surface clearly defined (network input, transactions, blocks, consensus)
- Vulnerability categories prioritized by severity
- Key modules identified for scanning

---

## Phase 3: Run the Static Vulnerability Scan

With threat model in place, run the scanner:

```bash
> /vuln-scan /path/to/conflux-rust \
  --extra /path/to/conflux-rust/SECURITY_SCAN_CONFIG/scan-extras.txt
```

**What this does:**
1. Reads the source code (doesn't build or run anything)
2. Scans for Rust vulnerabilities + blockchain-specific issues
3. Uses the threat model to focus on high-risk areas
4. Generates candidate findings with evidence and code references

**⏱ Duration:** 5-15 minutes depending on model

**✅ Expected output:** 
- `VULN-FINDINGS.json` — All candidate findings (50-200 expected for large codebase)
- `VULN-FINDINGS.md` — Human-readable summary
- Each finding includes:
  - File path and line numbers
  - Vulnerability type (panic, integer overflow, logic error, etc.)
  - Severity (critical, high, medium, low)
  - Evidence and reasoning
  - Suggested remediation

---

## Phase 4: Triage & Deduplication

Now filter, deduplicate, and rank the findings:

```bash
> /triage /path/to/conflux-rust/VULN-FINDINGS.json \
  --repo /path/to/conflux-rust \
  --fp-rules /path/to/conflux-rust/SECURITY_SCAN_CONFIG/fp-rules.txt
```

**What this does:**
1. Applies false positive rules (excludes test code, dead code, etc.)
2. Groups similar findings together
3. Ranks by severity and likelihood
4. Verifies evidence for each claim
5. Produces a prioritized list

**✅ Expected output:**
- `TRIAGE.json` — Deduplicated and ranked findings
- `TRIAGE.md` — Summary with prioritization
- Findings organized by:
  - **CONFIRMED** — High confidence, actionable
  - **LIKELY** — Medium confidence, worth reviewing
  - **POSSIBLE** — Lower confidence, may be false positive

---

## Phase 5: Generate Candidate Patches

For confirmed findings, generate candidate patches:

```bash
> /patch ./TRIAGE.json --repo /path/to/conflux-rust
```

**What this does:**
1. For each confirmed finding, proposes a fix
2. Explains the patch and why it works
3. Generates `.diff` files ready to apply
4. Includes before/after code comparison

**✅ Expected output:**
- `PATCHES/` directory with:
  - `finding_001.diff` — Patch for first finding
  - `finding_002.diff` — Patch for second finding
  - etc.
- Each patch includes:
  - Description of the vulnerability
  - Proposed fix
  - Testing strategy
  - Notes on edge cases

---

## Expected Findings for Conflux-rust

Based on the threat model, the scanner should look for:

### 🔴 Critical Priority (Must fix)
- **Panic on untrusted network input** — `unwrap()`, `expect()` on transaction/block data
- **Signature verification bypass** — Incorrect ECDSA validation logic
- **Integer overflow in balance/nonce** — Unchecked arithmetic in state transitions
- **Double spending vulnerability** — State transition logic flaw

### 🟠 High Priority (Should fix)
- **Out-of-bounds access** — Unsafe code in trie/storage operations
- **Consensus weight calculation error** — Fork resolution choosing wrong chain
- **EVM opcode misinterpretation** — Smart contract execution bugs
- **Integer overflow in gas calculation** — Resource accounting errors

### 🟡 Medium Priority (Consider fixing)
- **Panics in error paths** — Non-critical code crashes
- **Resource exhaustion** — Unbounded allocations from untrusted data
- **Race conditions** — Concurrent access issues

---

## Example Walkthrough

Here's what a real run might look like:

```bash
# 1. Start Claude Code
$ claude

# 2. Review threat model
> /threat-model review SECURITY_SCAN_CONFIG/threat-model.md
✓ Threat model looks comprehensive. 8 focus areas identified.

# 3. Run scan
> /vuln-scan /path/to/conflux-rust \
  --extra SECURITY_SCAN_CONFIG/scan-extras.txt
[Running static analysis...]
✓ Analyzed 1,250+ files
✓ Found 87 candidate vulnerabilities
→ VULN-FINDINGS.json generated

# 4. Triage
> /triage VULN-FINDINGS.json \
  --repo /path/to/conflux-rust \
  --fp-rules SECURITY_SCAN_CONFIG/fp-rules.txt
[Filtering and deduplicating...]
✓ Applied 15 false positive rules
✓ Deduplicated 34 duplicates
✓ Ranked 18 unique findings

Confirmed (8):
  1. Panic on invalid transaction signature — transaction.rs:245
  2. Integer overflow in balance transfer — state.rs:312
  3. Weight calculation error — consensus.rs:487
  ...

Likely (6):
  4. Unsafe pointer arithmetic — storage.rs:156
  ...

Possible (4):
  10. Potential race condition — network.rs:423
  ...

→ TRIAGE.json and TRIAGE.md generated

# 5. Generate patches
> /patch ./TRIAGE.json --repo /path/to/conflux-rust
[Generating patches for 8 confirmed findings...]
✓ Patch 001: Validate signature before unwrap()
✓ Patch 002: Use checked_sub for balance
✓ Patch 003: Fix weight overflow
...
→ PATCHES/ directory created with 8 diffs
```

---

## Output File Structure

After running all phases, you'll have:

```
conflux-rust/
├── SECURITY_SCAN_CONFIG/           # Our pre-built configs (already exists)
├── THREAT_MODEL.md                 # Generated or reviewed threat model
├── VULN-FINDINGS.json              # All candidate findings
├── VULN-FINDINGS.md                # Human-readable findings
├── TRIAGE.json                     # Deduplicated & ranked
├── TRIAGE.md                       # Summary with priorities
└── PATCHES/                        # Suggested fixes
    ├── finding_001.diff
    ├── finding_002.diff
    └── ...
```

---

## Next Steps After Static Scan

### Option 1: Review & Manual Fix
1. Review each finding in `TRIAGE.md`
2. Validate the proposed patches in `PATCHES/`
3. Apply patches locally and test
4. Submit PRs to conflux-rust

### Option 2: Continue to Autonomous Pipeline (Step 2)
For more comprehensive scanning with execution-verified findings:

```bash
cd defending-code-reference-harness

# Setup (one-time)
python3 -m venv .venv && .venv/bin/pip install -e .
./scripts/setup_sandbox.sh
export ANTHROPIC_API_KEY=sk-ant-...

# Run full pipeline
bin/vp-sandboxed run conflux-rust --auto-focus --runs 3 --parallel --stream
```

This will:
- Build a Docker container with conflux-rust
- Spawn 3 parallel agents to fuzz transaction/block parsing
- Verify each finding with a grader agent in a fresh container
- Generate exploitability reports
- Propose validated patches

---

## Troubleshooting

### Issue: "Model not found" or rate limits
**Solution:** Set `CLAUDE_CODE_SUBAGENT_MODEL` to your preferred model before starting Claude Code:
```bash
export CLAUDE_CODE_SUBAGENT_MODEL=claude-opus-4-1
```

### Issue: Too many false positives
**Solution:** Update `fp-rules.txt` to add more exclusion patterns specific to Conflux:
```bash
> /triage ./VULN-FINDINGS.json \
  --fp-rules custom-fp-rules.txt
```

### Issue: Scan takes too long
**Solution:** Narrow the scope:
```bash
# Scan only crates/cfxcore/ instead of entire repo
> /vuln-scan /path/to/conflux-rust/crates/cfxcore \
  --extra scan-extras.txt
```

### Issue: "No findings generated"
**Solution:** 
1. Verify threat model is being used
2. Run with a more capable model (Claude Opus)
3. Increase max_turns for the scan

---

## Files Reference

| File | Purpose |
|------|---------|
| `threat-model.md` | Attack surfaces and threat categories |
| `scan-extras.txt` | Rust and blockchain vulnerability definitions |
| `fp-rules.txt` | False positive filtering rules |
| `pipeline-config.yaml` | Configuration for autonomous pipeline (Step 2) |
| `Dockerfile` | Container definition for pipeline |
| `entry.rs` | Fuzzing harness for pipeline |

For more details, see: https://github.com/anthropics/defending-code-reference-harness/blob/main/README.md

