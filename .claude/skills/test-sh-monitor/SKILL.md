---
name: test-sh-monitor
description: >
  Guide for running and monitoring `dev-support/test.sh` in conflux-rust.
  Use this skill whenever the user wants to run tests, launch test.sh, monitor
  test progress, check test results, set up a new worktree for testing, or
  diagnose test failures in the conflux-rust project. Also trigger when the user
  asks about test phases, log keywords, build failures, or integration test
  failures in this repo.
---

# test.sh Running and Monitoring Guide

## Core Principle

**Always run the complete `test.sh` — never execute individual phases in isolation.**

`test.sh` sets critical environment variables (`CARGO_TARGET_DIR`, `RUSTFLAGS`, `CONFLUX_BENCH`), activates the venv, and manages symlinks. These side effects only take effect during a full run. In particular, `CARGO_TARGET_DIR=$ROOT_DIR/build` exists only within the `test.sh` process environment — manually running `cargo build` inside `tools/consensus_bench/` will drop artifacts in the wrong location, causing integration tests to pick up a stale binary.

---

## Step 0: Ask for Polling Interval

Before doing anything else, ask the user:

> "How often should I check the log? Options: **60s**, **120s**, or a custom value."

Remember the chosen interval — it will be used in the monitoring loop in Step 3.

---

## Step 1: Pre-flight Checks

Confirm these four items before launching to avoid discovering environment problems after a long wait:

```bash
# 1. uv is present
command -v uv || echo "MISSING: run: curl -LsSf https://astral.sh/uv/install.sh | sh"

# 2. submodules are initialized (required separately for each new worktree)
git submodule status | grep "^-" && echo "MISSING submodules: run git submodule update --init --recursive" || echo "submodules OK"

# 3. target directory state (must be a symlink, not a real directory)
ls -la target 2>/dev/null || echo "target not present (OK, test.sh will handle)"

# 4. venv (test.sh creates it automatically; this is just a sanity check)
ls .venv 2>/dev/null && echo "venv exists" || echo "venv absent (test.sh will create it)"
```

If submodules are missing:
```bash
git submodule update --init --recursive
```

---

## Step 2: Launch test.sh

**Prefer `run_in_background: true`** so the framework owns the process and notifies you on exit, structurally eliminating zombie process issues:

```bash
bash dev-support/test.sh > /tmp/test_run.log 2>&1
# (with run_in_background: true)
```

> **Why prefer run_in_background?** The framework-owned process is not a child of the current shell, so the framework reaps it — no need to handle zombies in the monitoring loop.

If you must background it manually, **do not use `kill -0` as the loop condition** — it cannot distinguish a running process from a zombie (`kill -0` returns 0 for both). Use `ps -o stat=` instead:

```bash
bash dev-support/test.sh > /tmp/test_run.log 2>&1 &
PID=$!
while [[ "$(ps -p $PID -o stat= 2>/dev/null)" =~ ^[^Z] ]]; do
    sleep 10
    tail -5 /tmp/test_run.log
done
wait $PID
echo "exit: $?"
tail -50 /tmp/test_run.log
```

`ps -o stat=` returns a status character: `S`/`R`/`D` = running normally, `Z` = zombie, empty = process gone. The regex `^[^Z]` exits the loop on either zombie or gone; `wait $PID` then reaps and returns the true exit code.

---

## Step 3: Periodic Monitoring

The core check logic is the same regardless of tool availability:

```bash
PASSED=$(grep -c "✓" /tmp/test_run.log 2>/dev/null || echo 0)
FAILED=$(grep -cE "[✖✗]" /tmp/test_run.log 2>/dev/null || echo 0)
RUNNING=$(pgrep -f "bash dev-support/test.sh" > /dev/null 2>&1 && echo "RUNNING" || echo "STOPPED")
PHASE=$(grep -oE "Phase [0-9]/[0-9]: [^=]+" /tmp/test_run.log 2>/dev/null | tail -1 || echo "unknown")
echo "[$(date '+%H:%M:%S')] $RUNNING phase=[$PHASE] passed=$PASSED failed=$FAILED"
tail -3 /tmp/test_run.log
```

Keep the check logic simple — count passes/fails, detect phase from anchors, tail the log. Do NOT attempt smart phase inference in the script; leave interpretation to the AI.

Below are two options depending on tool availability. **Prefer Option A** if the Monitor tool is available — it runs the polling loop as a background task whose stdout lines become chat notifications, eliminating the manual alternating pattern. Option B is the fallback for Claude Code versions that do not have the Monitor tool.

### Option A: With Monitor tool

Use Monitor as a log filter. The script runs a polling loop; each `echo` becomes a notification. Only emit output on noteworthy events — phase changes, new failures, or process exit — to avoid flooding the conversation:

```bash
Monitor({
  description: "test.sh watchdog",
  timeout_ms: 3600000,
  persistent: false,
  command: """
PREV_PHASE=""
PREV_FAILED=0
while true; do
  if [ ! -f /tmp/test_run.log ]; then sleep 10; continue; fi
  RUNNING=$(pgrep -f "bash dev-support/test.sh" > /dev/null 2>&1 && echo "yes" || echo "no")
  PASSED=$(grep -c "✓" /tmp/test_run.log 2>/dev/null || echo 0)
  FAILED=$(grep -cE "[✖✗]" /tmp/test_run.log 2>/dev/null || echo 0)
  PHASE=$(grep -oE "Phase [0-9]/[0-9]: [^=]+" /tmp/test_run.log 2>/dev/null | tail -1)

  if [ "$PHASE" != "$PREV_PHASE" ]; then
    echo "[$(date '+%H:%M:%S')] $PHASE | passed=$PASSED failed=$FAILED"
    PREV_PHASE="$PHASE"
  fi
  if [ "$FAILED" -gt "$PREV_FAILED" ]; then
    echo "[$(date '+%H:%M:%S')] NEW FAILURE: failed=$FAILED (was $PREV_FAILED)"
    grep -E "[✖✗]" /tmp/test_run.log 2>/dev/null | tail -5
    PREV_FAILED=$FAILED
  fi
  if [ "$RUNNING" = "no" ]; then
    echo "[$(date '+%H:%M:%S')] EXITED | passed=$PASSED failed=$FAILED"
    tail -10 /tmp/test_run.log
    exit 0
  fi
  sleep <interval>
done
"""
})
```

### Option B: Without Monitor tool

Use the foreground Bash + background sleep alternating pattern:

**Step A — foreground log check (no sleep):**

```bash
PASSED=$(grep -c "✓" /tmp/test_run.log 2>/dev/null || echo 0)
FAILED=$(grep -cE "[✖✗]" /tmp/test_run.log 2>/dev/null || echo 0)
RUNNING=$(pgrep -f "bash dev-support/test.sh" > /dev/null 2>&1 && echo "RUNNING" || echo "STOPPED")
PHASE=$(grep -oE "Phase [0-9]/[0-9]: [^=]+" /tmp/test_run.log 2>/dev/null | tail -1 || echo "unknown")
echo "[$(date '+%H:%M:%S')] $RUNNING phase=[$PHASE] passed=$PASSED failed=$FAILED"
tail -3 /tmp/test_run.log
```

**Step B — background timer (run_in_background: true):**
```bash
sleep <interval chosen in Step 0>
```

On timer notification → run Step A → run Step B → repeat.

> **Why this pattern?** The foreground Bash call returns immediately without blocking the conversation; every report is visible in real time. The background sleep is purely a timer. Common mistakes: background bash loop (intermediate output invisible), foreground sleep (blocks the conversation), background Agent for polling (same problem as background bash loop).

---

## The Four Phases

### Phase 1: cargo build (main project)
- **Anchor:** `=== Phase 1/4: Building main project ===`
- **Log signal:** continuous `Compiling xxx` (from cargo stderr; absent when build is cached)
- **Success anchor:** `=== Phase 1/4: Build succeeded ===`
- **Failure:** `error[E...]` from cargo stderr — process exits immediately (no success anchor)

### Phase 2: cargo build consensus_bench
- **Anchor:** `=== Phase 2/4: Building consensus_bench ===`
- **Success anchor:** `=== Phase 2/4: Build succeeded ===`
- **Special risk:** when the worktree is nested inside the parent repo, Cargo may walk up and resolve the wrong workspace
- **Failure signal:** `error: current package believes it's in a workspace`

### Phase 3: test_all.py (integration tests) — requires active monitoring
- **Anchor:** `=== Phase 3/4: Integration tests ===`
- **Key behavior:** parallel scheduling; a single test failure **does not** exit the process. Early break triggers: (1) >5 failures in a single round, or (2) any test that fails twice across retry rounds
- **Process alive ≠ tests passing** — tail the log regularly and count `✖`
- **Success anchor:** `=== Phase 3/4: Integration tests passed ===`
- **Failure:** any `✖`; exit code 1 or 80

### Phase 4: pytest
- **Anchor:** `=== Phase 4/4: Pytest ===`
- **Watch for:** `FAILED` and `ERROR` (pytest uses these, not `✖`)
- **Success anchor:** `=== Phase 4/4: Pytest passed ===`

---

## Log Keyword Reference

| Keyword | Phase | Meaning | Action |
|---------|-------|---------|--------|
| `=== Phase N/4:` | any | Phase anchor from test.sh | Reliable phase indicator |
| `Compiling` | 1/2 | Cargo compiling (stderr) | Normal; absent when cached |
| `error[E` | 1/2 | Rust compile error (stderr) | Read full log immediately |
| `Scanning num_nodes` | 3 | test_all.py starting | Build phases completed |
| `✓` | 3 | Single integration test passed | Normal |
| `✖` | 3 | Single integration test failed | Count; >5 means likely failure |
| `PASSED` | 4 | Single pytest passed | Normal |
| `FAILED` | 4 | Single pytest failed | Investigate |
| `The following test fails:` | 3 | Integration test summary | List of all failed tests |
| `ModuleNotFoundError` | any | Python env not ready | Stop, diagnose venv |
| `Cannot found contract` | 3 | Submodule not initialized | `git submodule update --init --recursive` |
| `externally-managed-environment` | startup | PEP 668, pip blocked | Check uv install; see activate_new_venv.sh |

**Not in the log:** `Build succeeded.` / `Build failed.` / `Integration test failed.` / `Pytest failed.` — these strings are captured into shell variables by `$()` and never printed to stdout/stderr. Use the `=== Phase ===` anchors instead.

---

## New Worktree Quick Start

When the current branch is already checked out by the main worktree, use `--detach` to avoid the branch conflict:

```bash
# 1. Create worktree
git worktree add --detach /home/ubuntu/worktrees/my-test HEAD

# 2. Initialize submodules (required for every new worktree)
cd /home/ubuntu/worktrees/my-test
git submodule update --init --recursive

# 3. (Optional) Reuse build artifacts to skip 30–50 min of compilation
#    Requires both worktrees to be on the same commit
ln -s /conflux-rust/build /home/ubuntu/worktrees/my-test/build

# 4. Launch (run_in_background: true)
bash dev-support/test.sh > /tmp/test_run.log 2>&1
```

---

## Three Monitoring Layers — All Required

1. **Process layer:** is the process still alive? (compile failures exit quickly)
2. **Log layer:** tail regularly and interpret keywords by phase
3. **Semantic layer:** in Phase 3, "process alive" does not mean "tests passing" — check the `✖` count
