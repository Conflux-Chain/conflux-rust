#!/usr/bin/env bash
set -euo pipefail

# Real-data replay smoke matrix for cfxpack directories and replay checkpoints.
#
# The script treats DATA_ROOT as read-only. It writes only under REPLAY_SMOKE_OUT
# (default: $HOME/cfx-replay-smoke/<timestamp>) and uses symlinked input subsets
# so a long packed directory can be reduced to a bounded replay segment.

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ORACLE_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
DATA_ROOT=${REPLAY_SMOKE_DATA_ROOT:-/cfx-minimal-execution/data}
OUT_ROOT=${REPLAY_SMOKE_OUT:-$HOME/cfx-replay-smoke/$(date -u +%Y%m%dT%H%M%SZ)}
CONFIG=${REPLAY_SMOKE_CONFIG:-}
PACK_DIRS=${REPLAY_SMOKE_PACK_DIRS:-"$DATA_ROOT/packed-full $DATA_ROOT/backup-packed-full"}
BACKUP_DIR=${REPLAY_SMOKE_BACKUP_DIR:-"$DATA_ROOT/replay-checkpoint/backup"}
BACKENDS=${REPLAY_SMOKE_BACKENDS:-all}
CKPT_GROUPS=${REPLAY_SMOKE_GROUPS:-1}
FILES_PER_SUBSET=${REPLAY_SMOKE_FILES_PER_SUBSET:-1}
BACKUP_LIMIT=${REPLAY_SMOKE_BACKUP_LIMIT:-1}
TIMEOUT=${REPLAY_SMOKE_TIMEOUT:-1200}
NICE=${REPLAY_SMOKE_NICE:-10}
MAX_MISMATCHES=${REPLAY_SMOKE_MAX_MISMATCHES:-1000000}
ANOMALY_STREAK=${REPLAY_SMOKE_ANOMALY_STREAK:-1000000}

mkdir -p "$OUT_ROOT"/{bin,cases,logs}
SUMMARY="$OUT_ROOT/summary.tsv"
printf 'backend\tcase\tphase\tstatus\tcheckpoint_height\tlog\n' > "$SUMMARY"

log() {
  printf '[replay-smoke] %s\n' "$*" >&2
}

skip() {
  log "skip: $*"
}

die() {
  log "error: $*"
  exit 1
}

[[ $CKPT_GROUPS =~ ^[0-9]+$ ]] || die "REPLAY_SMOKE_GROUPS must be numeric, got '$CKPT_GROUPS'"
log "settings: backends=$BACKENDS checkpoint_groups=$CKPT_GROUPS files_per_subset=$FILES_PER_SUBSET backup_limit=$BACKUP_LIMIT timeout=${TIMEOUT}s out=$OUT_ROOT"

split_csv_or_words() {
  printf '%s\n' "$1" | tr ',' ' '
}

epoch_start() {
  local base=${1##*/}
  [[ $base =~ _([0-9]+)_([0-9]+)\.cfxpack$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

epoch_end() {
  local base=${1##*/}
  [[ $base =~ _([0-9]+)_([0-9]+)\.cfxpack$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[2]}"
}

checkpoint_height_from_name() {
  local base=${1##*/}
  [[ $base =~ ^ckpt_([0-9]+)\.bin(\.zst)?$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

resolve_config() {
  if [[ -n $CONFIG ]]; then
    [[ -f $CONFIG ]] || die "REPLAY_SMOKE_CONFIG does not exist: $CONFIG"
    printf '%s\n' "$CONFIG"
    return
  fi
  for candidate in \
    "$DATA_ROOT/replay-checkpoint/hydra-v303.toml" \
    "$DATA_ROOT/replay-checkpoint/hydra-replay.toml"
  do
    if [[ -f $candidate ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  return 1
}

find_pack_dir_for_height() {
  local height=$1
  local dir file end
  for dir in $(split_csv_or_words "$PACK_DIRS"); do
    [[ -d $dir ]] || continue
    while IFS= read -r file; do
      end=$(epoch_end "$file") || continue
      if (( end > height )); then
        printf '%s\n' "$dir"
        return
      fi
    done < <(find "$dir" -maxdepth 1 -type f -name '*.cfxpack' -print | sort -V)
  done
  return 1
}

make_subset_dir() {
  local source_dir=$1
  local resume_height=$2
  local dest=$3
  local wanted=${4:-$FILES_PER_SUBSET}
  local linked=0
  local file end
  rm -rf "$dest"
  mkdir -p "$dest"
  while IFS= read -r file; do
    end=$(epoch_end "$file") || continue
    if (( end > resume_height )); then
      ln -s "$file" "$dest/${file##*/}"
      linked=$((linked + 1))
      if (( linked >= wanted )); then
        break
      fi
    fi
  done < <(find "$source_dir" -maxdepth 1 -type f -name '*.cfxpack' -print | sort -V)
  (( linked > 0 )) || return 1
}

expand_backends() {
  local raw=$1
  if [[ $raw == "all" ]]; then
    printf '%s\n' minimal minimal-verify lmdb lmdb-verify
    return
  fi
  split_csv_or_words "$raw" | tr ' ' '\n' | sed '/^$/d'
}

build_backend() {
  local backend=$1
  local dest="$OUT_ROOT/bin/$backend/cfx-replay-exec"
  if [[ -x $dest ]]; then
    printf '%s\n' "$dest"
    return
  fi
  mkdir -p "${dest%/*}"
  local features
  case "$backend" in
    minimal) features=backend-minimal-mpt ;;
    minimal-verify) features=backend-minimal-mpt,verify-incremental ;;
    lmdb) features=backend-minimal-mpt-lmdb ;;
    lmdb-verify) features=backend-minimal-mpt-lmdb,verify-incremental ;;
    *) die "unknown backend '$backend' (use minimal, minimal-verify, lmdb, lmdb-verify, or all)" ;;
  esac
  log "building release backend=$backend features=$features"
  (cd "$ORACLE_ROOT" && nice -n "$NICE" cargo build --release -p cfx-replay-data-executor \
    --bin cfx-replay-exec --no-default-features --features "$features")
  cp "$ORACLE_ROOT/target/release/cfx-replay-exec" "$dest"
  printf '%s\n' "$dest"
}

record() {
  local backend=$1 case_id=$2 phase=$3 status=$4 height=$5 log_path=$6
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$backend" "$case_id" "$phase" "$status" "$height" "$log_path" >> "$SUMMARY"
}

extract_written_height() {
  local log_path=$1
  grep -E 'wrote checkpoint .* at height [0-9]+' "$log_path" \
    | tail -1 \
    | sed -E 's/.* at height ([0-9]+).*/\1/'
}

run_replay_phase() {
  local bin=$1 backend=$2 case_id=$3 phase=$4 input_dir=$5 checkpoint=$6
  local log_path="$OUT_ROOT/logs/${backend}_${case_id}_${phase}.log"
  log "run backend=$backend case=$case_id phase=$phase input=$input_dir checkpoint=$checkpoint"
  set +e
  timeout "$TIMEOUT" nice -n "$NICE" "$bin" \
    --input "$input_dir" \
    --config "$CONFIG_PATH" \
    --checkpoint "$checkpoint" \
    --checkpoint-every-groups "$CKPT_GROUPS" \
    --checkpoint-every-seconds 3600 \
    --stop-after-checkpoint \
    --max-mismatches "$MAX_MISMATCHES" \
    --anomaly-streak "$ANOMALY_STREAK" \
    >"$log_path" 2>&1
  local status=$?
  set -e
  local height=""
  height=$(extract_written_height "$log_path" || true)
  if (( status == 0 )) && [[ -n $height && -s $checkpoint ]]; then
    record "$backend" "$case_id" "$phase" ok "$height" "$log_path"
    printf '%s\n' "$height"
    return 0
  fi
  record "$backend" "$case_id" "$phase" "fail:$status" "${height:-unknown}" "$log_path"
  log "phase failed; see $log_path"
  return "$status"
}

prepare_seed_checkpoint() {
  local seed=$1 dest=$2
  if [[ -z $seed ]]; then
    rm -f "$dest"
    return
  fi
  if [[ $seed == *.zst ]]; then
    zstd -q -d -f -o "$dest" "$seed"
  else
    cp "$seed" "$dest"
  fi
}

add_case() {
  local id=$1 height=$2 pack_dir=$3 seed=${4:-}
  printf '%s\t%s\t%s\t%s\n' "$id" "$height" "$pack_dir" "$seed" >> "$OUT_ROOT/cases.tsv"
}

CONFIG_PATH=$(resolve_config) || {
  skip "no replay config found under $DATA_ROOT/replay-checkpoint"
  log "summary: $SUMMARY"
  exit 0
}
log "using config $CONFIG_PATH"

: > "$OUT_ROOT/cases.tsv"

genesis_pack_dir=$(find_pack_dir_for_height 0 || true)
if [[ -n ${genesis_pack_dir:-} ]]; then
  add_case "genesis_${genesis_pack_dir##*/}" 0 "$genesis_pack_dir" ""
else
  skip "no packed cfxpack directory found for genesis"
fi

if [[ -d $BACKUP_DIR ]]; then
  added=0
  while IFS= read -r ckpt; do
    height=$(checkpoint_height_from_name "$ckpt" || true)
    [[ -n ${height:-} ]] || continue
    pack_dir=$(find_pack_dir_for_height "$height" || true)
    if [[ -z ${pack_dir:-} ]]; then
      skip "no cfxpack input found after checkpoint height $height ($ckpt)"
      continue
    fi
    add_case "backup_${height}" "$height" "$pack_dir" "$ckpt"
    added=$((added + 1))
    if (( added >= BACKUP_LIMIT )); then
      break
    fi
  done < <(find "$BACKUP_DIR" -maxdepth 1 -type f \( -name 'ckpt_*.bin' -o -name 'ckpt_*.bin.zst' \) -print | sort -V)
  (( added > 0 )) || skip "no usable backup checkpoints in $BACKUP_DIR"
else
  skip "backup checkpoint directory missing: $BACKUP_DIR"
fi

if [[ ! -s "$OUT_ROOT/cases.tsv" ]]; then
  skip "no runnable cases"
  log "summary: $SUMMARY"
  exit 0
fi

failures=0
while IFS=$'\t' read -r case_id seed_height pack_dir seed_ckpt; do
  for backend in $(expand_backends "$BACKENDS"); do
    bin=$(build_backend "$backend")
    case_dir="$OUT_ROOT/cases/${backend}_${case_id}"
    mkdir -p "$case_dir"
    ckpt="$case_dir/ckpt.bin"
    prepare_seed_checkpoint "$seed_ckpt" "$ckpt"

    input1="$case_dir/input_initial"
    if ! make_subset_dir "$pack_dir" "$seed_height" "$input1" "$FILES_PER_SUBSET"; then
      skip "case=$case_id backend=$backend: cannot build initial input subset from $pack_dir after $seed_height"
      record "$backend" "$case_id" initial skipped unknown ""
      continue
    fi

    if ! height1=$(run_replay_phase "$bin" "$backend" "$case_id" initial "$input1" "$ckpt"); then
      failures=$((failures + 1))
      continue
    fi

    input2="$case_dir/input_resume"
    if ! make_subset_dir "$pack_dir" "$height1" "$input2" "$FILES_PER_SUBSET"; then
      skip "case=$case_id backend=$backend: cannot build resume input subset from $pack_dir after $height1"
      record "$backend" "$case_id" resume skipped "$height1" ""
      continue
    fi

    if ! run_replay_phase "$bin" "$backend" "$case_id" resume "$input2" "$ckpt" >/dev/null; then
      failures=$((failures + 1))
      continue
    fi
  done
done < "$OUT_ROOT/cases.tsv"

log "summary: $SUMMARY"
if (( failures > 0 )); then
  die "$failures replay phase(s) failed"
fi
log "all replay smoke phases passed or were skipped"
