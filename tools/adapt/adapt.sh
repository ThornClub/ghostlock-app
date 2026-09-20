#!/usr/bin/env bash
#
# Adapt the vendor packages listed in tools/adapt/packages.json into src/kernels/.
#
# For every entry this runs the host offset extractor with --register, records
# the outcome, and appends a Markdown report to $SUMMARY_FILE. Entries are
# processed one at a time because src/kernels/offsets.h is a shared file and
# parallel writers would race on it.
#
# Exit status:
#   0  normal run (failed packages are reported, see FAIL_ON_ERROR)
#   1  environment failure (missing/unparsable package list, missing extractor)
#      or at least one failed package while FAIL_ON_ERROR=true
#
# A package that cannot be adapted is NOT fatal by default: vendor download
# links expire regularly and that must not block the remaining packages.

set -uo pipefail

PACKAGES="${PACKAGES:-tools/adapt/packages.json}"
EXTRACT_BIN="${EXTRACT_BIN:-tools/extract_rs/target/release/ghostlock-extract}"
WORKDIR="${WORKDIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ghostlock-adapt}"
SUMMARY_FILE="${SUMMARY_FILE:-${GITHUB_STEP_SUMMARY:-/dev/stdout}}"
FAIL_ON_ERROR="${FAIL_ON_ERROR:-false}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -f "$PACKAGES" ]; then
  echo "adapt: ERROR: package list not found: $PACKAGES" >&2
  exit 1
fi

if [ ! -x "$EXTRACT_BIN" ]; then
  echo "adapt: ERROR: extractor not found or not executable: $EXTRACT_BIN" >&2
  echo "adapt: build it with: cargo build --release --features http --manifest-path tools/extract_rs/Cargo.toml" >&2
  exit 1
fi

# Emit one record per entry, fields joined by ASCII 0x1F (unit separator).
# Not a tab: tab is IFS whitespace, so `read` collapses empty fields and a missing
# xbl_config would silently shift `notes` into --xbl-config.
# sys.stdout.buffer.write avoids Windows CRLF translation, which would leave a
# stray \r in the last field.
entries="$("$PYTHON_BIN" - "$PACKAGES" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, json.JSONDecodeError) as err:
    raise SystemExit(f"adapt: ERROR: cannot parse {path}: {err}")

packages = data.get("packages") if isinstance(data, dict) else None
if not isinstance(packages, list):
    raise SystemExit(f"adapt: ERROR: {path} must contain a top-level 'packages' array")

for index, package in enumerate(packages):
    if not isinstance(package, dict):
        raise SystemExit(f"adapt: ERROR: packages[{index}] must be an object")
    name = package.get("name")
    image = package.get("image")
    if not isinstance(name, str) or not name:
        raise SystemExit(f"adapt: ERROR: packages[{index}].name is required")
    if not isinstance(image, str) or not image:
        raise SystemExit(f"adapt: ERROR: packages[{index}].image is required")
    xbl_config = package.get("xbl_config") or ""
    notes = package.get("notes") or ""
    for field, value in (("name", name), ("image", image), ("xbl_config", xbl_config), ("notes", notes)):
        if not isinstance(value, str):
            raise SystemExit(f"adapt: ERROR: packages[{index}].{field} must be a string")
        # 0x1F is the record delimiter and newlines would split a record.
        if any(char in value for char in ("\x1f", "\n", "\r")):
            raise SystemExit(
                f"adapt: ERROR: packages[{index}].{field} must not contain control characters"
            )
    record = "\x1f".join([name, image, xbl_config, notes]) + "\n"
    sys.stdout.buffer.write(record.encode("utf-8"))
PY
)" || exit 1

names=()
images=()
xbl_configs=()
notes_list=()
while IFS=$'\x1f' read -r name image xbl_config notes; do
  [ -n "$name" ] || continue
  notes="${notes%$'\r'}"  # defensive: tolerate a CRLF-emitting interpreter
  names+=("$name")
  images+=("$image")
  xbl_configs+=("$xbl_config")
  notes_list+=("$notes")
done <<< "$entries"

total=${#names[@]}
mkdir -p "$WORKDIR"

rows=()
attention=()
warning_lines=()
readme_rows=()
failed_count=0

describe_exit() {
  case "$1" in
    2) echo "generic parse failure" ;;
    3) echo "pselect route not feasible" ;;
    4) echo "missing required offsets" ;;
    5) echo "kallsyms recovery failed" ;;
    6) echo "kernel already fixed the vulnerability" ;;
    *) echo "unexpected exit code" ;;
  esac
}

for index in "${!names[@]}"; do
  name="${names[$index]}"
  image="${images[$index]}"
  xbl_config="${xbl_configs[$index]}"
  notes="${notes_list[$index]}"

  # Fresh scratch dir per entry: full OTAs are large and the runner disk is small.
  find "$WORKDIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  stderr_file="$WORKDIR/stderr.log"

  echo "adapt: adapting '$name' ($image)"
  started=$(date +%s)
  # --work-dir keeps the extractor's payload scratch data inside the directory
  # that is wiped before the next entry; without it the extractor writes
  # ghostlock-payload-<pid>/ under the runner's system temp dir and those
  # directories accumulate for the whole run.
  if [ -n "$xbl_config" ]; then
    "$EXTRACT_BIN" "$image" --xbl-config "$xbl_config" --work-dir "$WORKDIR" --register 2>"$stderr_file"
  else
    "$EXTRACT_BIN" "$image" --work-dir "$WORKDIR" --register 2>"$stderr_file"
  fi
  code=$?
  duration=$(( $(date +%s) - started ))
  cat "$stderr_file"

  # Classification (evidence: tools/extract_rs/src/main.rs:456-486 and the
  # exit-code mapping at main.rs:541-552).
  #   0 + "wrote "             -> added (header written, include inserted)
  #   0 + "already registered" -> already_registered (no duplicate table)
  #   0 otherwise              -> ok_unknown (needs a manual look)
  #   6                        -> already_fixed (conclusive, not a failure)
  #   2/3/4/5 or anything else -> failed
  # "wrote " is checked first: a run that rewrites a header can still print
  # "warning: ... is already registered with ..." (report.rs:368), while an
  # early "already registered" return never prints "wrote ".
  if [ "$code" -eq 0 ]; then
    if grep -q "wrote " "$stderr_file"; then
      status="added"
    elif grep -q "already registered" "$stderr_file"; then
      status="already_registered"
    else
      status="ok_unknown"
    fi
  elif [ "$code" -eq 6 ]; then
    status="already_fixed"
  else
    status="failed"
  fi

  # Recover the registered release key for the README hints.
  release=""
  case "$status" in
    added)
      wrote_line=$(grep -m1 "^wrote " "$stderr_file" || true)
      if [ -n "$wrote_line" ]; then
        release="${wrote_line#wrote }"
        release="${release%/offsets.h}"
        release="${release##*/}"
      fi
      ;;
    already_registered)
      release=$(sed -n "s/^info: \(.*\) already registered.*/\1/p" "$stderr_file" | head -n1)
      ;;
  esac

  if [ -n "$notes" ]; then
    label="$name ($notes)"
  else
    label="$name"
  fi
  rows+=("| $label | $status | $code | $duration |")

  if [ "$status" = "failed" ]; then
    failed_count=$((failed_count + 1))
    attention+=("- \`$name\`: failed (exit $code: $(describe_exit "$code"))")
  elif [ "$status" = "already_fixed" ]; then
    attention+=("- \`$name\`: already fixed (exit 6: $(describe_exit 6)) - conclusive, not a failure")
  elif [ "$status" = "ok_unknown" ]; then
    attention+=("- \`$name\`: exit 0 without a recognized message; inspect the job log")
  fi

  warnings_text=$(grep "^warning:" "$stderr_file" || true)
  if [ -n "$warnings_text" ]; then
    while IFS= read -r warning; do
      warning_lines+=("- \`$name\`: $warning")
    done <<< "$warnings_text"
  fi

  if [ "$status" = "added" ] || [ "$status" = "already_registered" ]; then
    if [ -n "$release" ]; then
      readme_rows+=("| \`$release\` | $name |")
    else
      readme_rows+=("| (release not recovered) | $name |")
    fi
  fi

  echo "RESULT $name $status $code $duration"
done

{
  echo "## Kernel adaptation report"
  echo
  if [ "$total" -eq 0 ]; then
    echo "The package list \`$PACKAGES\` is empty; nothing to adapt."
  else
    echo "| Package | Status | Exit code | Duration (s) |"
    echo "|---|---|---|---|"
    printf "%s\n" "${rows[@]}"
    echo
    echo "Status legend:"
    echo
    echo "- \`added\` - new kernel registered (exit 0, header written)."
    echo "- \`already_registered\` - release already present, nothing written (exit 0)."
    echo "- \`already_fixed\` - exit 6, the kernel already contains the fix; conclusive, not a failure."
    echo "- \`failed\` - exit 2 (generic parse failure), 3 (pselect route infeasible), 4 (missing required offsets) or 5 (kallsyms recovery failed)."
    echo "- \`ok_unknown\` - exit 0 without a recognized message; inspect the job log."
    echo
    echo "Adaptations are **not verified on a real device**; smoke-test before announcing support."
  fi
  echo
  echo "### Needs attention"
  echo
  if [ "${#attention[@]}" -eq 0 ]; then
    echo "None."
  else
    printf "%s\n" "${attention[@]}"
  fi
  echo
  echo "### Extractor warnings"
  echo
  if [ "${#warning_lines[@]}" -eq 0 ]; then
    echo "None."
  else
    printf "%s\n" "${warning_lines[@]}"
  fi
  echo
  echo "### README device tables"
  echo
  if [ "${#readme_rows[@]}" -eq 0 ]; then
    echo "No usable rows; nothing to paste."
  else
    echo "Add these rows to README.md and README_ZH.md by hand (\`--register\` does not update them):"
    echo
    echo "| Kernel (uname -r) | Device |"
    echo "|---|---|"
    printf "%s\n" "${readme_rows[@]}"
  fi
} >> "$SUMMARY_FILE"

echo "adapt: finished: $total package(s), $failed_count failed"
if [ "$FAIL_ON_ERROR" = "true" ] && [ "$failed_count" -gt 0 ]; then
  echo "adapt: FAIL_ON_ERROR=true and $failed_count package(s) failed" >&2
  exit 1
fi
exit 0
