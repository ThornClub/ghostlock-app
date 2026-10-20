#!/usr/bin/env bash
#
# Adapt one batch of vendor packages into app/src/main/assets/kernel_profiles/.
#
# The package list is JSON with a top-level "packages" array; every entry has
# six string fields joined into 0x1F records below:
#   name, image, xbl_config, notes, release, kind
# The list is produced either by tools/adapt/plan.py (device list + daily
# polling) or directly by the workflow for an ad-hoc dispatch. This script is
# the only place that talks to the extractor on purpose, so all three entry
# points behave identically.
#
# For every entry it normalizes the declared input (gh:// release asset fetch,
# remote boot.img download, container unpacking - see "input normalization"),
# runs the host offset extractor with --format conf, registers the produced
# profile in kernel_profiles/index.conf, records the outcome, and appends a
# Markdown report to $SUMMARY_FILE. Entries are processed one at a time because
# index.conf is a shared file and parallel writers would race on it.
#
# Exit status:
#   0  normal run (failed packages are reported, see FAIL_ON_ERROR)
#   1  environment failure (missing/unparsable package list, missing extractor)
#      or at least one failed/unsupported package while FAIL_ON_ERROR=true
#
# A package that cannot be adapted is NOT fatal by default: vendor download
# links expire regularly and that must not block the remaining packages.

set -uo pipefail

# PACKAGES has no default: tools/adapt/devices.json is not in this shape.
# Generate the list with tools/adapt/plan.py (the workflow does) and point
# PACKAGES at the result.
PACKAGES="${PACKAGES:-}"
EXTRACT_BIN="${EXTRACT_BIN:-tools/extract_rs/target/release/ghostlock-extract}"
WORKDIR="${WORKDIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ghostlock-adapt}"
SUMMARY_FILE="${SUMMARY_FILE:-${GITHUB_STEP_SUMMARY:-/dev/stdout}}"
FAIL_ON_ERROR="${FAIL_ON_ERROR:-false}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CURL_BIN="${CURL_BIN:-curl}"
GH_BIN="${GH_BIN:-gh}"
# Repository used to resolve gh:// release assets. The workflow exports
# GITHUB_REPOSITORY; the fallback keeps local runs working.
GH_REPO="${GITHUB_REPOSITORY:-ThornClub/ghostlock-app}"
# Root used by the checks adapt.sh performs itself: the `release` early-skip
# existence check and the README coverage scan. The extractor writes to an
# explicit --out path, so in CI this stays "." while the stub tests can point
# it at a temporary tree.
REPO_ROOT="${REPO_ROOT:-.}"
# Bundled profile registry. The extractor no longer knows the repository
# layout: it writes a self-contained HOCON profile to --out, and this script
# owns both the file placement and the index.conf registration.
PROFILE_DIR="$REPO_ROOT/app/src/main/assets/kernel_profiles"
PROFILE_INDEX="$PROFILE_DIR/index.conf"

if [ -z "$PACKAGES" ] || [ ! -f "$PACKAGES" ]; then
  echo "adapt: ERROR: package list not found: ${PACKAGES:-<PACKAGES unset>}" >&2
  echo "adapt: generate one from tools/adapt/devices.json with tools/adapt/plan.py, or pass PACKAGES=<file>" >&2
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

# Empty means auto, matching tools/adapt/plan.py.
ALLOWED_KINDS = ("", "auto", "ota", "payload", "boot", "image")

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
    # `is None` rather than `or ""`: a falsy non-string value (false/0/[]/{})
    # must reach the type check below instead of being folded into "absent".
    raw_xbl = package.get("xbl_config")
    raw_notes = package.get("notes")
    raw_release = package.get("release")
    raw_kind = package.get("kind")
    xbl_config = "" if raw_xbl is None else raw_xbl
    notes = "" if raw_notes is None else raw_notes
    release = "" if raw_release is None else raw_release
    kind = "" if raw_kind is None else raw_kind
    # headers travel as "name\x1dvalue" pairs joined by \x1e; adapt.sh turns them
    # into curl -H arguments. They cannot ride along with the record delimiter
    # itself, so control characters are rejected here.
    raw_headers = package.get("headers")
    if raw_headers is None:
        raw_headers = {}
    if not isinstance(raw_headers, dict):
        raise SystemExit(f"adapt: ERROR: packages[{index}].headers must be an object")
    header_parts = []
    for header_name, header_value in sorted(raw_headers.items()):
        if not isinstance(header_name, str) or not header_name or not isinstance(header_value, str):
            raise SystemExit(
                f"adapt: ERROR: packages[{index}].headers must map non-empty strings to strings"
            )
        if any(char in header_name + header_value for char in ("\x1d", "\x1e", "\x1f", "\n", "\r")):
            raise SystemExit(
                f"adapt: ERROR: packages[{index}].headers must not contain control characters"
            )
        header_parts.append(header_name + "\x1d" + header_value)
    headers = "\x1e".join(header_parts)
    for field, value in (
        ("name", name),
        ("image", image),
        ("xbl_config", xbl_config),
        ("notes", notes),
        ("release", release),
        ("kind", kind),
    ):
        if not isinstance(value, str):
            raise SystemExit(f"adapt: ERROR: packages[{index}].{field} must be a string")
        # 0x1F is the record delimiter and newlines would split a record.
        if any(char in value for char in ("\x1f", "\n", "\r")):
            raise SystemExit(
                f"adapt: ERROR: packages[{index}].{field} must not contain control characters"
            )
    if kind not in ALLOWED_KINDS:
        raise SystemExit(
            f"adapt: ERROR: packages[{index}].kind must be one of auto, ota, payload, boot, image (got {kind!r})"
        )
    record = "\x1f".join([name, image, xbl_config, notes, release, kind, headers]) + "\n"
    sys.stdout.buffer.write(record.encode("utf-8"))
PY
)" || exit 1

names=()
images=()
xbl_configs=()
notes_list=()
releases=()
kinds=()
headers_blobs=()
while IFS=$'\x1f' read -r name image xbl_config notes release kind headers_blob; do
  [ -n "$name" ] || continue
  notes="${notes%$'\r'}"  # defensive: tolerate a CRLF-emitting interpreter
  headers_blob="${headers_blob%$'\r'}"  # headers is the last field
  names+=("$name")
  images+=("$image")
  xbl_configs+=("$xbl_config")
  notes_list+=("$notes")
  releases+=("$release")
  kinds+=("$kind")
  headers_blobs+=("$headers_blob")
done <<< "$entries"

total=${#names[@]}

rows=()
attention=()
warning_lines=()
readme_rows=()
failed_count=0

# ---------------------------------------------------------------------------
# Input normalization
#
# Every declared input must become either an http(s) URL the extractor can
# range-read (full OTA ZIP / payload.bin) or a local file path. Remote boot
# images cannot be handed over directly because payload.rs:11-15 treats every
# http(s) string as a payload, so an URL pointing at a bare boot.img derails in
# the payload reader. Rules (design.md section 3):
#
#   gh://<tag>/<asset>        fetch with `gh release download` (drafts work)
#   kind=boot|image           download first, then pass the local path
#   kind=ota|payload          pass through unchanged (URL or local path)
#   kind=auto/empty           infer from the URL path (query string ignored):
#                               .zip / .bin               -> pass through
#                               .img/.image/.lz4/.gz      -> download first
#                               anything else             -> probe Content-Type;
#                                                            image/* or gzip
#                                                            means download
#   local path                pass through (must exist)
#
# help globals set by the resolve / unpack / prepare helpers below:
#   resolved            usable input produced by resolve_input
#   resolve_error       human-readable failure reason
#   resolve_unsupported "true" when the container itself is unsupported
#   resolve_listing     first 20 unpacked entries, for the report
#   unpacked_path       image path after container inspection
#   prepared_image      extractor image input
#   prepared_xbl        extractor --xbl-config input ("" when unused)
#   prepare_error       failure reason surfaced in the report
#   prepare_unsupported "true" when the input container is unsupported
#   prepare_listing     unpacked content summary for the report

log_tail() {
  # Last few captured stderr lines on a single line, capped so a chatty tool
  # (zipinfo, curl with an HTML error page) cannot flood the report.
  tail -n 5 "$1" 2>/dev/null | tr '\n' ' ' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | cut -c1-300
}

# Basename of an URL, query string and hostile characters removed.
safe_basename() {
  local value="$1" base
  base="${value%%\?*}"
  base="${base%%#*}"
  base="${base##*/}"
  base="${base//[^A-Za-z0-9._-]/_}"
  [ -n "$base" ] || base="input"
  printf '%s' "$base"
}

# Release key carried by a generated profile. The extractor renders
# `release = "<uname -r>"` as a top-level line; anchoring on line start keeps
# the leading comment block and any nested keys out of the match.
profile_release() {
  sed -n 's/^release = "\(.*\)"$/\1/p' "$1" | head -n1
}

# Publish one generated profile: place it under its release name and register
# it in index.conf. The extractor only writes a self-contained HOCON file, so
# both steps belong here. Sets release / register_status ("added" or
# "already_registered") / register_error.
#
# index.conf holds a single `profiles = [ ... ]` array closed by the only line
# that is exactly `]`, entries have no trailing comma (HOCON allows omitting
# it), so inserting one equally formatted line before that bracket keeps the
# file valid without parsing HOCON here.
register_profile() {
  local tmp="$1" target entry file_existed=0
  release=""
  register_status=""
  register_error=""

  release=$(profile_release "$tmp")
  if [ -z "$release" ]; then
    register_error="the generated profile carries no release line"
    return 1
  fi

  target="$PROFILE_DIR/$release.conf"
  if [ -e "$target" ]; then
    # Re-run: the profile is already published. The index entry is still
    # checked below, so a profile left behind by a failed registration (or by a
    # hand-written file) heals instead of staying invisible to the app.
    file_existed=1
    rm -f "$tmp"
  else
    if ! mkdir -p "$PROFILE_DIR"; then
      register_error="cannot create $PROFILE_DIR"
      return 1
    fi
    if ! mv "$tmp" "$target"; then
      register_error="cannot move the generated profile to $target"
      return 1
    fi
  fi

  if grep -qF "release = \"$release\"" "$PROFILE_INDEX" 2>/dev/null; then
    if [ "$file_existed" -eq 1 ]; then
      register_status="already_registered"
    else
      register_status="added"
    fi
    return 0
  fi

  # Registration is the last step, so every failure from here rolls the profile
  # back: a file without an index entry is invisible to the app, and leaving it
  # behind would let a later entry's successful run carry it into the PR.
  entry="  { release = \"$release\", file = \"$release.conf\" }"
  # The `cr` branch keeps the inserted line consistent with its neighbours when
  # awk preserves CR (a CRLF working copy). MSYS awk strips CR on input, so such
  # a checkout is rewritten with LF here; git's `* text=auto` normalization keeps
  # the committed diff to the single added line either way.
  if ! awk -v entry="$entry" -v cr="$(printf '\r')" '
    { if (!inserted && ($0 == "]" || $0 == "]" cr)) {
        print entry ($0 == "]" cr ? cr : "")
        inserted = 1
      }
      print }
    END { exit inserted ? 0 : 3 }
  ' "$PROFILE_INDEX" > "$PROFILE_INDEX.tmp"; then
    rm -f "$PROFILE_INDEX.tmp"
    [ "$file_existed" -eq 1 ] || rm -f "$target"
    register_error="cannot insert $release into $PROFILE_INDEX (no top-level ] array close)"
    return 1
  fi
  if ! mv "$PROFILE_INDEX.tmp" "$PROFILE_INDEX"; then
    rm -f "$PROFILE_INDEX.tmp"
    [ "$file_existed" -eq 1 ] || rm -f "$target"
    register_error="cannot replace $PROFILE_INDEX"
    return 1
  fi
  register_status="added"
  return 0
}

# Turn the per-entry header blob ("name\x1dvalue" pairs joined by \x1e) into
# curl -H arguments. The blob is rebuilt for every entry, so the array is
# cleared here rather than appended to. Note: these headers reach curl's own
# requests (probe and downloads); the extractor's HTTP path for OTA / payload
# has no way to carry them, which prepare_input reports when it matters.
split_headers() {
  CURL_HEADER_ARGS=()
  [ -n "$1" ] || return 0
  local pair name value
  while IFS= read -r pair; do
    [ -n "$pair" ] || continue
    name="${pair%%$'\x1d'*}"
    value="${pair#*$'\x1d'}"
    CURL_HEADER_ARGS+=(-H "$name: $value")
  # Trailing newline matters: `while read` skips a final line without one, which
  # would silently drop the last (sorted) header.
  done < <(printf '%s\n' "$1" | tr $'\x1e' '\n')
}

# Download $2 into $WORKDIR/downloads; $1 is the role prefix ("image" or
# "xbl_config") so the two downloads cannot collide. Sets: resolved.
download_input() {
  local role="$1" value="$2" out err_file
  out="$WORKDIR/downloads/$role-$(safe_basename "$value")"
  mkdir -p "$WORKDIR/downloads"
  err_file="$WORKDIR/$role-curl.log"
  if ! "$CURL_BIN" -fL --retry 3 --retry-delay 5 "${CURL_HEADER_ARGS[@]}" -o "$out" "$value" 2>"$err_file"; then
    resolve_error="download failed: $(log_tail "$err_file")"
    return 1
  fi
  if [ ! -f "$out" ]; then
    resolve_error="download produced no file: $value"
    return 1
  fi
  resolved="$out"
}

# Content-Type of $1: HEAD first, then a 1-byte ranged GET for CDNs that refuse
# HEAD. Prints nothing when neither attempt yields a usable response.
probe_content_type() {
  local url="$1" headers_file="$WORKDIR/content-type.log" status

  rm -f "$headers_file"
  if "$CURL_BIN" -sSIL --max-time 30 "${CURL_HEADER_ARGS[@]}" -o "$headers_file" "$url" 2>/dev/null; then
    status=$(awk '/^HTTP\//{ code=$2 } END{ print code }' "$headers_file")
    if [ "${status#2}" != "$status" ]; then
      grep -i '^content-type:' "$headers_file" | tail -n 1 | sed -e 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z'
      return 0
    fi
  fi
  rm -f "$headers_file"
  if "$CURL_BIN" -sS -r 0-0 -L --max-time 30 "${CURL_HEADER_ARGS[@]}" -D "$headers_file" -o /dev/null "$url" 2>/dev/null; then
    status=$(awk '/^HTTP\//{ code=$2 } END{ print code }' "$headers_file")
    if [ "${status#2}" != "$status" ]; then
      grep -i '^content-type:' "$headers_file" | tail -n 1 | sed -e 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z'
      return 0
    fi
  fi
  return 0
}

# Resolve one declared value into $resolved. $1 role, $2 value, $3 effective kind.
resolve_input() {
  local role="$1" value="$2" kind="$3"
  resolved=""
  resolve_error=""
  resolve_unsupported="false"
  resolve_listing=""

  if [ -z "$value" ]; then
    resolve_error="input is empty"
    return 1
  fi

  # Proprietary containers (design.md section 6): no parser exists and a failed
  # unpack would only produce a cryptic error, so flag them upfront.
  if [ "$role" = "image" ]; then
    local lower="${value%%\?*}"
    lower="${lower,,}"
    case "$lower" in
      *.ozip)
        resolve_error="unsupported container format (.ozip)"
        resolve_unsupported="true"
        resolve_listing="OPPO/Realme encrypted OTA"
        return 1
        ;;
      *.ofp)
        resolve_error="unsupported container format (.ofp)"
        resolve_unsupported="true"
        resolve_listing="OPPO firmware image"
        return 1
        ;;
      *.app)
        resolve_error="unsupported container format (update.app)"
        resolve_unsupported="true"
        resolve_listing="Huawei update.app"
        return 1
        ;;
    esac
  fi

  case "$value" in
    gh://*)
      local spec="${value#gh://}" tag asset err_file
      tag="${spec%%/*}"
      asset="${spec#*/}"
      if [ -z "$tag" ] || [ "$asset" = "$spec" ] || [ -z "$asset" ]; then
        resolve_error="malformed gh:// input (expected gh://<tag>/<asset>): $value"
        return 1
      fi
      mkdir -p "$WORKDIR/downloads"
      err_file="$WORKDIR/$role-gh.log"
      if ! "$GH_BIN" release download "$tag" -R "$GH_REPO" -p "$asset" -D "$WORKDIR/downloads" 2>"$err_file"; then
        resolve_error="gh release download failed for '$tag/$asset': $(log_tail "$err_file")"
        return 1
      fi
      if [ ! -f "$WORKDIR/downloads/$asset" ]; then
        resolve_error="release '$tag' has no asset named '$asset'"
        return 1
      fi
      resolved="$WORKDIR/downloads/$asset"
      ;;
    http://* | https://* | file://*)
      case "$role:$kind" in
        xbl_config:*)
          # --xbl-config only accepts a local path, so a remote xbl_config is
          # downloaded whatever the entry's kind says.
          download_input "$role" "$value" || return 1
          ;;
        image:boot | image:image)
          download_input "$role" "$value" || return 1
          ;;
        image:ota | image:payload)
          # A full OTA / payload: the extractor range-reads it, so never pull it
          # down here.
          resolved="$value"
          ;;
        *)
          # kind=auto (or explicitly auto): infer from the URL path.
          local path_only content_type
          path_only="${value%%\?*}"
          case "$path_only" in
            *.zip | *.bin)
              resolved="$value"
              ;;
            *.img | *.image | *.lz4 | *.gz)
              # Covers boot.img, raw Image, Image.gz and LZ4 images alike.
              download_input "$role" "$value" || return 1
              ;;
            *)
              content_type="$(probe_content_type "$value")"
              case "$content_type" in
                image/* | application/gzip | application/x-gzip)
                  download_input "$role" "$value" || return 1
                  ;;
                *)
                  # Unknown suffix and no image content type: hand the URL to
                  # the extractor and let it report its own error.
                  resolved="$value"
                  ;;
              esac
              ;;
          esac
          ;;
      esac
      ;;
    *)
      if [ ! -f "$value" ]; then
        resolve_error="local input not found: $value"
        return 1
      fi
      resolved="$value"
      ;;
  esac
  return 0
}

# Inspect a local archive (design.md section 5): a zip / tar(.md5) without
# payload.bin is a "shell archive" around boot.img and is unpacked here.
# Remote archives are left to the extractor, which range-reads an OTA instead
# of downloading gigabytes. `kind` short-circuits the inspection: an explicit
# ota/payload declaration means "hand this to the extractor untouched", which
# is the documented escape hatch for a file whose extension lies.
# Sets unpacked_path, or returns 1 with the resolve_* globals filled in.
unpack_container() {
  local path="$1" kind="$2" lower archive_kind=""
  unpacked_path="$path"
  case "$kind" in
    ota | payload)
      return 0
      ;;
  esac
  lower="${path,,}"
  case "$lower" in
    *.zip)
      archive_kind="zip"
      ;;
    *.tar | *.tar.md5 | *.tgz | *.tar.gz)
      archive_kind="tar"
      ;;
    *)
      return 0
      ;;
  esac
  [ -f "$path" ] || return 0

  local listing
  if [ "$archive_kind" = "zip" ]; then
    if ! listing="$(unzip -Z1 "$path" 2>"$WORKDIR/unpack.log")"; then
      # Deliberately no tool output here: zipinfo/unzip dump whole paragraphs.
      # A file that cannot be read as an archive may simply not be one, so point
      # at the escape hatch instead of pretending we know what it is.
      resolve_error="'$path' is not a readable zip archive; if it is not an archive, declare kind=ota (or payload) to hand it to the extractor unchanged"
      return 1
    fi
  else
    if ! listing="$(tar tf "$path" 2>"$WORKDIR/unpack.log")"; then
      resolve_error="'$path' is not a readable tar archive; if it is not an archive, declare kind=ota (or payload) to hand it to the extractor unchanged"
      return 1
    fi
  fi

  if printf '%s\n' "$listing" | grep -qE '(^|/)payload\.bin$'; then
    # A real OTA: hand the archive over untouched.
    return 0
  fi

  local dest="$WORKDIR/unpacked"
  mkdir -p "$dest"
  if [ "$archive_kind" = "zip" ]; then
    if ! unzip -o -q "$path" -d "$dest" 2>"$WORKDIR/unpack.log"; then
      resolve_error="cannot unpack the zip archive: $(log_tail "$WORKDIR/unpack.log")"
      return 1
    fi
  else
    if ! tar xf "$path" -C "$dest" 2>"$WORKDIR/unpack.log"; then
      resolve_error="cannot unpack the tar archive: $(log_tail "$WORKDIR/unpack.log")"
      return 1
    fi
  fi

  # One directory level deep is allowed; bootloader*.img is never the kernel.
  local candidates boot
  candidates="$(find "$dest" -mindepth 1 -maxdepth 2 -type f -iname 'boot*.img' ! -iname 'bootloader*' | sort)"
  boot=""
  if [ -n "$candidates" ]; then
    boot="$(printf '%s\n' "$candidates" | grep -E '/boot\.img$' | head -n 1 || true)"
    if [ -z "$boot" ]; then
      # No plain boot.img: take the first variant (boot_a.img, boot-5.10.img).
      boot="$(printf '%s\n' "$candidates" | head -n 1)"
    fi
  fi
  if [ -z "$boot" ]; then
    resolve_unsupported="true"
    resolve_error="the archive contains no usable boot.img"
    resolve_listing="$(find "$dest" -mindepth 1 -maxdepth 2 | sort | sed -e "s#^$dest/##" | head -n 20 | paste -sd ', ' -)"
    [ -n "$resolve_listing" ] || resolve_listing="(empty archive)"
    return 1
  fi
  unpacked_path="$boot"
  return 0
}

# Normalize one entry's declared inputs. $1 name, $2 image, $3 xbl_config, $4 kind.
prepare_input() {
  local name="$1" image="$2" xbl="$3" kind="$4" image_path
  prepared_image=""
  prepared_xbl=""
  prepare_error=""
  prepare_unsupported="false"
  prepare_listing=""

  if ! resolve_input image "$image" "$kind"; then
    prepare_error="$resolve_error"
    prepare_unsupported="$resolve_unsupported"
    prepare_listing="$resolve_listing"
    return 1
  fi
  image_path="$resolved"

  if [ -n "$xbl" ]; then
    # The same fetch rules apply to xbl_config; container unpacking does not
    # (an xbl_config is never an archive).
    if ! resolve_input xbl_config "$xbl" boot; then
      prepare_error="xbl_config: $resolve_error"
      return 1
    fi
    prepared_xbl="$resolved"
  fi

  if ! unpack_container "$image_path" "$kind"; then
    prepare_error="$resolve_error"
    prepare_unsupported="$resolve_unsupported"
    prepare_listing="$resolve_listing"
    return 1
  fi
  prepared_image="$unpacked_path"
  return 0
}

# ---------------------------------------------------------------------------

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
  release_field="${releases[$index]}"
  kind="${kinds[$index]}"

  if [ -n "$notes" ]; then
    label="$name ($notes)"
  else
    label="$name"
  fi

  # Early skip: a maintained `release` field turns the entry into a pure
  # existence check in the registry, so a repeated GB-sized download and the
  # extractor run are avoided entirely. No scratch dir, no extractor call.
  # The index entry is checked too: a profile left behind by an interrupted
  # registration would otherwise short-circuit every later run and never become
  # visible to the app.
  if [ -n "$release_field" ] && [ -f "$PROFILE_DIR/$release_field.conf" ] &&
    grep -qF "release = \"$release_field\"" "$PROFILE_INDEX" 2>/dev/null; then
    echo "adapt: skipping '$name': $release_field is already registered (release field)"
    rows+=("| $label | already_registered (skipped by release field) | 0 | 0 |")
    readme_rows+=("| \`$release_field\` | $name |")
    echo "RESULT $name already_registered 0 0"
    continue
  fi

  # Fresh scratch dir per entry: full OTAs and downloaded images are large and
  # the runner disk is small. The find also drops downloads/ and unpacked/ left
  # by the previous entry. Created lazily so a run consisting only of skips
  # leaves no scratch behind.
  mkdir -p "$WORKDIR"
  find "$WORKDIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  stderr_file="$WORKDIR/stderr.log"

  # Per-entry request headers for curl (probe + downloads).
  split_headers "${headers_blobs[$index]}"

  started=$(date +%s)
  if ! prepare_input "$name" "$image" "$xbl_config" "$kind"; then
    duration=$(( $(date +%s) - started ))
    if [ "$prepare_unsupported" = "true" ]; then
      status="unsupported"
      rows+=("| $label | unsupported | - | $duration |")
      attention+=("- \`$name\`: unsupported input container (${prepare_listing:-unknown content}); extract \`boot.img\` with the vendor tool and re-submit it as a \`boot.img\` URL/path or \`gh://\` asset")
    else
      status="failed"
      rows+=("| $label | failed (input preparation) | - | $duration |")
      attention+=("- \`$name\`: input preparation failed: $prepare_error")
    fi
    echo "RESULT $name $status - $duration"
    failed_count=$((failed_count + 1))
    continue
  fi

  # The extractor range-reads OTA / payload URLs itself and has no way to send
  # custom headers, so an entry that needs them must be fetched by curl first.
  if [ "${#CURL_HEADER_ARGS[@]}" -gt 0 ] && [ "$prepared_image" = "$image" ]; then
    case "$prepared_image" in
      http://* | https://*)
        attention+=("- \`$name\`: request headers are sent by curl only; the extractor reads this URL directly, so declare kind=boot (or image) to download it first if the address needs them")
        ;;
    esac
  fi

  echo "adapt: adapting '$name' ($prepared_image)"
  if [ "$prepared_image" != "$image" ]; then
    echo "adapt: declared input '$image' resolved to '$prepared_image'"
  fi
  # --work-dir keeps the extractor's payload scratch data inside the directory
  # that is wiped before the next entry; without it the extractor writes
  # ghostlock-payload-<pid>/ under the runner's system temp dir and those
  # directories accumulate for the whole run. --format conf makes the extractor
  # emit a self-contained profile instead of a C header: registration moved
  # here because the extractor no longer knows the repository layout.
  tmp_conf="$WORKDIR/$(safe_basename "$prepared_image").profile.conf"
  rm -f "$tmp_conf"
  if [ -n "$prepared_xbl" ]; then
    "$EXTRACT_BIN" "$prepared_image" --xbl-config "$prepared_xbl" --work-dir "$WORKDIR" \
      --format conf --out "$tmp_conf" 2>"$stderr_file"
  else
    "$EXTRACT_BIN" "$prepared_image" --work-dir "$WORKDIR" \
      --format conf --out "$tmp_conf" 2>"$stderr_file"
  fi
  code=$?
  duration=$(( $(date +%s) - started ))
  cat "$stderr_file"

  # Classification. The extractor only reports whether the image could be
  # analysed (exit 0) or that the kernel is already fixed (exit 6); whether the
  # profile is new is decided by register_profile above.
  #   0 + register_status=added     -> added (a profile file or its index entry
  #                                   is new; both end up present)
  #   0 + already_registered       -> already_registered (file and index entry
  #                                   both already existed)
  #   0 otherwise                  -> failed (the profile could not be published)
  #   6                            -> already_fixed (conclusive, not a failure)
  #   2/3/4/5 or anything else     -> failed
  release=""
  register_error=""
  if [ "$code" -eq 0 ]; then
    if register_profile "$tmp_conf"; then
      status="$register_status"
    else
      status="failed"
    fi
  elif [ "$code" -eq 6 ]; then
    status="already_fixed"
  else
    status="failed"
  fi
  # A declared release field that disagrees with the extracted value is surfaced
  # here but never overrides the extractor: the payload metadata is authoritative,
  # the field only exists to skip a repeated download.
  if [ -n "$release_field" ] && [ -n "$release" ] && [ "$release_field" != "$release" ]; then
    attention+=("- \`$name\`: declared release \`$release_field\` does not match the extracted \`$release\`; the extracted value wins")
  fi

  rows+=("| $label | $status | $code | $duration |")

  if [ "$status" = "failed" ]; then
    failed_count=$((failed_count + 1))
    if [ -n "${register_error:-}" ]; then
      attention+=("- \`$name\`: profile not published: $register_error")
    else
      attention+=("- \`$name\`: failed (exit $code: $(describe_exit "$code"))")
    fi
  elif [ "$status" = "already_fixed" ]; then
    attention+=("- \`$name\`: already fixed (exit 6: $(describe_exit 6)) - conclusive, not a failure")
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
  # Machine-readable companion line for the polling ledger (tools/adapt/plan.py
  # --record reads it). Deliberately separate so the RESULT contract above stays
  # stable.
  if [ -n "$release" ]; then
    echo "RELEASE $name $release"
  fi
done

# Documentation coverage: every release listed in kernel_profiles/index.conf
# should have a row in both supported-device tables. index.conf is the authority
# here because the directory also holds templates and shared includes
# (execution-*.conf, credential-6x.conf, ...), which are not devices. Purely
# informational - a missing documentation row must not block an otherwise
# successful adaptation.
kernel_releases=()
if [ -f "$PROFILE_INDEX" ]; then
  while IFS= read -r kernel; do
    [ -n "$kernel" ] || continue
    # Reference templates live in the same index but document no device.
    case "$kernel" in *-template) continue ;; esac
    kernel_releases+=("$kernel")
  done < <(sed -n 's/^  *{ *release *= *"\([^"]*\)".*/\1/p' "$PROFILE_INDEX")
fi
total_kernels=${#kernel_releases[@]}

missing_in_readme=()
missing_in_readme_zh=()
for kernel in "${kernel_releases[@]}"; do
  grep -qF -- "$kernel" "$REPO_ROOT/docs/kernel_profiles/SUPPORTED_DEVICES.md" 2>/dev/null || missing_in_readme+=("$kernel")
  grep -qF -- "$kernel" "$REPO_ROOT/docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md" 2>/dev/null || missing_in_readme_zh+=("$kernel")
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
    echo "- \`added\` - new profile written and registered in kernel_profiles/index.conf (exit 0)."
    echo "- \`already_registered\` - the profile file already exists, nothing written (exit 0)."
    echo "- \`already_fixed\` - exit 6, the kernel already contains the fix; conclusive, not a failure."
    echo "- \`failed\` - exit 2 (generic parse failure), 3 (pselect route infeasible), 4 (missing required offsets) or 5 (kallsyms recovery failed); a profile that could not be published is reported with the reason here too."
    echo "- \`unsupported\` - the declared input is a container this pipeline cannot use (proprietary vendor container, or an archive with no \`boot.img\` / \`payload.bin\`); see Needs attention for the alternative."
    echo "- An exit code of \`-\` means the extractor never ran because the input could not be prepared (fetch or unpack failure); \`failed\` and \`unsupported\` both count towards \`FAIL_ON_ERROR\`."
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
  echo "### Device table rows"
  echo
  if [ "${#readme_rows[@]}" -eq 0 ]; then
    echo "No usable rows; nothing to paste."
  else
    echo "Add these rows to docs/kernel_profiles/SUPPORTED_DEVICES.md and SUPPORTED_DEVICES_ZH.md by hand (registering the profile does not update them):"
    echo
    echo "| Kernel (uname -r) | Device |"
    echo "|---|---|"
    printf "%s\n" "${readme_rows[@]}"
  fi
  echo
  echo "### Device table coverage"
  echo
  if [ "$total_kernels" -eq 0 ]; then
    echo "No releases found in \`$PROFILE_INDEX\`; nothing to check."
  elif [ "${#missing_in_readme[@]}" -eq 0 ] && [ "${#missing_in_readme_zh[@]}" -eq 0 ]; then
    echo "all $total_kernels releases are listed in docs/kernel_profiles/SUPPORTED_DEVICES.md and SUPPORTED_DEVICES_ZH.md"
  else
    echo "Registered kernels: $total_kernels."
    echo
    if [ "${#missing_in_readme[@]}" -gt 0 ]; then
      echo "**SUPPORTED_DEVICES.md** is missing ${#missing_in_readme[@]} release(s):"
      echo
      printf -- "- \`%s\`\n" "${missing_in_readme[@]}"
      echo
    fi
    if [ "${#missing_in_readme_zh[@]}" -gt 0 ]; then
      echo "**SUPPORTED_DEVICES_ZH.md** is missing ${#missing_in_readme_zh[@]} release(s):"
      echo
      printf -- "- \`%s\`\n" "${missing_in_readme_zh[@]}"
      echo
    fi
    echo "Warning only: the adapted kernels are usable; add the rows by hand (see above)."
  fi
} >> "$SUMMARY_FILE"

echo "adapt: finished: $total package(s), $failed_count failed or unsupported"
if [ "$FAIL_ON_ERROR" = "true" ] && [ "$failed_count" -gt 0 ]; then
  echo "adapt: FAIL_ON_ERROR=true and $failed_count package(s) failed" >&2
  exit 1
fi
exit 0
