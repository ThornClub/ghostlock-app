#!/usr/bin/env python3
"""Plan adaptation work from the device list and maintain the polling ledger.

There are three entry points into the adaptation pipeline and all of them end
in tools/adapt/adapt.sh:

  * ad-hoc dispatch - the workflow writes a one-entry pending file itself;
  * the checked-in device list - this script merges tools/adapt/devices.json
    (vendor presets + device entries) into pending.json;
  * the daily poller - same, but devices whose remote package fingerprint is
    already in the ledger are filtered out before adapt.sh runs.

Modes
-----
plan (default)
    Probe every selected tracked device with curl (unless --no-probe), decide
    which ones need adaptation, write pending.json plus a Markdown report, and
    refresh the ledger's address / fingerprint / checkedAt fields. Probe
    failures are not fatal: the device is reported as `no-validator` and is
    still enqueued, so the run can surface the real error through adapt.sh.

--record
    Fold one adapt.sh result (status / release) into the ledger after the run.
    Status and release are read from adapt.sh's RESULT / RELEASE lines.

--no-probe
    Offline mode for local tests: no network access at all. Every selected
    tracked device is enqueued, fingerprints are copied from the ledger when
    present, and the ledger is left untouched. Used by the validation tests and
    by a developer who wants to inspect the generated pending.json.

Ledger format
-------------
{"entries": {"<device name>": {"address", "fingerprint", "release", "status",
"checkedAt"}}}. The file lives in the Actions cache (RUNNER_TEMP), never in
the repository: a bot commit would trigger the upstream build.yml full build.
A lost cache degrades to "everything is unknown": one extra probe and, when
the package really is unchanged, one extra adaptation.

Fingerprint
-----------
The present validators of the remote package joined in a fixed order:
`etag:<ETag>|len:<Content-Length>|lm:<Last-Modified>` (missing fields are
skipped). When none of the three is exposed - including a failed probe - the
status is `no-validator` and the device is adapted again on every run; a
HEAD-refusing CDN is retried once with a 1-byte ranged GET.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ALLOWED_KINDS = ("auto", "ota", "payload", "boot", "image")
DEVICE_KEYS = ("name", "vendor", "address", "kind", "xbl_config", "tracked", "release", "notes", "headers")
VENDOR_KEYS = ("kind", "xbl_config", "tracked", "headers")
PROBE_TIMEOUT_SECONDS = "30"


def fail(message):
    print(f"adapt: ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_text(value, where, allow_empty=True):
    """Reject non-strings and control characters before they reach a record."""
    if not isinstance(value, str):
        fail(f"{where} must be a string")
    if any(ord(char) < 0x20 for char in value):
        fail(f"{where} must not contain control characters")
    if not allow_empty and not value:
        fail(f"{where} must not be empty")
    return value


def check_kind(value, where):
    if value is None:
        return None
    check_text(value, where)
    if value == "":
        # An empty kind is the same as auto, matching adapt.sh.
        return None
    if value not in ALLOWED_KINDS:
        fail(f"{where} must be one of {', '.join(ALLOWED_KINDS)} (got {value!r})")
    return value


def check_tracked(value, where):
    if value is None:
        return None
    if not isinstance(value, bool):
        fail(f"{where} must be a real boolean (true / false), not {type(value).__name__}")
    return value


def check_headers(value, where):
    if value is None:
        return {}
    if not isinstance(value, dict):
        fail(f"{where} must be an object of header name -> value")
    for name, item in value.items():
        check_text(name, f"{where} keys", allow_empty=False)
        check_text(item, f"{where}[{name!r}]")
    return value


def load_config(path):
    """Parse and validate the device list; returns (vendors, devices)."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read config {path}: {err}")
    if not isinstance(data, dict):
        fail(f"{path}: the top level must be an object")

    unknown = sorted(set(data) - {"comment", "vendors", "devices"})
    if unknown:
        fail(f"{path}: unknown top-level keys: {', '.join(unknown)}")

    vendors_in = data.get("vendors", {})
    if not isinstance(vendors_in, dict):
        fail(f"{path}: 'vendors' must be an object")
    vendors = {}
    for name, preset in vendors_in.items():
        where = f"{path}: vendors[{name!r}]"
        check_text(name, f"{path}: vendor name", allow_empty=False)
        if not isinstance(preset, dict):
            fail(f"{where} must be an object")
        unknown = sorted(set(preset) - set(VENDOR_KEYS))
        if unknown:
            fail(f"{where} has unknown keys: {', '.join(unknown)}")
        if "kind" in preset:
            check_kind(preset["kind"], f"{where}.kind")
        if "xbl_config" in preset and not isinstance(preset["xbl_config"], bool):
            fail(f"{where}.xbl_config must be a boolean (the address belongs on the device entry)")
        if "tracked" in preset:
            check_tracked(preset["tracked"], f"{where}.tracked")
        if "headers" in preset:
            check_headers(preset["headers"], f"{where}.headers")
        vendors[name] = preset

    devices_in = data.get("devices", [])
    if not isinstance(devices_in, list):
        fail(f"{path}: 'devices' must be an array")
    devices = []
    seen = set()
    for index, device in enumerate(devices_in):
        where = f"{path}: devices[{index}]"
        if not isinstance(device, dict):
            fail(f"{where} must be an object")
        unknown = sorted(set(device) - set(DEVICE_KEYS))
        if unknown:
            fail(f"{where} has unknown keys: {', '.join(unknown)}")
        name = check_text(device.get("name"), f"{where}.name", allow_empty=False)
        vendor = check_text(device.get("vendor"), f"{where}.vendor", allow_empty=False)
        check_text(device.get("address"), f"{where}.address", allow_empty=False)
        if vendor not in vendors:
            fail(f"{where}.vendor {vendor!r} is not defined under 'vendors'")
        if name in seen:
            fail(f"{where}.name {name!r} is already used by an earlier device")
        seen.add(name)
        if "kind" in device:
            check_kind(device["kind"], f"{where}.kind")
        if "xbl_config" in device:
            if not isinstance(device["xbl_config"], str):
                fail(f"{where}.xbl_config must be an address/path string (the boolean form belongs in the vendor preset)")
            check_text(device["xbl_config"], f"{where}.xbl_config")
        if "tracked" in device:
            check_tracked(device["tracked"], f"{where}.tracked")
        for field in ("release", "notes"):
            if field in device:
                check_text(device[field], f"{where}.{field}")
        if "headers" in device:
            check_headers(device["headers"], f"{where}.headers")
        devices.append(device)
    return vendors, devices


def load_ledger(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {"entries": {}}
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read ledger {path}: {err}")
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        fail(f"{path}: the ledger must be an object with an 'entries' object")
    for name, entry in data["entries"].items():
        if not isinstance(entry, dict):
            fail(f"{path}: ledger entry {name!r} must be an object")
    return data


def write_text(path, text):
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def save_ledger(path, ledger):
    write_text(path, json.dumps(ledger, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def effective_device(device, vendors, config_path):
    """vendor preset (+) device entry, device wins per key; headers replaced."""
    preset = vendors[device["vendor"]]
    merged = dict(preset)
    merged.update(device)

    kind = check_kind(merged.get("kind"), f"{config_path}: devices[{device['name']!r}].kind") or "auto"
    tracked = bool(merged.get("tracked"))
    xbl = merged.get("xbl_config")
    # An empty string overrides a vendor preset just as effectively as a false
    # one, so treat it as "no address supplied" rather than as a real value.
    if xbl is True or (xbl in ("", None) and preset.get("xbl_config") is True):
        fail(
            f"{config_path}: device {device['name']!r} inherits xbl_config: true from vendor "
            f"{device['vendor']!r} but supplies no xbl_config address"
        )
    address = device["address"]
    if tracked and address.startswith("gh://"):
        # A gh:// asset has no HTTP validators at all: curl cannot speak the gh
        # protocol, so the fingerprint would stay empty and the device would be
        # re-adapted on every scheduled run. Fail loudly instead.
        fail(
            f"{config_path}: device {device['name']!r} is tracked but uses a gh:// address, "
            "which exposes no HTTP validators; use an HTTP(S) address for polling or drop tracked"
        )
    if xbl is not True and not isinstance(xbl, (str, type(None))):
        fail(f"{config_path}: device {device['name']!r} xbl_config must be a string")
    return {
        "name": device["name"],
        "vendor": device["vendor"],
        "address": device["address"],
        "kind": kind,
        "xbl_config": xbl if isinstance(xbl, str) else "",
        "tracked": tracked,
        "release": merged.get("release") or "",
        "notes": merged.get("notes") or "",
        "headers": merged.get("headers") or {},
    }


def parse_headers(text):
    """Return (status, headers) of the final response block; names lowercased."""
    status = None
    headers = {}
    for line in text.replace("\r\n", "\n").splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            # A redirect chain dumps several blocks; keep the last one.
            headers = {}
        elif ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return status, headers


def fingerprint_of(headers, ranged=False):
    """Validators joined into one fingerprint.

    A 1-byte ranged GET always reports `content-length: 1`, which would pin the
    fingerprint to `len:1` forever; for that response the total size only lives
    in `content-range`, so Content-Length is ignored unless Content-Range is
    absent too.
    """
    parts = []
    if headers.get("etag"):
        parts.append(f"etag:{headers['etag']}")
    content_range = headers.get("content-range") or ""
    if content_range and "/" in content_range:
        total = content_range.rsplit("/", 1)[-1].strip()
        if total and total != "*":
            parts.append(f"len:{total}")
    elif headers.get("content-length") and not ranged:
        parts.append(f"len:{headers['content-length']}")
    if headers.get("last-modified"):
        parts.append(f"lm:{headers['last-modified']}")
    return "|".join(parts)


def probe(curl_bin, url, headers):
    """Return (fingerprint, note); an empty fingerprint means 'no validator'."""
    common = []
    for name, value in sorted(headers.items()):
        common += ["-H", f"{name}: {value}"]
    note = ""
    for attempt in (1, 2):
        if attempt == 1:
            # -L because a fixed "latest" address often redirects; without it
            # every redirecting endpoint would degrade to no-validator.
            command = [curl_bin, "-sSIL", "--max-time", PROBE_TIMEOUT_SECONDS] + common + [url]
        else:
            # Some CDNs refuse HEAD; a 1-byte ranged GET still exposes headers.
            command = [
                curl_bin,
                "-sS",
                "-r",
                "0-0",
                "-L",
                "--max-time",
                PROBE_TIMEOUT_SECONDS,
                "-D",
                "-",
                "-o",
                os.devnull,
            ] + common + [url]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=45)
        except FileNotFoundError:
            return "", f"probe failed: {curl_bin} not found"
        except subprocess.TimeoutExpired:
            note = "probe failed: curl timed out"
            continue
        except OSError as err:
            # Not executable, wrong architecture, permission denied, ...
            return "", f"probe failed: {curl_bin}: {err}"
        status, parsed = parse_headers(proc.stdout)
        if proc.returncode == 0 and status is not None and 200 <= status < 300:
            return fingerprint_of(parsed, ranged=attempt == 2), ""
        detail = [line for line in (proc.stderr or "").splitlines() if line.strip()]
        note = f"HEAD probe rejected (HTTP {status})" if status is not None else "probe failed"
        if detail:
            note += f": {detail[-1].strip()}"
    return "", note


def md_cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_summary(rows, no_probe):
    lines = ["## Device adaptation plan", ""]
    if not rows:
        lines.append("No devices are selected from the device list; nothing to adapt.")
    else:
        lines.append("| Device | Status | Fingerprint | Kind | Note |")
        lines.append("|---|---|---|---|---|")
        for name, status, fingerprint, kind, note in rows:
            shown = fingerprint[:8] if fingerprint else "-"
            lines.append(f"| {md_cell(name)} | {status} | `{md_cell(shown)}` | {kind} | {md_cell(note)} |")
    lines += [
        "",
        "Status legend:",
        "",
        "- `up-to-date` - the remote fingerprint matches the ledger; no download, no adaptation.",
        "- `pending` - new, changed, or first-seen package; queued for adapt.sh this run.",
        "- `no-validator` - the address exposes no ETag / Content-Length / Last-Modified (or the probe failed); queued every run.",
        "- `not-tracked` - listed for context; without `tracked: true` it is never queued by the poller.",
    ]
    if no_probe:
        lines += ["", "`--no-probe` was used: no device was contacted and the ledger was left untouched."]
    lines.append("")
    return "\n".join(lines)


def run_plan(args):
    vendors, devices = load_config(args.config)
    ledger = load_ledger(args.ledger)
    entries = ledger.setdefault("entries", {})

    selected = devices
    if args.only:
        wanted = [name.strip() for name in args.only.split(",") if name.strip()]
        known = {device["name"] for device in devices}
        missing = [name for name in wanted if name not in known]
        if missing:
            fail(f"--only names not found in {args.config}: {', '.join(missing)}")
        selected = [device for device in devices if device["name"] in wanted]

    curl_bin = os.environ.get("CURL_BIN", "curl")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pending = []
    rows = []

    for device in selected:
        eff = effective_device(device, vendors, args.config)
        name = eff["name"]
        note = ""
        if not eff["tracked"]:
            status = "not-tracked"
            fingerprint = ""
            enqueue = False
            note = "no `tracked: true`"
        else:
            old = entries.get(name) or {}
            if args.no_probe:
                fingerprint = old.get("fingerprint") or ""
                status = "pending"
                enqueue = True
                note = "no-probe run: enqueued without contacting the device"
            else:
                fingerprint, note = probe(curl_bin, eff["address"], eff["headers"])
                if not fingerprint:
                    status = "no-validator"
                    enqueue = True
                elif old.get("address") == eff["address"] and old.get("fingerprint") == fingerprint:
                    status = "up-to-date"
                    enqueue = False
                else:
                    status = "pending"
                    enqueue = True
        if enqueue:
            pending.append(
                {
                    "name": name,
                    "image": eff["address"],
                    "xbl_config": eff["xbl_config"],
                    "notes": eff["notes"],
                    "release": eff["release"],
                    # adapt.sh reads an empty kind as auto.
                    "kind": "" if eff["kind"] == "auto" else eff["kind"],
                    # curl -H material for the probe and for downloads that
                    # adapt.sh performs itself (see its split_headers).
                    "headers": eff["headers"],
                }
            )
        rows.append((name, status, fingerprint, eff["kind"], note))
        if eff["tracked"] and not args.no_probe:
            # Keep status / release untouched here: adapt.sh's result is folded
            # in later by --record.
            entry = entries.setdefault(name, {})
            entry["address"] = eff["address"]
            entry["fingerprint"] = fingerprint
            entry["checkedAt"] = now

    write_text(args.pending_out, json.dumps({"packages": pending}, indent=2, ensure_ascii=False) + "\n")
    write_text(args.summary_out, render_summary(rows, args.no_probe))
    if not args.no_probe:
        save_ledger(args.ledger, ledger)


def run_record(args):
    check_text(args.name, "--name", allow_empty=False)
    check_text(args.status, "--status", allow_empty=False)
    check_text(args.release, "--release")
    ledger = load_ledger(args.ledger)
    entry = ledger["entries"].setdefault(args.name, {})
    entry["status"] = args.status
    if args.release:
        # A failed run carries no release; keep the last known one.
        entry["release"] = args.release
    save_ledger(args.ledger, ledger)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="plan.py",
        description="Turn tools/adapt/devices.json into pending.json and maintain the polling ledger.",
    )
    parser.add_argument("--config", help="device list to read (tools/adapt/devices.json)")
    parser.add_argument("--ledger", help="polling ledger path")
    parser.add_argument("--pending-out", help="write the adapt.sh package list here")
    parser.add_argument("--summary-out", help="write the Markdown plan report here")
    parser.add_argument("--only", help="comma-separated device names to limit this run to")
    parser.add_argument("--no-probe", action="store_true", help="offline mode: no network, enqueue every tracked device")
    parser.add_argument("--record", action="store_true", help="fold one adapt.sh result into the ledger")
    parser.add_argument("--name", help="--record: device name")
    parser.add_argument("--release", default="", help="--record: kernel release (uname -r) recovered by adapt.sh")
    parser.add_argument("--status", default="", help="--record: adapt.sh status for this device")
    return parser


def main():
    args = build_parser().parse_args()
    if args.record:
        if not args.ledger or not args.name or not args.status:
            fail("--record needs --ledger, --name and --status")
        run_record(args)
        return 0
    if not (args.config and args.ledger and args.pending_out and args.summary_out):
        fail("needs --config, --ledger, --pending-out and --summary-out (or --record)")
    run_plan(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
