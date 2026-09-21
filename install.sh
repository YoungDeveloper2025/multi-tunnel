#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -Eeuo pipefail
PROGRAM='multi-tunnel'
INSTALL_DIR='/usr/local/lib/multi-tunnel'
LAUNCHER='/usr/local/bin/multi-tunnel'
repo=''
ref='main'
local_source=''
expected_sha=''
ref_was_set=false
work_dir=''
staged_script=''
staged_launcher=''
die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}
usage() {
    cat <<'HELP'
Install the Multi Tunnel 3.2.4 manager on Ubuntu 22.04+ (amd64).
Usage:
  sudo bash install.sh --local /path/to/repository
  sudo bash install.sh --local /path/to/multi-tunnel.py
  sudo bash /tmp/multi-install.sh --repo OWNER/REPO [--ref main]
Options:
  --local PATH    Install a local multi-tunnel.py or the file in this directory.
                  This mode never downloads the manager source.
  --repo NAME     Download multi-tunnel.py from the root of GitHub OWNER/REPO.
  --ref REF       GitHub branch, tag or commit; default: main.
  --sha256 HASH   Require the source file to match this 64-digit SHA256 hash.
  --help         Show this help.
Exactly one of --local and --repo is required. An explicit source prevents
an installer downloaded into /tmp from selecting an unrelated local file.
Ubuntu packages may be installed if dependencies are missing. The installer
does not create tunnels or start the interactive menu. After installation:
  sudo multi-tunnel
Create the Foreign side first. You can then configure Iran automatically
over SSH, or run the manager independently on Iran and import its code.
New tunnels follow Smite: native Backhaul/Rathole connect Foreign -> Iran;
GOST forwards from its Iran listeners directly to Foreign service ports.
Only the selected core is required. Existing schema-2/3 tunnels stay readable.
The SSH setup verifies cached engine SHA256 values and sends only missing files.
GOST TCP setup synchronizes the selected Iran ports before applying its config.
The authenticated health check and application-port checks are reported separately.
The Foreign-domain Cloudflare question still defaults to Yes; new Smite tunnels
require direct endpoints. Existing Cloudflare carrier configurations stay readable.
To remove the installed manager, ALL local tunnels and their managed engines:
  sudo multi-tunnel --uninstall
Or use main-menu option 7. Removal asks for confirmation and affects this server.
To skip this installer, run a downloaded manager directly:
  sudo python3 multi-tunnel.py
HELP
}
cleanup() {
    [[ -z "$staged_script" ]] || rm -f -- "$staged_script"
    [[ -z "$staged_launcher" ]] || rm -f -- "$staged_launcher"
    [[ -z "$work_dir" ]] || rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'printf "ERROR: Installer failed at line %s.\n" "$LINENO" >&2' ERR
while (($#)); do
    case "$1" in
        --local)
            (($# >= 2)) || die '--local requires a file or directory path.'
            [[ -n "$2" ]] || die '--local requires a nonempty path.'
            [[ -z "$local_source" ]] || die '--local may only be provided once.'
            local_source="$2"
            shift 2
            ;;
        --repo)
            (($# >= 2)) || die '--repo requires OWNER/REPO.'
            [[ -n "$2" ]] || die '--repo requires OWNER/REPO.'
            [[ -z "$repo" ]] || die '--repo may only be provided once.'
            repo="${2%.git}"
            shift 2
            ;;
        --ref)
            (($# >= 2)) || die '--ref requires a branch, tag or commit.'
            ref="$2"
            ref_was_set=true
            shift 2
            ;;
        --sha256)
            (($# >= 2)) || die '--sha256 requires a hash.'
            expected_sha="${2,,}"
            [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || die 'Invalid SHA256 hash.'
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *) die "Unknown argument: $1. Run --help for usage." ;;
    esac
done
[[ -n "$repo" || -n "$local_source" ]] || die 'Choose --local PATH or --repo OWNER/REPO. Run --help for examples.'
[[ -z "$repo" || -z "$local_source" ]] || die '--local and --repo cannot be combined.'
if [[ -n "$repo" ]]; then
    [[ "$repo" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die 'Repository must be OWNER/REPO, without a URL.'
    [[ "$ref" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die 'Invalid GitHub ref.'
    [[ "$ref" != *'..'* && "$ref" != *'//'* && "$ref" != */ && "$ref" != *'/./'* && "$ref" != */. ]] || die 'Invalid GitHub ref path.'
else
    [[ "$ref_was_set" == false ]] || die '--ref only applies to --repo.'
    if [[ -d "$local_source" ]]; then
        local_source="${local_source%/}/multi-tunnel.py"
    fi
    [[ -f "$local_source" && -r "$local_source" ]] || die "Cannot read local source: $local_source"
fi
((EUID == 0)) || die 'Run the installer with sudo bash install.sh ...'
[[ -r /etc/os-release ]] || die 'Cannot identify the operating system.'
# /etc/os-release is a system-owned shell-format identification file.
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die 'This release supports Ubuntu 22.04+ only.'
[[ "${VERSION_ID:-}" =~ ^([0-9]+)\.([0-9]+)$ ]] || die 'Cannot identify the Ubuntu version.'
os_major="${BASH_REMATCH[1]}"
os_minor="${BASH_REMATCH[2]}"
((10#$os_major > 22 || (10#$os_major == 22 && 10#$os_minor >= 4))) || die 'Ubuntu 22.04 or newer is required.'
[[ "$(dpkg --print-architecture)" == amd64 ]] || die 'This release supports amd64 (x86_64) only.'
packages=()
command -v python3 >/dev/null 2>&1 || packages+=(python3)
if [[ -n "$repo" ]]; then
    command -v curl >/dev/null 2>&1 || packages+=(curl)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
fi
if ((${#packages[@]})); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends "${packages[@]}"
fi
# Version 1 used the same installation path and controlled both nodes over SSH.
# Refuse to replace its manager while its configurations are still present.
/usr/bin/python3 - <<'PY'
import json
import pathlib
import sys
legacy = []
for config in pathlib.Path('/etc/multi-tunnel').glob('*/spec.json'):
    if config.parent.name.startswith('.'):
        continue
    try:
        value = json.loads(config.read_text())
        current = isinstance(value, dict) and type(value.get('schema_version')) is int and value.get('schema_version') in (2, 3, 4)
    except (OSError, ValueError):
        current = False
    if not current:
        legacy.append(config.parent.name)
if legacy:
    print('ERROR: Legacy or unreadable tunnel configurations exist: ' + ', '.join(sorted(legacy)), file=sys.stderr)
    print('Keep and use your previous script to remove or migrate those tunnels first, then run this installer again.', file=sys.stderr)
    print('The installed manager and tunnel configurations have not been replaced.', file=sys.stderr)
    sys.exit(1)
PY
work_dir="$(mktemp -d /tmp/multi-installer.XXXXXXXX)"
source_file="$work_dir/multi-tunnel.py"
if [[ -n "$repo" ]]; then
    # Allowed characters are URL-safe. Slashes in branch names remain slashes.
    source_url="https://raw.githubusercontent.com/$repo/$ref/multi-tunnel.py"
    printf 'Downloading %s at %s...\n' "$repo" "$ref"
    curl --fail --progress-bar --show-error --location --retry 3 --connect-timeout 20 --max-time 180 --proto '=https' --proto-redir '=https' --output "$source_file" "$source_url"
else
    cp -- "$local_source" "$source_file"
fi
[[ -s "$source_file" ]] || die 'The manager source is empty.'
if [[ -n "$expected_sha" ]]; then
    actual_sha="$(sha256sum "$source_file")"
    actual_sha="${actual_sha%% *}"
    [[ "$actual_sha" == "$expected_sha" ]] || die 'Source SHA256 mismatch; nothing was installed.'
fi
# Compile without executing the downloaded program or writing __pycache__.
/usr/bin/python3 - "$source_file" <<'PY'
import pathlib
import sys
source = pathlib.Path(sys.argv[1])
compile(source.read_bytes(), str(source), 'exec')
PY
install -d -m 755 "$INSTALL_DIR" /usr/local/bin
staged_script="$(mktemp "$INSTALL_DIR/.multi-tunnel.XXXXXXXX")"
install -m 755 "$source_file" "$staged_script"
staged_launcher="$(mktemp /usr/local/bin/.multi-tunnel.XXXXXXXX)"
cat > "$staged_launcher" <<'SH'
#!/bin/sh
exec /usr/bin/python3 /usr/local/lib/multi-tunnel/multi-tunnel.py "$@"
SH
chmod 755 "$staged_launcher"
/bin/sh -n "$staged_launcher"
mv -f -- "$staged_script" "$INSTALL_DIR/multi-tunnel.py"
staged_script=''
mv -f -- "$staged_launcher" "$LAUNCHER"
staged_launcher=''
printf '\nInstalled %s. Start the manager on this server with:\n  sudo multi-tunnel\n' "$PROGRAM"
