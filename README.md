# Multi Tunnel

A terminal manager for **Backhaul, Rathole and GOST** on **Ubuntu 22.04 or newer**, **amd64 / x86_64**, using IPv4.

Version **3.1.0** supports automatic setup of both servers over SSH, manual connection-code import, verified engine caching and complete local uninstallation. Menus are in English.

## Changes in 3.1.0

- Main-menu option **7** removes the installed manager, **all local tunnels and all managed engine binaries**. The same operation is available with `--uninstall` and asks for confirmation.
- The Cloudflare orange-proxy question defaults to **Yes**. Enter accepts `1) Yes`; choose `2) No` for a DNS-only Foreign domain. Foreign IP addresses skip the question.
- Manual and automatic GOST setup default to **WS** when Cloudflare is enabled. Selecting another transport requires explicit approval to switch to the Foreign IP and bypass Cloudflare.
- Panel installers appear only in the main menu. Per-tunnel management keeps its connection, configuration, certificate and SSH actions.
- Uninstall can run without downloading packages, including after an interrupted tunnel change. A failed uninstall leaves a checkpoint that blocks new tunnel operations until cleanup is retried.

The native engines, SHA256 cache checks, connection-port display, port-map preservation and longer readiness checks introduced in 3.0.0 remain supported.

## Installation

Put `install.sh` and `multi-tunnel.py` in the same directory on **Foreign**:

```bash
sudo bash install.sh --local ./multi-tunnel.py
sudo multi-tunnel
```

The installer installs the manager; it does not create a tunnel. Reopen the menu with `sudo multi-tunnel`.

You can also run a downloaded copy directly:

```bash
sudo python3 multi-tunnel.py
```

Python 3 must already be available for direct execution. Tunnel creation installs missing Ubuntu prerequisites when needed. Opening the menu, exiting and uninstalling do not install packages.

### Install from your GitHub repository

Upload the **updated** files to the root of your repository first. The example below assumes `YoungDeveloper2025/multi-tunnel`, branch `main`; change both references if yours differ. Downloading from a repository that still contains an older file installs that older version.

```bash
curl -fsSL --retry 3 https://raw.githubusercontent.com/YoungDeveloper2025/multi-tunnel/main/install.sh -o /tmp/multi-install.sh
sudo bash /tmp/multi-install.sh --repo YoungDeveloper2025/multi-tunnel --ref main
sudo multi-tunnel
```

If necessary, install `curl` with `sudo apt-get install -y curl ca-certificates`. The installer accepts `--sha256 HASH` to verify the manager source and `--help` for its options.

## Connection direction and engine selection

The direction below describes which server **initiates the tunnel connection**, not the direction of every application packet.

| Configuration | Connection initiated by | Connection target | Required engines |
|---|---|---|---|
| New Backhaul | Foreign | Iran control port | Backhaul |
| New Rathole | Foreign | Iran control port | Rathole |
| GOST TCP / UDP | Iran | Foreign application and health ports | GOST on Iran; health responder on Foreign |
| GOST WS / gRPC / TCPMux | Iran | Foreign transport port | GOST |
| Existing schema-2 Backhaul / Rathole | Iran, through the existing carrier | Foreign GOST TLS/WSS transport port | GOST plus the selected engine |

**New Backhaul and Rathole tunnels do not install or start a GOST carrier.** Their server listens on Iran; their client runs on Foreign. The control port must be reachable from Foreign, including through the Iran provider firewall. A proxied Foreign domain is not on this connection path.

Native Backhaul/Rathole TCP, UDP and WS modes do not add the previous GOST TLS layer. Use encrypted application traffic when encryption is required. GOST TCP/UDP forwarding is also unencrypted at the tunnel layer; the chained GOST modes use TLS.

Updating the manager does not convert existing schema-2 tunnels. Their previous TLS/WSS carrier remains supported. Recreate a tunnel to use the native architecture. Changing the engine when editing a Foreign tunnel also creates schema-3 settings; apply the resulting code on Iran.

## Automatic creation on Foreign

Select **1) Create tunnel → 2) Foreign → 1) Automatic**.

| Order | Question | Default / behavior |
|---|---|---|
| 1 | Tunnel engine | `1` Backhaul, `2` Rathole, `3` GOST; default Backhaul |
| 2 | Iran IPv4 address | Required |
| 3, GOST only | Foreign IP or domain | Detected Foreign public IPv4, editable |
| After a Foreign domain | Cloudflare orange proxy enabled? | `1) Yes`; choose `2) No` for DNS-only |
| Next | Transport | TCP; GOST with Cloudflare defaults to WS |
| Next | Download Ubuntu packages through Foreign over SSH? | `y` |
| Next | Iran SSH port and root password | Port `22`; password is required and hidden |

New Backhaul/Rathole use the supplied Iran IP directly, so they do not ask for a Foreign domain or Cloudflare.

Automatic defaults:

- Tunnel name: `mytunnel`. If it exists on either server, a local replacement question defaults to `y`. Choose `n` to retain that local tunnel and use an available name such as `mytunnel-2`.
- Iran user ports and Foreign service ports: `443,2083,2053,1115,1117`. Busy Iran user ports are remapped automatically. The final Iran port mapping is printed; use those ports in client configurations. Replacements preserve existing mappings for unchanged destinations when possible.
- New native control port: `8443` on **Iran**, checked over SSH before Iran setup. An existing native control port may be reused; busy ports get an available alternative, and the Foreign client configuration is updated to match.
- Chained GOST transport port: `8443` on **Foreign**. Another free port is selected if needed. Cloudflare uses supported HTTPS ports only.
- Engine binaries are pinned and verified. Iran's cache is inspected by version and SHA256; only a missing, corrupt or incompatible required binary is sent. Valid cached binaries are reused. The small manager script is still transferred to keep remote setup compatible.
- Iran startup is checked with an authenticated end-to-end probe for up to **60 seconds** before remote deployment is committed.

Each server's replacement operation has a temporary backup. Failure during local deployment restores that server's previous configuration. If Foreign setup succeeds but Iran setup fails, Foreign keeps the new configuration for retry; rollback is not coordinated across both servers. Resume from **Manage local tunnels → Foreign tunnel → 9) Set up Iran via SSH**.

## Cloudflare and certificates

For a **Foreign domain**, the orange-proxy question now defaults to **Yes** in both automatic and manual setup. An IP skips the question. In native Backhaul/Rathole manual setup, the endpoint is a **direct Iran address**; no Foreign Cloudflare question applies.

GOST with Cloudflare requires **WS**, carried over TLS. All GOST transport choices remain visible. Selecting TCP, UDP, gRPC or TCPMux asks whether to switch to a direct Foreign IPv4 connection. That separate confirmation defaults to **`n`**: pressing Enter preserves the proxied domain and returns to transport selection. Explicit `y` keeps the chosen transport, uses the Foreign IP and disables Cloudflare for that tunnel.

For GOST with Cloudflare:

- The domain must point to Foreign and Cloudflare SSL must use `Full (strict)`.
- Automatic mode reuses a valid certificate/key in `/etc/letsencrypt/live/DOMAIN/`. Otherwise, it requests a certificate using Certbot.
- HTTP validation must reach Foreign and TCP port `80` must be available and reachable. Another service is not stopped to free it.
- Manual mode asks for existing certificate and key paths on Foreign.

Without Cloudflare, chained GOST generates a self-signed certificate and includes the public CA in the connection code. The private key stays on Foreign. Simple GOST TCP/UDP and native Backhaul/Rathole do not need that tunnel certificate.

Existing schema-2 Backhaul/Rathole can retain their original GOST TLS/WSS carrier, including their existing Cloudflare setup.

## Manual setup

On Foreign, choose **1) Create tunnel → 2) Foreign → 2) Manual**. Enter a name, engine, endpoint, transport, ports and advanced settings. The endpoint is **Iran** for new Backhaul/Rathole and **Foreign** for GOST. Transport selection follows the endpoint and Cloudflare answers so that its default is compatible.

A mapping such as `1115:8080` means Iran port `1115` forwards to Foreign port `8080`.

After Foreign setup, the connection code appears on its own line. New tunnels use `MULTI3.`; existing `MULTI2.` codes are still accepted. The subsequent Iran-setup question accepts literal `y/n` without a default:

- `y`: enter the package-download route, Iran IP, SSH port and hidden root password. An existing Iran name can be replaced or a separate local tunnel can be added.
- `n`: install/run this manager on Iran, select **1) Create tunnel → 1) Iran**, and paste the complete connection code. Alternatively, save it in a file and enter `@/root/connection.txt`.

Manual imports use the agreed connection endpoint and control port; they do not negotiate a new control port over SSH. Do not publish connection codes: they contain authentication credentials.

## SSH and Ubuntu packages

Iran must already accept password-based SSH login for **root**. The manager does not change SSH settings or save the password in a file. The first host key is recorded; a changed recorded key blocks the connection.

Choosing Foreign internet routes Iran's APT requests through the same SSH session. Foreign must reach the package/download sources, and Iran's SSH server must allow port forwarding. No permanent APT proxy is written on Iran. Choosing the direct route uses Iran's own internet access.

Installed prerequisites and complete cached packages are excluded from required package downloads. If packages are missing, APT indexes may be fetched before the package size is shown. Indexes, Ubuntu packages and engine binaries have separate progress stages. Automatic mode accepts the package-size confirmation; manual setup lets you cancel it while preserving the Foreign tunnel.

The prerequisites include Python 3, OpenSSL, UFW, iproute2, CA certificates and iptables. SSH setup also needs the local SSH client and sshpass. APT targets missing prerequisites, although resolving dependencies may require upgrades.

Local package installation allows up to **300 seconds** for the dpkg lock. If Ubuntu updates still hold it, let them finish and retry. The manager does not delete lock files or stop automatic updates. `apt-get update` index locks are separate.

## Transports

| Engine | Supported transport choices |
|---|---|
| Backhaul | TCP, UDP, WS, WSMux, TCPMux |
| Rathole | TCP, WS |
| GOST | TCP, UDP, WS, gRPC, TCPMux |

Backhaul TCP also offers forwarding UDP over TCP in manual setup. Native Backhaul UDP requires both TCP and UDP reachability on its Iran control port. UFW rules are managed by the script; provider firewall rules must be configured separately. UFW is not enabled or reset automatically.

## Main menu and tunnel management

| Main-menu option | Action |
|---|---|
| 1 | Create tunnel |
| 2 | Manage local tunnels |
| 3 | Recover interrupted local change |
| 4 | Get a certificate for a subdomain |
| 5 | Install the latest mhsanaei/3x-ui panel |
| 6 | Install the latest alireza0/x-ui panel |
| 7 | Uninstall Multi Tunnel, all local tunnels and managed engines |
| 0 | Exit |

Tunnels are grouped by Backhaul, Rathole and GOST, then by name. Their management menu provides **Status, test tunnel connection, Edit, Delete this tunnel, Restart, Logs and certificate requests**. Foreign also has **Show connection code** and **Set up Iran via SSH**. Panel installation options are not repeated here.

**Delete this tunnel** removes only the selected local tunnel and its services; the manager and shared engine cache remain available. Use **main-menu option 7** for complete removal.

Status shows the engine, schema, transport, actual inter-server endpoint and port, connection direction, port mappings and local health port. Foreign's listed Iran user ports come from its requested mapping; consult Iran or the SSH setup result for automatically remapped Iran ports. Logs show the latest 60 entries per service in UTC.

On Iran, **2) test tunnel connection** retries an authenticated end-to-end probe for up to **30 seconds** and reports success or the failing local port/stage. An `active` process or an old successful probe does not prove current connectivity. Foreign's test menu displays local status and instructs you to test from Iran; SSH setup performs that check remotely.

Application services, such as Xray/VLESS, must be checked separately. A refused loopback health connection can mean that the tunnel's control channel has not become ready. A timeout to a public endpoint may be caused by routing or firewall rules; the manager cannot repair an unreachable network path by reinstalling an engine.

## Complete uninstall

On the server you want to clean, choose **7) Uninstall Multi Tunnel (ALL local tunnels and engines)** or run:

```bash
sudo multi-tunnel --uninstall
```

The confirmation defaults to **`n`**. Enter `y` to permanently remove:

- Every local Multi Tunnel service, including recognized orphaned services from interrupted changes, and their systemd unit files, drop-ins and enablement links.
- All tunnel configurations, tokens, connection codes, generated tunnel certificates, health records, local usage logs, backups and pending changes in `/etc/multi-tunnel`.
- All versions of the managed GOST, Backhaul and Rathole binaries, other cache files and the installed manager under `/usr/local/lib/multi-tunnel`.
- The `/usr/local/bin/multi-tunnel` launcher.
- UFW rules tagged `multi-v2` or `multi-certbot`, and the manager's IPv4/IPv6 sniffer-guard rules. Unrelated firewall rules are kept; no firewall reset is performed.

All tunnel services are stopped before their data and binaries are deleted. If a service cannot be stopped or firewall cleanup fails, the operation reports failure and can be retried with `--uninstall`; do not treat a partial cleanup as success. New setup is blocked while an uninstall checkpoint exists. The program exits after successful removal.

**This affects the current server only.** Repeat it on both Iran and Foreign to remove both sides. The manager does not retain SSH credentials for deleting a peer automatically.

Ubuntu packages, separately installed engines, 3x-ui/x-ui panels, `/etc/letsencrypt` certificates, system journal history and downloaded source/installer copies outside the installation directory are kept. If another service still needs a firewall opening previously tagged by this manager, give that service its own rule before removal.

If the launcher is missing, run a copy of this version directly:

```bash
sudo python3 multi-tunnel.py --uninstall
```

Uninstall needs neither internet access nor package installation. It uses the existing systemd and available firewall tools. It refuses to traverse an installation directory replaced by a symbolic link or a mounted filesystem.

## Certificates and panels

Main-menu **4) get cert for sub domain** installs Certbot and requests a certificate for the domain entered. The option is also available in tunnel management. HTTP validation needs reachable TCP port `80`. Successful issuance displays the fullchain and key paths under `/etc/letsencrypt/live/DOMAIN/`.

Main-menu options **5** and **6** run the official [mhsanaei/3x-ui installer](https://github.com/mhsanaei/3x-ui/blob/master/install.sh) or [alireza0/x-ui installer](https://github.com/alireza0/x-ui/blob/master/install.sh) without a pinned panel version. Their official installer chooses its current release and asks for panel settings.

Panel installation affects **the server where the menu is running**. The two panels share x-ui service names and paths; an existing installation triggers a separate confirmation before replacement. Uninstalling Multi Tunnel does not uninstall either panel.

## Progress, cancellation and recovery

Downloads and SSH transfers display progress and verify transferred files. Each progress bar describes its own stage, not overall two-server completion.

`Ctrl+C` at the main menu, tunnel selection or management selection exits. During an operation, it cancels that operation and returns to the menu after cleanup. Packages or panel changes already applied are not rolled back. Interrupted tunnel deployment can be recovered with main-menu option **3**. An interrupted **complete uninstall** is resumed with option **7** or `--uninstall`, not tunnel recovery.

## Updating and verification

Replace both release files and rerun the local installer to update the installed manager. Schema **2** and **3** configurations and `MULTI2.` / `MULTI3.` codes remain supported; a manager update alone does not recreate working tunnels. Automatic SSH setup also transfers the current manager to Iran. For manual setup, update the manager on both servers.

Old v1 configurations are not automatically migrated; use their original manager to remove or migrate them before normal setup. Complete uninstall in this release targets this project's managed installation paths and recognized service names; it does not contact old SSH peers.

Basic checks for these delivered files:

```bash
bash -n install.sh
python3 -c "from pathlib import Path; compile(Path('multi-tunnel.py').read_bytes(), 'multi-tunnel.py', 'exec')"
python3 multi-tunnel.py --version
```

Management, uninstall and configuration tests use isolated temporary directories and simulated host commands. Local engine tests do not establish reachability between two actual Iran and Foreign VPSs, exercise a live Cloudflare account or validate a real certificate request.

Smite inspired the requested features. This is an independent manager; the downloaded engines retain their own licenses. Source files are marked MIT.
