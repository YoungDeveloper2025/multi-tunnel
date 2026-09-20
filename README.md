# Multi Tunnel

A terminal manager for **Backhaul, Rathole and GOST** on **Ubuntu 22.04 or newer**, **amd64 / x86_64**, using IPv4.

Version **3.2.3** supports automatic setup of both servers over SSH, manual connection-code import, verified engine caching and complete local uninstallation. Menus are in English.

## Fixes in 3.2.3: GOST TCP installation and diagnostics

- **A separate health-test failure no longer removes a started GOST TCP tunnel during SSH setup.** Direct forwarding does not depend on the Foreign HMAC responder. The installer now keeps GOST TCP installed and reports `connection_ok: false` when that separate check fails. It does not report the connection as successful. Service startup failures, local storage errors and cancellation still trigger local rollback. Other transports and native Backhaul/Rathole retain their existing required-probe behavior.
- Manual and automatic SSH setup distinguish **installed, health unverified** from **connection verified** and show the actual Iran listening ports in either case. The initial GOST TCP installation probe has a 10-second retry budget; the management-menu probe retains its 30-second budget.
- Failed GOST TCP tests show the complete health route, including **Foreign's actual health port**, the Foreign echo service name, and a reminder to use the current connection code after replacing/editing Foreign. Empty/truncated replies are distinguished from a wrong authentication response.
- On a failed health test, Iran also attempts TCP handshakes to the configured Foreign application ports. These are labelled **TCP reachability only**; they do not prove that application authentication or forwarding through GOST works. Checks use a shared 8-second socket budget, with up to 2 seconds per destination; operating-system DNS resolution can add time.
- GOST TCP's generated forwarding configuration, pinned engine, pairing format and public port mappings are unchanged. The other menus, core caching, Cloudflare question, duplicate-name handling and uninstall behavior remain available.

The supplied **2.5.1** files and 3.2.2 already used the same GOST **3.3.0** TCP forwarding configuration and separate HMAC health responder. Their mandatory SSH probe rollback was also the same. This review did **not** establish a newly introduced TCP configuration regression or the cause of a particular VPS outage. It reproduced a specific failure mode: application traffic still forwards while the separate health responder is unavailable.

[Smite's GOST adapter](https://github.com/zZedix/Smite/blob/383f70bde53b307145cdd94a64e242e87d6361b4/node/app/core_adapters.py) starts direct TCP listeners forwarding to the Foreign service ports and does not require our separate HMAC responder. Its [Dockerfile](https://github.com/zZedix/Smite/blob/383f70bde53b307145cdd94a64e242e87d6361b4/node/Dockerfile) installs GOST **2.12.0**. This manager retains GOST **3.3.0**: the actual Smite TCP command was tested with both binaries, and both forwarded successfully. No engine downgrade or unrelated architecture change is included.

## Changes in 3.2.2

- **Manual creation on Foreign** now handles an existing tunnel name like Automatic mode: the replacement question defaults to **`y`**. Enter or `y` builds a replacement with the same name; `n` keeps the original and selects a free name such as `edge-2`.
- The same checks apply in both creation modes. Damaged configurations, symbolic links, interrupted changes and a tunnel with the wrong local role are not silently overwritten. New names skip existing tunnels and recovery paths and stay within the 24-character limit.
- Accepting replacement does not delete the old tunnel immediately. Complete the configuration questions first; saved settings provide editable defaults. Deployment replaces the old local services/configuration, while keeping shared cached cores. Cancelling before deployment leaves the existing tunnel running; a failed local deployment attempts to restore it through the existing recovery mechanism.
- Tunnel architectures, engine configurations, transport choices, caching, the Cloudflare question and other menu options remain as in 3.2.1.

## Fixes in 3.2.1

- The installer now accepts existing **schema-4** configurations when reinstalling or updating the manager. Version 3.2.0's installer incorrectly classified them as legacy configurations and stopped. Schemas 2/3 remain accepted; legacy, unknown or unreadable configurations are still rejected without replacing the manager.
- Manual **Set up Iran via SSH** now performs the same server-identity check as automatic setup, before remote package installation or file transfers. An SSH address pointing back to the Foreign server is rejected early.
- The Smite connection layout, generated engine configurations, menu options, Cloudflare question, selected-core cache handling and uninstall behavior are unchanged from 3.2.0. Engine versions remain pinned to GOST **3.3.0**, Backhaul **0.7.2** and Rathole **0.5.0**.

## Changes in 3.2.0

Only tunnel creation and the resulting connection layout have been changed to follow [Smite commit `383f70b`](https://github.com/zZedix/Smite/tree/383f70bde53b307145cdd94a64e242e87d6361b4):

- **Backhaul:** native server on Iran, client on Foreign. Only Backhaul is required.
- **Rathole:** native server on Iran, client on Foreign. Only Rathole is required.
- **GOST:** Iran listeners forward directly to Foreign application ports. There is no GOST receiver or outer TLS/WSS carrier on Foreign.
- New pairing codes use `MULTI4.` to distinguish the new GOST input-transport behavior from existing `MULTI2.` / `MULTI3.` configurations. Both servers need this manager for new codes.

Main and management menu options, SSH setup, APT routing, verified binary caching, port remapping, readiness tests, rollback, panel installation and complete uninstall are retained. The order and wording of endpoint questions follow the selected connection direction. Existing saved tunnels are not silently converted by a manager update.

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

The direction describes which server initiates the inter-server connection.

| New configuration | Initiator | Target | Required engines |
|---|---|---|---|
| Backhaul, all supported transports | Foreign | Iran control port | Backhaul on both servers |
| Rathole TCP / WS | Foreign | Iran control port | Rathole on both servers |
| GOST TCP / UDP | Iran | Foreign service and health ports | GOST on Iran; health responder on Foreign |
| GOST WS / gRPC / TCPMux | Iran, after receiving the matching transport on its input listener | Foreign service and health ports | GOST on Iran; health responder on Foreign |

New Backhaul/Rathole tunnels do not generate a `gost.json` or a GOST systemd unit. Foreign runs the native client, using Iran's address and control port. The manager opens the required local UFW rules; provider firewalls must also permit that port on Iran. Backhaul UDP needs both TCP and UDP on its control port.

For GOST, TCP and UDP accept ordinary traffic of the selected protocol. WS, gRPC and TCPMux instead accept the matching **GOST transport on Iran** and forward the decoded stream to the Foreign application. These are input transports, not an extra connection layer between Iran and Foreign. A regular TCP/VLESS client cannot connect directly to those encoded input listeners; use GOST TCP to forward an existing application's TCP/TLS/WS/gRPC bytes unchanged, or use a matching GOST client.

All new GOST targets, including the authenticated health responder, must be directly reachable on Foreign. Foreign application services must listen on a reachable interface. There is no single Foreign GOST transport port for the new layout. New tunnels do not add the former outer TLS encryption layer; application TLS remains independent.

## Relation to Smite and deliberate compatibility details

The reference is Smite's [tunnel creation router](https://github.com/zZedix/Smite/blob/383f70bde53b307145cdd94a64e242e87d6361b4/panel/app/routers/tunnels.py) and [core adapters](https://github.com/zZedix/Smite/blob/383f70bde53b307145cdd94a64e242e87d6361b4/node/app/core_adapters.py). This manager keeps its existing port mappings, tunables, systemd management and HMAC health test; it does not copy Smite's panel or node-agent infrastructure.

Two GOST command details needed correction for the existing pinned GOST **3.3.0** binary: Smite's WS command leaves `tcp://` inside the forwarding target, and its `tcpmux://` spelling parses as ordinary TCP. This release uses a valid `host:port` target and the supported **`mtcp`** listener/dialer for TCPMux. The direction and placement of the listener match Smite; these are functional configuration adaptations, not byte-for-byte copies of its commands.

## Automatic creation on Foreign

Select **1) Create tunnel → 2) Foreign → 1) Automatic**.

| Order | Question | Default / behavior |
|---|---|---|
| 1 | Tunnel engine | `1` Backhaul, `2` Rathole, `3` GOST; default Backhaul |
| 2 | Iran IPv4 address | Required; also the native Backhaul/Rathole control endpoint |
| GOST only | Foreign IP or domain | Detected Foreign public IPv4, editable |
| After a GOST Foreign domain | Cloudflare orange proxy enabled? | `1) Yes`; a new direct tunnel requires an IP or DNS-only domain |
| Next | Transport | TCP; all existing transport choices remain available |
| Next | Download Ubuntu packages through Foreign over SSH? | `y` |
| Next | Iran SSH port and root password | Port `22`; password is required and hidden |

Automatic defaults:

- Tunnel name: `mytunnel`. If it exists on either server, a local replacement question defaults to `y`. Choose `n` to retain that local tunnel and use an available name such as `mytunnel-2`.
- Iran user ports and Foreign service ports: `443,2083,2053,1115,1117`. Busy Iran user ports are remapped automatically. The final Iran port mapping is printed; use those ports in client configurations. Replacements preserve existing mappings for unchanged destinations when possible.
- Native Backhaul/Rathole control port: `8443` on **Iran**, checked over SSH before setup. An existing suitable control port may be reused; a busy port gets a free alternative, and Foreign is updated to match. New GOST tunnels forward to application ports directly and do not allocate a public carrier port.
- Engine binaries are pinned and verified. Iran's cache is inspected by version and SHA256; only a missing, corrupt or incompatible required binary is sent. Valid cached binaries are reused. The small manager script is still transferred to keep remote setup compatible.
- Iran startup is checked with an authenticated end-to-end probe for up to **60 seconds** before remote deployment is committed.

Each server's replacement operation has a temporary backup. Failure during local deployment restores that server's previous configuration. If Foreign setup succeeds but Iran setup fails, Foreign keeps the new configuration for retry; rollback is not coordinated across both servers. Resume from **Manage local tunnels → Foreign tunnel → 9) Set up Iran via SSH**.

## Cloudflare and certificates

New tunnels follow Smite's direct endpoint layout. A Foreign orange-proxied domain is not in the native Backhaul/Rathole connection path: those clients connect to **Iran**. The previous GOST WSS carrier has been removed from new tunnel creation.

For a Foreign domain entered during new GOST setup, the orange-proxy question retains its **Yes** default. If Yes is selected, the manager explains that direct forwarding requires a reachable Foreign IP or DNS-only domain and asks for a suitable endpoint. It does not silently change the answer or pretend the old Cloudflare carrier still exists. IP input skips this question. A new GOST domain with orange proxy disabled is accepted.

Saved schema-2/3 Cloudflare carrier tunnels still run with their previous TLS/WSS configuration. The standalone certificate menu is retained. Editing or recreating such a tunnel adopts the new layout and displays that change; its old Foreign Cloudflare endpoint is not reused as an Iran endpoint.

## Manual setup

On Foreign, choose **1) Create tunnel → 2) Foreign → 2) Manual**. Enter a name, engine, endpoint, transport, ports and advanced settings. The endpoint is **Iran** for Backhaul/Rathole and **Foreign** for GOST. Backhaul/Rathole ask for their Iran control port; GOST uses the mapped Foreign service ports. Domain inputs must be directly reachable for these new layouts.

If that name already belongs to a valid Foreign tunnel, the manager asks:

```text
Foreign already has a tunnel named edge. Delete it and create the new tunnel? (y/n) [y]:
```

- **Enter or `y`:** use the same name and continue configuring the replacement. You can select a different engine. Existing settings are offered as editable defaults; credentials are renewed when you build the replacement.
- **`n`:** preserve the old local tunnel and use an available name such as `edge-2`, `edge-3`, etc. The selected name is printed. Long names are shortened only as needed to fit the numeric suffix.
- **Ctrl+C:** cancel without deleting the existing tunnel. A later cancellation while entering settings also leaves it intact.

The Foreign and Iran replacement decisions are separate. To replace the same tunnel on both servers, accept replacement on Foreign and again during Iran SSH setup. Manual SSH setup on Iran retains its explicit `y/n` question without a default. Manual code import directly on Iran still requires **Edit** when that local name already exists. Using **Edit** on Foreign does not add a duplicate-name question.

A mapping such as `1115:8080` means Iran port `1115` forwards to Foreign port `8080`.

After Foreign setup, the connection code appears on its own line. New tunnels use `MULTI4.`; `MULTI2.`, `MULTI3.` and `MULTI4.` imports are accepted. The subsequent Iran-setup question accepts literal `y/n` without a default:

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

Backhaul TCP also offers forwarding UDP over TCP in manual setup. New Backhaul UDP requires both TCP and UDP reachability on its Iran control port. UFW rules are managed by the script; provider firewall rules must be configured separately. UFW is not enabled or reset automatically.

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

Status shows the engine, schema, transport, actual inter-server endpoint and port, connection direction, port mappings and local health port. Direct GOST also shows the separate Foreign health endpoint. Foreign's listed Iran user ports come from its requested mapping; consult Iran or the SSH setup result for automatically remapped Iran ports. Logs show the latest 60 entries per service in UTC.

On Iran, **2) test tunnel connection** retries an authenticated end-to-end probe with a **30-second** retry budget and reports success or the failing port/stage. For GOST TCP, failure is explicitly labelled **authenticated health check unsuccessful**, followed by separate Foreign application-port diagnostics. A failed health check still returns a failed verification result; it is not converted to PASS because a process or another port is reachable. New GOST WS/gRPC/TCPMux health checks also pass through the selected input transport using two loopback sockets in the existing GOST process; this adds no outer inter-server carrier. An `active` process or an old successful probe does not prove current connectivity. Foreign's test menu displays local status and instructs you to test from Iran; SSH setup performs that check remotely.

Application services, such as Xray/VLESS, must be checked separately. A refused loopback health connection can mean that the tunnel's control channel has not become ready. A timeout to a public endpoint may be caused by routing or firewall rules; the manager cannot repair an unreachable network path by reinstalling an engine.

For **direct GOST TCP**, the health path is `Iran 127.0.0.1:health_i -> Foreign endpoint:health_f`. It has no reverse control channel. If the local health listener refuses connections, inspect the Iran GOST service; if the Foreign health port is closed/filtered or the Foreign echo service is stopped, the auxiliary test fails even when application forwarding works. Allow the **displayed Foreign health port/TCP** in the provider firewall for authenticated testing. Application ports require their own rules and a service listening on the Foreign public interface. Do not open the loopback-only Iran health port to the Internet. A stale pairing code after changing Foreign can also prevent the authenticated reply.

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

Replace both release files and rerun the local installer to update the installed manager. Schema **2**, **3** and **4** configurations remain supported. If the old 3.2.0 installer reported that a schema-4 tunnel was legacy, use **both updated 3.2.3 files** and rerun it; do not delete that tunnel to get past the old guard. Updating the manager alone leaves existing tunnels running with their saved layout.

To apply the GOST TCP correction, install 3.2.3 on Foreign, then use **Manage -> Set up Iran via SSH** for that tunnel; the current manager is transferred to Iran. Accept replacement if the intended Iran tunnel already exists. For manual management, install 3.2.3 on both servers. If Iran already has the saved TCP configuration, updating the manager is enough to obtain the new menu diagnostics; a previous rolled-back installation must be retried. Full uninstall is unnecessary. Use the actual Iran ports printed by setup and test your application client as well as the separate health check.

To convert an existing tunnel to the new Smite layout, recreate it from Foreign in Automatic mode and accept replacement on both servers, or Edit on Foreign and apply the new `MULTI4.` code with Edit on Iran. Backhaul/Rathole now require a reachable Iran control port; GOST WS/gRPC/TCPMux now require a matching transport on the Iran input. Do not assume old clients continue to work with these changed transport roles. Other tunnels do not need to be uninstalled.

Automatic SSH setup transfers the current manager to Iran. For manual setup, update the manager on both servers before importing a `MULTI4.` code. Existing `MULTI2.` and `MULTI3.` codes can still be managed/imported with their original semantics.

Old v1 configurations are not automatically migrated; use their original manager to remove or migrate them before normal setup. Complete uninstall in this release targets this project's managed installation paths and recognized service names; it does not contact old SSH peers.

Basic checks for these delivered files:

```bash
bash -n install.sh
python3 -c "from pathlib import Path; compile(Path('multi-tunnel.py').read_bytes(), 'multi-tunnel.py', 'exec')"
python3 multi-tunnel.py --version
```

The 3.2.3 review passed **310 automated checks**: the **283 existing checks**, updated for the explicit deployment result and GOST TCP probe budget, plus **27 focused health/deployment checks**. The new checks cover keeping an unverified TCP deployment without claiming success, native/UDP rollback, startup failures, cancellation, real local TCP/HMAC responses, health-record storage errors, and SSH/automatic result handling. Fifteen existing checks specifically cover manual duplicate names: default/explicit confirmation, keeping the old tunnel with a free suffix, 24-character names, cancellation, damaged or interrupted configurations, wrong roles, symbolic links, changing engines, cleanup of old services, keeping cached cores and restoration after a simulated startup failure. System commands in deployment tests are simulated; files and the builder/deployment/recovery code run in isolated temporary directories.

The remaining checks include execution of the installer's compatibility guard against mixed schema-2/3/4 configurations, damaged files and unsupported schemas. Manual SSH tests check rejection of the same server before remote changes. Regression checks cover automatic setup, selected-core cache reuse, rollback, full uninstall, English menus, Cloudflare prompts and existing schema-2/3 behavior.

The previous 3.2.1 review passed 16 real-binary scenarios: all 13 new engine/transport combinations (including Backhaul UDP over TCP), two native wrong-token rejection cases and an existing schema-2 WSS carrier. Those checks exercised pairing, HMAC health, concurrent application port maps and native reconnects. The engine configuration generators and pinned binaries remain unchanged in 3.2.3; the full real-binary matrix was not rerun for this probe/deployment correction.

The focused TCP review runs the actual Smite adapter with GOST 2.12.0 and 3.3.0, then the delivered JSON configuration with GOST 3.3.0. Concurrent application requests are checked in each case. The manager's real Foreign echo service is started and authenticated through the Iran GOST listener; stopping only that echo service makes the probe fail while application requests continue to succeed. This demonstrates why auxiliary health failure must not automatically remove the direct TCP forwarder.

### GOST TCPMux cold-start limitation

An earlier concurrent cold-start check recorded `mtls: unrecognized connection` in an **external GOST 3.3.0 input client's** log, despite using the `mtcp` transport. This message is also used by GOST's [MTCP dialer](https://github.com/go-gost/x/blob/v0.16.0/dialer/mtcp/dialer.go). Reading that code together with its [session state check](https://github.com/go-gost/x/blob/v0.16.0/dialer/mtcp/conn.go) identifies a possible race: another concurrent Dial can discard a session before its first Handshake initializes it. The corresponding Handshake then rejects the replaced connection. These are the x-module sources referenced by [GOST 3.3.0](https://github.com/go-gost/gost/blob/v3.3.0/go.mod).

In the 3.2.1 review, 24 new external-client processes handled 384 concurrent application requests successfully: 12 starts used the default zero connection retries, and 12 used `handler.retries: 3`. The intermittent error did not recur in those runs. This does **not** establish that the upstream race is fixed, or that retries eliminate it. The bundled manager does not patch or rebuild GOST. If this error occurs with your own MTCP input client, its handler's `retries` setting can retry connection establishment; it is a mitigation to evaluate, not a server-side fix. The manager's existing authenticated health test already retries failed probes.

Tests use local processes and isolated temporary directories. They do not establish reachability between your actual Iran and Foreign VPSs, or test a live Cloudflare account.

This is an independent manager. Downloaded engines retain their own licenses; source files here are marked MIT.
