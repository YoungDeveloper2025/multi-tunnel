# Multi Tunnel

A terminal-based manager for **Backhaul, Rathole, and GOST** tunnels on **Ubuntu 22.04 or newer**, **amd64 / x86_64**, with IPv4.

Version **2.5.1** can configure both servers from the Foreign server using five main settings and SSH credentials. Manual setup and manual transfer of the `MULTI2.` connection code remain available.

**[Full Persian guide](README.fa.md)** · **[MIT license](LICENSE)** · **[Tunnel engine licenses](THIRD_PARTY_NOTICES.md)**

## Install from GitHub

These commands assume the proposed repository **`YoungDeveloper2025/multi-tunnel`** and the **`main`** branch. Upload the project files to the root of that repository first. If you use a different repository or branch, update the download URL, `--repo`, and `--ref` accordingly.

Run on the Foreign server:

```bash
curl -fsSL --retry 3 https://raw.githubusercontent.com/YoungDeveloper2025/multi-tunnel/main/install.sh -o /tmp/multi-install.sh && sudo bash /tmp/multi-install.sh --repo YoungDeveloper2025/multi-tunnel --ref main && sudo multi-tunnel
```

Or run the same installation in three steps:

```bash
curl -fsSL --retry 3 https://raw.githubusercontent.com/YoungDeveloper2025/multi-tunnel/main/install.sh -o /tmp/multi-install.sh
sudo bash /tmp/multi-install.sh --repo YoungDeveloper2025/multi-tunnel --ref main
sudo multi-tunnel
```

If `curl` is not installed:

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates
```

To reopen the menu later, run `sudo multi-tunnel`. The installer installs the manager; use the menu to create tunnels.

You can also install from local files:

```bash
sudo bash install.sh --local .
sudo multi-tunnel
```

To run the script directly without the installer, copy it to the server and run:

```bash
sudo python3 multi-tunnel.py
```

If Python is missing, install it first with `sudo apt-get install -y python3`. Ubuntu package installation requires access to the Ubuntu repositories.

## Create a tunnel on the Foreign server

Select `1) Create tunnel`, then `2) Foreign`. Choose **`1) Automatic`**, the default, or **`2) Manual`**.

### Automatic mode

The five main settings are requested in this order:

| Order | Setting | Default |
|---|---|---|
| `1` | Foreign IP address or domain | This server's detected public IP; editable |
| `2` | Iran server IPv4 address | No default |
| `3` | Tunnel engine: `1` Backhaul, `2` Rathole, `3` GOST | `1` — Backhaul |
| `4` | Transport type, selected from the engine's numbered list | `1` — TCP; for GOST with Cloudflare, `3` — WS |
| `5` | Download Ubuntu packages using Foreign internet through SSH? | `y`; press Enter to accept |

If you enter an IP address, the Cloudflare question is skipped. If you enter a domain, an additional question asks whether the Cloudflare orange proxy is enabled.

After these settings, enter the Iran SSH port, default `22`, and the `root` password, which is hidden while typing. Pressing Enter accepts a displayed default. The Iran IP address and password must be supplied.

The script checks SSH access and Iran prerequisites, then configures both servers and tests the tunnel. It uses defaults for the name, ports, and advanced settings:

- The initial name is `mytunnel`. If that name already exists on either server, a confirmation asks whether to delete and recreate that server's tunnel, default `y`. Press `y` or Enter to replace it, or `n` to preserve it and use an available name such as `mytunnel-2`. Invalid responses repeat the question.
- Your selected transport is preserved. The default is TCP, except **GOST with Cloudflare**, which defaults to WS. With Cloudflare enabled, Backhaul and Rathole carry the selected inner transport through an outer GOST WSS connection. Selecting TCP does not disable Cloudflare.
- Default Iran listening ports and Foreign destination ports are `443,2083,2053,1115,1117`. If an Iran listening port is busy, a free port is selected and the final mapping is displayed. Use those final Iran ports in client configurations.
- The Foreign transport port, when required, defaults to `8443`. If it is unavailable, another free port is selected. Automatic Cloudflare alternatives are `2087` and `2096`.
- For Cloudflare, the script reuses a valid certificate and key in `/etc/letsencrypt/live/DOMAIN/`. If they are missing or invalid, Certbot requests a certificate without asking again for the domain or file paths. DNS and HTTP validation must reach this Foreign server, and port `80` must be available. The script does not stop another service to free that port. Cloudflare SSL must use `Full (strict)`.

For GOST with the orange proxy enabled, all transport options remain visible, but this implementation can pass through Cloudflare only with WS. Selecting another transport offers a direct connection to the Foreign server's actual IPv4 address, with confirmation defaulting to `n`. Only explicit approval replaces the domain with that IP and disables Cloudflare for this tunnel, while retaining the selected transport. If the actual IP was not detected, the script asks for it. Declining returns to transport selection, where you can choose WS.

Automatic mode displays the required package download size and applies the default approval `y` without another size confirmation. Complete cached packages are excluded from the download size.

Replacement uses a temporary backup on each server. After successful local setup, the old manager-owned tunnel files and services are removed. If that local operation fails, the previous configuration is restored. If Foreign setup succeeds but the Iran stage fails, the Foreign tunnel remains available for retry; rollback is not coordinated across both servers.

### Manual mode

The script asks for the tunnel name, default `mytunnel`, engine, transport, IP or domain, ports, and advanced settings. The default engine is Backhaul and the default transport is TCP. The detected Foreign public IP is the default endpoint; an IP address skips the Cloudflare question.

A port mapping such as `1115:8080` forwards Iran port `1115` to Foreign port `8080`.

For Cloudflare, provide the paths to the existing certificate and private key on the **Foreign server**. This certificate secures the tunnel's WSS connection. Simple GOST TCP/UDP forwarding does not require a tunnel certificate.

After Foreign setup, the connection code is displayed on its own line. The script asks whether to configure Iran from this server. This question accepts only `y` or `n`, with no default. Choose `n` to import the code manually on Iran. Choose `y` to enter the Ubuntu package download route, Iran IP, SSH port, default `22`, and hidden root password.

If the tunnel name already exists on Iran, manual setup asks whether to replace it, with no default:

- **`y`** replaces the tunnel under the same local name. If startup or the connection test fails, the previous configuration is restored.
- **`n`** preserves the old tunnel and selects an available name such as `mytunnel-2`. Busy Iran listening ports are also reassigned, and the final mapping is displayed.

Questions have spacing above and below them, and standard menus use numbers. In the manual flow, Iran setup, package download routing, and duplicate-name replacement require `y/n` without a default; Enter or an invalid answer repeats the question. The package download size confirmation for Foreign internet defaults to `y`. Selecting `n` there cancels further Iran setup while preserving the Foreign tunnel.

## SSH connection and package downloads on Iran

The Iran server must already accept password-based SSH login for **root**. The manager does not change SSH settings, send an SSH login key to Iran, or save the password in a file. The host key is recorded on the first connection; a change to that recorded key blocks the connection.

The manager and required binaries are transferred from Foreign to Iran and verified with SHA256. Choosing `y` for the download route sends Iran's APT requests through the same SSH session using Foreign's internet connection; `n` uses Iran's direct internet connection. With `y`, Iran does not need direct access to Ubuntu repositories or GitHub; Foreign must be able to reach the download sources, and Iran's SSH server must allow port forwarding. No permanent proxy configuration is written on Iran.

If all prerequisites are installed, their package download size is zero and APT is not run for them. If packages are missing, repository indexes are fetched first, then the required package download size is displayed, accounting for dependencies and cached packages. Repository indexes and tunnel binaries have separate download sizes; indexes may be fetched before the package size is announced. APT targets only missing prerequisites, although a required dependency may need an upgrade. This method does not create an offline `.deb` archive.

To repeat Iran setup using the current Foreign configuration, open **Foreign tunnel management → `9) Set up Iran via SSH`**. This option uses the manual questions and replacement confirmation; it does not require recreating the Foreign side.

## Ubuntu package manager lock

If `unattended-upgr` holds `/var/lib/dpkg/lock-frontend`, Ubuntu is already installing updates. An `SSH tool installation failed` message comes from installing SSH prerequisites on the **Foreign server**, before the SSH connection to Iran starts.

Version 2.5.1 gives local package installations up to **300 seconds** to acquire the dpkg lock, with additional time for the installation itself. It uses APT's native `DPkg::Lock::Timeout`; it does not remove lock files or stop automatic updates. Repository index locks used by `apt-get update` are separate; if those are busy, let the other APT operation finish and retry.

You can install the SSH prerequisites on Foreign directly:

```bash
sudo apt-get -o DPkg::Lock::Timeout=300 install -y openssh-client sshpass
sudo multi-tunnel
```

Then select **Manage local tunnels → your Foreign tunnel → `9) Set up Iran via SSH`**. The saved Foreign tunnel does not need to be recreated. If the lock is still held after the wait expires, let the update finish and retry. Do not delete dpkg lock files.

## Manual setup on Iran

If you choose `n` at the end of Foreign setup, run the script on Iran yourself, select `1) Create tunnel`, then `1) Iran`, and enter the complete `MULTI2.` code. You can also save the code in a file and enter `@/root/connection.txt` instead.

The connection code contains authentication credentials; do not publish it in a GitHub repository. The Foreign certificate's private key is not included in the connection code and is not transferred to Iran.

## Transport types

| Engine | Transport types |
|---|---|
| Backhaul | TCP, UDP, WS, WSMux, TCPMux |
| Rathole | TCP, WS |
| GOST | TCP, UDP, WS, gRPC, TCPMux |

In this project's design, Backhaul and Rathole use an additional **GOST TLS/WSS** transport so that the connection endpoint remains on Foreign. Backhaul UDP traffic also passes through a reliable stream. Simple GOST TCP/UDP forwarding connects directly from Iran to the destination port on Foreign.

## Management and connection tests

Main menu: `1` create, `2` manage tunnels, `3` recover interrupted operations, `4` get a certificate, `5` install the latest `mhsanaei/3x-ui`, `6` install the latest `alireza0/x-ui`, and `0` exit.

The management menu provides status, connection tests, editing, deletion, restart, and logs. Tunnels are grouped in the order Backhaul, Rathole, and GOST, then sorted by name within each group. On Foreign, you can also display the connection code and set up Iran over SSH.

On Iran, **`2) test tunnel connection`** runs a live test and displays one of these messages:

```text
Tunnel connection successful.
Tunnel connection unsuccessful.
```

The test checks the tunnel path; VLESS configuration and Xray service health must be checked separately. An `active` service state alone does not confirm successful connectivity. The regular test option on Foreign shows local status and instructions for testing from Iran; SSH setup runs the test remotely on Iran.

## Getting a certificate

The main menu's **`4) get cert for sub domain`** option installs Certbot and requests a certificate for the domain you enter. This option is also available in tunnel management.

Validation requests must reach this server, and inbound TCP port `80` must be available and reachable. After successful issuance, the paths are displayed:

```text
/etc/letsencrypt/live/tunnel.example.com/fullchain.pem
/etc/letsencrypt/live/tunnel.example.com/privkey.pem
```

For Cloudflare, point the domain to Foreign's IP and set SSL to `Full (strict)`. The certificate must cover the tunnel domain. Certificate issuance, renewal, and Cloudflare configuration are explained in the [Persian guide](README.fa.md).

## Panel installation

In the main menu, option `5` installs the latest `mhsanaei/3x-ui`, and option `6` installs the latest `alireza0/x-ui`. In Foreign tunnel management, these are options `10` and `11`; in Iran tunnel management, they are `8` and `9`.

The selected option downloads the project's official installer from its `master` branch and runs it without specifying a version; the official installer determines the latest release. Installation takes place on **the server where the menu is running**. To install a panel on Foreign, open the menu on Foreign. Usually, you only need one of these panels: both use the `x-ui` service name and paths and are not designed to coexist on the same server. Installing another panel may modify an existing installation.

Installer sources: [mhsanaei/3x-ui](https://github.com/mhsanaei/3x-ui/blob/master/install.sh) and [alireza0/x-ui](https://github.com/alireza0/x-ui/blob/master/install.sh). The panel menu does not automatically install the panel on Iran, and the temporary APT route used for Iran setup does not apply to panel installation.

## Progress and cancellation

File downloads and transfers to Iran display the amount transferred and a progress percentage; transferred files are verified before success is confirmed. APT stages also display their progress. When a stage's total size is not known in advance, activity is shown instead of a fabricated overall percentage or remaining time.

Pressing `Ctrl+C` in the main menu, tunnel selection, management menu, or recovery selection exits the program completely without displaying the menu again. While answering configuration questions or running an operation, `Ctrl+C` cancels that operation and returns to the menu after cleanup. The temporary SSH connection and download route are closed. Cancellation does not uninstall packages already installed or undo changes made by a panel installer; after interrupting APT, you may need to check the package state or rerun installation. Tunnel configuration recovery uses the existing recovery mechanism for that operation.

## Updating

From versions **2.0, 2.1, 2.2, 2.3, 2.4, and 2.5.0**, you can replace the script with the new file or run the new installer. `schema_version: 2` configurations and `MULTI2.` codes remain compatible; updating the manager alone does not require recreating working tunnels. Editing Foreign settings still generates a new connection code that must be applied on Iran.

The installer does not automatically migrate old v1 configurations. The installed program is at `/usr/local/lib/multi-tunnel/multi-tunnel.py`, and configurations are in `/etc/multi-tunnel`.

## Code checks

```bash
bash -n install.sh
python3 -m unittest discover -s tests -v
```

Automatic setup also shows progress for each stage; the progress bar for one file download or transfer does not represent overall setup progress across both servers. Automated tests do not replace connection testing on two real Iran and Foreign VPSs; these tests do not perform actual APT installation, change a server's firewall, or issue a real certificate. Details of local engine testing are in the [Persian guide](README.fa.md).

Smite inspired the requested features; its source code was not copied into this project. This is an independent project, and downloaded engines retain their own licenses.
