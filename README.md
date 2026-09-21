# Multi Tunnel

Terminal manager for **Backhaul, Rathole and GOST** on **Ubuntu 22.04+**, **amd64 / x86_64**, using IPv4. Supports automatic setup over SSH and manual pairing.

## Local installation

Place `install.sh` and `multi-tunnel.py` together on the **Foreign server**, then run:

```bash
sudo bash install.sh --local ./multi-tunnel.py
sudo multi-tunnel
```

## GitHub installation

Put both updated files in your repository root. This example uses `YoungDeveloper2025/multi-tunnel`, branch `main`; replace the repository and branch if needed. Requires `curl` and CA certificates.

```bash
curl -fsSL --retry 3 https://raw.githubusercontent.com/YoungDeveloper2025/multi-tunnel/main/install.sh -o /tmp/multi-install.sh
sudo bash /tmp/multi-install.sh --repo YoungDeveloper2025/multi-tunnel --ref main
sudo multi-tunnel
```

## Setup and management

- **Automatic:** on Foreign, select **Create tunnel → Foreign → Automatic** and enter the Iran server's IPv4, SSH port and root password. Missing Iran packages can be downloaded through Foreign over SSH.
- **Manual:** create the Foreign side first, then install the manager on Iran and import the connection code.
- **Update:** reinstall the manager on Foreign, then use **Manage local tunnels → Restart**, followed by **Set up Iran via SSH** for the existing tunnel.
- Reopen the menu with `sudo multi-tunnel` to view status/logs, test, edit, restart or delete tunnels.

## Connection notes

- Backhaul and Rathole connect **Foreign → Iran**. GOST forwards **Iran → Foreign application ports**.
- Use direct IPs or DNS-only domains. Allow the displayed ports in your provider firewall; the manager adds local UFW rules.
- For ordinary TCP applications, choose **GOST TCP**. Foreign services must listen on an interface reachable from Iran. GOST WS/gRPC/TCPMux require a matching transport on the Iran input.
- GOST TCP SSH setup synchronizes the selected Iran ports with the Foreign configuration. Use those Iran ports in your client.
- The authenticated health check uses a separate port. Its result does not establish whether your application works; test with your actual client too.

## Uninstall

Remove the manager, all managed tunnels and cached engines from the current server:

```bash
sudo multi-tunnel --uninstall
```
