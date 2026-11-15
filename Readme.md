# Windows OpenVPN Auto-Deploy (`Deploy-OpenVpnHost.ps1`)

A self-contained, interactive PowerShell script that turns a Windows 10/11 machine into a full-tunnel OpenVPN server and generates ready-to-import unified `.ovpn` profiles for both the server and remote clients—with **zero external dependencies**.

Unlike traditional setups, **this script does not require OpenSSL or Easy-RSA**. It generates all 2048-bit RSA keys, a local Certificate Authority (CA), and X.509 certificates natively in memory using Windows .NET Cryptography APIs (`CNG` / `CertificateRequest`).

## Features

* **Zero External Dependencies:** Generates RSA-2048 private keys, a self-signed CA, and CA-signed server/client certificates natively in PowerShell via .NET CNG—no OpenSSL installation or `PATH` configuration required.
* **Unified Inline `.ovpn` Profiles:** Embeds `<ca>`, `<cert>`, `<key>`, and `<tls-crypt>` blocks directly inside `server.ovpn` and `<client>.ovpn`, eliminating Windows backslash path errors and external file dependencies.
* **Modern Cryptographic Defaults & OpenVPN 2.6/2.7+ Ready:**
  * Uses `AES-256-GCM` data channel encryption and `SHA256` HMAC authentication.
  * Embeds a `<tls-crypt>` static key (`ta.key`) to encrypt control-channel handshakes and block unauthorized port scans.
  * Uses Elliptic Curve Diffie-Hellman (`dh none`) for fast handshakes and full compatibility with modern OpenVPN and OpenSSL 3.x/4.x builds.
  * Attaches proper Extended Key Usage (EKU) OIDs (`serverAuth` and `clientAuth`) so `remote-cert-tls server` passes strict verification on iOS and Android OpenVPN Connect clients.
* **Multi-Client Support:** Re-running the script preserves your existing `ca.crt`, `ca.key`, `server.crt`, and `ta.key` in `%USERPROFILE%\OpenVPN_Keys`, allowing you to generate profiles for additional devices without invalidating your running server or existing clients.
* **Automated Windows Networking:**
  * **Auto-Elevation:** Automatically restarts with Administrator privileges (safely handling UNC network paths).
  * **Public IP Auto-Discovery:** Detects your current public WAN IP address via `api.ipify.org`.
  * **IP Packet Forwarding:** Enables `IPEnableRouter = 1` in the Windows Registry so traffic can route between the VPN tunnel and your local network.
  * **Internet Connection Sharing (ICS):** Automatically detects your active internet adapter (`Wi-Fi` or `Ethernet`) and shares its connection with the `OpenVPN Data Channel Offload` (or `TAP-Windows`) adapter, with step-by-step manual fallback instructions if needed.

## Prerequisites

1. **Operating System:** Windows 10 or Windows 11 with PowerShell 5.1 or newer.
2. **OpenVPN Community Edition:** Installed on the Windows host machine ([Download OpenVPN](https://openvpn.net/community-downloads/)), which provides the OpenVPN GUI and the `OpenVPN Data Channel Offload` virtual adapter.
3. **Static Local IP (Recommended):** Set a static IP or DHCP reservation on your router for the Windows host PC so port forwarding remains consistent.
4. **Router Port Forwarding:** Forward **UDP port `1194`** on your router to the local LAN IP address of your Windows host PC.
5. **Windows Firewall:** Allow inbound traffic on **UDP port `1194`** (or allow `openvpn.exe` through Windows Defender Firewall).

## Quick Start

### 1. Download and Run the Script

Download `Deploy-OpenVpnHost.ps1` to your Windows host, open PowerShell, and run it (it will automatically prompt for UAC Administrator elevation):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Deploy-OpenVpnHost.ps1
```

*(Alternatively, run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` once to allow running local scripts directly via `.\Deploy-OpenVpnHost.ps1`.)*

### 2. Follow the Interactive Prompts

The script will auto-elevate to Administrator, detect your public IP, and prompt you for three values (press **Enter** to accept the auto-detected defaults):

1. **Server Public IP or DDNS:** Auto-filled with your current public WAN IP.
2. **Client Name:** Defaults to `mobile-client`.
3. **Local Home Network Base IP:** Defaults to `192.168.0.0` (adjust if your LAN uses `192.168.1.0`, `10.0.0.0`, etc.).

> **Note:** If this is the first time `IPEnableRouter` is enabled on your PC, the script will display a warning asking you to **reboot your PC** once it finishes so Windows packet forwarding takes effect.

### 3. Import the Server Profile (Windows Host)

The script outputs your generated files to your **Desktop**:

* `server.ovpn`
* `<client-name>.ovpn`

To start the server:

1. Copy `server.ovpn` from your Desktop to `C:\Program Files\OpenVPN\config\` (ensure no old `.ovpn` files remain in that folder).
2. Launch **OpenVPN GUI**, right-click its system tray icon, and click **Connect**.
3. The tray icon will turn green once the server is listening on UDP `1194`.

### 4. Import the Client Profile (Mobile / Remote Device)

1. Transfer `<client-name>.ovpn` (e.g., `mobile-client.ovpn`) from your Desktop to your phone or remote laptop.
2. Open **OpenVPN Connect** (or your preferred OpenVPN client), import the `.ovpn` file, and toggle the connection on.

## Adding More Client Devices

To generate a profile for a second device (e.g., a laptop or tablet) without resetting your server:

1. Run `.\Deploy-OpenVpnHost.ps1` again.
2. When prompted for **Client Name**, enter a unique name such as `work-laptop`.
3. The script will reuse your existing CA, server certificate, and `ta.key`, sign a new client certificate, and output `work-laptop.ovpn` on your Desktop.

## File Locations

| Path | Description |
| :--- | :--- |
| `%USERPROFILE%\OpenVPN_Keys\` | Stores your persistent CA, server, client, and `ta.key` files. **Back this folder up securely.** |
| `%USERPROFILE%\Desktop\server.ovpn` | Ready-to-import OpenVPN server configuration with inline keys. |
| `%USERPROFILE%\Desktop\<client>.ovpn` | Ready-to-import OpenVPN client profile with inline keys. |

## Troubleshooting

* **Clients connect to the LAN (`192.168.0.x`) but have no internet access:**
  * Confirm you have rebooted Windows at least once after `IPEnableRouter` was enabled.
  * Verify that **Internet Connection Sharing (ICS)** is active on your internet-facing adapter: press `Win + R`, type `ncpa.cpl`, right-click your active **Wi-Fi** or **Ethernet** adapter -> **Properties** -> **Sharing** tab, and confirm it is shared with **OpenVPN Data Channel Offload**.
  * Disconnect and reconnect the server profile in the OpenVPN GUI after modifying sharing settings.
* **Connection times out from cellular data:**
  * Ensure **UDP port `1194`** is forwarded to your PC's static/reserved LAN IP in your router settings, and verify Windows Defender Firewall allows inbound UDP traffic on port `1194`.
  * Test from cellular data or an external network—many consumer routers block hairpin NAT (connecting to your public IP from inside your own Wi-Fi).
* **"Running scripts is disabled on this system" error:**
  * Run with `-ExecutionPolicy Bypass` as shown in the Quick Start section, or enable local scripts once via `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`.

## License

This project is open-source and available under the [MIT License](LICENSE).