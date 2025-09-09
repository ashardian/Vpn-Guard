# 🛡️ VPN Guard

A lightweight **VPN security toolkit for Linux** that protects against IP leaks, DNS leaks, and accidental exposure when your VPN drops.  
Supports **WireGuard**, **OpenVPN**, and other VPN apps that create network interfaces (`wg*`, `tun*`, `ppp*`).  

No dependencies. No pip installs. Pure Python + iptables + sysctl. Works on most Linux distributions (Debian, Ubuntu, Fedora, Arch, etc).  

---

## ✨ Features

- 🔍 **Auto-detects VPN interface** (`wg0`, `tun0`, `ppp0`, etc).
- 🌐 **Disable/Enable IPv6** (runtime + permanent).
- 🔒 **VPN Killswitch** — blocks all traffic outside VPN interface.
- 🔑 **Secure DNS** — force DNS to VPN or custom resolver.
- 🧰 **Verification** — check IPv6, VPN interface, DNS, and firewall rules.
- ⚡ **Secure Mode** — one-click protection (IPv6 disabled + killswitch + safe DNS).
- ♻️ **Restore Defaults** — reset system back to normal (IPv6 + open firewall).
- 📝 **Logging** — all actions logged to `/var/log/vpn_guard.log`.

---

## 📦 Installation

Clone the repo:

```bash
git clone https://github.com/ashardian/vpn-guard.git
cd vpn-guard
````

Make the script executable:

```bash
chmod +x vpn_guard.py
```

Run with root:

```bash
sudo ./vpn_guard.py
```

---

## 🎮 Usage

When you run the script, you’ll see an interactive menu:

```
==============================
   VPN Security Toolkit
==============================
1) Disable IPv6
2) Enable IPv6
3) Enable killswitch
4) Disable killswitch
5) Set VPN DNS
6) Verify status
7) Secure Mode (all protections)
8) Restore Defaults
9) Exit
```

### 🛠️ Example Workflows

#### ✅ One-click protection

* Select **7 (Secure Mode)** → disables IPv6, enables killswitch, sets safe DNS.

#### 🔍 Verify security

* Select **6 (Verify status)** → shows IPv6 status, VPN interface, DNS, firewall rules.

#### ♻️ Reset system

* Select **8 (Restore Defaults)** → resets firewall and re-enables IPv6.

---

## 🔐 How It Works

* **IPv6 leaks**: Many VPNs don’t tunnel IPv6, so the script disables IPv6 system-wide to prevent leaks.
* **Killswitch**: Uses `iptables` to drop all traffic except via your VPN interface and loopback.
* **DNS leaks**: Overwrites `/etc/resolv.conf` with a secure DNS (default `1.1.1.1` or VPN DNS).
* **Verification**: Checks `/proc/sys/net/ipv6`, current DNS, iptables rules, and VPN interface status.

---

## ⚠️ Requirements

* Linux system (tested on Debian, Ubuntu, Fedora, Arch).
* Root privileges (`sudo`).
* VPN must create a network interface (`wg0`, `tun0`, or `ppp0`).

---

## 📝 Logs

All actions are logged to:

```
/var/log/vpn_guard.log
```

---

## 🤝 Contributing

Pull requests are welcome!
If you find a bug or want a feature, open an [issue](https://github.com/yourusername/vpn-guard-universal/issues).

---

## 📜 License

This project is licensed under the **MIT License** — free to use, modify, and share.

---

## 👨‍💻 Author

Created by [Ashar Dian](https://github.com/ashardian)
Feel free to fork, improve, and share 🚀
