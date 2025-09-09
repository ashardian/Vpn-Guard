#!/usr/bin/env python3
import os
import subprocess
import sys
from datetime import datetime

LOG_FILE = "/var/log/vpn_guard.log"

def log(msg):
    """Log to console + file"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except PermissionError:
        pass

def run_cmd(cmd, check=True):
    """Run shell command safely"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        if check:
            log(f"[ERROR] {cmd}\n{result.stderr.strip()}")
        return None

def detect_vpn_iface():
    """Detect VPN interface automatically (wg, tun, ppp)"""
    out = run_cmd("ip -o link show | awk -F': ' '{print $2}'", check=False)
    if not out:
        return None
    candidates = [line for line in out.splitlines() if line.startswith(("wg", "tun", "ppp"))]
    return candidates[0] if candidates else None

def detect_dns():
    """Read current DNS"""
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except Exception:
        pass
    return "unknown"

def ipv6_status():
    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "?"

def disable_ipv6():
    log("Disabling IPv6...")
    run_cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    run_cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    config = "/etc/sysctl.d/99-disable-ipv6.conf"
    content = "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n"
    try:
        with open(config, "w") as f:
            f.write(content)
    except PermissionError:
        log("[WARN] Could not write sysctl config file")
    run_cmd(f"sysctl -p {config}")
    log("IPv6 disabled permanently.")

def enable_ipv6():
    log("Enabling IPv6...")
    run_cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
    run_cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=0")
    try:
        os.remove("/etc/sysctl.d/99-disable-ipv6.conf")
    except FileNotFoundError:
        pass
    log("IPv6 re-enabled.")

def setup_killswitch(iface):
    if not iface:
        log("[ERROR] No VPN interface detected")
        return
    log(f"Setting up killswitch for {iface}...")
    run_cmd("iptables -F")
    run_cmd("iptables -X")
    run_cmd("iptables -P INPUT DROP")
    run_cmd("iptables -P OUTPUT DROP")
    run_cmd("iptables -P FORWARD DROP")
    run_cmd("iptables -A INPUT -i lo -j ACCEPT")
    run_cmd("iptables -A OUTPUT -o lo -j ACCEPT")
    run_cmd("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    run_cmd("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    run_cmd(f"iptables -A OUTPUT -o {iface} -j ACCEPT")
    run_cmd(f"iptables -A INPUT -i {iface} -j ACCEPT")
    log("Killswitch active.")

def disable_killswitch():
    log("Disabling killswitch...")
    run_cmd("iptables -F")
    run_cmd("iptables -X")
    run_cmd("iptables -P INPUT ACCEPT")
    run_cmd("iptables -P OUTPUT ACCEPT")
    run_cmd("iptables -P FORWARD ACCEPT")
    log("Firewall reset, killswitch disabled.")

def set_vpn_dns(dns="1.1.1.1"):
    log(f"Setting DNS to {dns}...")
    try:
        with open("/etc/resolv.conf", "w") as f:
            f.write(f"nameserver {dns}\n")
        log(f"DNS set to {dns}")
    except PermissionError:
        log("[WARN] Cannot write /etc/resolv.conf")

def verify(iface):
    log("--- Verification ---")
    log(f"IPv6 disabled: {'YES' if ipv6_status() == '1' else 'NO'}")
    if iface:
        if run_cmd(f"ip link show {iface}", check=False):
            log(f"VPN interface {iface} exists ✅")
        else:
            log(f"VPN interface {iface} not found ❌")
    else:
        log("No VPN interface detected ❌")
    log(f"Current DNS: {detect_dns()}")
    fw = run_cmd("iptables -L OUTPUT -v -n", check=False)
    if fw: log("\n[iptables OUTPUT]\n" + fw)

def secure_mode(iface, dns="1.1.1.1"):
    log("Enabling secure mode (VPN-only traffic)...")
    disable_ipv6()
    setup_killswitch(iface)
    set_vpn_dns(dns)
    verify(iface)

def restore_defaults():
    log("Restoring system defaults...")
    enable_ipv6()
    disable_killswitch()
    log("System back to normal state.")

def menu():
    print("""
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
""")
    return input("Select option (1-9): ").strip()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("❌ Run this script as root (sudo).")

    iface = detect_vpn_iface()
    log(f"Auto-detected VPN interface: {iface if iface else 'None'}")

    while True:
        choice = menu()
        if choice == "1": disable_ipv6()
        elif choice == "2": enable_ipv6()
        elif choice == "3": setup_killswitch(iface)
        elif choice == "4": disable_killswitch()
        elif choice == "5":
            dns = input("Enter DNS (default 1.1.1.1): ").strip() or "1.1.1.1"
            set_vpn_dns(dns)
        elif choice == "6": verify(iface)
        elif choice == "7":
            dns = input("Enter DNS (default 1.1.1.1): ").strip() or "1.1.1.1"
            secure_mode(iface, dns)
        elif choice == "8": restore_defaults()
        elif choice == "9":
            log("Exiting VPN Security Toolkit ✅")
            break
        else:
            print("❌ Invalid choice, try again.")

