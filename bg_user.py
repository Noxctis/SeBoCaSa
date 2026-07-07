import socket
import time
import random
import threading
import subprocess
import os

# If running on PC2, set this to PC4's IP (192.168.50.50)
# If running on PC4, set this to PC2's IP (192.168.50.40)
TARGET_IP = "192.168.50.50" 

def simulate_web_traffic():
    """Simulates random TCP connections (like loading web pages)"""
    while True:
        try:
            # Simulate bursts of normal traffic
            time.sleep(random.uniform(0.5, 3.0))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((TARGET_IP, 80)) # Will fail if no web server, but generates the TCP SYN packets!
            sock.close()
        except:
            pass

def simulate_background_pings():
    """Simulates occasional network health checks (ICMP)"""
    while True:
        time.sleep(random.uniform(2.0, 10.0))
        subprocess.run(["ping", "-n", "1", TARGET_IP], stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    print(f"[*] Starting Legitimate Background Traffic to {TARGET_IP}...")
    threading.Thread(target=simulate_web_traffic, daemon=True).start()
    threading.Thread(target=simulate_background_pings, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Background traffic stopped.")
        os._exit(0)