from scapy.all import sniff, IP
from sklearn.tree import DecisionTreeClassifier
import pandas as pd
import requests
import threading
import time
import sys

CONTROLLER_IP = "192.168.50.240"
SWITCH_DPID = "00:00:00:e0:4c:68:00:28" 
MONITOR_INTERFACE = "Ethernet"

MIN_PPS_THRESHOLD = 10
WHITELIST_IPS = {"192.168.50.50", "192.168.50.240"}

try:
    df = pd.read_csv('training_data.csv')
    features = ['pps', 'bps', 'avg_size']
    clf = DecisionTreeClassifier(max_depth=5, criterion='entropy', random_state=42)
    clf.fit(df[features].values, df['label'])
    print(f"[+] Model trained successfully on {len(df)} data points.")
except Exception as e:
    print(f"[-] Training Error: {e}")
    sys.exit(1)

traffic_stats = {}
stats_lock = threading.Lock()
blocked_ips = set()

def block_attacker(ip):
    if ip in blocked_ips: return
    print(f"\n[!!!] VOLUMETRIC FLOOD DETECTED: {ip} - DEPLOYING OPENFLOW RULE")
    
    payload = {
        "switch": SWITCH_DPID, 
        "name": f"block-{ip}",
        "priority": "32767", 
        "eth_type": "0x0800",
        "ipv4_src": f"{ip}/32", 
        "active": "true", 
        "actions": "" 
    }
    
    try:
        resp = requests.post(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json=payload)
        if resp.status_code == 200:
            blocked_ips.add(ip)
    except Exception as e:
        print(f"[-] API Error: {e}")

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        with stats_lock:
            if ip not in traffic_stats:
                traffic_stats[ip] = [0, 0]
            traffic_stats[ip][0] += 1       
            traffic_stats[ip][1] += len(pkt) 

def analyze_traffic():
    global traffic_stats
    while True:
        time.sleep(1.0) 
        
        with stats_lock:
            current = traffic_stats.copy()
            traffic_stats.clear()

        for ip, data in current.items():
            pps = data[0]
            bps = data[1]
            avg_size = bps / pps if pps > 0 else 0
            
            if pps < MIN_PPS_THRESHOLD:
                continue
                
            prediction = clf.predict([[pps, bps, avg_size]])[0]

            if prediction == 1 and ip not in blocked_ips:
                if ip in WHITELIST_IPS:
                    print(f"\n[i] Ignored flood from WHITELISTED IP: {ip}")
                else:
                    block_attacker(ip)

def cleanup():
    print("\n[!] Shutting down. Removing OpenFlow drop rules...")
    for ip in blocked_ips:
        try:
            requests.delete(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json={"name": f"block-{ip}"})
        except: pass
    sys.exit(0)

if __name__ == '__main__':
    threading.Thread(target=analyze_traffic, daemon=True).start()
    print("[*] ML Agent is monitoring traffic...")
    try:
        sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)
    except KeyboardInterrupt:
        cleanup()