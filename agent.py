from scapy.all import sniff, IP, TCP, UDP, ICMP
from sklearn.tree import DecisionTreeClassifier
import pandas as pd
import requests
import threading
import time
import sys

CONTROLLER_IP = "192.168.50.240"
SWITCH_DPID = "00:00:00:e0:4c:68:00:28"
MONITOR_INTERFACE = "Ethernet"

try:
    print("[*] Training Decision Tree Classifier from custom dataset...")
    df = pd.read_csv('training_data.csv')
    features = ['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio']
    clf = DecisionTreeClassifier(max_depth=5, criterion='entropy', random_state=42)
    clf.fit(df[features].values, df['label'])
    print(f"[+] Model trained successfully on {len(df)} records.")
except Exception as e:
    print(f"[-] Training Error: {e}")
    sys.exit(1)

traffic_stats = {}
stats_lock = threading.Lock()
blocked_ips = set()

def block_attacker(ip):
    if ip in blocked_ips: return
    print(f"\n[!!!] MALICIOUS FLOOD DETECTED: {ip} - DEPLOYING OPENFLOW RULE")
    
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
            print(f"[+] Successfully pushed hardware drop rule for {ip}")
    except Exception as e:
        print(f"[-] API Error: {e}")

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        with stats_lock:
            if ip not in traffic_stats:
                traffic_stats[ip] = {'count': 0, 'bytes': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
            traffic_stats[ip]['count'] += 1
            traffic_stats[ip]['bytes'] += len(pkt)
            if TCP in pkt: traffic_stats[ip]['tcp'] += 1
            elif UDP in pkt: traffic_stats[ip]['udp'] += 1
            elif ICMP in pkt: traffic_stats[ip]['icmp'] += 1

def analyze_traffic():
    global traffic_stats
    while True:
        time.sleep(1.0) 
        with stats_lock:
            current = traffic_stats.copy()
            traffic_stats.clear()

        for ip, data in current.items():
            pps = data['count']
            bps = data['bytes']
            avg_size = bps / pps if pps > 0 else 0
            tcp_r = data['tcp'] / pps
            udp_r = data['udp'] / pps
            icmp_r = data['icmp'] / pps
            
            prediction = clf.predict([[pps, bps, avg_size, tcp_r, udp_r, icmp_r]])[0]
            if prediction == 1 and ip not in blocked_ips:
                block_attacker(ip)

def cleanup():
    print("\n\n[!] Shutting down. Removing OpenFlow drop rules...")
    for ip in blocked_ips:
        try:
            requests.delete(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json={"name": f"block-{ip}"})
            print(f"[+] Restored traffic for {ip}")
        except Exception as e:
            pass
    print("Cleanup complete. Exiting.")
    sys.exit(0)

if __name__ == '__main__':
    threading.Thread(target=analyze_traffic, daemon=True).start()
    print("[*] Multi-Feature Decision Tree Agent Running...")
    print("[*] Press Ctrl+C to exit and restore network traffic.")
    try:
        sniff(iface=MONITOR_INTERFACE, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        cleanup()