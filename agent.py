from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer
from sklearn.tree import DecisionTreeClassifier
import pandas as pd
import requests
import threading
import time
import sys
import signal

CONTROLLER_IP = "192.168.50.240"
MONITOR_INTERFACE = "Ethernet"
MIN_PPS_THRESHOLD = 10
WHITELIST_IPS = {"192.168.50.40", "192.168.50.50", "192.168.50.240"}
SWITCH_DPID = ""

def get_switch_dpid():
    print("[*] Polling Floodlight Controller for active switches...")
    try:
        response = requests.get(f"http://{CONTROLLER_IP}:8080/wm/core/controller/switches/json", timeout=5)
        if response.status_code == 200:
            switches = response.json()
            if switches:
                dpid = switches[0].get('switchDPID')
                print(f"[+] Successfully locked onto Switch DPID: {dpid}")
                return dpid
        print("[-] No switches connected to the controller.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to reach Floodlight API: {e}")
        sys.exit(1)

try:
    df = pd.read_csv('training_data.csv')
    features = ['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio']
    clf = DecisionTreeClassifier(max_depth=5, criterion='entropy', random_state=42)
    clf.fit(df[features].values, df['label'])
except Exception as e:
    print(f"[-] Training Error: {e}"); sys.exit(1)

traffic_stats = {}
stats_lock = threading.Lock()
blocked_ips = set()

def block_attacker(ip):
    if ip in blocked_ips: return
    print(f"\n[!!!] VOLUMETRIC FLOOD DETECTED: {ip} - DEPLOYING OPENFLOW RULE")
    
    payload = {
        "switch": SWITCH_DPID, 
        "name": f"block-{ip.replace('.', '_')}", # Fixed naming convention for OVS
        "priority": "32768", 
        "eth_type": "0x0800", 
        "ipv4_src": f"{ip}", 
        "active": "true", 
        "actions": ""
    }
    
    # Modern Floodlight Endpoint (v1.0+)
    endpoint_new = f"http://{CONTROLLER_IP}:8080/wm/staticentrypusher/json"
    # Legacy Floodlight Endpoint (v0.9)
    endpoint_old = f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json"
    
    try:
        res = requests.post(endpoint_new, json=payload, timeout=2)
        if res.status_code == 200:
            print("[+] OpenFlow Rule ACCEPTED by Controller (Modern API).")
            blocked_ips.add(ip)
        else:
            print(f"[-] Modern API rejected rule: {res.text}. Trying Legacy API...")
            
            res_old = requests.post(endpoint_old, json=payload, timeout=2)
            if res_old.status_code == 200:
                print("[+] OpenFlow Rule ACCEPTED by Controller (Legacy API).")
                blocked_ips.add(ip)
            else:
                print(f"[-] Legacy API also rejected rule: {res_old.text}")
                
    except Exception as e:
        print(f"[-] API Request Failed to reach Controller: {e}")

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        with stats_lock:
            if ip not in traffic_stats:
                traffic_stats[ip] = {'count': 0, 'bytes': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
            traffic_stats[ip]['count'] += 1
            traffic_stats[ip]['bytes'] += len(pkt)
            if TCP in pkt: traffic_stats[ip]['tcp'] += 1
            if UDP in pkt: traffic_stats[ip]['udp'] += 1
            if ICMP in pkt: traffic_stats[ip]['icmp'] += 1

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
            if pps < MIN_PPS_THRESHOLD: continue
            
            avg_size = bps / pps
            tcp_r = data['tcp'] / pps
            udp_r = data['udp'] / pps
            icmp_r = data['icmp'] / pps
            
            # Use a dataframe or 2D array without feature names warning
            if clf.predict([[pps, bps, avg_size, tcp_r, udp_r, icmp_r]])[0] == 1 and ip not in blocked_ips:
                if ip not in WHITELIST_IPS: block_attacker(ip)

def cleanup(sig=None, frame=None):
    print("\n[!] Shutting down. Removing OpenFlow drop rules...")
    for ip in blocked_ips:
        try:
            requests.delete(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json={"name": f"block-{ip}"})
        except:
            pass
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, cleanup)
    SWITCH_DPID = get_switch_dpid()
    
    threading.Thread(target=analyze_traffic, daemon=True).start()
    print("[*] ML Agent is monitoring traffic. Press Ctrl+C to stop and clear rules...")
    
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)