from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer
from sklearn.tree import DecisionTreeClassifier
import pandas as pd
import requests
import threading
import time
import sys
import signal
import subprocess

CONTROLLER_IP = "192.168.50.240"
MONITOR_INTERFACE = "Ethernet"
MIN_PPS_THRESHOLD = 10
WHITELIST_IPS = {"192.168.50.240"}
SWITCH_DPID = ""
OVS_BRIDGE = "br0" # Adjust if your bridge name differs

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
    print(f"[-] Training Error: {e}")
    sys.exit(1)

traffic_stats = {}
stats_lock = threading.Lock()
blocked_ips = set()

def verify_mitigation_latency(ip, t_detect):
    time.sleep(2.0)
    try:
        cmd = f"date +%s.%3N && sudo ovs-ofctl dump-flows {OVS_BRIDGE} | grep 'nw_src={ip}'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            t_query = float(lines[0])
            duration_part = [part for part in lines[1].split(',') if 'duration=' in part][0]
            d_flow = float(duration_part.split('=')[1].replace('s', ''))
            
            install_time = t_query - d_flow
            latency_ms = (install_time - t_detect) * 1000
            
            print(f"\n[*] True Datapath Mitigation Latency for {ip}: {latency_ms:.2f} ms")
        else:
            print(f"\n[-] Could not find flow rule in OVS for {ip} to calculate latency.")
            
    except Exception as e:
        print(f"\n[-] Automated latency calculation failed: {e}")

def block_attacker(ip):
    if ip in blocked_ips: return
    
    t_detect = time.time()
    
    print(f"\n[!!!] VOLUMETRIC FLOOD DETECTED: {ip} - DEPLOYING OPENFLOW RULE")
    print(f"[*] Detection Timestamp (T_detect): {t_detect:.3f}")
    
    payload = {
        "switch": SWITCH_DPID, 
        "name": f"block-{ip.replace('.', '_')}", 
        "priority": "32768", 
        "eth_type": "0x0800", 
        "ipv4_src": f"{ip}", 
        "active": "true", 
        "actions": ""
    }
    
    endpoint_new = f"http://{CONTROLLER_IP}:8080/wm/staticentrypusher/json"
    endpoint_old = f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json"
    
    try:
        res = requests.post(endpoint_new, json=payload, timeout=2)
        if res.status_code == 200:
            api_latency_ms = (time.time() - t_detect) * 1000
            print(f"[+] OpenFlow Rule ACCEPTED by Controller (Modern API). API Latency: {api_latency_ms:.2f} ms")
            blocked_ips.add(ip)
            threading.Thread(target=verify_mitigation_latency, args=(ip, t_detect), daemon=True).start()
        else:
            print(f"[-] Modern API rejected rule: {res.text}. Trying Legacy API...")
            
            res_old = requests.post(endpoint_old, json=payload, timeout=2)
            if res_old.status_code == 200:
                api_latency_ms = (time.time() - t_detect) * 1000
                print(f"[+] OpenFlow Rule ACCEPTED by Controller (Legacy API). API Latency: {api_latency_ms:.2f} ms")
                blocked_ips.add(ip)
                threading.Thread(target=verify_mitigation_latency, args=(ip, t_detect), daemon=True).start()
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
            
            if clf.predict([[pps, bps, avg_size, tcp_r, udp_r, icmp_r]])[0] == 1 and ip not in blocked_ips:
                if ip not in WHITELIST_IPS: block_attacker(ip)

def cleanup(sig=None, frame=None):
    print("\n[!] Shutting down. Removing OpenFlow drop rules...")
    
    endpoint_new = f"http://{CONTROLLER_IP}:8080/wm/staticentrypusher/json"
    endpoint_old = f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json"
    
    for ip in blocked_ips:
        rule_name = f"block-{ip.replace('.', '_')}"
        payload = {"name": rule_name}
        
        try:
            res_new = requests.delete(endpoint_new, json=payload, timeout=2)
            res_old = requests.delete(endpoint_old, json=payload, timeout=2)
            print(f"[+] Successfully removed OpenFlow rule: {rule_name}")
        except Exception as e:
            print(f"[-] Failed to contact controller to remove rule {rule_name}: {e}")
            
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, cleanup)
    SWITCH_DPID = get_switch_dpid()
    
    threading.Thread(target=analyze_traffic, daemon=True).start()
    print("[*] ML Agent is monitoring traffic. Press Ctrl+C to stop and clear rules...")
    
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)