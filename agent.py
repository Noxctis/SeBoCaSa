from scapy.all import sniff, IP, TCP, UDP, ICMP
from sklearn.tree import DecisionTreeClassifier
import pandas as pd
import requests
import threading
import time
import sys
import signal

CONTROLLER_IP = "192.168.50.240" 
SWITCH_DPID = "00:00:54:af:97:bf:39:4f" 
MONITOR_INTERFACE = "Ethernet" 

# Sanity Check Threshold to prevent False Positives on background noise
MIN_PPS_THRESHOLD = 10 

try:
    print("[*] Loading 3-feature protocol-agnostic dataset...")
    df = pd.read_csv('training_data.csv')
    
    # FIX: Automatically delete any blank or corrupted rows
    df.dropna(inplace=True)
    
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
    print(f"\n[!!!] TOTAL VOLUMETRIC FLOOD DETECTED: {ip} - BLOCKING ALL IPv4")
    
    payload = {
        "switch": SWITCH_DPID, 
        "name": f"block-{ip}",
        "priority": "40000", 
        "eth_type": "0x0800",
        # Removed the /32. Some versions of Floodlight reject the CIDR notation.
        "ipv4_src": f"{ip}", 
        "active": "true", 
        "actions": "" 
    }
    
    try:
        resp = requests.post(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json=payload)
        if resp.status_code == 200:
            blocked_ips.add(ip)
            print(f"[+] Controller accepted the rule: {resp.text}")
        else:
            # THIS WILL PRINT THE EXACT REASON IT FAILED
            print(f"[-] CONTROLLER REJECTED RULE! Status Code: {resp.status_code}")
            print(f"[-] Error Details: {resp.text}")
    except Exception as e:
        print(f"[-] Connection Error to Controller: {e}")
    
    try:
        resp = requests.post(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json=payload)
        if resp.status_code == 200:
            blocked_ips.add(ip)
    except Exception as e:
        print(f"[-] API Error: {e}")

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        length = len(pkt)
        
        # --- STATEFUL INSPECTION LOGIC ---
        is_initiator = False
        
        if ICMP in pkt:
            # Type 8 is an Echo Request (The actual ping).
            # This automatically ignores Type 3 (Destination Unreachable) reply storms!
            if pkt[ICMP].type == 8: 
                is_initiator = True
                
        elif TCP in pkt:
            # Only count packets attempting to START a connection (SYN flag)
            # This ignores normal ACKs and RST reply storms.
            if pkt[TCP].flags == 'S': 
                is_initiator = True
                
        elif UDP in pkt:
            # UDP is stateless. We count it, but because the victim's OS replies 
            # using ICMP (which we filtered above), the victim remains safe.
            is_initiator = True

        # Only add to the ML statistics if the PC is actively initiating the traffic
        if is_initiator:
            with stats_lock:
                if ip not in traffic_stats:
                    traffic_stats[ip] = [0, 0]
                traffic_stats[ip][0] += 1       # Count
                traffic_stats[ip][1] += length  # Bytes

def analyze_traffic():
    global traffic_stats
    while True:
        time.sleep(1.0) 
        
        # 1. Lock the dictionary, copy the data, and clear it immediately
        with stats_lock:
            current = traffic_stats.copy()
            traffic_stats.clear()

        # 2. Analyze the safe copy
        for ip, data in current.items():
            # FIX: Access the list by index (0 = Count, 1 = Bytes)
            pps = data[0]
            bps = data[1]
            avg_size = bps / pps if pps > 0 else 0
            
            # 3. Ignore normal Windows background noise (Sanity Check)
            if pps < MIN_PPS_THRESHOLD:
                continue
            
            prediction = clf.predict([[pps, bps, avg_size]])[0]

            if prediction == 1 and ip not in blocked_ips:
                block_attacker(ip)

def cleanup():
    print("\n[!] Shutting down. Removing OpenFlow drop rules...")
    for ip in blocked_ips:
        try:
            requests.delete(f"http://{CONTROLLER_IP}:8080/wm/staticflowpusher/json", json={"name": f"block-{ip}"})
        except: pass
    sys.exit(0)

# Register OS signals for graceful shutdown (ensures cleanup runs on Ctrl+C / kill)
signal.signal(signal.SIGINT, lambda signum, frame: cleanup())
try:
    signal.signal(signal.SIGTERM, lambda signum, frame: cleanup())
except AttributeError:
    # Windows may not have SIGTERM; ignore if unavailable
    pass

threading.Thread(target=analyze_traffic, daemon=True).start()
print("[*] ML Agent is monitoring traffic...")
try:
    # FIX: Sniff all IP traffic to catch UDPQ
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)
except KeyboardInterrupt:
    cleanup()