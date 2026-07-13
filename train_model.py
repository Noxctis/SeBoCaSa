from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer
import threading
import time
import csv
import os
import signal
import sys

MONITOR_INTERFACE = "Ethernet" # Change to match your agent.py interface
CSV_FILE = "training_data.csv"
MIN_PPS_THRESHOLD = 5

traffic_stats = {}
stats_lock = threading.Lock()
is_collecting = True

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

def collect_data(label):
    global traffic_stats
    
    # Write header if file doesn't exist
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'label'])

    print(f"[*] Extracting features and appending to {CSV_FILE} as Label {label}...")
    
    while is_collecting:
        time.sleep(1.0) 
        with stats_lock:
            current = traffic_stats.copy()
            traffic_stats.clear()

        with open(CSV_FILE, mode='a', newline='') as f:
            writer = csv.writer(f)
            for ip, data in current.items():
                pps = data['count']
                bps = data['bytes']
                if pps < MIN_PPS_THRESHOLD: continue
                
                avg_size = round(bps / pps, 2)
                tcp_r = round(data['tcp'] / pps, 2)
                udp_r = round(data['udp'] / pps, 2)
                icmp_r = round(data['icmp'] / pps, 2)
                
                writer.writerow([pps, bps, avg_size, tcp_r, udp_r, icmp_r, label])
                print(f"[+] Logged: IP={ip} | PPS={pps} | BPS={bps} | AvgSize={avg_size} | Label={label}")

def cleanup(sig=None, frame=None):
    global is_collecting
    is_collecting = False
    print("\n[*] Stopping data collection.")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, cleanup)
    
    print("Select traffic type to record:")
    print("0 - Normal Traffic (NFC Transactions)")
    print("1 - Attack Traffic (DDoS Floods)")
    choice = input("Enter label (0 or 1): ").strip()
    
    if choice not in ['0', '1']:
        print("Invalid choice. Exiting.")
        sys.exit(1)
        
    threading.Thread(target=collect_data, args=(int(choice),), daemon=True).start()
    
    print(f"[*] Sniffer started on {MONITOR_INTERFACE}. Press Ctrl+C to stop.")
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)