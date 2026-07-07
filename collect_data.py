from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
import csv
import sys
import os

MONITOR_INTERFACE = "Ethernet" # Replace with your interface
stats = {}
stats_lock = threading.Lock()

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        length = len(pkt)
        with stats_lock:
            if ip not in stats:
                stats[ip] = [0, 0]
            stats[ip][0] += 1       # Count
            stats[ip][1] += length  # Bytes

def log_traffic(label, duration):
    print(f"[*] Recording 3 features (ALL IP PROTOCOLS) for {duration} seconds. Label: {label}")
    
    if not os.path.isfile('training_data.csv'):
        with open('training_data.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['pps', 'bps', 'avg_packet_size', 'label'])

    with open('training_data.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        for i in range(duration):
            time.sleep(1.0)
            
            with stats_lock:
                current_stats = stats.copy()
                stats.clear()
                
            if not current_stats:
                writer.writerow([0, 0, 0, label])
            else:
                for ip, data in current_stats.items():
                    pps = data[0]
                    bps = data[1]
                    avg_size = bps / pps if pps > 0 else 0
                    writer.writerow([pps, bps, avg_size, label])
            
            sys.stdout.write(f"\r[+] Progress: {i+1}/{duration}s")
            sys.stdout.flush()
            
    print("\n[+] Data collection finished.")
    os._exit(0)

if __name__ == '__main__':
    label = int(sys.argv[1])
    duration = int(sys.argv[2])
    threading.Thread(target=log_traffic, args=(label, duration), daemon=True).start()
    
    # FIX: Changed 'icmp' to 'ip' to capture UDP and mixed vectors
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)