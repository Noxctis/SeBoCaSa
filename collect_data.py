from scapy.all import sniff, IP
import threading
import time
import csv
import sys
import os

MONITOR_INTERFACE = "Ethernet" 
ATTACKER_IP = "192.168.50.30"

stats = {}
stats_lock = threading.Lock()

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        length = len(pkt)
        with stats_lock:
            if ip not in stats:
                stats[ip] = [0, 0] 
            stats[ip][0] += 1
            stats[ip][1] += length

def log_traffic(is_attack_phase, duration):
    global stats
    print(f"[*] Recording 3 volume features for {duration} seconds. (Attack Phase: {is_attack_phase})")
    
    if not os.path.isfile('training_data.csv'):
        with open('training_data.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['pps', 'bps', 'avg_size', 'label'])

    with open('training_data.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        for i in range(duration):
            time.sleep(1.0)
            
            with stats_lock:
                current_stats = stats.copy()
                stats.clear()
                
            if current_stats:
                for ip, data in current_stats.items():
                    pps = data[0]
                    bps = data[1]
                    avg_size = bps / pps if pps > 0 else 0
                    
                    label = 1 if (is_attack_phase == 1 and ip == ATTACKER_IP) else 0
                    writer.writerow([pps, bps, avg_size, label])
            
            sys.stdout.write(f"\r[+] Progress: {i+1}/{duration}s")
            sys.stdout.flush()
            
    print("\n[+] Collection finished.")
    os._exit(0)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python collect_data.py <is_attack_phase (0 or 1)> <duration_in_seconds>")
        sys.exit(1)
        
    is_attack = int(sys.argv[1])
    duration = int(sys.argv[2])
    
    threading.Thread(target=log_traffic, args=(is_attack, duration), daemon=True).start()
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)