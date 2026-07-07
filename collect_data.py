from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
import csv
import sys
import os

MONITOR_INTERFACE = "Ethernet"
stats = {}
stats_lock = threading.Lock()

def packet_handler(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        length = len(pkt)
        is_tcp = 1 if TCP in pkt else 0
        is_udp = 1 if UDP in pkt else 0
        is_icmp = 1 if ICMP in pkt else 0
        
        with stats_lock:
            if ip not in stats:
                stats[ip] = {'count': 0, 'bytes': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
            stats[ip]['count'] += 1
            stats[ip]['bytes'] += length
            stats[ip]['tcp'] += is_tcp
            stats[ip]['udp'] += is_udp
            stats[ip]['icmp'] += is_icmp

def log_traffic(label, duration):
    global stats
    if not os.path.isfile('training_data.csv'):
        with open('training_data.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'label'])

    with open('training_data.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        for i in range(duration):
            time.sleep(1.0)
            
            with stats_lock:
                current_stats = stats.copy()
                stats.clear()
                
            if not current_stats:
                writer.writerow([0, 0, 0, 0, 0, 0, label])
            else:
                for ip, data in current_stats.items():
                    pps = data['count']
                    bps = data['bytes']
                    avg_size = bps / pps if pps > 0 else 0
                    tcp_r = data['tcp'] / pps
                    udp_r = data['udp'] / pps
                    icmp_r = data['icmp'] / pps
                    writer.writerow([pps, bps, avg_size, tcp_r, udp_r, icmp_r, label])
            
            sys.stdout.write(f"\r[+] Progress: {i+1}/{duration}s")
            sys.stdout.flush()
            
    print("\n[+] Collection finished.")
    os._exit(0)

if __name__ == '__main__':
    label = int(sys.argv[1])
    duration = int(sys.argv[2])
    threading.Thread(target=log_traffic, args=(label, duration), daemon=True).start()
    sniff(iface=MONITOR_INTERFACE, prn=packet_handler, store=False)