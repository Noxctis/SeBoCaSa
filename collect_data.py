from scapy.all import sniff, IP, TCP, UDP, ICMP
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
        with stats_lock:
            if ip not in stats:
                stats[ip] = {'count': 0, 'bytes': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
            stats[ip]['count'] += 1
            stats[ip]['bytes'] += len(pkt)
            if TCP in pkt: stats[ip]['tcp'] += 1
            if UDP in pkt: stats[ip]['udp'] += 1
            if ICMP in pkt: stats[ip]['icmp'] += 1

def log_traffic(is_attack_phase, duration):
    global stats
    if not os.path.isfile('training_data.csv'):
        with open('training_data.csv', 'w', newline='') as f:
            csv.writer(f).writerow(['pps', 'bps', 'avg_size', 'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'label'])

    with open('training_data.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        for i in range(duration):
            time.sleep(1.0)
            with stats_lock:
                current = stats.copy()
                stats.clear()
                
            if current:
                for ip, data in current.items():
                    pps = data['count']
                    bps = data['bytes']
                    avg_size = bps / pps if pps > 0 else 0
                    tcp_r = data['tcp'] / pps
                    udp_r = data['udp'] / pps
                    icmp_r = data['icmp'] / pps
                    label = 1 if (is_attack_phase == 1 and ip == ATTACKER_IP) else 0
                    writer.writerow([pps, bps, avg_size, tcp_r, udp_r, icmp_r, label])
            sys.stdout.write(f"\r[+] Collection Progress: {i+1}/{duration}s")
            sys.stdout.flush()
    os._exit(0)

if __name__ == '__main__':
    threading.Thread(target=log_traffic, args=(int(sys.argv[1]), int(sys.argv[2])), daemon=True).start()
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=packet_handler, store=False)