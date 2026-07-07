import socket
import time
import random
import threading
import os

# If running on PC2 (POS Terminal), target = PC4's IP (192.168.50.50)
# If running on PC4 (Auth Server), target = PC2's IP (192.168.50.40)
TARGET_IP = "192.168.50.50" 
PAYMENT_PORT = 8443 

def simulate_nfc_handshake():
    """Simulates the 6-step SPDL cryptographic protocol from the professor's charts."""
    transaction_id = 1000
    while True:
        try:
            # Simulate the time delay of a customer tapping an NFC card
            time.sleep(random.uniform(2.0, 5.0))
            transaction_id += 1
            
            print(f"\n[+] --- INITIATING NFC TRANSACTION #{transaction_id} ---")
            print(f"[*] (Step 1-2) POS <-> Card: Exchanging Nonce, TD, and SignatureC...")
            time.sleep(0.5)
            
            # Simulate the network transmission to the Authentication Server (AS)
            print(f"[*] (Step 3) POS -> AS: Transmitting encrypted payload to {TARGET_IP}:{PAYMENT_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((TARGET_IP, PAYMENT_PORT)) 
            sock.close()
            
            print(f"[*] (Step 4-6) AS -> POS: Conf1, Conf2 verified. Payment Authorized.")
            print(f"[+] --- TRANSACTION #{transaction_id} SUCCESSFUL ---")
            
        except Exception as e:
            # If the network is choked by a DDoS, the transaction times out
            print(f"[-] !!! NFC TRANSACTION #{transaction_id} FAILED: Connection Timeout !!!")

if __name__ == "__main__":
    print(f"[*] Starting NFC Payment Protocol Simulation targeting {TARGET_IP}...")
    threading.Thread(target=simulate_nfc_handshake, daemon=True).start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down NFC Simulator.")
        os._exit(0)