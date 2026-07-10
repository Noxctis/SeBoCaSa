import socket
import time
import random
import threading
import json
import os
import uuid

TARGET_IP = "192.168.50.40" 
PAYMENT_PORT = 8443 

def simulate_nfc_handshake():
    while True:
        try:
            time.sleep(random.uniform(2.0, 5.0))
            
            td_nonce = str(uuid.uuid4())[:8]
            random_c = str(uuid.uuid4())[:8]
            
            print(f"\n[+] --- INITIATING NFC TRANSACTION ---")
            print(f"[*] (Step 1-2) POS <-> Card completed locally.")
            
            request_payload = {
                "C": "Card_ID_9921",
                "POS": "POS_Terminal_01",
                "AS": "Auth_Server_Main",
                "TD": td_nonce,
                "RandomC": random_c,
                "RequestPOS": "Auth_Req",
                "CertC": "Cert_Card_Valid",
                "CertIB": "Cert_IssBank_Valid",
                "SignatureC": f"Hash(C, POS, AS, {random_c})_secKey(C)"
            }
            
            print(f"[*] (Step 3) Sending POS, AS, C, {{TD, (2)}}K(AS,POS) to {TARGET_IP}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # INCREASED TIMEOUT to 10 seconds for SDN Flow Setup
            sock.settimeout(10.0) 
            sock.connect((TARGET_IP, PAYMENT_PORT)) 
            sock.sendall(json.dumps(request_payload).encode('utf-8'))
            
            response = sock.recv(4096).decode('utf-8')
            if response:
                as_data = json.loads(response)
                print(f"[*] (Step 5) Received Conf1, Conf2, SignatureAS.")
                print(f"[+] --- TRANSACTION SUCCESSFUL ---")
            
            sock.close()
            
        except socket.timeout:
            print(f"[-] !!! TRANSACTION FAILED: Socket Timeout (Check SDN Controller or Network Route)")
        except ConnectionRefusedError:
            print(f"[-] !!! TRANSACTION FAILED: Connection Refused (Check Windows Firewall on PC4)")
        except Exception as e:
            print(f"[-] !!! TRANSACTION FAILED: {e}")

if __name__ == "__main__":
    print(f"[*] Starting SPDL NFC Protocol targeting {TARGET_IP}...")
    threading.Thread(target=simulate_nfc_handshake, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        os._exit(0)