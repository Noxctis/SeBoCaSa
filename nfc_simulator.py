import socket
import json
import time
import random
import uuid

TARGET_IP = "192.168.50.40"
PAYMENT_PORT = 8443
transaction_counter = 1

def simulate_nfc_handshake():
    global transaction_counter
    while True:
        try:
            time.sleep(random.uniform(2.0, 5.0))
            
            td_nonce = str(uuid.uuid4())[:8]
            random_c = str(uuid.uuid4())[:8]
            
            print(f"\n[+] --- INITIATING NFC TRANSACTION #{transaction_counter} ---")
            print(f"[*] (Step 1-2) POS <-> Card completed locally.")
            
            request_payload = {
                "TransactionNumber": transaction_counter,
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
            sock.settimeout(10.0) 
            sock.connect((TARGET_IP, PAYMENT_PORT)) 
            sock.sendall(json.dumps(request_payload).encode('utf-8'))
            
            response = sock.recv(4096).decode('utf-8')
            if response:
                as_data = json.loads(response)
                print(f"[*] (Step 5) Received Conf1, Conf2, SignatureAS for TX #{as_data.get('TransactionNumber')}.")
                print(f"[+] --- TRANSACTION #{transaction_counter} SUCCESSFUL ---")
            
            sock.close()
            transaction_counter += 1
            
        except socket.timeout:
            print(f"[-] !!! TRANSACTION #{transaction_counter} FAILED: Socket Timeout")
        except ConnectionRefusedError:
            print(f"[-] !!! TRANSACTION #{transaction_counter} FAILED: Connection Refused")
        except Exception as e:
            print(f"[-] !!! TRANSACTION #{transaction_counter} FAILED: {e}")

if __name__ == "__main__":
    simulate_nfc_handshake()