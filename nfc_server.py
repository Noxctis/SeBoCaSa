import socket
import threading
import json
import os

PAYMENT_PORT = 8443

def handle_transaction(conn, addr):
    try:
        # Receive Step 3 from POS
        data = conn.recv(4096).decode('utf-8')
        if not data: return
        
        payload = json.loads(data)
        print(f"\n[+] Received SPDL Payload from POS {addr[0]}")
        print(f"    - Transaction Data (TD): {payload.get('TD')}")
        print(f"    - Card Nonce (RandomC): {payload.get('RandomC')}")
        print(f"    - Card Signature: {payload.get('SignatureC')}")
        
        print("[*] (Step 4) Verifying Certificates and generating AS Response...")
        
        # Construct Step 4 (AS -> POS)
        response_payload = {
            "Conf1": f"POS, C, AS, K(POS,C), {payload.get('TD')}, {payload.get('RandomC')}, CertIB, AuthC",
            "Conf2": f"POS, C, AS, K(POS,C), {payload.get('TD')}, {payload.get('RandomC')}, AuthPOS",
            "SignatureAS": "Hash(POS, C, AS, K(POS,C), TD, RandomC, AuthPOS)_secKey(AS)"
        }
        
        conn.sendall(json.dumps(response_payload).encode('utf-8'))
        print("[+] Sent {Conf1, Conf2} K(AS,POS) to POS Terminal.")
        print("[+] Payment Authorized.")
    except Exception as e:
        print(f"[-] Transaction Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PAYMENT_PORT))
    server.listen(5)
    
    print(f"[*] NFC Authentication Server (AS) Active on Port {PAYMENT_PORT}")
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_transaction, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        os._exit(0)