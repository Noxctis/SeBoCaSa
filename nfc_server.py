import socket
import json

BIND_IP = "0.0.0.0"
PAYMENT_PORT = 8443

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, PAYMENT_PORT))
    server.listen(5)
    print(f"[*] Authentication Server listening on {BIND_IP}:{PAYMENT_PORT}")

    while True:
        client, addr = server.accept()
        try:
            data = client.recv(4096).decode('utf-8')
            if data:
                payload = json.loads(data)
                tx_num = payload.get("TransactionNumber", "Unknown")
                
                print(f"\n[+] Received Transaction #{tx_num} from POS ({addr[0]})")
                print(f"[*] (Step 4) AS verifying CertC, CertIB, SignatureC...")
                
                response_payload = {
                    "TransactionNumber": tx_num,
                    "Conf1": "Conf_POS_Valid",
                    "Conf2": "Conf_C_Valid",
                    "SignatureAS": f"Hash({tx_num}, Conf1, Conf2)_secKey(AS)"
                }
                
                client.sendall(json.dumps(response_payload).encode('utf-8'))
                print(f"[*] (Step 5) Sent confirmation back to POS.")
                
        except Exception as e:
            print(f"[-] Error processing transaction: {e}")
        finally:
            client.close()

if __name__ == "__main__":
    run_server()