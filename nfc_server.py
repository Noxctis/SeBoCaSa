import socket
import json

BIND_IP = "0.0.0.0"
PAYMENT_PORT = 8443

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allows the port to be reused immediately if you restart the script
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind((BIND_IP, PAYMENT_PORT))
    server.listen(100) # Increased queue size to resist TCP flood exhaustion
    print(f"[*] Authentication Server listening on {BIND_IP}:{PAYMENT_PORT}")

    while True:
        try:
            client, addr = server.accept()
            client.settimeout(2.0) # Drop attacker connections if they hang
            
            try:
                data = client.recv(4096).decode('utf-8')
                if data:
                    payload = json.loads(data) # Attacker garbage will fail here
                    tx_num = payload.get("TransactionNumber", "Unknown")
                    
                    response_payload = {
                        "TransactionNumber": tx_num,
                        "Conf1": "Conf_POS_Valid",
                        "Conf2": "Conf_C_Valid",
                        "SignatureAS": f"Hash({tx_num}, Conf1, Conf2)_secKey(AS)"
                    }
                    
                    client.sendall(json.dumps(response_payload).encode('utf-8'))
                    print(f"[+] Processed Transaction #{tx_num} from POS ({addr[0]})")
                    
            except json.JSONDecodeError:
                pass # Ignore random payload data from attackers
            except socket.timeout:
                pass # Ignore connections that don't send data
            except Exception:
                pass
            finally:
                client.close() # Always close the client socket
                
        except Exception as e:
            print(f"[-] Server Error: {e}")
            # Server loop remains alive even if an accept fails

if __name__ == "__main__":
    run_server()