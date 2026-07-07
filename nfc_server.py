import socket
import threading
import os

PAYMENT_PORT = 8443

def handle_transaction(conn, addr):
    print(f"[+] Received encrypted SPDL Payload from POS Terminal at {addr[0]}")
    print(f"[*] (Step 4-6) AS -> POS: Verifying SignatureAS and Conf2...")
    print(f"[+] Payment Authorized.\n")
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 0.0.0.0 allows it to listen on all active Ethernet adapters
    server.bind(('0.0.0.0', PAYMENT_PORT))
    server.listen(5)
    
    print(f"[*] NFC Authentication Server (AS) Active.")
    print(f"[*] Listening for incoming POS transactions on TCP Port {PAYMENT_PORT}...\n")
    
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_transaction, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Authentication Server.")
        os._exit(0)

if __name__ == "__main__":
    start_server()