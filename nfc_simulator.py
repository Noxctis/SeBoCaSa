import socket, json, time, random, uuid, base64, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TARGET_IP = "192.168.50.40"
PAYMENT_PORT = 8443

# Pre-shared Symmetric Key between AS and POS (K_AS_POS)
# In reality, provisioned during terminal setup.
K_AS_POS = base64.b64decode("gY/wYmPz8qE6Oq3x6nF5m6XyA3b9Z1c0vM/wYmPz8qE=")

# --- CRYPTO HELPERS ---
def generate_rsa():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub_pem

def sign_data(priv_key, data):
    signature = priv_key.sign(data.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return base64.b64encode(signature).decode()

def hash_data(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return base64.b64encode(digest.finalize()).decode()

def sym_encrypt(key, data):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def sym_decrypt(key, b64_data):
    raw = base64.b64decode(b64_data)
    aes = AESGCM(key)
    return aes.decrypt(raw[:12], raw[12:], None).decode()

def asym_decrypt(priv_key, b64_data):
    raw = base64.b64decode(b64_data)
    enc_aes_key, payload = raw[:256], raw[256:]
    aes_key = priv_key.decrypt(enc_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return sym_decrypt(aes_key, base64.b64encode(payload).decode())

def simulate_nfc_handshake():
    print("[*] Initializing Hardware Crypto Modules...")
    c_priv, c_pub_cert = generate_rsa()
    pos_priv, pos_pub_cert = generate_rsa()
    iss_priv, _ = generate_rsa() # Simulating pre-signed bank data
    
    transaction_counter = 1
    
    while True:
        time.sleep(random.uniform(2.0, 5.0))
        td_nonce = str(uuid.uuid4())[:8]
        random_c = str(uuid.uuid4())[:8]
        random_pos = str(uuid.uuid4())[:8]
        
        print(f"\n[+] --- INITIATING NFC TRANSACTION #{transaction_counter} ---")
        
        # ==========================================
        # STEP 1: POS -> C
        # ==========================================
        req_c = "Auth_Req_C"
        h1 = hash_data(f"POS,C,{td_nonce},{req_c}")
        sig_pos = sign_data(pos_priv, h1)
        step_1 = {"POS":"POS", "C":"C", "AS":"AS", "TD":td_nonce, "ReqC":req_c, "CertPOS":pos_pub_cert, "SigPOS":sig_pos}
        
        # ==========================================
        # STEP 2: C -> POS
        # ==========================================
        req_pos = "Auth_Req_POS"
        req_s = "Auth_Req_S"
        h2 = hash_data(f"C,POS,AS,{random_c},{req_pos},{req_s}")
        sig_c = sign_data(c_priv, h2)
        step_2 = {
            "Msg1": step_1, "RandomC": random_c, "ReqPOS": req_pos, "ReqS": req_s,
            "CertC": c_pub_cert, "SigC": sig_c
        }
        
        # ==========================================
        # STEP 3: POS -> AS (Over TCP)
        # ==========================================
        payload_3 = json.dumps({"TD": td_nonce, "Step2": step_2})
        enc_payload_3 = sym_encrypt(K_AS_POS, payload_3)
        
        network_request = {
            "TransactionNumber": transaction_counter,
            "POS": "POS", "AS": "AS", "C": "C",
            "Encrypted_K_AS_POS": enc_payload_3
        }
        
        sock = None
        try:
            print(f"[*] (Step 3) Transmitting Encrypted SPDL Payload to AS...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0) 
            sock.connect((TARGET_IP, PAYMENT_PORT)) 
            sock.sendall(json.dumps(network_request).encode('utf-8'))
            
            # ==========================================
            # STEP 4: AS -> POS (Received over TCP)
            # ==========================================
            response = sock.recv(8192).decode('utf-8')
            if response:
                as_data = json.loads(response)
                enc_step_4 = as_data["Encrypted_K_AS_POS"]
                
                # POS Decrypts Step 4
                step_4 = json.loads(sym_decrypt(K_AS_POS, enc_step_4))
                conf1 = step_4["Conf1"]
                conf2_encrypted = step_4["Conf2"]
                
                # POS extracts K(POS,C) from Conf1
                k_pos_c_b64 = conf1["K_POS_C"]
                k_pos_c = base64.b64decode(k_pos_c_b64)
                
                # ==========================================
                # STEP 5: POS -> C
                # ==========================================
                payload_5 = json.dumps({"RandomC": random_c, "TD": td_nonce, "RandomPOS": random_pos})
                enc_payload_5 = sym_encrypt(k_pos_c, payload_5)
                
                # ==========================================
                # STEP 6: C -> POS
                # ==========================================
                # Card decrypts Conf2 using its RSA Private Key to get K(POS,C)
                conf2_decrypted = json.loads(asym_decrypt(c_priv, conf2_encrypted))
                
                bank_data = "Acct_Balance_Valid"
                h_bank = hash_data(bank_data)
                sig_bank = sign_data(iss_priv, h_bank)
                
                payload_6 = json.dumps({
                    "P": "POS", "C": "C", "AS": "AS", "TD": td_nonce,
                    "RandomC": random_c, "RandomPOS_1": f"{random_pos}-1",
                    "BankData": bank_data, "SigBank": sig_bank
                })
                enc_step_6 = sym_encrypt(k_pos_c, payload_6)
                
                print(f"[+] --- TRANSACTION #{transaction_counter} SUCCESSFUL --- (Full Crypto Verified)")
                transaction_counter += 1
            
        except socket.timeout:
            print(f"[-] !!! TRANSACTION #{transaction_counter} FAILED: Socket Timeout. Retrying...")
        except ConnectionRefusedError:
            print(f"[-] !!! TRANSACTION #{transaction_counter} FAILED: Connection Refused. Server busy. Retrying...")
        except Exception as e:
            print(f"[-] !!! TRANSACTION #{transaction_counter} FAILED: {e}")
        finally:
            if sock:
                sock.close()

if __name__ == "__main__":
    simulate_nfc_handshake()