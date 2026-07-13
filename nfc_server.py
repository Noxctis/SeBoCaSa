import socket, json, base64, os
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BIND_IP = "0.0.0.0"
PAYMENT_PORT = 8443

# Pre-shared Symmetric Key between AS and POS (K_AS_POS)
K_AS_POS = base64.b64decode("gY/wYmPz8qE6Oq3x6nF5m6XyA3b9Z1c0vM/wYmPz8qE=")

# --- CRYPTO HELPERS ---
def generate_as_rsa():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives.asymmetric import rsa
    return priv

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

def asym_encrypt(pub_key_pem, data):
    pub_key = serialization.load_pem_public_key(pub_key_pem.encode())
    aes_key = AESGCM.generate_key(bit_length=256)
    enc_aes_key = pub_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    ct = base64.b64decode(sym_encrypt(aes_key, data))
    return base64.b64encode(enc_aes_key + ct).decode()

def run_server():
    print("[*] Generating AS RSA Keys...")
    from cryptography.hazmat.primitives.asymmetric import rsa
    as_priv = generate_as_rsa()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, PAYMENT_PORT))
    server.listen(100)
    print(f"[*] Authentication Server listening on {BIND_IP}:{PAYMENT_PORT}")

    while True:
        try:
            client, addr = server.accept()
            client.settimeout(2.0)
            
            try:
                data = client.recv(8192).decode('utf-8')
                if data:
                    payload = json.loads(data)
                    tx_num = payload.get("TransactionNumber", "Unknown")
                    print(f"\n[+] Received Transaction #{tx_num} from POS ({addr[0]})")
                    
                    # Decrypt Step 3
                    enc_payload_3 = payload.get("Encrypted_K_AS_POS")
                    step_3 = json.loads(sym_decrypt(K_AS_POS, enc_payload_3))
                    
                    td_nonce = step_3["TD"]
                    step_2 = step_3["Step2"]
                    random_c = step_2["RandomC"]
                    c_pub_cert = step_2["CertC"] # Extract C's public key
                    
                    # AS generates the K(POS,C) session key
                    k_pos_c = AESGCM.generate_key(bit_length=256)
                    k_pos_c_b64 = base64.b64encode(k_pos_c).decode()
                    
                    # ==========================================
                    # STEP 4: AS -> POS
                    # ==========================================
                    conf1 = {
                        "POS":"POS", "C":"C", "AS":"AS", "K_POS_C": k_pos_c_b64, 
                        "TD": td_nonce, "RandomC": random_c, "AuthC": "Verified"
                    }
                    
                    h_as = hash_data(f"POS,C,AS,{k_pos_c_b64},{td_nonce},{random_c},AuthPOS")
                    sig_as = sign_data(as_priv, h_as)
                    
                    conf2_plaintext = json.dumps({
                        "POS":"POS", "C":"C", "AS":"AS", "K_POS_C": k_pos_c_b64,
                        "TD": td_nonce, "RandomC": random_c, "AuthPOS": "Verified",
                        "SigAS": sig_as
                    })
                    
                    # Hybrid RSA Encrypt Conf2 with Card's Public Key
                    conf2_encrypted = asym_encrypt(c_pub_cert, conf2_plaintext)
                    
                    step_4 = {"Conf1": conf1, "Conf2": conf2_encrypted}
                    enc_step_4 = sym_encrypt(K_AS_POS, json.dumps(step_4))
                    
                    response_payload = {
                        "TransactionNumber": tx_num,
                        "Encrypted_K_AS_POS": enc_step_4
                    }
                    
                    client.sendall(json.dumps(response_payload).encode('utf-8'))
                    print(f"[*] Processed Step 4. Sent Encrypted {Conf1, Conf2} back to POS.")
                    
            except json.JSONDecodeError:
                pass 
            except socket.timeout:
                pass
            except Exception as e:
                print(f"[-] Crypto/Verification Error: {e}")
            finally:
                client.close()
                
        except Exception as e:
            print(f"[-] Server Error: {e}")

if __name__ == "__main__":
    run_server()