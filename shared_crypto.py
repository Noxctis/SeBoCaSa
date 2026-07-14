import os
import hashlib
import pickle
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class NFCCryptoEngine:
    @staticmethod
    def generate_rsa():
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return sk, sk.public_key()

    @staticmethod
    def hash_payload(*args):
        h = hashlib.sha256()
        for arg in args:
            h.update(str(arg).encode())
        return h.digest()

    @staticmethod
    def sign(sk, data):
        return sk.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    @staticmethod
    def verify(pk, signature, data):
        try:
            pk.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except:
            return False

    @staticmethod
    def encrypt_asymmetric(pk, data):
        aes_key = AESGCM.generate_key(bit_length=256)
        encrypted_key = pk.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return encrypted_key + nonce + ciphertext

    @staticmethod
    def decrypt_asymmetric(sk, encrypted_payload):
        encrypted_key = encrypted_payload[:256]
        nonce = encrypted_payload[256:268]
        ciphertext = encrypted_payload[268:]
        aes_key = sk.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def encrypt_symmetric(key, data):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, data, None)

    @staticmethod
    def decrypt_symmetric(key, payload):
        nonce = payload[:12]
        ciphertext = payload[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

# ==========================================
# SOCKET HELPERS
# ==========================================
def send_msg(sock, msg_data):
    serialized = pickle.dumps(msg_data)
    sock.sendall(struct.pack('>I', len(serialized)) + serialized)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen: return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return pickle.loads(recvall(sock, msglen))

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data.extend(packet)
    return data

# ==========================================
# GLOBAL STATE & KEY MANAGEMENT
# ==========================================
crypto = NFCCryptoEngine()
KEY_FILE = "nfc_keys.dat"

def load_or_generate_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key_data = pickle.load(f)
        
        sk_P = serialization.load_pem_private_key(key_data['sk_P'], password=None)
        pk_P = serialization.load_pem_public_key(key_data['pk_P'])
        sk_C = serialization.load_pem_private_key(key_data['sk_C'], password=None)
        pk_C = serialization.load_pem_public_key(key_data['pk_C'])
        sk_AS = serialization.load_pem_private_key(key_data['sk_AS'], password=None)
        pk_AS = serialization.load_pem_public_key(key_data['pk_AS'])
        sk_IB = serialization.load_pem_private_key(key_data['sk_IB'], password=None)
        pk_IB = serialization.load_pem_public_key(key_data['pk_IB'])
        k_AS_P = key_data['k_AS_P']
        
        return sk_P, pk_P, sk_C, pk_C, sk_AS, pk_AS, sk_IB, pk_IB, k_AS_P
    else:
        print(f"Generating new keys and saving to {KEY_FILE}...")
        
        sk_P, pk_P = crypto.generate_rsa()
        sk_C, pk_C = crypto.generate_rsa()
        sk_AS, pk_AS = crypto.generate_rsa()
        sk_IB, pk_IB = crypto.generate_rsa()
        k_AS_P = AESGCM.generate_key(bit_length=256)
        
        key_data = {
            'sk_P': sk_P.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
            'pk_P': pk_P.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
            'sk_C': sk_C.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
            'pk_C': pk_C.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
            'sk_AS': sk_AS.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
            'pk_AS': pk_AS.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
            'sk_IB': sk_IB.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
            'pk_IB': pk_IB.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
            'k_AS_P': k_AS_P
        }
        
        with open(KEY_FILE, "wb") as f:
            pickle.dump(key_data, f)
            
        return sk_P, pk_P, sk_C, pk_C, sk_AS, pk_AS, sk_IB, pk_IB, k_AS_P

sk_P, pk_P, sk_C, pk_C, sk_AS, pk_AS, sk_IB, pk_IB, k_AS_P = load_or_generate_keys()

ID_P = b"POS"
ID_C = b"C"
ID_AS = b"AS"