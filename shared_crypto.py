import os
import hashlib
import pickle
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
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

# Socket Helpers
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

crypto = NFCCryptoEngine()

# Static testbed keys (Must be identical on both ends)
sk_P = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pk_P = sk_P.public_key()
sk_C = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pk_C = sk_C.public_key()
sk_AS = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pk_AS = sk_AS.public_key()
sk_IB = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pk_IB = sk_IB.public_key()

k_AS_P = b'\x00' * 32 # Static 256-bit AES key for AS-POS link

ID_P = b"POS"
ID_C = b"C"
ID_AS = b"AS"