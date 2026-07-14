import socket
import time
from shared_crypto import *

def step_2_card_response(msg_1):
    ID_P_rx, ID_C_rx, ID_AS_rx, TD, ReqC, CertP, CertAB, sig_P = msg_1
    if not crypto.verify(pk_P, sig_P, crypto.hash_payload(ID_P_rx, ID_C_rx, TD, ReqC)):
        raise Exception("POS Signature Invalid")

    idC = b"IdC"
    RandomC = os.urandom(8)
    ReqP, ReqS = b"RequestPOS", b"RequestS"
    CertC, CertIB = b"Certificate(C)", b"Certificate(IssBank)"
    
    hash_val = crypto.hash_payload(ID_C, ID_P, ID_AS, RandomC, ReqP, ReqS)
    sig_C = crypto.sign(sk_C, hash_val)
    
    inner_payload = pickle.dumps((msg_1, RandomC, ReqP, ReqS, CertC, CertIB, sig_C))
    msg_2_encrypted = crypto.encrypt_asymmetric(pk_AS, inner_payload)
    
    msg_2 = (ID_C, ID_P, ID_AS, idC, msg_2_encrypted)
    return TD, RandomC, msg_2

def step_6_card_finalize(msg_5):
    Conf2, conf2_outer = msg_5
    
    conf2_inner = crypto.decrypt_asymmetric(sk_C, Conf2)
    ID_P_rx, ID_C_rx, ID_AS_rx, kpc, TD, RandomC_rx, AuthPOS, sig_AS = pickle.loads(conf2_inner)
    
    decrypted_outer = crypto.decrypt_symmetric(kpc, conf2_outer)
    RandomC, TD_rx, RandomPOS = pickle.loads(decrypted_outer)
    
    RandomPOS_1 = crypto.hash_payload(RandomPOS)[:8]
    BankData = b"BankData"
    
    sig_IB = crypto.sign(sk_IB, crypto.hash_payload(BankData))
    payload_6 = pickle.dumps((ID_P, ID_C, ID_AS, TD, RandomC, RandomPOS_1, BankData, sig_IB))
    return crypto.encrypt_symmetric(kpc, payload_6)

def simulate_transaction(server_ip, server_port=8443):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            
            msg_1 = recv_msg(s)
            TD_card, RandomC_card, msg_2 = step_2_card_response(msg_1)
            send_msg(s, (TD_card, RandomC_card, msg_2))
            
            msg_5 = recv_msg(s)
            msg_6 = step_6_card_finalize(msg_5)
            send_msg(s, msg_6)
            
    except ConnectionRefusedError:
        print("Waiting for Server...")

if __name__ == "__main__":
    SERVER_IP = "192.168.50.40" # Replace with PC n's actual SDN IP address
    while True:
        simulate_transaction(SERVER_IP)
        time.sleep(1) # Interval for normal traffic generation