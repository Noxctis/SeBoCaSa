import socket
from shared_crypto import *

def step_1_pos_init():
    TD = os.urandom(8)
    ReqC = b"RequestC"
    CertP, CertAB = b"Certificate(POS)", b"Certificate(AcqBank)"
    hash_val = crypto.hash_payload(ID_P, ID_C, TD, ReqC)
    sig_P = crypto.sign(sk_P, hash_val)
    return (ID_P, ID_C, ID_AS, TD, ReqC, CertP, CertAB, sig_P)

def step_3_pos_forward_to_as(TD, msg_2):
    payload = pickle.dumps((TD, msg_2))
    encrypted_payload = crypto.encrypt_symmetric(k_AS_P, payload)
    return (ID_P, ID_AS, ID_C, encrypted_payload)

def step_4_as_process(msg_3):
    ID_P_rx, ID_AS_rx, ID_C_rx, encrypted_payload = msg_3
    decrypted = crypto.decrypt_symmetric(k_AS_P, encrypted_payload)
    TD, msg_2 = pickle.loads(decrypted)
    
    ID_C_msg2, ID_P_msg2, ID_AS_msg2, idC, msg_2_encrypted = msg_2
    inner_payload = crypto.decrypt_asymmetric(sk_AS, msg_2_encrypted)
    msg_1, RandomC, ReqP, ReqS, CertC, CertIB, sig_C = pickle.loads(inner_payload)
    
    kpc = AESGCM.generate_key(bit_length=256)
    AuthC, AuthPOS = b"AuthC", b"AuthPOS"
    
    Conf1 = (ID_P, ID_C, ID_AS, kpc, TD, RandomC, CertIB, AuthC)
    hash_AS = crypto.hash_payload(ID_P, ID_C, ID_AS, kpc, TD, RandomC, AuthPOS)
    sig_AS = crypto.sign(sk_AS, hash_AS)
    
    conf2_inner = pickle.dumps((ID_P, ID_C, ID_AS, kpc, TD, RandomC, AuthPOS, sig_AS))
    Conf2 = crypto.encrypt_asymmetric(pk_C, conf2_inner)
    return crypto.encrypt_symmetric(k_AS_P, pickle.dumps((Conf1, Conf2)))

def step_5_pos_forward_to_card(msg_4):
    decrypted = crypto.decrypt_symmetric(k_AS_P, msg_4)
    Conf1, Conf2 = pickle.loads(decrypted)
    ID_P_rx, ID_C_rx, ID_AS_rx, kpc, TD, RandomC, CertIB, AuthC = Conf1
    
    RandomPOS = os.urandom(8)
    conf2_outer = crypto.encrypt_symmetric(kpc, pickle.dumps((RandomC, TD, RandomPOS)))
    return kpc, (Conf2, conf2_outer)

def step_6_pos_verify_bankdata(msg_6, kpc):
    decrypted = crypto.decrypt_symmetric(kpc, msg_6)
    ID_P_rx, ID_C_rx, ID_AS_rx, TD, RandomC, RandomPOS_1, BankData, sig_IB = pickle.loads(decrypted)
    if crypto.verify(pk_IB, sig_IB, crypto.hash_payload(BankData)):
        return BankData
    return None

def run_server(host='0.0.0.0', port=8443):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(10)
        print(f"POS/AS Listening on {host}:{port}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    msg_1 = step_1_pos_init()
                    send_msg(conn, msg_1)
                    
                    TD_card, RandomC_card, msg_2 = recv_msg(conn)
                    msg_3 = step_3_pos_forward_to_as(TD_card, msg_2)
                    msg_4 = step_4_as_process(msg_3)
                    kpc_pos, msg_5 = step_5_pos_forward_to_card(msg_4)
                    
                    send_msg(conn, msg_5)
                    msg_6 = recv_msg(conn)
                    
                    final_data = step_6_pos_verify_bankdata(msg_6, kpc_pos)
                    print(f"Transaction verified: {final_data}")
                except Exception as e:
                    pass

if __name__ == "__main__":
    run_server()