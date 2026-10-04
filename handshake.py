from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
import os, struct, hashlib, hmac

NODE_RSA_PRIV = rsa.generate_private_key(65537, 3072)
GW_RSA_PRIV = rsa.generate_private_key(65537, 3072)

with open("ffdhe3072.pem", "rb") as f:
    ffdh3072 = serialization.load_pem_parameters(f.read())

def tlv_encode(field):
    val = field.encode() if isinstance(field, str) else field
    return struct.pack('>I', len(val)) + val

def transcript(gw_id, node_id, gw_pub, node_pub, gw_nonce, node_nonce):
    return (tlv_encode("CSCE465-KDF-v1") +
            tlv_encode("ffdhe3072") +
            tlv_encode(gw_id) +
            tlv_encode(node_id) +
            tlv_encode(gw_pub) +
            tlv_encode(node_pub) +
            tlv_encode(gw_nonce) +
            tlv_encode(node_nonce))

def sign(private_key, role, th):
    return private_key.sign(role + th, 
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                            salt_length=padding.PSS.MAX_LENGTH), 
                            hashes.SHA256())

def verify(public_key, role, th, signature):
    try:
        public_key.verify(signature, role + th,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                          salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        return True
    except Exception:
        return False

def derive_keys(z, th):
    k_master = hashlib.sha256(b"CSCE465-KDF-v1" + z + th).digest()
    k_g2n_enc = hmac.new(k_master, b"gateway-to-node encryption" + th, hashlib.sha256).digest()
    k_g2n_mac = hmac.new(k_master, b"gateway-to-node MAC" + th, hashlib.sha256).digest()
    k_n2g_enc = hmac.new(k_master, b"node-to-gateway encryption" + th, hashlib.sha256).digest()
    k_n2g_mac = hmac.new(k_master, b"node-to-gateway MAC" + th, hashlib.sha256).digest()
    session_id = hmac.new(k_master, b"session identifier" + th, hashlib.sha256).digest()[:8]
    keys = {
        "k_g2n_enc": k_g2n_enc,
        "k_g2n_mac": k_g2n_mac,
        "k_n2g_enc": k_n2g_enc,
        "k_n2g_mac": k_n2g_mac,
        "session_id": session_id
    }
    return keys

def initiate_hs():
    # generate DH key pair and nonce
    dh_private = ffdh3072.generate_private_key()
    dh_public = dh_private.public_key().public_numbers().y.to_bytes(384, 'big')
    nonce = os.urandom(16)
    return dh_private, dh_public, nonce

def respond_hs(gw_id, node_id, gw_pub, gw_nonce):
    # generate DH key pair and nonce
    dh_private = ffdh3072.generate_private_key()
    dh_public = dh_private.public_key().public_numbers().y.to_bytes(384, 'big')
    nonce = os.urandom(16)

    # generate and hash transcript
    ts = transcript(gw_id, node_id, gw_pub, dh_public, gw_nonce, nonce)
    th = hashlib.sha256(ts).digest()

    # key derivation
    pubkey = dh.DHPublicNumbers(int.from_bytes(gw_pub, 'big'), ffdh3072.parameter_numbers()).public_key()
    z = dh_private.exchange(pubkey).rjust(384, b'\x00')
    keys = derive_keys(z, th)

    # sign transcript
    sig = sign(NODE_RSA_PRIV, b"node", th)
    return dh_public, nonce, sig, NODE_RSA_PRIV.public_key()

def finalize_hs(gw_id, gw_priv, node_id, gw_pub, node_pub, gw_nonce, node_nonce, sig, node_rsa_pubkey):
    # generate and hash transcript
    ts = transcript(gw_id, node_id, gw_pub, node_pub, gw_nonce, node_nonce)
    th = hashlib.sha256(ts).digest()

    # verify signature
    if not verify(node_rsa_pubkey, b"node", th, sig):
        raise ValueError("Signature verification failed")

    # key derivation
    pubkey = dh.DHPublicNumbers(int.from_bytes(node_pub, 'big'), ffdh3072.parameter_numbers()).public_key()
    z = gw_priv.exchange(pubkey).rjust(384, b'\x00')
    keys = derive_keys(z, th)
    

def main():
    # simulate handshake
    gw_id = b"gateway-1"
    node_id = b"node-1"

    # gateway initiates handshake
    gw_dh_priv, gw_dh_pub, gw_nonce = initiate_hs()

    # node responds to handshake
    node_dh_pub, node_nonce, sig, node_rsa_pubkey = respond_hs(gw_id, node_id, gw_dh_pub, gw_nonce)

    # gateway finalizes handshake
    finalize_hs(gw_id, gw_dh_priv, node_id, gw_dh_pub, node_dh_pub, gw_nonce, node_nonce, sig, node_rsa_pubkey)
    print("Handshake completed successfully. Session keys derived.")


if __name__ == "__main__":
    main()
