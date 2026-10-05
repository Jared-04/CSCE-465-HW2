from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
import handshake
from secure_record import Session

'''
This test simulates a handshake failure due to an attacker modifying the handshake messages.

1. Gateway initiates handshake with Node.
2. Node responds to handshake with Gateway.
3. Attacker modifies the handshake messages.
4. Gateway attempts to finalize the handshake and should detect the tampering.
'''

if __name__ == "__main__":
    # simulate handshake
    gw_id = b"gateway-1"
    node_id = b"node-1"

    # gateway initiates handshake
    gw_dh_priv, gw_dh_pub, gw_nonce = handshake.initiate_hs()

    # node responds to handshake
    node_dh_pub, node_nonce, sig, node_rsa_pub = handshake.respond_hs(gw_id, node_id, gw_dh_pub, gw_nonce)

    # generate different RSA key pair 
    newkey = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    newkey_pub = newkey.public_key()

    # gateway finalizes handshake
    try:
        keys = handshake.finalize_hs(gw_id, gw_dh_priv, node_id, gw_dh_pub, node_dh_pub, gw_nonce, node_nonce, sig, newkey_pub)
    except ValueError as e:
        print(f"Handshake failed due to tampering: {e}")

