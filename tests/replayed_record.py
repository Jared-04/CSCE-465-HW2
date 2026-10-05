from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from secure_record import Session

'''
This test simulates an attacker attempting to replay a previously sent secure record.

1. Gateway initiates handshake with Node.
2. Node responds to handshake with Gateway.
3. Gateway finalizes handshake with Node.
4. Gateway sends a secure record to Node.
5. Attacker intercepts the secure record and replays it to Node.

'''

if __name__ == "__main__":
    # simulate handshake
    gateway = Session("gateway", direction=0)
    node = Session("node", direction=1)

    gateway.do_handshake(node)
    print("Handshake completed successfully. Session keys derived.")

    # gateway to node exchange
    msg = b"Message to node..."
    head1 = {
        'version': 1,
        'direction': 0,
        'message_type': 1
    }
    encrypted_msg1 = gateway.seal(head1, msg)
    tag1 = encrypted_msg1[-32:]

    # user receives the message and processes it
    decrypted_msg1 = node.open_record(head1, encrypted_msg1)
    print(f"Received at Node: {decrypted_msg1}")

    # attacker replays the message to node
    print("Attacker replays the message to Node...")
    try: 
        decrypted_msg1 = node.open_record(head1, bytes(encrypted_msg1))
        print(f"Decrypted message at Node: {decrypted_msg1}")
    except ValueError as e:
        print(f"Tampering detected: {e}")

    