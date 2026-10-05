from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from secure_record import Session

'''
This is the test for the valid handshake with bidirectional communication.

1. Gateway initiates handshake with Node.
2. Node responds to handshake with Gateway.
3. Gateway finalizes handshake with Node.
4. Gateway sends a secure record to Node.
5. Node opens the secure record and verifies the contents.
6. Node sends a secure record to Gateway.
7. Gateway opens the secure record and verifies the contents.
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
    decrypted_msg1 = node.open_record(head1, encrypted_msg1)
    print(f"Sent from Gateway: {msg}")
    print(f"Received at Node: {decrypted_msg1}")

    # node to gateway exchange
    msg2 = b"Message to gateway..."
    head2 = {
        'version': 1,
        'direction': 1, 
        'message_type': 1
    }
    encrypted_msg2 = node.seal(head2, msg2)
    tag2 = encrypted_msg2[-32:]
    decrypted_msg2 = gateway.open_record(head2, encrypted_msg2)
    print(f"Sent from Node: {msg2}")
    print(f"Received at Gateway: {decrypted_msg2}")