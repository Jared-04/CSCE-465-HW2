from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, struct, hashlib, hmac

class Session:
    def __init__(self, k_enc, k_mac, session_id, direction):
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.session_id = session_id
        self.direction = direction

        self.send_sequence = 0
        self.recv_sequence = 0

    def seal(self, head_info, plaintext):
        # create header
        v_byte = struct.pack('>B', head_info['version'])
        d_byte = struct.pack('>B', head_info['direction'])
        sq_bytes = struct.pack('>Q', head_info['sequence'])
        msg_t_byte = struct.pack('>B', head_info['message_type'])

        # create IV
        iv = self.session_id + sq_bytes

        # encrypt plaintext
        cipher = Cipher(algorithms.AES(self.k_enc), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        ct_len = struct.pack('>I', len(ciphertext))

        # finish header
        header = v_byte + d_byte + sq_bytes + msg_t_byte + ct_len

        # compute tag
        tag = hmac.new(self.k_mac, header + iv + ciphertext, hashlib.sha256).digest()

        self.send_sequence += 1

        return header + ciphertext + tag

    def open_record(self, expected_header, record):
        # parse header
        v_byte = struct.unpack('>B', record[0:1])[0]
        d_byte = struct.unpack('>B', record[1:2])[0]
        sq_bytes = struct.unpack('>Q', record[2:10])[0]
        msg_t_byte = struct.unpack('>B', record[10:11])[0]
        ct_len = struct.unpack('>I', record[11:15])[0]

        if v_byte != expected_header['version']:
            raise ValueError("Version mismatch")
        if d_byte != expected_header['direction']:
            raise ValueError("Direction mismatch")
        if sq_bytes != expected_header['sequence']:
            raise ValueError("Sequence mismatch")
        if msg_t_byte != expected_header['message_type']:
            raise ValueError("Message type mismatch")

        # compute tag and verify
        iv = self.session_id + record[2:10]
        tag = hmac.new(self.k_mac, record[:15] + iv + record[15:15+ct_len], hashlib.sha256).digest()
        if not hmac.compare_digest(tag, record[-32:]):
            raise ValueError("Tag mismatch")

        # decrypt ciphertext
        ciphertext = record[15:15+ct_len]
        cipher = Cipher(algorithms.AES(self.k_enc), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        self.recv_sequence += 1

        return plaintext

def main():
    # Example usage
    k_enc = os.urandom(32)  
    k_mac = os.urandom(32)  
    session_id = os.urandom(8)  

    gateway = Session(k_enc, k_mac, session_id, direction=0)
    node = Session(k_enc, k_mac, session_id, direction=1)

    head_info = {
        'version': 1,
        'direction': 0,  
        'sequence': 1,
        'message_type': 1
    }

    plaintext = b"Hello, this is a secure message."

    # Seal the record
    sealed_record = gateway.seal(head_info, plaintext)
    print("Sealed record:", sealed_record.hex())

    # Open the record
    plaintext = node.open_record(head_info, sealed_record)
    print("Decrypted plaintext:", plaintext.decode('utf-8'))

if __name__ == "__main__":
    main()