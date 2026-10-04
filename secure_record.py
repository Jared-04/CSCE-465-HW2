from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, struct, hashlib, hmac

def seal(k_enc, k_mac, session_id, head_info, plaintext):
    # create header
    v_byte = struct.pack('>B', head_info['version'])
    d_byte = struct.pack('>B', head_info['direction'])
    sq_bytes = struct.pack('>Q', head_info['sequence'])
    msg_t_byte = struct.pack('>B', head_info['message_type'])

    # create IV
    iv = session_id + sq_bytes

    # encrypt plaintext
    cipher = Cipher(algorithms.AES(k_enc), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    ct_len = struct.pack('>I', len(ciphertext))

    # finish header
    header = v_byte + d_byte + sq_bytes + msg_t_byte + ct_len

    # compute tag
    tag = hmac.new(k_mac, header + iv + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag, tag

def open_record(k_enc, k_mac, session_id, expected_header, expected_tag, record):
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
    iv = session_id + record[2:10]
    tag = hmac.new(k_mac, record[:15] + iv + record[15:15+ct_len], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Tag mismatch")

    # decrypt ciphertext
    ciphertext = record[15:15+ct_len]
    cipher = Cipher(algorithms.AES(k_enc), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def main():
    # Example usage
    k_enc = os.urandom(32)  
    k_mac = os.urandom(32)  
    session_id = os.urandom(8)  

    head_info = {
        'version': 1,
        'direction': 0,  
        'sequence': 1,
        'message_type': 1
    }

    plaintext = b"Hello, this is a secure message."

    # Seal the record
    sealed_record, tag = seal(k_enc, k_mac, session_id, head_info, plaintext)
    print("Sealed record:", sealed_record.hex())
    print("Tag:", tag.hex())

    # Open the record
    plaintext = open_record(k_enc, k_mac, session_id, head_info, tag, sealed_record)
    print("Decrypted plaintext:", plaintext.decode('utf-8'))

if __name__ == "__main__":
    main()