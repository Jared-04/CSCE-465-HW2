from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def aes_encrypt(plain_t, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    cipher_t = encryptor.update(plain_t) + encryptor.finalize()
    return cipher_t

def aes_decrypt(cipher_t, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plain_t = decryptor.update(cipher_t) + decryptor.finalize()
    return plain_t

def relay(cipher_t):
    # relay attack to change READ to COPY
    # construct a value to XOR only READ with READ ^ COPY
    s_read = b"READ"
    s_copy = b"COPY"
    # we assume the attacker knows the position of READ command
    lead_b = b"\x00" * 11
    tail_b = b"\x00" * 21
    xor_b = bytes(r^c for r,c in zip(s_read,s_copy))
    relay_val = lead_b + xor_b + tail_b
    # perform cipher text XOR relay value
    mal_cipher_t = bytes(c^r for c,r in zip(cipher_t,relay_val))
    return mal_cipher_t

def main():
    command = b'{"action":"READ","path":"notes.txt"}'
    key = os.urandom(32)
    iv = os.urandom(16)
    print(f"User 1 encrypts command: {command.decode('utf-8')}")
    cipher_t = aes_encrypt(command, key, iv)
    print(f"User 1 sends {cipher_t.hex()} to User 2")
    print("Attacker intercepts, wants to change READ to COPY")
    mal_cipher_t = relay(cipher_t)
    print(f"Attacker changes ciphertext to {mal_cipher_t.hex()}")
    mod_t = aes_decrypt(mal_cipher_t, key, iv)
    print(f"This malicious ciphertext User 2 receives decrypts to {mod_t.decode('utf-8')}")
    print("The attacker then resends the same ciphertext to replay the action")
    replay_t = aes_decrypt(mal_cipher_t, key, iv)
    print(f"User 2 decrypts and acts on the same command again: {replay_t.decode('utf-8')}")


if __name__ == "__main__":
    main()
