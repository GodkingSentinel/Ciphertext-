from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import base64

def derive_key(password, salt, iterations=100000):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(input_file, output_file, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(iv)  # Write the IV at the beginning of the file
        while True:
            chunk = f_in.read(64 * 1024)
            if not chunk:
                break
            padded_chunk = padder.update(chunk)
            f_out.write(encryptor.update(padded_chunk))
        final_padding = padder.finalize()
        f_out.write(encryptor.update(final_padding))
        f_out.write(encryptor.finalize())

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        iv = f_in.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        while True:
            chunk = f_in.read(64 * 1024)
            if not chunk:
                break
            decrypted_chunk = decryptor.update(chunk)
            unpadded_chunk = unpadder.update(decrypted_chunk)
            f_out.write(unpadded_chunk)
        f_out.write(unpadder.finalize())
        f_out.write(decryptor.finalize())