import time
import os
import importlib.util
import numpy as np
import math

# Function to measure Shannon entropy (Randomness of ciphertext)

def shannon_entropy(data):
    if len(data) == 0:
        return 0  # No data means entropy is 0

    byte_counts = {byte: data.count(byte) for byte in set(data)}
    total_bytes = len(data)
    
    return -sum((count / total_bytes) * math.log2(count / total_bytes) 
                for count in byte_counts.values() if count > 0)  # Skip zero counts


# Function to modify ciphertext slightly and check decryption
def bitflip_resilience(decrypt_fn, secret_key, ciphertext):
    if isinstance(ciphertext, tuple):  # Lattice-based ciphertext (tuple of arrays)
        modified_ciphertext = (bytearray(ciphertext[0]), bytearray(ciphertext[1]))
        modified_ciphertext[1][0] ^= 1  # Flip one bit
    else:  # ECC ciphertext (bytes)
        modified_ciphertext = bytearray(ciphertext)
        modified_ciphertext[0] ^= 1  # Flip one bit

    try:
        decrypted = decrypt_fn(secret_key, modified_ciphertext)
        return decrypted != message  # If decryption fails, it's resilient
    except:
        return True  # If error occurs, it means corruption detected (good)

# Load Crypto1 (Lattice-based)
crypto1_path = "Crypto1.py"
spec1 = importlib.util.spec_from_file_location("crypto1", crypto1_path)
crypto1 = importlib.util.module_from_spec(spec1)
spec1.loader.exec_module(crypto1)

# Load Crypto2 (ECC-based)
crypto2_path = "Crypto2.py"
spec2 = importlib.util.spec_from_file_location("crypto2", crypto2_path)
crypto2 = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(crypto2)

# Test message
message = 10  # Example plaintext

### 🏗️ LATTICE-BASED ENCRYPTION (Crypto1.py) ###
lattice_public, lattice_secret = crypto1.keygen()

start_time = time.time()
lattice_cipher = crypto1.encrypt(lattice_public, message)
lattice_encrypt_time = time.time() - start_time

start_time = time.time()
lattice_decrypted = crypto1.decrypt(lattice_secret, lattice_cipher)
lattice_decrypt_time = time.time() - start_time

lattice_cipher_size = sum(x.nbytes for x in lattice_cipher)  # Total bytes of ciphertext
lattice_entropy = shannon_entropy(lattice_cipher[1].tobytes())  # Measure entropy
lattice_bitflip_resilience = bitflip_resilience(crypto1.decrypt, lattice_secret, lattice_cipher)

### 🏗️ ECC ENCRYPTION (Crypto2.py) ###
ecc_private = crypto2.ECC.generate(curve="P-256")
ecc_public = ecc_private.public_key()

start_time = time.time()
ecc_cipher = crypto2.ecc_encrypt(ecc_public, message)
ecc_encrypt_time = time.time() - start_time

start_time = time.time()
ecc_decrypted = crypto2.ecc_decrypt(ecc_private, *ecc_cipher)
ecc_decrypt_time = time.time() - start_time

ecc_cipher_size = len(ecc_cipher)  # Ciphertext size in bytes
ecc_entropy = shannon_entropy(ecc_cipher)  # Measure entropy
ecc_bitflip_resilience = bitflip_resilience(crypto2.ecc_decrypt, ecc_private, ecc_cipher)

### 📊 COMPARISON RESULTS ###
print("\n🔍 Comparison Results:")
print(f"✅ Original Message: {message}")
print(f"🛡️ Lattice Decrypted: {lattice_decrypted} | ECC Decrypted: {ecc_decrypted}")
print(f"⏱️ Lattice Encryption Time: {lattice_encrypt_time:.6f}s | ECC Encryption Time: {ecc_encrypt_time:.6f}s")
print(f"⏳ Lattice Decryption Time: {lattice_decrypt_time:.6f}s | ECC Decryption Time: {ecc_decrypt_time:.6f}s")
print(f"📦 Lattice Cipher Size: {lattice_cipher_size} bytes | ECC Cipher Size: {ecc_cipher_size} bytes")
print(f"🔐 Lattice Key Size: {lattice_secret.nbytes * 8} bits | ECC Key Size: 256 bits")
print(f"🎲 Lattice Cipher Entropy: {lattice_entropy:.2f} | ECC Cipher Entropy: {ecc_entropy:.2f}")
print(f"🛡️ Lattice Bitflip Resilience: {lattice_bitflip_resilience} | ECC Bitflip Resilience: {ecc_bitflip_resilience}")
print(f"Lattice Ciphertext (Bytes): {lattice_cipher[1].tobytes().hex()}")
print(f"Byte Distribution: {[lattice_cipher[1].tobytes().count(byte) for byte in set(lattice_cipher[1].tobytes())]}")
