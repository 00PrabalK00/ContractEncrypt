from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import binascii
import re
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

# Generate ECC Key Pair
def generate_ecc_key():
    private_key = ECC.generate(curve="P-256")  # Using secp256r1
    public_key = private_key.public_key()
    return private_key, public_key

# Key Derivation using ECDH
def derive_shared_secret(private_key, public_key):
    shared_x = private_key.d * public_key.pointQ  # Perform ECDH key agreement
    shared_secret = SHA256.new(shared_x.x.to_bytes()).digest()  # Hash to create AES key
    return shared_secret[:16]  # AES key (16 bytes)

# AES Encryption (CBC Mode)
def ecc_encrypt(public_key, message):
    message_bytes = message.to_bytes(2, byteorder='big')  # Convert int to bytes
    padded_message = message_bytes.ljust(16, b'\0')  # Pad to 16 bytes
    iv = get_random_bytes(16)  # Initialization vector
    key = derive_shared_secret(private_key, public_key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_message)
    return iv, ciphertext

# AES Decryption
def ecc_decrypt(private_key, iv, ciphertext):
    key = derive_shared_secret(private_key, public_key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(ciphertext).rstrip(b'\0')  # Remove padding
    return int.from_bytes(decrypted_bytes, byteorder='big')

# Run ECC Encryption/Decryption
private_key, public_key = generate_ecc_key()
message = 10  # Test message
iv, ciphertext = ecc_encrypt(public_key, message)
decrypted_message = ecc_decrypt(private_key, iv, ciphertext)

# Print formatted output for easier parsing
print(f"Original Message: {message}")
print(f"Decrypted Message: {decrypted_message}")
print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}\n")

# Extractable ECC parameters
ecc_public_key = public_key.export_key(format='OpenSSH')
ecc_prime = ECC._curves['P-256'].p  # Get prime modulus

print(f"ECC Public Key: {ecc_public_key}")
print(f"ECC Prime (Curve Modulus): {ecc_prime}")

# Quantum Attack (Simulated)
def shor_circuit(n):
    print(f"\n🔹 Running Simulated Quantum Attack on {n} (ECC Prime)...")

    backend = AerSimulator()
    qc = QuantumCircuit(4, 4)
    qc.h([0, 1, 2])
    qc.cx(2, 3)
    qc.measure([0, 1, 2], [0, 1, 2])

    # Simulate the quantum circuit
    result = backend.run(qc).result()
    counts = result.get_counts()

    print("\n🔹 Quantum Measurement Results:", counts)

# Run attack only if ECC prime is extracted
if ecc_prime:
    shor_circuit(ecc_prime)
else:
    print("\n❌ Failed to extract ECC Prime.")
